import argparse
import io
import json
import os
import secrets
import sqlite3
import tarfile
import threading
import time
import zipfile
from pathlib import Path

from aiohttp import WSMsgType, web


@web.middleware
async def cors_middleware(request: web.Request, handler):
    if request.method == 'OPTIONS':
        response = web.Response(status=204)
    else:
        response = await handler(request)

    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET,POST,PUT,PATCH,DELETE,OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
    return response


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='FLEX agent registry')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8780)
    parser.add_argument('--db-path', default=os.getenv('FLEX_DB_PATH', '/data/flex.db'))
    return parser.parse_args()


class RegistryState:
    def __init__(self, db_path: str) -> None:
        self.ui_clients: set[web.WebSocketResponse] = set()
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        self.last_cleanup_epoch = 0
        self._init_db()
        self._ensure_retention_settings()

    def _init_db(self) -> None:
        schema = '''
CREATE TABLE IF NOT EXISTS agents (
  agent_id TEXT PRIMARY KEY,
  agent_name TEXT NOT NULL,
  status TEXT NOT NULL,
  total_packets INTEGER NOT NULL DEFAULT 0,
  active_connections INTEGER NOT NULL DEFAULT 0,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  hostname TEXT,
  platform TEXT
);

CREATE TABLE IF NOT EXISTS assets (
  ip TEXT PRIMARY KEY,
  label TEXT,
  role TEXT NOT NULL DEFAULT 'Unknown',
  criticality TEXT NOT NULL DEFAULT 'normal',
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  last_agent_id TEXT
);

CREATE TABLE IF NOT EXISTS connections (
  connection_key TEXT PRIMARY KEY,
  connection_id TEXT NOT NULL,
  src_ip TEXT NOT NULL,
  dst_ip TEXT NOT NULL,
  protocol TEXT NOT NULL,
  port INTEGER NOT NULL,
  packets INTEGER NOT NULL,
  bytes_per_sec REAL NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  last_agent_id TEXT NOT NULL,
  last_agent_name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS diff_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,
  message TEXT NOT NULL,
  connection_key TEXT NOT NULL,
  src_ip TEXT NOT NULL,
  dst_ip TEXT NOT NULL,
  protocol TEXT NOT NULL,
  port INTEGER NOT NULL,
  agent_id TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tokens (
  token TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
'''
        with self.lock:
            self.db.executescript(schema)
            self.db.commit()

    def _ensure_retention_settings(self) -> None:
        default_connection_days = str(max(1, int(os.getenv('FLEX_CONNECTION_RETENTION_DAYS', '30'))))
        default_event_days = str(max(1, int(os.getenv('FLEX_EVENT_RETENTION_DAYS', '14'))))
        with self.lock:
            connection_row = self.db.execute('SELECT value FROM settings WHERE key = ?', ('connection_retention_days',)).fetchone()
            if connection_row is None:
                self.db.execute('INSERT INTO settings(key, value) VALUES(?, ?)', ('connection_retention_days', default_connection_days))
            event_row = self.db.execute('SELECT value FROM settings WHERE key = ?', ('event_retention_days',)).fetchone()
            if event_row is None:
                self.db.execute('INSERT INTO settings(key, value) VALUES(?, ?)', ('event_retention_days', default_event_days))
            legacy_row = self.db.execute('SELECT value FROM settings WHERE key = ?', ('packet_retention_days',)).fetchone()
            if legacy_row is not None:
                self.db.execute(
                    'INSERT OR REPLACE INTO settings(key, value) VALUES(?, ?)',
                    ('event_retention_days', legacy_row['value']),
                )
                self.db.execute('DELETE FROM settings WHERE key = ?', ('packet_retention_days',))
                self.db.commit()

    def close(self) -> None:
        with self.lock:
            self.db.close()

    def query_all(self, sql: str, params: tuple = ()) -> list[dict]:
        with self.lock:
            rows = self.db.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    def query_one(self, sql: str, params: tuple = ()):
        with self.lock:
            row = self.db.execute(sql, params).fetchone()
        return dict(row) if row else None

    def execute(self, sql: str, params: tuple = ()) -> None:
        with self.lock:
            self.db.execute(sql, params)
            self.db.commit()

    def execute_many(self, sql: str, seq_of_params: list[tuple]) -> None:
        with self.lock:
            self.db.executemany(sql, seq_of_params)
            self.db.commit()

    def get_retention_policy(self) -> dict:
        connection_days_row = self.query_one('SELECT value FROM settings WHERE key = ?', ('connection_retention_days',))
        event_days_row = self.query_one('SELECT value FROM settings WHERE key = ?', ('event_retention_days',))
        try:
            connection_days = max(1, int(connection_days_row['value'])) if connection_days_row else 30
        except (TypeError, ValueError):
            connection_days = 30
        try:
            event_days = max(1, int(event_days_row['value'])) if event_days_row else 14
        except (TypeError, ValueError):
            event_days = 14
        return {'connection_retention_days': connection_days, 'event_retention_days': event_days}

    def set_retention_policy(self, connection_days: int | None = None, event_days: int | None = None) -> dict:
        if connection_days is not None:
            safe_connection_days = max(1, min(connection_days, 3650))
            self.execute(
                'INSERT OR REPLACE INTO settings(key, value) VALUES(?, ?)',
                ('connection_retention_days', str(safe_connection_days)),
            )
        if event_days is not None:
            safe_event_days = max(1, min(event_days, 3650))
            self.execute(
                'INSERT OR REPLACE INTO settings(key, value) VALUES(?, ?)',
                ('event_retention_days', str(safe_event_days)),
            )
        return self.get_retention_policy()

    def purge_packet_data(self, connection_days: int, event_days: int) -> dict:
        connection_cutoff = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() - connection_days * 24 * 60 * 60))
        event_cutoff = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() - event_days * 24 * 60 * 60))
        with self.lock:
            conn_deleted = self.db.execute('DELETE FROM connections WHERE last_seen < ?', (connection_cutoff,)).rowcount
            diff_deleted = self.db.execute('DELETE FROM diff_events WHERE created_at < ?', (event_cutoff,)).rowcount
            self.db.commit()
        return {
            'deleted_connections': conn_deleted,
            'deleted_diffs': diff_deleted,
            'connection_cutoff': connection_cutoff,
            'event_cutoff': event_cutoff,
        }

    def clear_packet_data(self, target: str) -> dict:
        with self.lock:
            deleted_connections = 0
            deleted_diffs = 0
            if target in ('all', 'connections'):
                deleted_connections = self.db.execute('DELETE FROM connections').rowcount
            if target in ('all', 'diffs'):
                deleted_diffs = self.db.execute('DELETE FROM diff_events').rowcount
            self.db.commit()
        return {'deleted_connections': deleted_connections, 'deleted_diffs': deleted_diffs}

    def delete_selected_packet_data(self, connection_keys: list[str], diff_ids: list[int]) -> dict:
        with self.lock:
            deleted_connections = 0
            deleted_diffs = 0
            if connection_keys:
                placeholders = ','.join(['?'] * len(connection_keys))
                deleted_connections = self.db.execute(
                    f'DELETE FROM connections WHERE connection_key IN ({placeholders})', tuple(connection_keys)
                ).rowcount
            if diff_ids:
                placeholders = ','.join(['?'] * len(diff_ids))
                deleted_diffs = self.db.execute(f'DELETE FROM diff_events WHERE id IN ({placeholders})', tuple(diff_ids)).rowcount
            self.db.commit()
        return {'deleted_connections': deleted_connections, 'deleted_diffs': deleted_diffs}


def _infer_asset_role(protocol: str, is_source: bool) -> str:
    industrial = {'Modbus/TCP', 'PROFINET', 'EtherNet/IP', 'OPC UA', 'DNP3', 'IEC 104'}
    if protocol in industrial:
        return 'HMI/SCADA Candidate' if is_source else 'PLC/Controller Candidate'
    if protocol in {'DNS', 'NTP'}:
        return 'Infra Service' if not is_source else 'Client Node'
    return 'Client Node' if is_source else 'Service Endpoint'


def _prefer_role(current: str, candidate: str) -> str:
    priority = {
        'Unknown': 0,
        'Client Node': 1,
        'Service Endpoint': 2,
        'Infra Service': 3,
        'HMI/SCADA Candidate': 4,
        'PLC/Controller Candidate': 5,
    }
    if priority.get(candidate, 0) > priority.get(current, 0):
        return candidate
    return current


async def _on_shutdown(app: web.Application) -> None:
    state: RegistryState = app['state']
    state.close()


def _utc_now() -> str:
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


def _build_windows_zip() -> bytes:
    base_dir = Path('/app')
    agent_script = (base_dir / 'packet-agent' / 'agent.py').read_text(encoding='utf-8')
    req = (base_dir / 'packet-agent' / 'requirements.txt').read_text(encoding='utf-8')
    bootstrap = """@echo off
setlocal
if not exist .venv (
  python -m venv .venv
)
call .venv\\Scripts\\activate.bat
pip install -r requirements.txt
python agent.py config
python agent.py install-service
endlocal
"""

    body = io.BytesIO()
    with zipfile.ZipFile(body, mode='w', compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('agent.py', agent_script)
        archive.writestr('requirements.txt', req)
        archive.writestr('setup-agent.cmd', bootstrap)
        archive.writestr(
            'README.txt',
            '1) setup-agent.cmd を実行\n2) 画面で発行したトークンを入力\n3) Windowsサービス(FLEXAgent)として自動登録\n',
        )
    return body.getvalue()


def _build_linux_tar() -> bytes:
    base_dir = Path('/app')
    agent_script = (base_dir / 'packet-agent' / 'agent.py').read_text(encoding='utf-8')
    req = (base_dir / 'packet-agent' / 'requirements.txt').read_text(encoding='utf-8')
    bootstrap = """#!/usr/bin/env bash
set -euo pipefail
if [ ! -d .venv ]; then
  python3 -m venv .venv
fi
source .venv/bin/activate
pip install -r requirements.txt
python agent.py config
sudo python agent.py install-service
"""

    body = io.BytesIO()
    with tarfile.open(fileobj=body, mode='w:gz') as archive:
        files = {
            'agent.py': agent_script.encode('utf-8'),
            'requirements.txt': req.encode('utf-8'),
            'setup-agent.sh': bootstrap.encode('utf-8'),
            'README.txt': '1) ./setup-agent.sh 実行\n2) トークン入力\n3) systemdサービス登録\n'.encode('utf-8'),
        }
        for name, content in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            info.mode = 0o755 if name.endswith('.sh') else 0o644
            archive.addfile(info, io.BytesIO(content))
    return body.getvalue()


async def _broadcast_ui(state: RegistryState, message: dict) -> None:
    if not state.ui_clients:
        return

    body = json.dumps(message)
    disconnected: list[web.WebSocketResponse] = []
    for client in state.ui_clients:
        try:
            await client.send_str(body)
        except Exception:
            disconnected.append(client)

    for client in disconnected:
        state.ui_clients.discard(client)


async def issue_token(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    payload = await request.json() if request.can_read_body else {}
    ttl = int(payload.get('ttl_minutes', 15) or 15)
    ttl = max(1, min(ttl, 1440))

    token = secrets.token_urlsafe(24)
    expires_at = int(time.time()) + ttl * 60
    state.execute('INSERT OR REPLACE INTO tokens(token, expires_at, created_at) VALUES (?, ?, ?)', (token, expires_at, int(time.time())))

    base_http = f"{request.scheme}://{request.host}"
    ws_scheme = 'wss' if request.scheme == 'https' else 'ws'
    base_ws = f'{ws_scheme}://{request.host}'

    return web.json_response(
        {
            'token': token,
            'expires_at': expires_at,
            'registry_http_url': base_http,
            'registry_ws_agent_url': f'{base_ws}/ws/agent',
            'download': {
                'windows': f'{base_http}/api/download/windows',
                'linux': f'{base_http}/api/download/linux',
            },
        }
    )


async def register_agent(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    payload = await request.json()
    token = str(payload.get('token', '')).strip()
    agent_name = str(payload.get('agent_name', '')).strip() or 'Unnamed Agent'

    if not token:
        return web.json_response({'error': 'token required'}, status=400)

    token_row = state.query_one('SELECT expires_at FROM tokens WHERE token = ?', (token,))
    expires_at = token_row['expires_at'] if token_row else None
    if expires_at is None:
        return web.json_response({'error': 'invalid token'}, status=400)

    if expires_at <= int(time.time()):
        state.execute('DELETE FROM tokens WHERE token = ?', (token,))
        return web.json_response({'error': 'token expired'}, status=400)

    state.execute('DELETE FROM tokens WHERE token = ?', (token,))

    agent_id = f"agent-{secrets.token_hex(5)}"
    ws_scheme = 'wss' if request.scheme == 'https' else 'ws'
    upstream_url = f'{ws_scheme}://{request.host}/ws/agent'

    return web.json_response(
        {
            'agent_id': agent_id,
            'agent_name': agent_name,
            'upstream_url': upstream_url,
            'issued_at': _utc_now(),
        }
    )


def _load_topology_snapshot(state: RegistryState, diff_limit: int = 200) -> dict:
    agents = state.query_all('SELECT * FROM agents ORDER BY last_seen DESC')
    assets = state.query_all('SELECT * FROM assets ORDER BY last_seen DESC')
    connections = state.query_all('SELECT * FROM connections ORDER BY last_seen DESC LIMIT 2000')
    diffs = state.query_all('SELECT * FROM diff_events ORDER BY id DESC LIMIT ?', (diff_limit,))
    retention_policy = state.get_retention_policy()
    return {
        'agents': agents,
        'assets': assets,
        'connections': connections,
        'diffs': diffs,
        'timestamp': _utc_now(),
        **retention_policy,
    }


async def get_snapshot(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    return web.json_response(_load_topology_snapshot(state))


async def get_assets(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    return web.json_response({'assets': state.query_all('SELECT * FROM assets ORDER BY last_seen DESC')})


async def patch_asset(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    ip = request.match_info['ip']
    payload = await request.json() if request.can_read_body else {}
    existing = state.query_one('SELECT * FROM assets WHERE ip = ?', (ip,))
    if not existing:
        return web.json_response({'error': 'asset not found'}, status=404)

    label = payload.get('label', existing['label'])
    role = payload.get('role', existing['role'])
    criticality = payload.get('criticality', existing['criticality'])
    state.execute('UPDATE assets SET label = ?, role = ?, criticality = ? WHERE ip = ?', (label, role, criticality, ip))
    return web.json_response({'asset': state.query_one('SELECT * FROM assets WHERE ip = ?', (ip,))})


async def delete_asset(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    ip = request.match_info['ip']
    existing = state.query_one('SELECT ip FROM assets WHERE ip = ?', (ip,))
    if not existing:
        return web.json_response({'error': 'asset not found'}, status=404)
    state.execute('DELETE FROM assets WHERE ip = ?', (ip,))
    await _broadcast_ui(state, {'type': 'topology_snapshot', 'payload': _load_topology_snapshot(state)})
    return web.json_response({'deleted_ip': ip})


async def delete_selected_assets(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    payload = await request.json() if request.can_read_body else {}
    ips = payload.get('ips', [])
    if not isinstance(ips, list):
        return web.json_response({'error': 'ips must be array'}, status=400)
    safe_ips = [str(ip).strip() for ip in ips if str(ip).strip()]
    if not safe_ips:
        return web.json_response({'deleted_count': 0})

    placeholders = ','.join(['?'] * len(safe_ips))
    with state.lock:
        deleted_count = state.db.execute(f'DELETE FROM assets WHERE ip IN ({placeholders})', tuple(safe_ips)).rowcount
        state.db.commit()

    await _broadcast_ui(state, {'type': 'topology_snapshot', 'payload': _load_topology_snapshot(state)})
    return web.json_response({'deleted_count': deleted_count})


async def clear_assets(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    with state.lock:
        deleted_count = state.db.execute('DELETE FROM assets').rowcount
        state.db.commit()
    await _broadcast_ui(state, {'type': 'topology_snapshot', 'payload': _load_topology_snapshot(state)})
    return web.json_response({'deleted_count': deleted_count})


async def initialize_assets(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    with state.lock:
        updated_count = state.db.execute(
            """
            UPDATE assets
            SET label = NULL,
                role = 'Unknown',
                criticality = 'normal'
            """
        ).rowcount
        state.db.commit()
    await _broadcast_ui(state, {'type': 'topology_snapshot', 'payload': _load_topology_snapshot(state)})
    return web.json_response({'initialized_count': updated_count})


async def get_diffs(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    try:
        limit = max(1, min(int(request.query.get('limit', '200')), 1000))
    except ValueError:
        limit = 200
    rows = state.query_all('SELECT * FROM diff_events ORDER BY id DESC LIMIT ?', (limit,))
    return web.json_response({'diffs': rows})


async def get_retention_policy(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    return web.json_response(state.get_retention_policy())


async def put_retention_policy(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    payload = await request.json() if request.can_read_body else {}
    connection_days = None
    event_days = None

    try:
        if 'connection_retention_days' in payload:
            connection_days = int(payload.get('connection_retention_days'))
        if 'event_retention_days' in payload:
            event_days = int(payload.get('event_retention_days'))
    except (TypeError, ValueError):
        return web.json_response({'error': 'retention days must be integer'}, status=400)

    applied = state.set_retention_policy(connection_days=connection_days, event_days=event_days)
    cleanup = state.purge_packet_data(applied['connection_retention_days'], applied['event_retention_days'])
    return web.json_response({**applied, 'cleanup': cleanup})


async def clear_packets(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    payload = await request.json() if request.can_read_body else {}
    target = str(payload.get('target', 'all')).strip().lower()
    if target not in ('all', 'connections', 'diffs'):
        return web.json_response({'error': 'target must be all|connections|diffs'}, status=400)
    deleted = state.clear_packet_data(target)
    await _broadcast_ui(state, {'type': 'topology_snapshot', 'payload': _load_topology_snapshot(state)})
    return web.json_response({'target': target, **deleted})


async def delete_selected_packets(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    payload = await request.json() if request.can_read_body else {}
    connection_keys = payload.get('connection_keys', [])
    diff_ids = payload.get('diff_ids', [])
    if not isinstance(connection_keys, list) or not isinstance(diff_ids, list):
        return web.json_response({'error': 'connection_keys and diff_ids must be arrays'}, status=400)
    safe_connection_keys = [str(item) for item in connection_keys if str(item).strip()]
    safe_diff_ids: list[int] = []
    for item in diff_ids:
        try:
            safe_diff_ids.append(int(item))
        except (TypeError, ValueError):
            continue
    deleted = state.delete_selected_packet_data(safe_connection_keys, safe_diff_ids)
    await _broadcast_ui(state, {'type': 'topology_snapshot', 'payload': _load_topology_snapshot(state)})
    return web.json_response(deleted)


async def download_windows(_: web.Request) -> web.Response:
    body = _build_windows_zip()
    return web.Response(
        body=body,
        headers={
            'Content-Type': 'application/zip',
            'Content-Disposition': 'attachment; filename="flex-agent-windows.zip"',
        },
    )


async def download_linux(_: web.Request) -> web.Response:
    body = _build_linux_tar()
    return web.Response(
        body=body,
        headers={
            'Content-Type': 'application/gzip',
            'Content-Disposition': 'attachment; filename="flex-agent-linux.tar.gz"',
        },
    )


async def ws_ui(request: web.Request) -> web.WebSocketResponse:
    state: RegistryState = request.app['state']
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    state.ui_clients.add(ws)

    await ws.send_str(json.dumps({'type': 'topology_snapshot', 'payload': _load_topology_snapshot(state)}))

    try:
        async for message in ws:
            if message.type == WSMsgType.ERROR:
                break
    finally:
        state.ui_clients.discard(ws)

    return ws


async def ws_agent(request: web.Request) -> web.WebSocketResponse:
    state: RegistryState = request.app['state']
    ws = web.WebSocketResponse()
    await ws.prepare(request)

    bound_agent_id: str | None = None
    bound_agent_name = 'Unknown Agent'

    try:
        async for message in ws:
            if message.type != WSMsgType.TEXT:
                continue

            try:
                body = json.loads(message.data)
            except Exception:
                continue

            msg_type = body.get('type')
            payload = body.get('payload', {})
            if not isinstance(payload, dict):
                payload = {}

            agent_id = str(payload.get('agent_id', '')).strip() or bound_agent_id
            agent_name = str(payload.get('agent_name', '')).strip() or 'Unknown Agent'

            if msg_type in ('hello', 'heartbeat') and agent_id:
                bound_agent_id = agent_id
                bound_agent_name = agent_name
                state_payload = {
                    'agent_id': agent_id,
                    'agent_name': agent_name,
                    'status': 'connected',
                    'total_packets': int(payload.get('total_packets', 0) or 0),
                    'active_connections': int(payload.get('active_connections', 0) or 0),
                    'last_seen': payload.get('timestamp') or _utc_now(),
                }
                now = _utc_now()
                existing = state.query_one('SELECT first_seen FROM agents WHERE agent_id = ?', (agent_id,))
                first_seen = existing['first_seen'] if existing else now
                state.execute(
                    '''
                    INSERT OR REPLACE INTO agents(
                        agent_id, agent_name, status, total_packets, active_connections, first_seen, last_seen, hostname, platform
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''',
                    (
                        agent_id,
                        agent_name,
                        'connected',
                        state_payload['total_packets'],
                        state_payload['active_connections'],
                        first_seen,
                        state_payload['last_seen'],
                        str(payload.get('hostname', '')),
                        str(payload.get('platform', '')),
                    ),
                )
                await _broadcast_ui(state, {'type': 'registry_agent_update', 'payload': state_payload})

            if msg_type == 'connection_update' and bound_agent_id:
                now_epoch = int(time.time())
                if now_epoch - state.last_cleanup_epoch >= 60:
                    state.last_cleanup_epoch = now_epoch
                    policy = state.get_retention_policy()
                    state.purge_packet_data(policy['connection_retention_days'], policy['event_retention_days'])

                enriched = {
                    **payload,
                    'agent_id': bound_agent_id,
                    'agent_name': bound_agent_name,
                }
                src_ip = str(enriched.get('src_ip', '')).strip()
                dst_ip = str(enriched.get('dst_ip', '')).strip()
                protocol = str(enriched.get('protocol', '')).strip() or 'Unknown'
                port = int(enriched.get('port', 0) or 0)
                packets = int(enriched.get('packets', 0) or 0)
                bytes_per_sec = float(enriched.get('bytes_per_sec', 0) or 0)
                last_seen = str(enriched.get('last_seen', '')).strip() or _utc_now()
                connection_id = str(enriched.get('connection_id', '')).strip() or f'{src_ip}|{dst_ip}|{protocol}|{port}'
                connection_key = f'{src_ip}|{dst_ip}|{protocol}|{port}'

                existing_connection = state.query_one('SELECT first_seen FROM connections WHERE connection_key = ?', (connection_key,))
                first_seen = existing_connection['first_seen'] if existing_connection else last_seen
                state.execute(
                    '''
                    INSERT OR REPLACE INTO connections(
                      connection_key, connection_id, src_ip, dst_ip, protocol, port, packets, bytes_per_sec, first_seen, last_seen, last_agent_id, last_agent_name
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''',
                    (
                        connection_key,
                        connection_id,
                        src_ip,
                        dst_ip,
                        protocol,
                        port,
                        packets,
                        bytes_per_sec,
                        first_seen,
                        last_seen,
                        bound_agent_id,
                        bound_agent_name,
                    ),
                )

                for ip, is_source in ((src_ip, True), (dst_ip, False)):
                    if not ip:
                        continue
                    existing_asset = state.query_one('SELECT role, first_seen FROM assets WHERE ip = ?', (ip,))
                    candidate_role = _infer_asset_role(protocol, is_source)
                    if existing_asset:
                        role = _prefer_role(existing_asset['role'], candidate_role)
                        asset_first_seen = existing_asset['first_seen']
                    else:
                        role = candidate_role
                        asset_first_seen = last_seen
                    state.execute(
                        '''
                        INSERT OR REPLACE INTO assets(ip, label, role, criticality, first_seen, last_seen, last_agent_id)
                        VALUES(
                          ?,
                          COALESCE((SELECT label FROM assets WHERE ip = ?), NULL),
                          ?,
                          COALESCE((SELECT criticality FROM assets WHERE ip = ?), 'normal'),
                          ?, ?, ?
                        )
                        ''',
                        (ip, ip, role, ip, asset_first_seen, last_seen, bound_agent_id),
                    )

                if existing_connection is None:
                    message_text = f'New flow discovered: {protocol} {src_ip} -> {dst_ip} (port {port})'
                    state.execute(
                        '''
                        INSERT INTO diff_events(event_type, message, connection_key, src_ip, dst_ip, protocol, port, agent_id, created_at)
                        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''',
                        ('new_connection', message_text, connection_key, src_ip, dst_ip, protocol, port, bound_agent_id, _utc_now()),
                    )
                    await _broadcast_ui(
                        state,
                        {
                            'type': 'connection_diff',
                            'payload': {
                                'event_type': 'new_connection',
                                'message': message_text,
                                'connection_key': connection_key,
                                'src_ip': src_ip,
                                'dst_ip': dst_ip,
                                'protocol': protocol,
                                'port': port,
                                'agent_id': bound_agent_id,
                                'created_at': _utc_now(),
                            },
                        },
                    )

                await _broadcast_ui(state, {'type': 'connection_update', 'payload': enriched})
    finally:
        if bound_agent_id:
            existing_agent = state.query_one('SELECT * FROM agents WHERE agent_id = ?', (bound_agent_id,))
            if existing_agent:
                disconnected_payload = {
                    'agent_id': bound_agent_id,
                    'agent_name': existing_agent['agent_name'],
                    'status': 'disconnected',
                    'total_packets': existing_agent['total_packets'],
                    'active_connections': existing_agent['active_connections'],
                    'last_seen': _utc_now(),
                }
                state.execute(
                    'UPDATE agents SET status = ?, last_seen = ? WHERE agent_id = ?',
                    ('disconnected', disconnected_payload['last_seen'], bound_agent_id),
                )
                await _broadcast_ui(state, {'type': 'registry_agent_update', 'payload': disconnected_payload})

    return ws


def build_app(db_path: str) -> web.Application:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    app = web.Application(middlewares=[cors_middleware])
    app['state'] = RegistryState(db_path)
    app.on_shutdown.append(_on_shutdown)

    app.router.add_post('/api/tokens', issue_token)
    app.router.add_post('/api/register', register_agent)
    app.router.add_get('/api/topology/snapshot', get_snapshot)
    app.router.add_get('/api/assets', get_assets)
    app.router.add_patch('/api/assets/{ip}', patch_asset)
    app.router.add_delete('/api/assets/{ip}', delete_asset)
    app.router.add_post('/api/assets/delete-selected', delete_selected_assets)
    app.router.add_post('/api/assets/clear', clear_assets)
    app.router.add_post('/api/assets/initialize', initialize_assets)
    app.router.add_get('/api/diffs', get_diffs)
    app.router.add_get('/api/retention-policy', get_retention_policy)
    app.router.add_put('/api/retention-policy', put_retention_policy)
    app.router.add_post('/api/packets/clear', clear_packets)
    app.router.add_post('/api/packets/delete-selected', delete_selected_packets)
    app.router.add_get('/api/download/windows', download_windows)
    app.router.add_get('/api/download/linux', download_linux)
    app.router.add_route('OPTIONS', '/api/tokens', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/register', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/topology/snapshot', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/assets', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/assets/{ip}', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/assets/delete-selected', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/assets/clear', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/assets/initialize', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/diffs', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/retention-policy', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/packets/clear', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/packets/delete-selected', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/download/windows', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/download/linux', lambda _: web.Response(status=204))
    app.router.add_get('/ws/ui', ws_ui)
    app.router.add_get('/ws/agent', ws_agent)
    app.router.add_get('/api/health', lambda _: web.json_response({'status': 'ok', 'timestamp': _utc_now()}))

    return app


def main() -> None:
    args = parse_args()
    web.run_app(build_app(args.db_path), host=args.host, port=args.port)


if __name__ == '__main__':
    main()
