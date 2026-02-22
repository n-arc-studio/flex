import argparse
import asyncio
import csv
import hashlib
import hmac
import importlib
import ipaddress
import io
import json
import os
import secrets
import sqlite3
import tarfile
import threading
import time
import urllib.request
import urllib.error
import zipfile
from pathlib import Path

from aiohttp import WSMsgType, web


OUI_VENDOR_MAP = {
    '00:1A:79': 'Siemens',
    '00:0E:8C': 'Schneider Electric',
    '00:1B:1B': 'Rockwell Automation',
    '00:30:DE': 'Mitsubishi Electric',
    '00:80:F4': 'Yokogawa',
}

INDUSTRIAL_PROTOCOLS = {'Modbus/TCP', 'PROFINET', 'EtherNet/IP', 'OPC UA', 'DNP3', 'IEC 104'}
SEVERITY_LEVELS = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
DEFAULT_ESCALATION_MINUTES = {'low': 0, 'medium': 120, 'high': 30, 'critical': 10}
DEFAULT_INTEGRATION_RETRY_BASE_SECONDS = 5
DEFAULT_INTEGRATION_RETRY_MAX_SECONDS = 300
DEFAULT_INTEGRATION_MAX_ATTEMPTS = 6
DEFAULT_INTEGRATION_DEDUP_TTL_SECONDS = 86400
DEFAULT_INBOUND_NONCE_TTL_SECONDS = 600
DEFAULT_QUEUE_ARCHIVE_AFTER_HOURS = 24
_BCRYPT = None


def _bcrypt_module():
    global _BCRYPT
    if _BCRYPT is None:
        _BCRYPT = importlib.import_module('bcrypt')
    return _BCRYPT


def _normalize_mac(mac: str) -> str:
    raw = ''.join(c for c in str(mac).upper() if c in '0123456789ABCDEF')
    if len(raw) != 12:
        return ''
    return ':'.join(raw[i:i + 2] for i in range(0, 12, 2))


def _vendor_from_mac(mac: str) -> str | None:
    normalized = _normalize_mac(mac)
    if not normalized:
        return None
    return OUI_VENDOR_MAP.get(normalized[:8])


def _infer_device_type(protocol: str, port: int, is_source: bool) -> tuple[str, float]:
    if protocol in {'PROFINET', 'EtherNet/IP'}:
        return ('PLC', 0.88) if not is_source else ('HMI/SCADA', 0.72)
    if protocol == 'Modbus/TCP':
        if port == 502 and not is_source:
            return ('PLC', 0.93)
        return ('HMI/SCADA', 0.76)
    if protocol == 'OPC UA':
        return ('OT Server', 0.78) if not is_source else ('HMI/SCADA', 0.7)
    if protocol in {'DNS', 'NTP'}:
        return ('Infra Service', 0.82) if not is_source else ('Client Node', 0.6)
    return ('Service Endpoint', 0.55) if not is_source else ('Client Node', 0.55)


def _severity_from_score(score: int) -> str:
    if score >= 80:
        return 'critical'
    if score >= 55:
        return 'high'
    if score >= 30:
        return 'medium'
    return 'low'


def _risk_score(protocol: str, port: int, src_criticality: str, dst_criticality: str, is_new_connection: bool) -> int:
    score = 15
    if protocol in INDUSTRIAL_PROTOCOLS:
        score += 25
    if port in (502, 102, 44818, 2222, 4840):
        score += 20
    if src_criticality in {'high', 'critical'}:
        score += 15
    if dst_criticality in {'high', 'critical'}:
        score += 20
    if is_new_connection:
        score += 15
    return max(0, min(100, score))


def _hash_password(password: str) -> str:
    if not password:
        raise ValueError('password required')
    bcrypt_mod = _bcrypt_module()
    return bcrypt_mod.hashpw(password.encode('utf-8'), bcrypt_mod.gensalt(rounds=12)).decode('utf-8')


def _verify_password(password: str, password_hash: str) -> bool:
    if not password or not password_hash:
        return False
    try:
        bcrypt_mod = _bcrypt_module()
        return bcrypt_mod.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    except Exception:
        return False


def _extract_bearer_token(request: web.Request) -> str:
    auth_header = request.headers.get('Authorization', '').strip()
    if auth_header.lower().startswith('bearer '):
        return auth_header[7:].strip()
    token_query = str(request.query.get('token', '')).strip()
    return token_query


def _actor_from_request(state: 'RegistryState', request: web.Request) -> dict:
    token = _extract_bearer_token(request)
    if not token:
        return {'username': 'anonymous', 'role': 'viewer', 'must_change_password': False}
    session = state.query_one(
        '''
        SELECT s.username, u.role, u.must_change_password
        FROM sessions s
        JOIN users u ON u.username = s.username
        WHERE s.token = ? AND s.expires_at > ?
        ''',
        (token, int(time.time())),
    )
    if not session:
        return {'username': 'anonymous', 'role': 'viewer', 'must_change_password': False}
    return {
        'username': session['username'],
        'role': session['role'],
        'must_change_password': bool(session.get('must_change_password', 0)),
    }


def _require_role(state: 'RegistryState', request: web.Request, minimum: str = 'operator') -> tuple[bool, dict]:
    actor = _actor_from_request(state, request)
    if actor.get('username') == 'anonymous':
        return False, actor
    role_order = {'viewer': 1, 'operator': 2, 'admin': 3}
    if role_order.get(actor['role'], 0) < role_order.get(minimum, 0):
        return False, actor
    return True, actor


def _audit_log(state: 'RegistryState', actor: str, action: str, target: str, details: dict | None = None) -> None:
    state.execute(
        '''
        INSERT INTO audit_logs(actor, action, target, details_json, created_at)
        VALUES(?, ?, ?, ?, ?)
        ''',
        (actor, action, target, json.dumps(details or {}, ensure_ascii=False), _utc_now()),
    )


def _json_dumps(payload: dict) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def _build_signature(secret: str, timestamp: str, body_text: str) -> str:
    signed = f'{timestamp}.{body_text}'.encode('utf-8')
    return hmac.new(secret.encode('utf-8'), signed, hashlib.sha256).hexdigest()


def _build_event_dedup_key(event_type: str, payload: dict) -> str:
    for key in ('external_id', 'ticket_id', 'alert_id', 'diff_event_id', 'connection_key', 'id'):
        value = payload.get(key)
        if value not in (None, ''):
            return f'{event_type}:{key}:{value}'
    digest = hashlib.sha256(_json_dumps(payload).encode('utf-8')).hexdigest()
    return f'{event_type}:hash:{digest}'


def _send_webhook(url: str, payload: dict, api_key: str | None = None) -> tuple[bool, str]:
    if not url:
        return False, 'webhook empty'
    try:
        body_text = _json_dumps(payload)
        body = body_text.encode('utf-8')
        headers = {'Content-Type': 'application/json'}
        if api_key:
            timestamp = str(int(time.time()))
            headers['X-Flex-Timestamp'] = timestamp
            headers['X-Flex-Signature'] = f'v1={_build_signature(api_key, timestamp, body_text)}'
            headers['X-Flex-Key-Id'] = 'integration-api-key'
            headers['X-API-Key'] = api_key
        request = urllib.request.Request(url, data=body, headers=headers, method='POST')
        with urllib.request.urlopen(request, timeout=3):
            pass
        return True, 'ok'
    except urllib.error.HTTPError as exc:
        return False, f'http_error:{exc.code}'
    except Exception as exc:
        return False, f'error:{exc}'


def _queue_integration_delivery(state: 'RegistryState', integration: dict, event_type: str, payload: dict) -> tuple[bool, str]:
    now_epoch = int(time.time())
    dedup_key = _build_event_dedup_key(event_type, payload)
    existing = state.query_one(
        '''
        SELECT id FROM integration_dedup
        WHERE integration_id = ? AND dedup_key = ? AND expires_at > ?
        ''',
        (integration['id'], dedup_key, now_epoch),
    )
    if existing:
        return False, 'duplicate'

    expires_at = now_epoch + int(os.getenv('FLEX_INTEGRATION_DEDUP_TTL_SECONDS', str(DEFAULT_INTEGRATION_DEDUP_TTL_SECONDS)))
    now_utc = _utc_now()
    payload_json = _json_dumps(payload)
    state.execute(
        '''
        INSERT INTO integration_dedup(integration_id, dedup_key, expires_at, created_at)
        VALUES(?, ?, ?, ?)
        ''',
        (integration['id'], dedup_key, expires_at, now_utc),
    )
    state.execute(
        '''
        INSERT INTO integration_delivery_queue(
            integration_id, event_type, payload_json, dedup_key,
            status, attempt_count, next_retry_at, created_at, updated_at
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''',
        (integration['id'], event_type, payload_json, dedup_key, 'queued', 0, now_epoch, now_utc, now_utc),
    )
    return True, 'queued'


def _drain_integration_delivery_queue(state: 'RegistryState', limit: int = 50) -> dict:
    now_epoch = int(time.time())
    rows = state.query_all(
        '''
        SELECT q.*, i.endpoint_url, i.api_key, i.name
        FROM integration_delivery_queue q
        JOIN integrations i ON i.id = q.integration_id
        WHERE q.status = 'queued' AND q.next_retry_at <= ? AND i.enabled = 1
        ORDER BY q.id ASC
        LIMIT ?
        ''',
        (now_epoch, max(1, min(limit, 500))),
    )
    if not rows:
        return {'processed': 0, 'delivered': 0, 'failed': 0, 'dead': 0}

    base_delay = max(1, int(os.getenv('FLEX_INTEGRATION_BACKOFF_BASE_SECONDS', str(DEFAULT_INTEGRATION_RETRY_BASE_SECONDS))))
    max_delay = max(base_delay, int(os.getenv('FLEX_INTEGRATION_BACKOFF_MAX_SECONDS', str(DEFAULT_INTEGRATION_RETRY_MAX_SECONDS))))
    max_attempts = max(1, int(os.getenv('FLEX_INTEGRATION_MAX_ATTEMPTS', str(DEFAULT_INTEGRATION_MAX_ATTEMPTS))))
    processed = 0
    delivered = 0
    failed = 0
    dead = 0
    for row in rows:
        processed += 1
        payload = json.loads(row['payload_json']) if row.get('payload_json') else {}
        ok, status_text = _send_webhook(row['endpoint_url'], payload, row.get('api_key'))
        attempt_count = int(row['attempt_count'] or 0) + 1
        now_utc = _utc_now()
        if ok:
            delivered += 1
            state.execute(
                '''
                UPDATE integration_delivery_queue
                SET status = ?, attempt_count = ?, last_error = ?, last_attempt_at = ?, updated_at = ?
                WHERE id = ?
                ''',
                ('delivered', attempt_count, None, now_utc, now_utc, row['id']),
            )
            state.execute(
                'UPDATE integrations SET last_status = ?, last_synced_at = ? WHERE id = ?',
                ('ok', now_utc, row['integration_id']),
            )
            continue

        failed += 1
        if attempt_count >= max_attempts:
            dead += 1
            queue_status = 'dead'
            next_retry = 0
        else:
            queue_status = 'queued'
            backoff = min(max_delay, base_delay * (2 ** (attempt_count - 1)))
            jitter = secrets.randbelow(base_delay + 1)
            next_retry = int(time.time()) + backoff + jitter
        state.execute(
            '''
            UPDATE integration_delivery_queue
            SET status = ?, attempt_count = ?, next_retry_at = ?, last_error = ?, last_attempt_at = ?, updated_at = ?
            WHERE id = ?
            ''',
            (queue_status, attempt_count, next_retry, status_text, now_utc, now_utc, row['id']),
        )
        state.execute(
            'UPDATE integrations SET last_status = ?, last_synced_at = ? WHERE id = ?',
            (f'failed:{status_text}', now_utc, row['integration_id']),
        )

    state.execute('DELETE FROM integration_dedup WHERE expires_at <= ?', (int(time.time()),))
    _archive_integration_queue(state)
    return {'processed': processed, 'delivered': delivered, 'failed': failed, 'dead': dead}


def _archive_integration_queue(state: 'RegistryState', older_than_hours: int | None = None) -> int:
    keep_hours = older_than_hours if older_than_hours is not None else int(
        os.getenv('FLEX_INTEGRATION_ARCHIVE_AFTER_HOURS', str(DEFAULT_QUEUE_ARCHIVE_AFTER_HOURS))
    )
    keep_hours = max(1, min(keep_hours, 24 * 365))
    cutoff_epoch = int(time.time()) - keep_hours * 3600
    rows = state.query_all(
        '''
        SELECT * FROM integration_delivery_queue
        WHERE status IN ('delivered', 'dead', 'cancelled')
          AND (strftime('%s', updated_at) <= ?)
        ORDER BY id ASC
        LIMIT 1000
        ''',
        (cutoff_epoch,),
    )
    if not rows:
        return 0
    archived = 0
    for row in rows:
        state.execute(
            '''
            INSERT INTO integration_delivery_archive(
                queue_id, integration_id, event_type, payload_json, dedup_key,
                status, attempt_count, last_error, last_attempt_at, archived_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            (
                row['id'],
                row['integration_id'],
                row['event_type'],
                row['payload_json'],
                row['dedup_key'],
                row['status'],
                row['attempt_count'],
                row['last_error'],
                row['last_attempt_at'],
                _utc_now(),
            ),
        )
        state.execute('DELETE FROM integration_delivery_queue WHERE id = ?', (row['id'],))
        archived += 1
    return archived


def _dispatch_integration(state: 'RegistryState', integration: dict, event_type: str, payload: dict) -> tuple[bool, str]:
    body = {
        'type': event_type,
        'source': 'flex',
        'integration': integration['name'],
        'payload': payload,
        'timestamp': _utc_now(),
    }
    queued, queue_status = _queue_integration_delivery(state, integration, event_type, body)
    if not queued and queue_status == 'duplicate':
        state.execute(
            'UPDATE integrations SET last_status = ?, last_synced_at = ? WHERE id = ?',
            ('duplicate_dropped', _utc_now(), integration['id']),
        )
    return queued, queue_status


def _dispatch_integration_by_id(state: 'RegistryState', integration_id: int, event_type: str, payload: dict) -> tuple[bool, str]:
    integration = state.query_one(
        "SELECT * FROM integrations WHERE id = ? AND enabled = 1 AND direction IN ('outbound','both')",
        (integration_id,),
    )
    if not integration:
        return False, 'integration_not_available'
    return _dispatch_integration(state, integration, event_type, payload)


def _parse_mapping(raw: str | None) -> dict:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _mapped_value(payload: dict, mapping: dict, key: str, default_keys: list[str], default_value=None):
    candidate = mapping.get(key)
    if isinstance(candidate, str) and candidate.strip():
        value = payload.get(candidate.strip())
        if value not in (None, ''):
            return value
    for default_key in default_keys:
        value = payload.get(default_key)
        if value not in (None, ''):
            return value
    return default_value


def _dispatch_integrations(state: 'RegistryState', event_type: str, payload: dict) -> None:
    integrations = state.query_all(
        "SELECT * FROM integrations WHERE enabled = 1 AND direction IN ('outbound','both') ORDER BY id ASC"
    )
    for integration in integrations:
        _dispatch_integration(state, integration, event_type, payload)
    _drain_integration_delivery_queue(state, limit=100)


def _apply_escalation_rules(state: 'RegistryState') -> None:
    policies = state.query_all('SELECT * FROM escalation_policies ORDER BY id ASC')
    if not policies:
        return
    policy_map = {p['severity']: p for p in policies}
    open_alerts = state.query_all("SELECT * FROM alerts WHERE status = 'open' ORDER BY id ASC")
    now_epoch = int(time.time())
    for alert in open_alerts:
        policy = policy_map.get(alert['severity'])
        if not policy:
            continue
        threshold_minutes = int(policy['threshold_minutes'])
        if threshold_minutes <= 0:
            continue
        created_epoch = int(time.mktime(time.strptime(alert['created_at'], '%Y-%m-%dT%H:%M:%SZ')))
        elapsed_minutes = (now_epoch - created_epoch) // 60
        if elapsed_minutes < threshold_minutes:
            continue
        already = state.query_one(
            'SELECT id FROM escalation_events WHERE alert_id = ? AND policy_id = ?',
            (alert['id'], policy['id']),
        )
        if already:
            continue
        state.execute(
            '''
            INSERT INTO escalation_events(alert_id, policy_id, severity, channel, target, status, created_at)
            VALUES(?, ?, ?, ?, ?, ?, ?)
            ''',
            (alert['id'], policy['id'], alert['severity'], policy['channel'], policy['target'], 'triggered', _utc_now()),
        )
        _dispatch_integrations(
            state,
            'alert.escalated',
            {
                'alert_id': alert['id'],
                'severity': alert['severity'],
                'channel': policy['channel'],
                'target': policy['target'],
                'elapsed_minutes': elapsed_minutes,
            },
        )


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


def _required_role_for_path(path: str, method: str) -> str | None:
    if path == '/api/health':
        return None
    if path == '/api/auth/login':
        return None
    if path == '/api/register' and method == 'POST':
        return None
    if path.startswith('/api/inbound/') and method == 'POST':
        return None
    if path.startswith('/api/auth/'):
        return 'viewer'
    if path.startswith('/api/users'):
        return 'admin'
    if path.startswith('/api/'):
        return 'operator'
    return None


@web.middleware
async def auth_middleware(request: web.Request, handler):
    if request.method == 'OPTIONS':
        return await handler(request)
    required_role = _required_role_for_path(request.path, request.method)
    if required_role is None:
        return await handler(request)
    state: RegistryState = request.app['state']
    ok, actor = _require_role(state, request, required_role)
    if not ok:
        return web.json_response({'error': 'unauthorized'}, status=401)
    if actor.get('must_change_password') and request.path not in {'/api/auth/change-password', '/api/auth/me', '/api/auth/logout'}:
        return web.json_response({'error': 'password_change_required'}, status=403)
    request['actor'] = actor
    return await handler(request)


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
        self._migrate_db()
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
    platform TEXT,
    ws_token TEXT,
    ws_token_expires INTEGER
);

CREATE TABLE IF NOT EXISTS assets (
  ip TEXT PRIMARY KEY,
  label TEXT,
  role TEXT NOT NULL DEFAULT 'Unknown',
  criticality TEXT NOT NULL DEFAULT 'normal',
    mac TEXT,
    vendor TEXT,
    device_type TEXT,
    identify_confidence REAL NOT NULL DEFAULT 0,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
    last_agent_id TEXT,
    last_protocol_seen TEXT
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
    severity TEXT NOT NULL DEFAULT 'low',
    risk_score INTEGER NOT NULL DEFAULT 0,
    triage_status TEXT NOT NULL DEFAULT 'open',
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

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    diff_event_id INTEGER NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    assignee TEXT,
    note TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    details_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS integrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    provider TEXT NOT NULL,
    endpoint_url TEXT NOT NULL,
    api_key TEXT,
    inbound_mapping_json TEXT NOT NULL DEFAULT '{}',
    outbound_mapping_json TEXT NOT NULL DEFAULT '{}',
    direction TEXT NOT NULL DEFAULT 'outbound',
    enabled INTEGER NOT NULL DEFAULT 1,
    last_status TEXT,
    last_synced_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runbooks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    severity TEXT NOT NULL,
    owner TEXT,
    steps TEXT NOT NULL,
    escalation_minutes INTEGER NOT NULL DEFAULT 30,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS escalation_policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    severity TEXT NOT NULL,
    threshold_minutes INTEGER NOT NULL,
    channel TEXT NOT NULL,
    target TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS escalation_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER NOT NULL,
    policy_id INTEGER NOT NULL,
    severity TEXT NOT NULL,
    channel TEXT NOT NULL,
    target TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS integration_delivery_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    integration_id INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    dedup_key TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_retry_at INTEGER NOT NULL,
    last_error TEXT,
    last_attempt_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS integration_dedup (
    integration_id INTEGER NOT NULL,
    dedup_key TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (integration_id, dedup_key)
);

CREATE TABLE IF NOT EXISTS inbound_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    integration_id INTEGER NOT NULL,
    source TEXT NOT NULL,
    event_type TEXT NOT NULL,
    external_id TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    details_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(integration_id, event_type, external_id)
);

CREATE TABLE IF NOT EXISTS inbound_replay_guard (
    integration_id INTEGER NOT NULL,
    nonce TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (integration_id, nonce)
);

CREATE TABLE IF NOT EXISTS external_ticket_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    integration_id INTEGER NOT NULL,
    alert_id INTEGER NOT NULL,
    external_id TEXT NOT NULL,
    source TEXT,
    last_status TEXT,
    updated_at TEXT NOT NULL,
    UNIQUE(integration_id, alert_id, external_id)
);

CREATE TABLE IF NOT EXISTS integration_delivery_archive (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    queue_id INTEGER NOT NULL,
    integration_id INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    dedup_key TEXT NOT NULL,
    status TEXT NOT NULL,
    attempt_count INTEGER NOT NULL,
    last_error TEXT,
    last_attempt_at TEXT,
    archived_at TEXT NOT NULL
);
'''
        with self.lock:
            self.db.executescript(schema)
            self.db.commit()

    def _migrate_db(self) -> None:
        def add_column_if_missing(table: str, column: str, definition: str) -> None:
            cols = {row['name'] for row in self.db.execute(f'PRAGMA table_info({table})').fetchall()}
            if column not in cols:
                self.db.execute(f'ALTER TABLE {table} ADD COLUMN {column} {definition}')

        with self.lock:
            add_column_if_missing('agents', 'ws_token', 'TEXT')
            add_column_if_missing('agents', 'ws_token_expires', 'INTEGER')
            add_column_if_missing('assets', 'mac', 'TEXT')
            add_column_if_missing('assets', 'vendor', 'TEXT')
            add_column_if_missing('assets', 'device_type', 'TEXT')
            add_column_if_missing('assets', 'identify_confidence', 'REAL NOT NULL DEFAULT 0')
            add_column_if_missing('assets', 'last_protocol_seen', 'TEXT')
            add_column_if_missing('diff_events', 'severity', "TEXT NOT NULL DEFAULT 'low'")
            add_column_if_missing('diff_events', 'risk_score', 'INTEGER NOT NULL DEFAULT 0')
            add_column_if_missing('diff_events', 'triage_status', "TEXT NOT NULL DEFAULT 'open'")
            add_column_if_missing('users', 'must_change_password', 'INTEGER NOT NULL DEFAULT 0')
            add_column_if_missing('integrations', 'inbound_mapping_json', "TEXT NOT NULL DEFAULT '{}'")
            add_column_if_missing('integrations', 'outbound_mapping_json', "TEXT NOT NULL DEFAULT '{}'")
            self.db.execute(
                '''
                CREATE TABLE IF NOT EXISTS alerts (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  diff_event_id INTEGER NOT NULL,
                  severity TEXT NOT NULL,
                  status TEXT NOT NULL DEFAULT 'open',
                  assignee TEXT,
                  note TEXT,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL
                )
                '''
            )
            self.db.execute(
                '''
                CREATE TABLE IF NOT EXISTS users (
                  username TEXT PRIMARY KEY,
                  password_hash TEXT NOT NULL,
                  role TEXT NOT NULL,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL
                )
                '''
            )
            self.db.execute(
                '''
                CREATE TABLE IF NOT EXISTS sessions (
                  token TEXT PRIMARY KEY,
                  username TEXT NOT NULL,
                  expires_at INTEGER NOT NULL,
                  created_at INTEGER NOT NULL
                )
                '''
            )
            self.db.execute(
                '''
                CREATE TABLE IF NOT EXISTS audit_logs (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  actor TEXT NOT NULL,
                  action TEXT NOT NULL,
                  target TEXT NOT NULL,
                  details_json TEXT NOT NULL,
                  created_at TEXT NOT NULL
                )
                '''
            )
            self.db.execute(
                '''
                CREATE TABLE IF NOT EXISTS integrations (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  provider TEXT NOT NULL,
                  endpoint_url TEXT NOT NULL,
                  api_key TEXT,
                                    inbound_mapping_json TEXT NOT NULL DEFAULT '{}',
                                    outbound_mapping_json TEXT NOT NULL DEFAULT '{}',
                  direction TEXT NOT NULL DEFAULT 'outbound',
                  enabled INTEGER NOT NULL DEFAULT 1,
                  last_status TEXT,
                  last_synced_at TEXT,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL
                )
                '''
            )
            self.db.execute(
                '''
                CREATE TABLE IF NOT EXISTS runbooks (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  severity TEXT NOT NULL,
                  owner TEXT,
                  steps TEXT NOT NULL,
                  escalation_minutes INTEGER NOT NULL DEFAULT 30,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL
                )
                '''
            )
            self.db.execute(
                '''
                CREATE TABLE IF NOT EXISTS escalation_policies (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  severity TEXT NOT NULL,
                  threshold_minutes INTEGER NOT NULL,
                  channel TEXT NOT NULL,
                  target TEXT NOT NULL,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL
                )
                '''
            )
            self.db.execute(
                '''
                CREATE TABLE IF NOT EXISTS escalation_events (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  alert_id INTEGER NOT NULL,
                  policy_id INTEGER NOT NULL,
                  severity TEXT NOT NULL,
                  channel TEXT NOT NULL,
                  target TEXT NOT NULL,
                  status TEXT NOT NULL,
                  created_at TEXT NOT NULL
                )
                '''
            )
            self.db.execute(
                '''
                CREATE TABLE IF NOT EXISTS integration_delivery_queue (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  integration_id INTEGER NOT NULL,
                  event_type TEXT NOT NULL,
                  payload_json TEXT NOT NULL,
                  dedup_key TEXT NOT NULL,
                  status TEXT NOT NULL DEFAULT 'queued',
                  attempt_count INTEGER NOT NULL DEFAULT 0,
                  next_retry_at INTEGER NOT NULL,
                  last_error TEXT,
                  last_attempt_at TEXT,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL
                )
                '''
            )
            self.db.execute(
                '''
                CREATE TABLE IF NOT EXISTS integration_dedup (
                  integration_id INTEGER NOT NULL,
                  dedup_key TEXT NOT NULL,
                  expires_at INTEGER NOT NULL,
                  created_at TEXT NOT NULL,
                  PRIMARY KEY (integration_id, dedup_key)
                )
                '''
            )
            self.db.execute(
                '''
                CREATE TABLE IF NOT EXISTS inbound_events (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  integration_id INTEGER NOT NULL,
                  source TEXT NOT NULL,
                  event_type TEXT NOT NULL,
                  external_id TEXT NOT NULL,
                  payload_hash TEXT NOT NULL,
                  details_json TEXT NOT NULL,
                  created_at TEXT NOT NULL,
                  UNIQUE(integration_id, event_type, external_id)
                )
                '''
            )
            self.db.execute(
                '''
                CREATE TABLE IF NOT EXISTS inbound_replay_guard (
                  integration_id INTEGER NOT NULL,
                  nonce TEXT NOT NULL,
                  expires_at INTEGER NOT NULL,
                  created_at TEXT NOT NULL,
                  PRIMARY KEY (integration_id, nonce)
                )
                '''
            )
            self.db.execute(
                '''
                CREATE TABLE IF NOT EXISTS external_ticket_links (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  integration_id INTEGER NOT NULL,
                  alert_id INTEGER NOT NULL,
                  external_id TEXT NOT NULL,
                  source TEXT,
                  last_status TEXT,
                  updated_at TEXT NOT NULL,
                  UNIQUE(integration_id, alert_id, external_id)
                )
                '''
            )
            self.db.execute(
                '''
                CREATE TABLE IF NOT EXISTS integration_delivery_archive (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  queue_id INTEGER NOT NULL,
                  integration_id INTEGER NOT NULL,
                  event_type TEXT NOT NULL,
                  payload_json TEXT NOT NULL,
                  dedup_key TEXT NOT NULL,
                  status TEXT NOT NULL,
                  attempt_count INTEGER NOT NULL,
                  last_error TEXT,
                  last_attempt_at TEXT,
                  archived_at TEXT NOT NULL
                )
                '''
            )
            self.db.commit()

    def _ensure_retention_settings(self) -> None:
        default_connection_days = str(max(1, int(os.getenv('FLEX_CONNECTION_RETENTION_DAYS', '30'))))
        default_event_days = str(max(1, int(os.getenv('FLEX_EVENT_RETENTION_DAYS', '14'))))
        default_notify_min = str(max(0, min(int(os.getenv('FLEX_NOTIFY_MIN_RISK', '55')), 100)))
        with self.lock:
            connection_row = self.db.execute('SELECT value FROM settings WHERE key = ?', ('connection_retention_days',)).fetchone()
            if connection_row is None:
                self.db.execute('INSERT INTO settings(key, value) VALUES(?, ?)', ('connection_retention_days', default_connection_days))
            event_row = self.db.execute('SELECT value FROM settings WHERE key = ?', ('event_retention_days',)).fetchone()
            if event_row is None:
                self.db.execute('INSERT INTO settings(key, value) VALUES(?, ?)', ('event_retention_days', default_event_days))
            notify_row = self.db.execute('SELECT value FROM settings WHERE key = ?', ('notification_webhook',)).fetchone()
            if notify_row is None:
                self.db.execute('INSERT INTO settings(key, value) VALUES(?, ?)', ('notification_webhook', ''))
            notify_min_row = self.db.execute('SELECT value FROM settings WHERE key = ?', ('notification_min_risk',)).fetchone()
            if notify_min_row is None:
                self.db.execute('INSERT INTO settings(key, value) VALUES(?, ?)', ('notification_min_risk', default_notify_min))

            admin_row = self.db.execute('SELECT username FROM users WHERE username = ?', ('admin',)).fetchone()
            if admin_row is None:
                admin_password = os.getenv('FLEX_ADMIN_PASSWORD', '').strip()
                if len(admin_password) < 12:
                    raise RuntimeError('FLEX_ADMIN_PASSWORD is required and must be at least 12 characters on first startup')
                now = _utc_now()
                self.db.execute(
                    'INSERT INTO users(username, password_hash, role, must_change_password, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?)',
                    ('admin', _hash_password(admin_password), 'admin', 1, now, now),
                )

            policy_count = self.db.execute('SELECT COUNT(*) AS c FROM escalation_policies').fetchone()['c']
            if policy_count == 0:
                now = _utc_now()
                for severity in ('medium', 'high', 'critical'):
                    self.db.execute(
                        '''
                        INSERT INTO escalation_policies(severity, threshold_minutes, channel, target, created_at, updated_at)
                        VALUES(?, ?, ?, ?, ?, ?)
                        ''',
                        (
                            severity,
                            DEFAULT_ESCALATION_MINUTES[severity],
                            'email',
                            'ot-oncall@example.local',
                            now,
                            now,
                        ),
                    )

            runbook_count = self.db.execute('SELECT COUNT(*) AS c FROM runbooks').fetchone()['c']
            if runbook_count == 0:
                now = _utc_now()
                self.db.execute(
                    '''
                    INSERT INTO runbooks(name, severity, owner, steps, escalation_minutes, created_at, updated_at)
                    VALUES(?, ?, ?, ?, ?, ?, ?)
                    ''',
                    (
                        'Unknown OT Flow Triage',
                        'high',
                        'OT Team',
                        '1) Asset owner確認\n2) Change管理票照合\n3) 未承認なら遮断検討\n4) 証跡保存',
                        30,
                        now,
                        now,
                    ),
                )
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


def _safe_float(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _is_loopback_ip(ip_text: str) -> bool:
    try:
        return ipaddress.ip_address(str(ip_text)).is_loopback
    except ValueError:
        return False


def _dispatch_webhook(state: RegistryState, payload: dict) -> None:
    settings = state.query_one('SELECT value FROM settings WHERE key = ?', ('notification_webhook',))
    webhook_url = settings['value'].strip() if settings and settings.get('value') else ''
    if not webhook_url:
        return
    try:
        body = json.dumps(payload).encode('utf-8')
        request = urllib.request.Request(webhook_url, data=body, headers={'Content-Type': 'application/json'}, method='POST')
        with urllib.request.urlopen(request, timeout=2):
            pass
    except Exception:
        return


def _upsert_asset_with_identification(
    state: RegistryState,
    ip: str,
    is_source: bool,
    protocol: str,
    port: int,
    mac: str,
    last_seen: str,
    agent_id: str,
) -> dict | None:
    if not ip:
        return None
    existing_asset = state.query_one('SELECT * FROM assets WHERE ip = ?', (ip,))
    candidate_role = _infer_asset_role(protocol, is_source)
    inferred_type, inferred_confidence = _infer_device_type(protocol, port, is_source)
    vendor = _vendor_from_mac(mac)
    normalized_mac = _normalize_mac(mac)

    if existing_asset:
        role = _prefer_role(existing_asset['role'], candidate_role)
        first_seen = existing_asset['first_seen']
        current_confidence = _safe_float(existing_asset.get('identify_confidence'), 0.0)
        confidence = max(current_confidence, inferred_confidence)
        device_type = existing_asset.get('device_type') or inferred_type
        asset_vendor = existing_asset.get('vendor') or vendor
        asset_mac = existing_asset.get('mac') or normalized_mac
    else:
        role = candidate_role
        first_seen = last_seen
        confidence = inferred_confidence
        device_type = inferred_type
        asset_vendor = vendor
        asset_mac = normalized_mac

    state.execute(
        '''
        INSERT OR REPLACE INTO assets(
            ip, label, role, criticality, mac, vendor, device_type, identify_confidence,
            first_seen, last_seen, last_agent_id, last_protocol_seen
        ) VALUES(
            ?,
            COALESCE((SELECT label FROM assets WHERE ip = ?), NULL),
            ?,
            COALESCE((SELECT criticality FROM assets WHERE ip = ?), 'normal'),
            ?, ?, ?, ?, ?, ?, ?, ?
        )
        ''',
        (
            ip,
            ip,
            role,
            ip,
            asset_mac,
            asset_vendor,
            device_type,
            confidence,
            first_seen,
            last_seen,
            agent_id,
            protocol,
        ),
    )
    return state.query_one('SELECT * FROM assets WHERE ip = ?', (ip,))


def _build_audit_report(state: RegistryState, days: int) -> dict:
    days = max(1, min(days, 365))
    cutoff = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() - days * 24 * 60 * 60))
    totals = {
        'assets_total': state.query_one('SELECT COUNT(*) AS c FROM assets')['c'],
        'connections_total': state.query_one('SELECT COUNT(*) AS c FROM connections')['c'],
        'events_total': state.query_one('SELECT COUNT(*) AS c FROM diff_events WHERE created_at >= ?', (cutoff,))['c'],
        'alerts_open': state.query_one("SELECT COUNT(*) AS c FROM alerts WHERE status = 'open'")['c'],
        'alerts_ack': state.query_one("SELECT COUNT(*) AS c FROM alerts WHERE status = 'acknowledged'")['c'],
        'alerts_resolved': state.query_one("SELECT COUNT(*) AS c FROM alerts WHERE status = 'resolved'")['c'],
    }
    protocol_rows = state.query_all(
        '''
        SELECT protocol, COUNT(*) AS count
        FROM connections
        WHERE last_seen >= ?
        GROUP BY protocol
        ORDER BY count DESC
        ''',
        (cutoff,),
    )
    critical_assets = state.query_all(
        "SELECT ip, label, role, criticality, identify_confidence FROM assets WHERE criticality IN ('high','critical') ORDER BY last_seen DESC LIMIT 100"
    )
    recent_events = state.query_all(
        '''
        SELECT id, created_at, event_type, severity, risk_score, triage_status, message
        FROM diff_events
        WHERE created_at >= ?
        ORDER BY id DESC
        LIMIT 300
        ''',
        (cutoff,),
    )
    return {
        'generated_at': _utc_now(),
        'period_days': days,
        'cutoff': cutoff,
        'summary': totals,
        'protocol_distribution': protocol_rows,
        'critical_assets': critical_assets,
        'recent_events': recent_events,
    }


def _verify_signed_payload(headers, body_bytes: bytes, secret: str) -> tuple[bool, str, str, str]:
    if not secret:
        return False, 'integration api_key is required for signed inbound webhook', '', ''
    timestamp = str(headers.get('X-Flex-Timestamp', '')).strip()
    signature = str(headers.get('X-Flex-Signature', '')).strip()
    nonce = str(headers.get('X-Flex-Nonce', '')).strip()
    if not timestamp or not signature or not nonce:
        return False, 'missing signature headers', '', ''
    if signature.startswith('v1='):
        signature = signature[3:]
    try:
        ts_epoch = int(timestamp)
    except (TypeError, ValueError):
        return False, 'invalid timestamp', '', ''
    if abs(int(time.time()) - ts_epoch) > 300:
        return False, 'timestamp skew too large', '', ''
    body_text = body_bytes.decode('utf-8') if body_bytes else ''
    expected = _build_signature(secret, timestamp, body_text)
    if not hmac.compare_digest(signature, expected):
        return False, 'invalid signature', '', ''
    return True, 'ok', timestamp, nonce


def _check_and_store_inbound_nonce(state: 'RegistryState', integration_id: int, nonce: str, timestamp: str) -> tuple[bool, str]:
    try:
        ts_epoch = int(timestamp)
    except (TypeError, ValueError):
        return False, 'invalid timestamp'
    now_epoch = int(time.time())
    ttl = max(60, int(os.getenv('FLEX_INBOUND_NONCE_TTL_SECONDS', str(DEFAULT_INBOUND_NONCE_TTL_SECONDS))))
    expires_at = max(now_epoch + 1, ts_epoch + ttl)
    existing = state.query_one(
        'SELECT nonce FROM inbound_replay_guard WHERE integration_id = ? AND nonce = ? AND expires_at > ?',
        (integration_id, nonce, now_epoch),
    )
    if existing:
        return False, 'replay detected'
    state.execute(
        'INSERT OR REPLACE INTO inbound_replay_guard(integration_id, nonce, expires_at, created_at) VALUES(?, ?, ?, ?)',
        (integration_id, nonce, expires_at, _utc_now()),
    )
    state.execute('DELETE FROM inbound_replay_guard WHERE expires_at <= ?', (now_epoch,))
    return True, 'ok'


async def _integration_retry_loop(app: web.Application) -> None:
    state: RegistryState = app['state']
    while True:
        try:
            _drain_integration_delivery_queue(state, limit=100)
            await asyncio.sleep(5)
        except asyncio.CancelledError:
            break
        except Exception:
            await asyncio.sleep(5)


async def _on_startup(app: web.Application) -> None:
    app['integration_retry_task'] = asyncio.create_task(_integration_retry_loop(app))


async def _on_shutdown(app: web.Application) -> None:
    retry_task = app.get('integration_retry_task')
    if retry_task:
        retry_task.cancel()
        try:
            await retry_task
        except asyncio.CancelledError:
            pass
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
    agent_ws_token = secrets.token_urlsafe(32)
    agent_ws_expires = int(time.time()) + int(os.getenv('FLEX_AGENT_WS_TOKEN_TTL_SECONDS', '2592000'))
    ws_scheme = 'wss' if request.scheme == 'https' else 'ws'
    upstream_url = f'{ws_scheme}://{request.host}/ws/agent?agent_id={agent_id}&token={agent_ws_token}'
    now = _utc_now()
    state.execute(
        '''
        INSERT OR REPLACE INTO agents(
            agent_id, agent_name, status, total_packets, active_connections,
            first_seen, last_seen, hostname, platform, ws_token, ws_token_expires
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''',
        (
            agent_id,
            agent_name,
            'registered',
            0,
            0,
            now,
            now,
            str(payload.get('hostname', '')),
            str(payload.get('platform', '')),
            agent_ws_token,
            agent_ws_expires,
        ),
    )

    return web.json_response(
        {
            'agent_id': agent_id,
            'agent_name': agent_name,
            'upstream_url': upstream_url,
            'issued_at': _utc_now(),
        }
    )


async def login(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    payload = await request.json() if request.can_read_body else {}
    username = str(payload.get('username', '')).strip()
    password = str(payload.get('password', '')).strip()
    if not username or not password:
        return web.json_response({'error': 'username/password required'}, status=400)
    user = state.query_one('SELECT username, password_hash, role, must_change_password FROM users WHERE username = ?', (username,))
    if not user or not _verify_password(password, user['password_hash']):
        return web.json_response({'error': 'invalid credentials'}, status=401)
    token = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + int(os.getenv('FLEX_SESSION_TTL_SECONDS', '43200'))
    state.execute('INSERT OR REPLACE INTO sessions(token, username, expires_at, created_at) VALUES(?, ?, ?, ?)', (token, username, expires_at, int(time.time())))
    _audit_log(state, username, 'auth.login', f'user:{username}', {'expires_at': expires_at})
    return web.json_response(
        {
            'token': token,
            'username': username,
            'role': user['role'],
            'expires_at': expires_at,
            'must_change_password': bool(user.get('must_change_password', 0)),
        }
    )


async def logout(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    token = _extract_bearer_token(request)
    if token:
        session = state.query_one('SELECT username FROM sessions WHERE token = ?', (token,))
        state.execute('DELETE FROM sessions WHERE token = ?', (token,))
        if session:
            _audit_log(state, session['username'], 'auth.logout', f'user:{session["username"]}', {})
    return web.json_response({'status': 'ok'})


async def me(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    actor = _actor_from_request(state, request)
    return web.json_response(actor)


async def change_password(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    token = _extract_bearer_token(request)
    if not token:
        return web.json_response({'error': 'unauthorized'}, status=401)
    session = state.query_one('SELECT username FROM sessions WHERE token = ? AND expires_at > ?', (token, int(time.time())))
    if not session:
        return web.json_response({'error': 'unauthorized'}, status=401)
    payload = await request.json() if request.can_read_body else {}
    current_password = str(payload.get('current_password', '')).strip()
    new_password = str(payload.get('new_password', '')).strip()
    if len(new_password) < 12:
        return web.json_response({'error': 'new password must be at least 12 characters'}, status=400)
    user = state.query_one('SELECT username, password_hash FROM users WHERE username = ?', (session['username'],))
    if not user or not _verify_password(current_password, user['password_hash']):
        return web.json_response({'error': 'current password invalid'}, status=400)
    state.execute(
        'UPDATE users SET password_hash = ?, must_change_password = 0, updated_at = ? WHERE username = ?',
        (_hash_password(new_password), _utc_now(), session['username']),
    )
    state.execute('DELETE FROM sessions WHERE username = ?', (session['username'],))
    _audit_log(state, session['username'], 'auth.change_password', f'user:{session["username"]}', {})
    return web.json_response({'status': 'password_changed_relogin_required'})


async def get_users(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    ok, actor = _require_role(state, request, 'admin')
    if not ok:
        return web.json_response({'error': 'forbidden'}, status=403)
    rows = state.query_all('SELECT username, role, must_change_password, created_at, updated_at FROM users ORDER BY username ASC')
    _audit_log(state, actor['username'], 'users.list', 'users', {})
    return web.json_response({'users': rows})


async def upsert_user(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    ok, actor = _require_role(state, request, 'admin')
    if not ok:
        return web.json_response({'error': 'forbidden'}, status=403)
    payload = await request.json() if request.can_read_body else {}
    username = str(payload.get('username', '')).strip()
    password = str(payload.get('password', '')).strip()
    role = str(payload.get('role', 'viewer')).strip().lower()
    must_change = 1 if bool(payload.get('must_change_password', True)) else 0
    if role not in {'viewer', 'operator', 'admin'}:
        return web.json_response({'error': 'invalid role'}, status=400)
    if not username:
        return web.json_response({'error': 'username required'}, status=400)
    existing = state.query_one('SELECT username FROM users WHERE username = ?', (username,))
    now = _utc_now()
    if existing:
        if password:
            state.execute(
                'UPDATE users SET password_hash = ?, role = ?, must_change_password = ?, updated_at = ? WHERE username = ?',
                (_hash_password(password), role, must_change, now, username),
            )
        else:
            state.execute('UPDATE users SET role = ?, must_change_password = ?, updated_at = ? WHERE username = ?', (role, must_change, now, username))
    else:
        if not password:
            return web.json_response({'error': 'password required for new user'}, status=400)
        state.execute(
            'INSERT INTO users(username, password_hash, role, must_change_password, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?)',
            (username, _hash_password(password), role, must_change, now, now),
        )
    _audit_log(state, actor['username'], 'users.upsert', f'user:{username}', {'role': role})
    return web.json_response({'user': state.query_one('SELECT username, role, must_change_password, created_at, updated_at FROM users WHERE username = ?', (username,))})


async def delete_user(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    ok, actor = _require_role(state, request, 'admin')
    if not ok:
        return web.json_response({'error': 'forbidden'}, status=403)
    username = request.match_info['username']
    if username == 'admin':
        return web.json_response({'error': 'cannot delete admin'}, status=400)
    state.execute('DELETE FROM users WHERE username = ?', (username,))
    state.execute('DELETE FROM sessions WHERE username = ?', (username,))
    _audit_log(state, actor['username'], 'users.delete', f'user:{username}', {})
    return web.json_response({'deleted': username})


async def get_audit_logs(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    ok, actor = _require_role(state, request, 'operator')
    if not ok:
        return web.json_response({'error': 'forbidden'}, status=403)
    limit = max(1, min(int(request.query.get('limit', '200')), 2000))
    rows = state.query_all('SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?', (limit,))
    _audit_log(state, actor['username'], 'audit.list', 'audit_logs', {'limit': limit})
    return web.json_response({'logs': rows})


async def get_integrations(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    ok, _ = _require_role(state, request, 'operator')
    if not ok:
        return web.json_response({'error': 'forbidden'}, status=403)
    return web.json_response({'integrations': state.query_all('SELECT * FROM integrations ORDER BY id DESC')})


async def upsert_integration(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    ok, actor = _require_role(state, request, 'operator')
    if not ok:
        return web.json_response({'error': 'forbidden'}, status=403)
    payload = await request.json() if request.can_read_body else {}
    integration_id = payload.get('id')
    name = str(payload.get('name', '')).strip()
    provider = str(payload.get('provider', 'webhook')).strip()
    endpoint_url = str(payload.get('endpoint_url', '')).strip()
    api_key = str(payload.get('api_key', '')).strip() or None
    inbound_mapping_json = _json_dumps(payload.get('inbound_mapping', {})) if isinstance(payload.get('inbound_mapping', {}), dict) else str(payload.get('inbound_mapping_json', '{}'))
    outbound_mapping_json = _json_dumps(payload.get('outbound_mapping', {})) if isinstance(payload.get('outbound_mapping', {}), dict) else str(payload.get('outbound_mapping_json', '{}'))
    direction = str(payload.get('direction', 'outbound')).strip().lower()
    enabled = 1 if bool(payload.get('enabled', True)) else 0
    if direction not in {'outbound', 'inbound', 'both'}:
        return web.json_response({'error': 'invalid direction'}, status=400)
    if not name or not endpoint_url:
        return web.json_response({'error': 'name/endpoint_url required'}, status=400)
    now = _utc_now()
    if integration_id:
        state.execute(
            '''
            UPDATE integrations
            SET name = ?, provider = ?, endpoint_url = ?, api_key = ?, inbound_mapping_json = ?, outbound_mapping_json = ?, direction = ?, enabled = ?, updated_at = ?
            WHERE id = ?
            ''',
            (name, provider, endpoint_url, api_key, inbound_mapping_json, outbound_mapping_json, direction, enabled, now, int(integration_id)),
        )
        row = state.query_one('SELECT * FROM integrations WHERE id = ?', (int(integration_id),))
    else:
        state.execute(
            '''
            INSERT INTO integrations(name, provider, endpoint_url, api_key, inbound_mapping_json, outbound_mapping_json, direction, enabled, created_at, updated_at)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            (name, provider, endpoint_url, api_key, inbound_mapping_json, outbound_mapping_json, direction, enabled, now, now),
        )
        row = state.query_one('SELECT * FROM integrations ORDER BY id DESC LIMIT 1')
    _audit_log(state, actor['username'], 'integrations.upsert', f'integration:{row["id"]}', {'name': name, 'enabled': enabled})
    return web.json_response({'integration': row})


async def delete_integration(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    ok, actor = _require_role(state, request, 'operator')
    if not ok:
        return web.json_response({'error': 'forbidden'}, status=403)
    integration_id = int(request.match_info['id'])
    state.execute('DELETE FROM integrations WHERE id = ?', (integration_id,))
    _audit_log(state, actor['username'], 'integrations.delete', f'integration:{integration_id}', {})
    return web.json_response({'deleted_id': integration_id})


async def test_integration(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    ok, actor = _require_role(state, request, 'operator')
    if not ok:
        return web.json_response({'error': 'forbidden'}, status=403)
    integration_id = int(request.match_info['id'])
    integration = state.query_one('SELECT * FROM integrations WHERE id = ?', (integration_id,))
    if not integration:
        return web.json_response({'error': 'integration not found'}, status=404)
    ok_send, status = _send_webhook(
        integration['endpoint_url'],
        {'type': 'flex.integration.test', 'timestamp': _utc_now()},
        integration.get('api_key'),
    )
    state.execute('UPDATE integrations SET last_status = ?, last_synced_at = ? WHERE id = ?', (status if ok_send else f'failed:{status}', _utc_now(), integration_id))
    _audit_log(state, actor['username'], 'integrations.test', f'integration:{integration_id}', {'status': status})
    return web.json_response({'ok': ok_send, 'status': status})


async def get_integration_delivery_queue(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    ok, actor = _require_role(state, request, 'operator')
    if not ok:
        return web.json_response({'error': 'forbidden'}, status=403)
    status_filter = str(request.query.get('status', '')).strip().lower()
    limit = max(1, min(int(request.query.get('limit', '200')), 1000))
    params: tuple = (limit,)
    sql = '''
        SELECT q.*, i.name AS integration_name
        FROM integration_delivery_queue q
        JOIN integrations i ON i.id = q.integration_id
    '''
    if status_filter in {'queued', 'delivered', 'dead'}:
        sql += ' WHERE q.status = ? ORDER BY q.id DESC LIMIT ?'
        params = (status_filter, limit)
    else:
        sql += ' ORDER BY q.id DESC LIMIT ?'
    rows = state.query_all(sql, params)
    stats = state.query_all('SELECT status, COUNT(*) AS count FROM integration_delivery_queue GROUP BY status')
    _audit_log(state, actor['username'], 'integrations.queue.list', 'integration_delivery_queue', {'status': status_filter, 'limit': limit})
    return web.json_response({'queue': rows, 'stats': stats})


async def retry_integration_delivery_queue(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    ok, actor = _require_role(state, request, 'operator')
    if not ok:
        return web.json_response({'error': 'forbidden'}, status=403)
    payload = await request.json() if request.can_read_body else {}
    reset_dead = bool(payload.get('reset_dead', False))
    if reset_dead:
        state.execute(
            '''
            UPDATE integration_delivery_queue
            SET status = 'queued', next_retry_at = ?, updated_at = ?
            WHERE status = 'dead'
            ''',
            (int(time.time()), _utc_now()),
        )
    result = _drain_integration_delivery_queue(state, limit=200)
    _audit_log(state, actor['username'], 'integrations.queue.retry', 'integration_delivery_queue', {'reset_dead': reset_dead, **result})
    return web.json_response({'result': result, 'reset_dead': reset_dead})


async def queue_action_integration_delivery(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    ok, actor = _require_role(state, request, 'operator')
    if not ok:
        return web.json_response({'error': 'forbidden'}, status=403)
    queue_id = int(request.match_info['id'])
    payload = await request.json() if request.can_read_body else {}
    action = str(payload.get('action', '')).strip().lower()
    row = state.query_one('SELECT * FROM integration_delivery_queue WHERE id = ?', (queue_id,))
    if not row:
        return web.json_response({'error': 'queue item not found'}, status=404)
    now_utc = _utc_now()
    if action == 'hold':
        state.execute('UPDATE integration_delivery_queue SET status = ?, updated_at = ? WHERE id = ?', ('hold', now_utc, queue_id))
    elif action == 'cancel':
        state.execute('UPDATE integration_delivery_queue SET status = ?, updated_at = ? WHERE id = ?', ('cancelled', now_utc, queue_id))
    elif action == 'retry':
        state.execute(
            'UPDATE integration_delivery_queue SET status = ?, next_retry_at = ?, updated_at = ? WHERE id = ?',
            ('queued', int(time.time()), now_utc, queue_id),
        )
        _drain_integration_delivery_queue(state, limit=50)
    elif action == 'archive':
        state.execute(
            '''
            INSERT INTO integration_delivery_archive(
                queue_id, integration_id, event_type, payload_json, dedup_key,
                status, attempt_count, last_error, last_attempt_at, archived_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            (
                row['id'],
                row['integration_id'],
                row['event_type'],
                row['payload_json'],
                row['dedup_key'],
                row['status'],
                row['attempt_count'],
                row['last_error'],
                row['last_attempt_at'],
                now_utc,
            ),
        )
        state.execute('DELETE FROM integration_delivery_queue WHERE id = ?', (queue_id,))
    else:
        return web.json_response({'error': 'action must be hold|cancel|retry|archive'}, status=400)
    _audit_log(state, actor['username'], 'integrations.queue.action', f'queue:{queue_id}', {'action': action})
    return web.json_response({'ok': True, 'queue_id': queue_id, 'action': action})


async def archive_integration_delivery_queue(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    ok, actor = _require_role(state, request, 'operator')
    if not ok:
        return web.json_response({'error': 'forbidden'}, status=403)
    payload = await request.json() if request.can_read_body else {}
    older_than_hours = int(payload.get('older_than_hours', DEFAULT_QUEUE_ARCHIVE_AFTER_HOURS) or DEFAULT_QUEUE_ARCHIVE_AFTER_HOURS)
    archived = _archive_integration_queue(state, older_than_hours=older_than_hours)
    _audit_log(state, actor['username'], 'integrations.queue.archive', 'integration_delivery_queue', {'archived': archived, 'older_than_hours': older_than_hours})
    return web.json_response({'archived': archived, 'older_than_hours': older_than_hours})


async def get_inbound_events(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    ok, actor = _require_role(state, request, 'operator')
    if not ok:
        return web.json_response({'error': 'forbidden'}, status=403)
    limit = max(1, min(int(request.query.get('limit', '200')), 1000))
    rows = state.query_all(
        '''
        SELECT e.*, i.name AS integration_name
        FROM inbound_events e
        JOIN integrations i ON i.id = e.integration_id
        ORDER BY e.id DESC
        LIMIT ?
        ''',
        (limit,),
    )
    _audit_log(state, actor['username'], 'inbound.list', 'inbound_events', {'limit': limit})
    return web.json_response({'events': rows})


async def get_integration_metrics(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    ok, actor = _require_role(state, request, 'operator')
    if not ok:
        return web.json_response({'error': 'forbidden'}, status=403)
    now_epoch = int(time.time())
    since_epoch = now_epoch - 24 * 3600
    counters = state.query_all('SELECT status, COUNT(*) AS count FROM integration_delivery_queue GROUP BY status')
    processed_24h_row = state.query_one(
        "SELECT COUNT(*) AS c FROM integration_delivery_archive WHERE strftime('%s', archived_at) >= ?",
        (since_epoch,),
    )
    delivered_24h_row = state.query_one(
        "SELECT COUNT(*) AS c FROM integration_delivery_archive WHERE status = 'delivered' AND strftime('%s', archived_at) >= ?",
        (since_epoch,),
    )
    dead_24h_row = state.query_one(
        "SELECT COUNT(*) AS c FROM integration_delivery_archive WHERE status = 'dead' AND strftime('%s', archived_at) >= ?",
        (since_epoch,),
    )
    success_rate = 0.0
    processed_24h = int(processed_24h_row['c']) if processed_24h_row else 0
    delivered_24h = int(delivered_24h_row['c']) if delivered_24h_row else 0
    dead_24h = int(dead_24h_row['c']) if dead_24h_row else 0
    if processed_24h > 0:
        success_rate = round((delivered_24h / processed_24h) * 100.0, 2)
    inbound_24h_row = state.query_one(
        "SELECT COUNT(*) AS c FROM inbound_events WHERE strftime('%s', created_at) >= ?",
        (since_epoch,),
    )
    _audit_log(state, actor['username'], 'integrations.metrics', 'integrations', {'processed_24h': processed_24h, 'delivered_24h': delivered_24h})
    return web.json_response(
        {
            'queue_status_counts': counters,
            'processed_24h': processed_24h,
            'delivered_24h': delivered_24h,
            'dead_24h': dead_24h,
            'inbound_24h': int(inbound_24h_row['c']) if inbound_24h_row else 0,
            'success_rate_24h': success_rate,
        }
    )


def _normalize_alert_status(raw: str, fallback: str = 'open') -> str:
    status = str(raw or '').strip().lower()
    if status in {'open', 'acknowledged', 'resolved'}:
        return status
    return fallback


async def ingest_cmms_ticket(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    integration_id = int(request.match_info['integration_id'])
    integration = state.query_one(
        "SELECT * FROM integrations WHERE id = ? AND enabled = 1 AND direction IN ('inbound','both')",
        (integration_id,),
    )
    if not integration:
        return web.json_response({'error': 'inbound integration not found'}, status=404)

    body_bytes = await request.read()
    ok_sig, sig_msg, timestamp, nonce = _verify_signed_payload(request.headers, body_bytes, integration.get('api_key') or '')
    if not ok_sig:
        return web.json_response({'error': sig_msg}, status=401)
    ok_nonce, nonce_msg = _check_and_store_inbound_nonce(state, integration_id, nonce, timestamp)
    if not ok_nonce:
        return web.json_response({'error': nonce_msg}, status=409)

    try:
        payload = json.loads(body_bytes.decode('utf-8') if body_bytes else '{}')
    except Exception:
        return web.json_response({'error': 'invalid json payload'}, status=400)
    if not isinstance(payload, dict):
        return web.json_response({'error': 'payload must be object'}, status=400)

    inbound_mapping = _parse_mapping(integration.get('inbound_mapping_json'))
    event_type = str(_mapped_value(payload, inbound_mapping, 'event_type', ['event_type'], 'cmms.ticket.upsert')).strip()
    source = str(_mapped_value(payload, inbound_mapping, 'source', ['source'], integration.get('provider') or 'cmms')).strip() or 'cmms'
    external_id = str(_mapped_value(payload, inbound_mapping, 'external_id', ['external_id', 'ticket_id', 'id'], '')).strip()
    if not external_id:
        return web.json_response({'error': 'external_id or ticket_id is required'}, status=400)

    duplicated = state.query_one(
        'SELECT id FROM inbound_events WHERE integration_id = ? AND event_type = ? AND external_id = ?',
        (integration_id, event_type, external_id),
    )
    if duplicated:
        return web.json_response({'ok': True, 'duplicate': True, 'external_id': external_id})

    now = _utc_now()
    status = _normalize_alert_status(str(_mapped_value(payload, inbound_mapping, 'status', ['status'], 'open')))
    assignee = str(_mapped_value(payload, inbound_mapping, 'assignee', ['assignee'], '')).strip() or None
    note = str(_mapped_value(payload, inbound_mapping, 'note', ['note', 'description'], '')).strip() or None
    severity = str(_mapped_value(payload, inbound_mapping, 'severity', ['severity'], 'medium')).strip().lower()
    if severity not in SEVERITY_LEVELS:
        severity = 'medium'

    action = 'created'
    alert_id = _mapped_value(payload, inbound_mapping, 'alert_id', ['alert_id'], None)
    target_alert = state.query_one('SELECT * FROM alerts WHERE id = ?', (int(alert_id),)) if alert_id not in (None, '') else None
    if not target_alert:
        link_row = state.query_one(
            'SELECT alert_id FROM external_ticket_links WHERE integration_id = ? AND external_id = ? ORDER BY id DESC LIMIT 1',
            (integration_id, external_id),
        )
        if link_row:
            target_alert = state.query_one('SELECT * FROM alerts WHERE id = ?', (int(link_row['alert_id']),))
    if target_alert:
        state.execute(
            'UPDATE alerts SET status = ?, assignee = ?, note = ?, updated_at = ? WHERE id = ?',
            (status, assignee, note, now, int(alert_id)),
        )
        if status in {'acknowledged', 'resolved'}:
            state.execute('UPDATE diff_events SET triage_status = ? WHERE id = ?', (status, target_alert['diff_event_id']))
        alert_row = state.query_one('SELECT * FROM alerts WHERE id = ?', (int(alert_id),))
        action = 'updated'
    else:
        src_ip = str(_mapped_value(payload, inbound_mapping, 'src_ip', ['src_ip'], '0.0.0.0')).strip() or '0.0.0.0'
        dst_ip = str(_mapped_value(payload, inbound_mapping, 'dst_ip', ['dst_ip'], '0.0.0.0')).strip() or '0.0.0.0'
        protocol = str(_mapped_value(payload, inbound_mapping, 'protocol', ['protocol'], 'CMMS')).strip() or 'CMMS'
        port = max(0, int(_mapped_value(payload, inbound_mapping, 'port', ['port'], 0) or 0))
        risk_score = max(0, min(100, int(_mapped_value(payload, inbound_mapping, 'risk_score', ['risk_score'], 55) or 55)))
        message = str(_mapped_value(payload, inbound_mapping, 'message', ['title', 'summary'], f'Inbound ticket {external_id}')).strip()
        connection_key = str(_mapped_value(payload, inbound_mapping, 'connection_key', ['connection_key'], f'inbound|{external_id}|{protocol}|{port}')).strip()
        state.execute(
            '''
            INSERT INTO diff_events(
                event_type, message, severity, risk_score, triage_status,
                connection_key, src_ip, dst_ip, protocol, port, agent_id, created_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            ('cmms_ticket', message, severity, risk_score, status, connection_key, src_ip, dst_ip, protocol, port, f'inbound-{source}', now),
        )
        diff_row = state.query_one('SELECT * FROM diff_events ORDER BY id DESC LIMIT 1')
        state.execute(
            'INSERT INTO alerts(diff_event_id, severity, status, assignee, note, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?)',
            (diff_row['id'], severity, status, assignee, note, now, now),
        )
        alert_row = state.query_one('SELECT * FROM alerts ORDER BY id DESC LIMIT 1')

    payload_hash = hashlib.sha256(body_bytes).hexdigest()
    state.execute(
        '''
        INSERT INTO inbound_events(integration_id, source, event_type, external_id, payload_hash, details_json, created_at)
        VALUES(?, ?, ?, ?, ?, ?, ?)
        ''',
        (integration_id, source, event_type, external_id, payload_hash, _json_dumps({'alert_id': alert_row['id'], 'action': action}), now),
    )
    state.execute(
        '''
        INSERT OR REPLACE INTO external_ticket_links(integration_id, alert_id, external_id, source, last_status, updated_at)
        VALUES(?, ?, ?, ?, ?, ?)
        ''',
        (integration_id, alert_row['id'], external_id, source, status, now),
    )

    _dispatch_integrations(
        state,
        'ticket.ingested',
        {
            'integration_id': integration_id,
            'source': source,
            'external_id': external_id,
            'event_type': event_type,
            'action': action,
            'alert_id': alert_row['id'],
        },
    )
    await _broadcast_ui(state, {'type': 'topology_snapshot', 'payload': _load_topology_snapshot(state)})
    return web.json_response({'ok': True, 'duplicate': False, 'action': action, 'alert_id': alert_row['id'], 'external_id': external_id})


async def ingest_ticket(request: web.Request) -> web.Response:
    return await ingest_cmms_ticket(request)


async def get_runbooks(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    ok, _ = _require_role(state, request, 'operator')
    if not ok:
        return web.json_response({'error': 'forbidden'}, status=403)
    return web.json_response({'runbooks': state.query_all('SELECT * FROM runbooks ORDER BY id DESC')})


async def upsert_runbook(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    ok, actor = _require_role(state, request, 'operator')
    if not ok:
        return web.json_response({'error': 'forbidden'}, status=403)
    payload = await request.json() if request.can_read_body else {}
    runbook_id = payload.get('id')
    name = str(payload.get('name', '')).strip()
    severity = str(payload.get('severity', 'medium')).strip().lower()
    owner = str(payload.get('owner', '')).strip() or None
    steps = str(payload.get('steps', '')).strip()
    escalation_minutes = int(payload.get('escalation_minutes', 30) or 30)
    if severity not in SEVERITY_LEVELS:
        return web.json_response({'error': 'invalid severity'}, status=400)
    if not name or not steps:
        return web.json_response({'error': 'name/steps required'}, status=400)
    now = _utc_now()
    if runbook_id:
        state.execute(
            '''
            UPDATE runbooks SET name = ?, severity = ?, owner = ?, steps = ?, escalation_minutes = ?, updated_at = ? WHERE id = ?
            ''',
            (name, severity, owner, steps, escalation_minutes, now, int(runbook_id)),
        )
        row = state.query_one('SELECT * FROM runbooks WHERE id = ?', (int(runbook_id),))
    else:
        state.execute(
            'INSERT INTO runbooks(name, severity, owner, steps, escalation_minutes, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?)',
            (name, severity, owner, steps, escalation_minutes, now, now),
        )
        row = state.query_one('SELECT * FROM runbooks ORDER BY id DESC LIMIT 1')
    _audit_log(state, actor['username'], 'runbooks.upsert', f'runbook:{row["id"]}', {'severity': severity})
    return web.json_response({'runbook': row})


async def delete_runbook(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    ok, actor = _require_role(state, request, 'operator')
    if not ok:
        return web.json_response({'error': 'forbidden'}, status=403)
    runbook_id = int(request.match_info['id'])
    state.execute('DELETE FROM runbooks WHERE id = ?', (runbook_id,))
    _audit_log(state, actor['username'], 'runbooks.delete', f'runbook:{runbook_id}', {})
    return web.json_response({'deleted_id': runbook_id})


async def get_escalation_policies(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    ok, _ = _require_role(state, request, 'operator')
    if not ok:
        return web.json_response({'error': 'forbidden'}, status=403)
    return web.json_response({'policies': state.query_all('SELECT * FROM escalation_policies ORDER BY id ASC')})


async def upsert_escalation_policy(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    ok, actor = _require_role(state, request, 'operator')
    if not ok:
        return web.json_response({'error': 'forbidden'}, status=403)
    payload = await request.json() if request.can_read_body else {}
    policy_id = payload.get('id')
    severity = str(payload.get('severity', 'high')).strip().lower()
    threshold_minutes = max(0, int(payload.get('threshold_minutes', 30) or 30))
    channel = str(payload.get('channel', 'email')).strip()
    target = str(payload.get('target', '')).strip()
    if severity not in SEVERITY_LEVELS:
        return web.json_response({'error': 'invalid severity'}, status=400)
    if not target:
        return web.json_response({'error': 'target required'}, status=400)
    now = _utc_now()
    if policy_id:
        state.execute(
            '''
            UPDATE escalation_policies
            SET severity = ?, threshold_minutes = ?, channel = ?, target = ?, updated_at = ?
            WHERE id = ?
            ''',
            (severity, threshold_minutes, channel, target, now, int(policy_id)),
        )
        row = state.query_one('SELECT * FROM escalation_policies WHERE id = ?', (int(policy_id),))
    else:
        state.execute(
            '''
            INSERT INTO escalation_policies(severity, threshold_minutes, channel, target, created_at, updated_at)
            VALUES(?, ?, ?, ?, ?, ?)
            ''',
            (severity, threshold_minutes, channel, target, now, now),
        )
        row = state.query_one('SELECT * FROM escalation_policies ORDER BY id DESC LIMIT 1')
    _audit_log(state, actor['username'], 'escalation_policies.upsert', f'policy:{row["id"]}', {'severity': severity})
    return web.json_response({'policy': row})


async def delete_escalation_policy(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    ok, actor = _require_role(state, request, 'operator')
    if not ok:
        return web.json_response({'error': 'forbidden'}, status=403)
    policy_id = int(request.match_info['id'])
    state.execute('DELETE FROM escalation_policies WHERE id = ?', (policy_id,))
    _audit_log(state, actor['username'], 'escalation_policies.delete', f'policy:{policy_id}', {})
    return web.json_response({'deleted_id': policy_id})


async def get_sla_summary(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    ok, actor = _require_role(state, request, 'operator')
    if not ok:
        return web.json_response({'error': 'forbidden'}, status=403)

    open_counts = state.query_all(
        '''
        SELECT severity, COUNT(*) AS count
        FROM alerts
        WHERE status = 'open'
        GROUP BY severity
        '''
    )
    ack_times = state.query_all(
        '''
        SELECT (strftime('%s', a.updated_at) - strftime('%s', a.created_at)) AS sec
        FROM alerts a
        WHERE a.status IN ('acknowledged', 'resolved')
        ORDER BY a.id DESC
        LIMIT 500
        '''
    )
    resolve_times = state.query_all(
        '''
        SELECT (strftime('%s', a.updated_at) - strftime('%s', a.created_at)) AS sec
        FROM alerts a
        WHERE a.status = 'resolved'
        ORDER BY a.id DESC
        LIMIT 500
        '''
    )
    mtta = int(sum(max(0, row['sec']) for row in ack_times) / len(ack_times)) if ack_times else 0
    mttr = int(sum(max(0, row['sec']) for row in resolve_times) / len(resolve_times)) if resolve_times else 0
    recent_escalations = state.query_all('SELECT * FROM escalation_events ORDER BY id DESC LIMIT 200')
    _audit_log(state, actor['username'], 'sla.summary', 'sla', {'mtta_seconds': mtta, 'mttr_seconds': mttr})
    return web.json_response({'open_by_severity': open_counts, 'mtta_seconds': mtta, 'mttr_seconds': mttr, 'escalations': recent_escalations})


def _load_topology_snapshot(state: RegistryState, diff_limit: int = 200) -> dict:
    agents = state.query_all('SELECT * FROM agents ORDER BY last_seen DESC')
    assets = state.query_all('SELECT * FROM assets ORDER BY last_seen DESC')
    connections = state.query_all('SELECT * FROM connections ORDER BY last_seen DESC LIMIT 2000')
    diffs = state.query_all('SELECT * FROM diff_events ORDER BY id DESC LIMIT ?', (diff_limit,))
    alerts = state.query_all(
        '''
        SELECT a.*, d.message, d.protocol, d.port, d.src_ip, d.dst_ip, d.risk_score
        FROM alerts a
        JOIN diff_events d ON d.id = a.diff_event_id
        ORDER BY a.id DESC
        LIMIT 300
        '''
    )
    webhook_row = state.query_one('SELECT value FROM settings WHERE key = ?', ('notification_webhook',))
    min_risk_row = state.query_one('SELECT value FROM settings WHERE key = ?', ('notification_min_risk',))
    integrations = state.query_all('SELECT * FROM integrations ORDER BY id DESC LIMIT 100')
    runbooks = state.query_all('SELECT * FROM runbooks ORDER BY id DESC LIMIT 100')
    policies = state.query_all('SELECT * FROM escalation_policies ORDER BY id ASC')
    recent_audit = state.query_all('SELECT * FROM audit_logs ORDER BY id DESC LIMIT 150')
    queue_stats = state.query_all('SELECT status, COUNT(*) AS count FROM integration_delivery_queue GROUP BY status')
    queue_recent = state.query_all('SELECT * FROM integration_delivery_queue ORDER BY id DESC LIMIT 120')
    inbound_recent = state.query_all('SELECT * FROM inbound_events ORDER BY id DESC LIMIT 120')
    archive_recent = state.query_all('SELECT * FROM integration_delivery_archive ORDER BY id DESC LIMIT 120')
    retention_policy = state.get_retention_policy()
    return {
        'agents': agents,
        'assets': assets,
        'connections': connections,
        'diffs': diffs,
        'alerts': alerts,
        'integrations': integrations,
        'runbooks': runbooks,
        'escalation_policies': policies,
        'audit_logs': recent_audit,
        'integration_queue_stats': queue_stats,
        'integration_queue': queue_recent,
        'inbound_events': inbound_recent,
        'integration_queue_archive': archive_recent,
        'timestamp': _utc_now(),
        'notification_webhook': webhook_row['value'] if webhook_row else '',
        'notification_min_risk': int(min_risk_row['value']) if min_risk_row else 55,
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


async def patch_diff(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    ok, actor = _require_role(state, request, 'operator')
    if not ok:
        return web.json_response({'error': 'forbidden'}, status=403)
    diff_id = request.match_info['id']
    payload = await request.json() if request.can_read_body else {}
    triage_status = str(payload.get('triage_status', '')).strip().lower()
    if triage_status not in {'open', 'acknowledged', 'resolved'}:
        return web.json_response({'error': 'triage_status must be open|acknowledged|resolved'}, status=400)
    existing = state.query_one('SELECT id FROM diff_events WHERE id = ?', (diff_id,))
    if not existing:
        return web.json_response({'error': 'diff not found'}, status=404)
    state.execute('UPDATE diff_events SET triage_status = ? WHERE id = ?', (triage_status, diff_id))
    if triage_status in {'acknowledged', 'resolved'}:
        state.execute(
            'UPDATE alerts SET status = ?, updated_at = ? WHERE diff_event_id = ? AND status != ?',
            (triage_status, _utc_now(), diff_id, 'resolved'),
        )
    _audit_log(state, actor['username'], 'diffs.patch', f'diff:{diff_id}', {'triage_status': triage_status})
    await _broadcast_ui(state, {'type': 'topology_snapshot', 'payload': _load_topology_snapshot(state)})
    return web.json_response({'diff': state.query_one('SELECT * FROM diff_events WHERE id = ?', (diff_id,))})


async def get_alerts(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    status = str(request.query.get('status', '')).strip().lower()
    params: tuple = ()
    sql = '''
        SELECT a.*, d.message, d.protocol, d.port, d.src_ip, d.dst_ip, d.risk_score
        FROM alerts a
        JOIN diff_events d ON d.id = a.diff_event_id
    '''
    if status in {'open', 'acknowledged', 'resolved'}:
        sql += ' WHERE a.status = ?'
        params = (status,)
    sql += ' ORDER BY a.id DESC LIMIT 500'
    return web.json_response({'alerts': state.query_all(sql, params)})


async def patch_alert(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    ok, actor = _require_role(state, request, 'operator')
    if not ok:
        return web.json_response({'error': 'forbidden'}, status=403)
    alert_id = request.match_info['id']
    payload = await request.json() if request.can_read_body else {}
    status = str(payload.get('status', '')).strip().lower()
    if status not in {'open', 'acknowledged', 'resolved'}:
        return web.json_response({'error': 'status must be open|acknowledged|resolved'}, status=400)
    assignee = str(payload.get('assignee', '')).strip() or None
    note = str(payload.get('note', '')).strip() or None
    existing = state.query_one('SELECT * FROM alerts WHERE id = ?', (alert_id,))
    if not existing:
        return web.json_response({'error': 'alert not found'}, status=404)
    state.execute(
        'UPDATE alerts SET status = ?, assignee = ?, note = ?, updated_at = ? WHERE id = ?',
        (status, assignee, note, _utc_now(), alert_id),
    )
    if status in {'acknowledged', 'resolved'}:
        state.execute('UPDATE diff_events SET triage_status = ? WHERE id = ?', (status, existing['diff_event_id']))
    _dispatch_integrations(
        state,
        'alert.status_changed',
        {
            'alert_id': int(alert_id),
            'status': status,
            'assignee': assignee,
            'note': note,
        },
    )
    linked = state.query_all('SELECT * FROM external_ticket_links WHERE alert_id = ?', (int(alert_id),))
    for link in linked:
        _dispatch_integration_by_id(
            state,
            int(link['integration_id']),
            'ticket.sync',
            {
                'alert_id': int(alert_id),
                'external_id': link['external_id'],
                'status': status,
                'assignee': assignee,
                'note': note,
                'updated_at': _utc_now(),
            },
        )
        state.execute(
            'UPDATE external_ticket_links SET last_status = ?, updated_at = ? WHERE id = ?',
            (status, _utc_now(), int(link['id'])),
        )
    _audit_log(state, actor['username'], 'alerts.patch', f'alert:{alert_id}', {'status': status, 'assignee': assignee})
    await _broadcast_ui(state, {'type': 'topology_snapshot', 'payload': _load_topology_snapshot(state)})
    return web.json_response({'alert': state.query_one('SELECT * FROM alerts WHERE id = ?', (alert_id,))})


async def get_notification_settings(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    ok, _ = _require_role(state, request, 'operator')
    if not ok:
        return web.json_response({'error': 'forbidden'}, status=403)
    webhook = state.query_one('SELECT value FROM settings WHERE key = ?', ('notification_webhook',))
    minimum = state.query_one('SELECT value FROM settings WHERE key = ?', ('notification_min_risk',))
    return web.json_response(
        {
            'notification_webhook': webhook['value'] if webhook else '',
            'notification_min_risk': int(minimum['value']) if minimum else 55,
        }
    )


async def put_notification_settings(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    ok, actor = _require_role(state, request, 'operator')
    if not ok:
        return web.json_response({'error': 'forbidden'}, status=403)
    payload = await request.json() if request.can_read_body else {}
    webhook = str(payload.get('notification_webhook', '')).strip()
    try:
        minimum = max(0, min(int(payload.get('notification_min_risk', 55)), 100))
    except (TypeError, ValueError):
        return web.json_response({'error': 'notification_min_risk must be integer'}, status=400)

    state.execute('INSERT OR REPLACE INTO settings(key, value) VALUES(?, ?)', ('notification_webhook', webhook))
    state.execute('INSERT OR REPLACE INTO settings(key, value) VALUES(?, ?)', ('notification_min_risk', str(minimum)))
    _audit_log(state, actor['username'], 'notification_settings.put', 'settings', {'notification_min_risk': minimum})
    return web.json_response({'notification_webhook': webhook, 'notification_min_risk': minimum})


async def get_audit_report(request: web.Request) -> web.Response:
    state: RegistryState = request.app['state']
    ok, actor = _require_role(state, request, 'operator')
    if not ok:
        return web.json_response({'error': 'forbidden'}, status=403)
    try:
        days = int(request.query.get('days', '30'))
    except ValueError:
        days = 30
    fmt = str(request.query.get('format', 'json')).strip().lower()
    report = _build_audit_report(state, days)
    _audit_log(state, actor['username'], 'reports.audit', f'period:{days}d', {'format': fmt})
    if fmt != 'csv':
        return web.json_response(report)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['section', 'key', 'value'])
    for key, value in report['summary'].items():
        writer.writerow(['summary', key, value])
    for item in report['protocol_distribution']:
        writer.writerow(['protocol_distribution', item['protocol'], item['count']])
    for event in report['recent_events']:
        writer.writerow(['event', event['id'], f"{event['created_at']}|{event['severity']}|{event['triage_status']}|{event['message']}"])

    body = output.getvalue().encode('utf-8')
    return web.Response(
        body=body,
        headers={
            'Content-Type': 'text/csv; charset=utf-8',
            'Content-Disposition': f'attachment; filename="flex-audit-{days}d.csv"',
        },
    )


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
    ok, actor = _require_role(state, request, 'operator')
    if not ok:
        raise web.HTTPUnauthorized(reason='unauthorized')
    if actor.get('must_change_password'):
        raise web.HTTPForbidden(reason='password_change_required')
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
    token = str(request.query.get('token', '')).strip()
    agent_id_query = str(request.query.get('agent_id', '')).strip()
    if not token or not agent_id_query:
        raise web.HTTPUnauthorized(reason='agent token required')
    auth_agent = state.query_one(
        'SELECT agent_id, agent_name FROM agents WHERE agent_id = ? AND ws_token = ? AND ws_token_expires > ?',
        (agent_id_query, token, int(time.time())),
    )
    if not auth_agent:
        raise web.HTTPUnauthorized(reason='invalid agent token')
    ws = web.WebSocketResponse()
    await ws.prepare(request)

    bound_agent_id: str | None = auth_agent['agent_id']
    bound_agent_name = auth_agent['agent_name'] or 'Unknown Agent'

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

            if agent_id != bound_agent_id:
                continue

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
                existing = state.query_one(
                    'SELECT first_seen, ws_token, ws_token_expires, hostname, platform FROM agents WHERE agent_id = ?',
                    (agent_id,),
                )
                first_seen = existing['first_seen'] if existing else now
                ws_token = existing['ws_token'] if existing else None
                ws_token_expires = existing['ws_token_expires'] if existing else None
                hostname = str(payload.get('hostname', '')).strip() or (existing['hostname'] if existing else '')
                platform_name = str(payload.get('platform', '')).strip() or (existing['platform'] if existing else '')
                state.execute(
                    '''
                    INSERT OR REPLACE INTO agents(
                        agent_id, agent_name, status, total_packets, active_connections,
                        first_seen, last_seen, hostname, platform, ws_token, ws_token_expires
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''',
                    (
                        agent_id,
                        agent_name,
                        'connected',
                        state_payload['total_packets'],
                        state_payload['active_connections'],
                        first_seen,
                        state_payload['last_seen'],
                        hostname,
                        platform_name,
                        ws_token,
                        ws_token_expires,
                    ),
                )
                await _broadcast_ui(state, {'type': 'registry_agent_update', 'payload': state_payload})

            if msg_type == 'connection_update' and bound_agent_id:
                now_epoch = int(time.time())
                if now_epoch - state.last_cleanup_epoch >= 60:
                    state.last_cleanup_epoch = now_epoch
                    policy = state.get_retention_policy()
                    state.purge_packet_data(policy['connection_retention_days'], policy['event_retention_days'])
                    _apply_escalation_rules(state)

                enriched = {
                    **payload,
                    'agent_id': bound_agent_id,
                    'agent_name': bound_agent_name,
                }
                src_ip = str(enriched.get('src_ip', '')).strip()
                dst_ip = str(enriched.get('dst_ip', '')).strip()
                if _is_loopback_ip(src_ip) or _is_loopback_ip(dst_ip):
                    continue
                protocol = str(enriched.get('protocol', '')).strip() or 'Unknown'
                port = int(enriched.get('port', 0) or 0)
                packets = int(enriched.get('packets', 0) or 0)
                bytes_per_sec = float(enriched.get('bytes_per_sec', 0) or 0)
                last_seen = str(enriched.get('last_seen', '')).strip() or _utc_now()
                src_mac = str(enriched.get('src_mac', '')).strip()
                dst_mac = str(enriched.get('dst_mac', '')).strip()
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

                src_asset = _upsert_asset_with_identification(
                    state=state,
                    ip=src_ip,
                    is_source=True,
                    protocol=protocol,
                    port=port,
                    mac=src_mac,
                    last_seen=last_seen,
                    agent_id=bound_agent_id,
                )
                dst_asset = _upsert_asset_with_identification(
                    state=state,
                    ip=dst_ip,
                    is_source=False,
                    protocol=protocol,
                    port=port,
                    mac=dst_mac,
                    last_seen=last_seen,
                    agent_id=bound_agent_id,
                )

                if existing_connection is None:
                    src_criticality = src_asset['criticality'] if src_asset else 'normal'
                    dst_criticality = dst_asset['criticality'] if dst_asset else 'normal'
                    risk_score = _risk_score(protocol, port, src_criticality, dst_criticality, True)
                    severity = _severity_from_score(risk_score)
                    src_type = src_asset['device_type'] if src_asset and src_asset.get('device_type') else 'Unknown'
                    dst_type = dst_asset['device_type'] if dst_asset and dst_asset.get('device_type') else 'Unknown'
                    message_text = (
                        f'New flow discovered: {protocol} {src_ip}({src_type}) -> '
                        f'{dst_ip}({dst_type}) port {port}, risk={risk_score}'
                    )
                    state.execute(
                        '''
                        INSERT INTO diff_events(
                            event_type, message, severity, risk_score, triage_status,
                            connection_key, src_ip, dst_ip, protocol, port, agent_id, created_at
                        )
                        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''',
                        (
                            'new_connection',
                            message_text,
                            severity,
                            risk_score,
                            'open',
                            connection_key,
                            src_ip,
                            dst_ip,
                            protocol,
                            port,
                            bound_agent_id,
                            _utc_now(),
                        ),
                    )

                    diff_row = state.query_one('SELECT * FROM diff_events WHERE id = last_insert_rowid()')
                    if diff_row is None:
                        diff_row = state.query_one('SELECT * FROM diff_events ORDER BY id DESC LIMIT 1')

                    notify_min_row = state.query_one('SELECT value FROM settings WHERE key = ?', ('notification_min_risk',))
                    notify_min = int(notify_min_row['value']) if notify_min_row else 55
                    if severity in {'high', 'critical'}:
                        state.execute(
                            'INSERT INTO alerts(diff_event_id, severity, status, assignee, note, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?)',
                            (diff_row['id'], severity, 'open', None, None, _utc_now(), _utc_now()),
                        )
                        _dispatch_integrations(
                            state,
                            'alert.created',
                            {
                                'alert_id': diff_row['id'],
                                'severity': severity,
                                'risk_score': risk_score,
                                'message': message_text,
                                'src_ip': src_ip,
                                'dst_ip': dst_ip,
                                'protocol': protocol,
                                'port': port,
                            },
                        )
                    if risk_score >= notify_min:
                        _dispatch_webhook(
                            state,
                            {
                                'type': 'flex.alert',
                                'severity': severity,
                                'risk_score': risk_score,
                                'protocol': protocol,
                                'src_ip': src_ip,
                                'dst_ip': dst_ip,
                                'port': port,
                                'agent_id': bound_agent_id,
                                'created_at': _utc_now(),
                            },
                        )

                    await _broadcast_ui(
                        state,
                        {
                            'type': 'connection_diff',
                            'payload': {
                                'id': diff_row['id'] if diff_row else None,
                                'event_type': 'new_connection',
                                'message': message_text,
                                'severity': severity,
                                'risk_score': risk_score,
                                'triage_status': 'open',
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
    app = web.Application(middlewares=[cors_middleware, auth_middleware])
    app['state'] = RegistryState(db_path)
    app.on_startup.append(_on_startup)
    app.on_shutdown.append(_on_shutdown)

    app.router.add_post('/api/tokens', issue_token)
    app.router.add_post('/api/register', register_agent)
    app.router.add_post('/api/auth/login', login)
    app.router.add_post('/api/auth/logout', logout)
    app.router.add_get('/api/auth/me', me)
    app.router.add_post('/api/auth/change-password', change_password)
    app.router.add_get('/api/users', get_users)
    app.router.add_post('/api/users', upsert_user)
    app.router.add_delete('/api/users/{username}', delete_user)
    app.router.add_get('/api/audit-logs', get_audit_logs)
    app.router.add_get('/api/integrations', get_integrations)
    app.router.add_post('/api/integrations', upsert_integration)
    app.router.add_delete('/api/integrations/{id}', delete_integration)
    app.router.add_post('/api/integrations/{id}/test', test_integration)
    app.router.add_get('/api/integrations/queue', get_integration_delivery_queue)
    app.router.add_post('/api/integrations/queue/retry', retry_integration_delivery_queue)
    app.router.add_post('/api/integrations/queue/{id}/action', queue_action_integration_delivery)
    app.router.add_post('/api/integrations/queue/archive', archive_integration_delivery_queue)
    app.router.add_get('/api/integrations/metrics', get_integration_metrics)
    app.router.add_get('/api/inbound/events', get_inbound_events)
    app.router.add_post('/api/inbound/cmms/{integration_id}', ingest_cmms_ticket)
    app.router.add_post('/api/inbound/ticket/{integration_id}', ingest_ticket)
    app.router.add_get('/api/runbooks', get_runbooks)
    app.router.add_post('/api/runbooks', upsert_runbook)
    app.router.add_delete('/api/runbooks/{id}', delete_runbook)
    app.router.add_get('/api/escalation-policies', get_escalation_policies)
    app.router.add_post('/api/escalation-policies', upsert_escalation_policy)
    app.router.add_delete('/api/escalation-policies/{id}', delete_escalation_policy)
    app.router.add_get('/api/sla/summary', get_sla_summary)
    app.router.add_get('/api/topology/snapshot', get_snapshot)
    app.router.add_get('/api/assets', get_assets)
    app.router.add_patch('/api/assets/{ip}', patch_asset)
    app.router.add_delete('/api/assets/{ip}', delete_asset)
    app.router.add_post('/api/assets/delete-selected', delete_selected_assets)
    app.router.add_post('/api/assets/clear', clear_assets)
    app.router.add_post('/api/assets/initialize', initialize_assets)
    app.router.add_get('/api/diffs', get_diffs)
    app.router.add_patch('/api/diffs/{id}', patch_diff)
    app.router.add_get('/api/alerts', get_alerts)
    app.router.add_patch('/api/alerts/{id}', patch_alert)
    app.router.add_get('/api/notification-settings', get_notification_settings)
    app.router.add_put('/api/notification-settings', put_notification_settings)
    app.router.add_get('/api/reports/audit', get_audit_report)
    app.router.add_get('/api/retention-policy', get_retention_policy)
    app.router.add_put('/api/retention-policy', put_retention_policy)
    app.router.add_post('/api/packets/clear', clear_packets)
    app.router.add_post('/api/packets/delete-selected', delete_selected_packets)
    app.router.add_get('/api/download/windows', download_windows)
    app.router.add_get('/api/download/linux', download_linux)
    app.router.add_route('OPTIONS', '/api/tokens', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/register', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/auth/login', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/auth/logout', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/auth/me', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/auth/change-password', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/users', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/users/{username}', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/audit-logs', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/integrations', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/integrations/{id}', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/integrations/{id}/test', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/integrations/queue', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/integrations/queue/retry', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/integrations/queue/{id}/action', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/integrations/queue/archive', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/integrations/metrics', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/inbound/events', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/inbound/cmms/{integration_id}', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/inbound/ticket/{integration_id}', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/runbooks', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/runbooks/{id}', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/escalation-policies', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/escalation-policies/{id}', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/sla/summary', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/topology/snapshot', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/assets', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/assets/{ip}', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/assets/delete-selected', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/assets/clear', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/assets/initialize', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/diffs', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/diffs/{id}', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/alerts', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/alerts/{id}', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/notification-settings', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/reports/audit', lambda _: web.Response(status=204))
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
