import argparse
import io
import json
import secrets
import tarfile
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
    response.headers['Access-Control-Allow-Methods'] = 'GET,POST,OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
    return response


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='FLEX agent registry')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8780)
    return parser.parse_args()


class RegistryState:
    def __init__(self) -> None:
        self.ui_clients: set[web.WebSocketResponse] = set()
        self.agent_states: dict[str, dict] = {}
        self.tokens: dict[str, int] = {}


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
    state.tokens[token] = expires_at

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

    expires_at = state.tokens.get(token)
    if expires_at is None:
        return web.json_response({'error': 'invalid token'}, status=400)

    if expires_at <= int(time.time()):
        state.tokens.pop(token, None)
        return web.json_response({'error': 'token expired'}, status=400)

    state.tokens.pop(token, None)

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

    await ws.send_str(
        json.dumps(
            {
                'type': 'registry_snapshot',
                'payload': {
                    'agents': list(state.agent_states.values()),
                    'timestamp': _utc_now(),
                },
            }
        )
    )

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
                state_payload = {
                    'agent_id': agent_id,
                    'agent_name': agent_name,
                    'status': 'connected',
                    'total_packets': int(payload.get('total_packets', 0) or 0),
                    'active_connections': int(payload.get('active_connections', 0) or 0),
                    'last_seen': payload.get('timestamp') or _utc_now(),
                }
                state.agent_states[agent_id] = state_payload
                await _broadcast_ui(state, {'type': 'registry_agent_update', 'payload': state_payload})

            if msg_type == 'connection_update' and bound_agent_id:
                enriched = {
                    **payload,
                    'agent_id': bound_agent_id,
                    'agent_name': state.agent_states.get(bound_agent_id, {}).get('agent_name', 'Unknown Agent'),
                }
                await _broadcast_ui(state, {'type': 'connection_update', 'payload': enriched})
    finally:
        if bound_agent_id and bound_agent_id in state.agent_states:
            disconnected_payload = {**state.agent_states[bound_agent_id], 'status': 'disconnected', 'last_seen': _utc_now()}
            state.agent_states[bound_agent_id] = disconnected_payload
            await _broadcast_ui(state, {'type': 'registry_agent_update', 'payload': disconnected_payload})

    return ws


def build_app() -> web.Application:
    app = web.Application(middlewares=[cors_middleware])
    app['state'] = RegistryState()

    app.router.add_post('/api/tokens', issue_token)
    app.router.add_post('/api/register', register_agent)
    app.router.add_get('/api/download/windows', download_windows)
    app.router.add_get('/api/download/linux', download_linux)
    app.router.add_route('OPTIONS', '/api/tokens', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/register', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/download/windows', lambda _: web.Response(status=204))
    app.router.add_route('OPTIONS', '/api/download/linux', lambda _: web.Response(status=204))
    app.router.add_get('/ws/ui', ws_ui)
    app.router.add_get('/ws/agent', ws_agent)
    app.router.add_get('/api/health', lambda _: web.json_response({'status': 'ok', 'timestamp': _utc_now()}))

    return app


def main() -> None:
    args = parse_args()
    web.run_app(build_app(), host=args.host, port=args.port)


if __name__ == '__main__':
    main()
