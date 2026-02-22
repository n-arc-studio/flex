import hashlib
import hmac
import importlib.util
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from urllib.parse import urlparse

from aiohttp.test_utils import TestClient, TestServer


REGISTRY_FILE = Path(__file__).resolve().parents[1] / 'registry.py'
spec = importlib.util.spec_from_file_location('flex_registry_module', REGISTRY_FILE)
registry = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(registry)


def _sign(secret: str, timestamp: str, body: str) -> str:
    payload = f'{timestamp}.{body}'.encode('utf-8')
    return hmac.new(secret.encode('utf-8'), payload, hashlib.sha256).hexdigest()


class RegistryRegressionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.original_admin_password = os.environ.get('FLEX_ADMIN_PASSWORD')
        os.environ['FLEX_ADMIN_PASSWORD'] = 'RegressionAdmin#2026'
        self.admin_password = 'RegressionAdmin#2026'
        self.admin_password_after_change = 'RegressionAdminChanged#2026'

        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmp_dir.name) / 'test-flex.db')
        app = registry.build_app(self.db_path)
        self.server = TestServer(app)
        await self.server.start_server()
        self.client = TestClient(self.server)
        await self.client.start_server()

        await self._bootstrap_admin()

    async def asyncTearDown(self) -> None:
        await self.client.close()
        await self.server.close()
        self.tmp_dir.cleanup()
        if self.original_admin_password is None:
            os.environ.pop('FLEX_ADMIN_PASSWORD', None)
        else:
            os.environ['FLEX_ADMIN_PASSWORD'] = self.original_admin_password

    async def _login_admin(self) -> str:
        response = await self.client.post(
            '/api/auth/login',
            json={'username': 'admin', 'password': self.admin_password},
        )
        self.assertEqual(response.status, 200)
        payload = await response.json()
        return payload['token']

    async def _bootstrap_admin(self) -> None:
        response = await self.client.post(
            '/api/auth/login',
            json={'username': 'admin', 'password': self.admin_password},
        )
        self.assertEqual(response.status, 200)
        payload = await response.json()
        if not payload.get('must_change_password'):
            return

        token = payload['token']
        change = await self.client.post(
            '/api/auth/change-password',
            headers={'Authorization': f'Bearer {token}'},
            json={'current_password': self.admin_password, 'new_password': self.admin_password_after_change},
        )
        self.assertEqual(change.status, 200)
        self.admin_password = self.admin_password_after_change

    async def _auth_headers(self) -> dict:
        token = await self._login_admin()
        return {'Authorization': f'Bearer {token}'}

    async def _register_agent(self, agent_name: str = 'test-agent') -> dict:
        headers = await self._auth_headers()
        issue = await self.client.post('/api/tokens', headers=headers, json={'ttl_minutes': 15})
        self.assertEqual(issue.status, 200)
        issue_payload = await issue.json()

        register_res = await self.client.post(
            '/api/register',
            json={'token': issue_payload['token'], 'agent_name': agent_name, 'hostname': 'test-host', 'platform': 'win'},
        )
        self.assertEqual(register_res.status, 200)
        return await register_res.json()

    async def test_login_and_snapshot_requires_auth(self):
        no_auth = await self.client.get('/api/topology/snapshot')
        self.assertEqual(no_auth.status, 401)

        token = await self._login_admin()
        response = await self.client.get('/api/topology/snapshot', headers={'Authorization': f'Bearer {token}'})
        self.assertEqual(response.status, 200)
        body = await response.json()
        self.assertIn('agents', body)
        self.assertIn('connections', body)

    async def test_health_endpoint_is_public(self):
        response = await self.client.get('/api/health')
        self.assertEqual(response.status, 200)
        payload = await response.json()
        self.assertEqual(payload.get('status'), 'ok')
        self.assertTrue(payload.get('timestamp'))

    async def test_register_rejects_expired_enrollment_token(self):
        headers = await self._auth_headers()
        issue = await self.client.post('/api/tokens', headers=headers, json={'ttl_minutes': 1})
        self.assertEqual(issue.status, 200)
        token_payload = await issue.json()
        token = token_payload['token']

        # Force-expire the token in DB to avoid sleeps in tests
        state = self.server.app['state']
        state.execute('UPDATE tokens SET expires_at = ? WHERE token = ?', (int(time.time()) - 1, token))

        register_res = await self.client.post(
            '/api/register',
            json={'token': token, 'agent_name': 'expired-token-agent', 'hostname': 'test-host', 'platform': 'win'},
        )
        self.assertEqual(register_res.status, 400)
        body = await register_res.json()
        self.assertEqual(body.get('error'), 'token expired')

    async def test_ws_hello_preserves_agent_ws_token(self):
        registered = await self._register_agent('token-preserve-agent')
        upstream_url = registered['upstream_url']
        agent_id = registered['agent_id']

        parsed = urlparse(upstream_url)
        upstream_path = parsed.path + (f'?{parsed.query}' if parsed.query else '')

        state = self.server.app['state']
        before = state.query_one('SELECT ws_token, ws_token_expires FROM agents WHERE agent_id = ?', (agent_id,))
        self.assertIsNotNone(before)
        self.assertTrue(before['ws_token'])

        ws = await self.client.ws_connect(upstream_path)
        await ws.send_str(
            json.dumps(
                {
                    'type': 'hello',
                    'payload': {
                        'agent_id': agent_id,
                        'agent_name': 'token-preserve-agent',
                        'timestamp': registry._utc_now(),
                        'total_packets': 10,
                        'active_connections': 2,
                    },
                }
            )
        )
        await ws.close()

        after = state.query_one('SELECT ws_token, ws_token_expires FROM agents WHERE agent_id = ?', (agent_id,))
        self.assertEqual(before['ws_token'], after['ws_token'])
        self.assertEqual(before['ws_token_expires'], after['ws_token_expires'])

    async def test_loopback_connection_is_filtered(self):
        registered = await self._register_agent('loopback-filter-agent')
        upstream_url = registered['upstream_url']
        agent_id = registered['agent_id']

        parsed = urlparse(upstream_url)
        upstream_path = parsed.path + (f'?{parsed.query}' if parsed.query else '')

        ws = await self.client.ws_connect(upstream_path)
        await ws.send_str(
            json.dumps(
                {
                    'type': 'hello',
                    'payload': {
                        'agent_id': agent_id,
                        'agent_name': 'loopback-filter-agent',
                        'timestamp': registry._utc_now(),
                        'total_packets': 0,
                        'active_connections': 0,
                    },
                }
            )
        )
        await ws.send_str(
            json.dumps(
                {
                    'type': 'connection_update',
                    'payload': {
                        'connection_id': 'loop001',
                        'src_ip': '127.0.0.1',
                        'dst_ip': '127.0.0.1',
                        'protocol': 'TCP/80',
                        'port': 80,
                        'packets': 3,
                        'bytes_per_sec': 1.0,
                        'last_seen': registry._utc_now(),
                    },
                }
            )
        )
        await ws.close()

        state = self.server.app['state']
        loopback_connection = state.query_one(
            "SELECT connection_key FROM connections WHERE src_ip LIKE '127.%' OR dst_ip LIKE '127.%' OR src_ip='::1' OR dst_ip='::1'"
        )
        self.assertIsNone(loopback_connection)

    async def test_signed_inbound_webhook_replay_is_blocked(self):
        headers = await self._auth_headers()
        create = await self.client.post(
            '/api/integrations',
            headers=headers,
            json={
                'name': 'cmms-inbound',
                'provider': 'cmms',
                'endpoint_url': 'https://example.invalid/webhook',
                'api_key': 'secret-key-1',
                'direction': 'inbound',
                'enabled': True,
            },
        )
        self.assertEqual(create.status, 200)
        integration = (await create.json())['integration']
        integration_id = integration['id']

        body = {
            'event_type': 'cmms.ticket.upsert',
            'external_id': 'TICKET-1001',
            'status': 'open',
            'severity': 'high',
            'summary': 'Inbound ticket test',
        }
        body_text = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
        ts = str(int(time.time()))
        nonce = 'nonce-regression-1'
        signature = _sign('secret-key-1', ts, body_text)
        signed_headers = {
            'X-Flex-Timestamp': ts,
            'X-Flex-Nonce': nonce,
            'X-Flex-Signature': f'v1={signature}',
            'Content-Type': 'application/json',
        }

        first = await self.client.post(
            f'/api/inbound/cmms/{integration_id}',
            data=body_text.encode('utf-8'),
            headers=signed_headers,
        )
        self.assertEqual(first.status, 200)
        first_payload = await first.json()
        self.assertTrue(first_payload.get('ok'))

        replay = await self.client.post(
            f'/api/inbound/cmms/{integration_id}',
            data=body_text.encode('utf-8'),
            headers=signed_headers,
        )
        self.assertEqual(replay.status, 409)

    async def test_integration_queue_api_auth_and_metrics(self):
        unauthorized = await self.client.get('/api/integrations/queue?limit=5')
        self.assertEqual(unauthorized.status, 401)

        headers = await self._auth_headers()
        queue = await self.client.get('/api/integrations/queue?limit=5', headers=headers)
        self.assertEqual(queue.status, 200)
        queue_payload = await queue.json()
        self.assertIn('queue', queue_payload)
        self.assertIn('stats', queue_payload)

        metrics = await self.client.get('/api/integrations/metrics', headers=headers)
        self.assertEqual(metrics.status, 200)
        metrics_payload = await metrics.json()
        self.assertIn('processed_24h', metrics_payload)
        self.assertIn('success_rate_24h', metrics_payload)


if __name__ == '__main__':
    unittest.main()
