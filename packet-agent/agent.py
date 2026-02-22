import argparse
import asyncio
import hashlib
import ipaddress
import json
import os
import platform
import signal
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Set, Tuple
from urllib import error, request

from scapy.all import IP, TCP, UDP, get_if_list, sniff
from websockets.asyncio.client import connect
from websockets.asyncio.server import ServerConnection, serve

PROTOCOL_PORT_MAP = {
    502: 'Modbus/TCP',
    44818: 'EtherNet/IP',
    34964: 'PROFINET',
    4840: 'OPC UA',
    20000: 'DNP3',
    2404: 'IEC 104',
    47808: 'BACnet/IP',
    443: 'HTTPS',
    80: 'HTTP',
    53: 'DNS',
    123: 'NTP',
    22: 'SSH',
}


def parse_protocol_port_map(raw: str) -> Dict[int, str]:
    mapping: Dict[int, str] = {}
    if not raw:
        return mapping

    for item in raw.split(','):
        part = item.strip()
        if not part or ':' not in part:
            continue
        name, port_text = part.rsplit(':', 1)
        name = name.strip()
        port_text = port_text.strip()
        if not name:
            continue
        try:
            port = int(port_text)
        except ValueError:
            continue
        if 0 < port <= 65535:
            mapping[port] = name

    return mapping


def parse_endpoint_protocol_map(raw: str) -> Dict[frozenset[str], str]:
    mapping: Dict[frozenset[str], str] = {}
    if not raw:
        return mapping

    for item in raw.split(','):
        part = item.strip()
        if not part or ':' not in part:
            continue

        pair_text, name = part.rsplit(':', 1)
        name = name.strip()
        if not name or '-' not in pair_text:
            continue

        ip1, ip2 = [segment.strip() for segment in pair_text.split('-', 1)]
        if not ip1 or not ip2:
            continue

        mapping[frozenset((ip1, ip2))] = name

    return mapping


@dataclass
class ConnectionStat:
    src_ip: str
    dst_ip: str
    protocol: str
    port: int
    packets: int = 0
    total_bytes: int = 0
    window_bytes: int = 0
    last_seen: float = 0.0


class ReverseDnsResolver:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled
        self._cache: Dict[str, Optional[str]] = {}
        self._lock = threading.Lock()

    def _is_candidate(self, ip: str) -> bool:
        if ip == '255.255.255.255':
            return False
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if parsed.is_loopback or parsed.is_multicast:
            return False
        return parsed.is_private or parsed.is_link_local

    def resolve(self, ip: str) -> Optional[str]:
        if not self.enabled or not self._is_candidate(ip):
            return None
        with self._lock:
            if ip in self._cache:
                return self._cache[ip]
        try:
            host = socket.gethostbyaddr(ip)[0]
        except Exception:
            host = None
        with self._lock:
            self._cache[ip] = host
        return host


def infer_protocol(port: int, l4_protocol: str, protocol_port_map: Dict[int, str]) -> str:
    if port in protocol_port_map:
        return protocol_port_map[port]
    return f'{l4_protocol}/{port}'


class PacketAggregator:
    def __init__(
        self,
        idle_timeout_seconds: int = 120,
        protocol_port_map: Optional[Dict[int, str]] = None,
        endpoint_protocol_map: Optional[Dict[frozenset[str], str]] = None,
        rdns_resolver: Optional[ReverseDnsResolver] = None,
    ) -> None:
        self._stats: Dict[Tuple[str, str, str, int], ConnectionStat] = {}
        self._lock = threading.Lock()
        self._idle_timeout_seconds = idle_timeout_seconds
        self._total_packets = 0
        self._protocol_port_map = protocol_port_map or dict(PROTOCOL_PORT_MAP)
        self._endpoint_protocol_map = endpoint_protocol_map or {}
        self._rdns_resolver = rdns_resolver or ReverseDnsResolver(enabled=False)

    def ingest_packet(self, packet) -> None:
        if IP not in packet:
            return

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        if TCP in packet:
            l4_protocol = 'TCP'
            src_port = int(packet[TCP].sport)
            dst_port = int(packet[TCP].dport)
        elif UDP in packet:
            l4_protocol = 'UDP'
            src_port = int(packet[UDP].sport)
            dst_port = int(packet[UDP].dport)
        else:
            return

        has_dst_mapping = dst_port in self._protocol_port_map
        has_src_mapping = src_port in self._protocol_port_map

        if has_dst_mapping:
            protocol = infer_protocol(dst_port, l4_protocol, self._protocol_port_map)
            service_port = dst_port
            flow_src_ip = src_ip
            flow_dst_ip = dst_ip
        elif has_src_mapping:
            protocol = infer_protocol(src_port, l4_protocol, self._protocol_port_map)
            service_port = src_port
            flow_src_ip = dst_ip
            flow_dst_ip = src_ip
        else:
            service_port = min(src_port, dst_port)
            protocol = infer_protocol(service_port, l4_protocol, self._protocol_port_map)
            flow_src_ip, flow_dst_ip = sorted((src_ip, dst_ip))

        endpoint_protocol = self._endpoint_protocol_map.get(frozenset((src_ip, dst_ip)))
        if endpoint_protocol:
            protocol = endpoint_protocol
            flow_src_ip, flow_dst_ip = sorted((src_ip, dst_ip))

        key = (flow_src_ip, flow_dst_ip, protocol, service_port)
        now = time.time()
        packet_size = len(packet)

        with self._lock:
            self._total_packets += 1
            stat = self._stats.get(key)
            if stat is None:
                stat = ConnectionStat(src_ip=flow_src_ip, dst_ip=flow_dst_ip, protocol=protocol, port=service_port)
                self._stats[key] = stat

            stat.packets += 1
            stat.total_bytes += packet_size
            stat.window_bytes += packet_size
            stat.last_seen = now

    def snapshot(self, interval_seconds: float) -> list[dict]:
        now = time.time()
        payloads: list[dict] = []

        with self._lock:
            stale_keys = []

            for key, stat in self._stats.items():
                if now - stat.last_seen > self._idle_timeout_seconds:
                    stale_keys.append(key)
                    continue

                bytes_per_sec = stat.window_bytes / interval_seconds
                stat.window_bytes = 0

                connection_id = hashlib.md5(
                    f'{stat.src_ip}|{stat.dst_ip}|{stat.protocol}|{stat.port}'.encode('utf-8')
                ).hexdigest()[:12]

                payloads.append(
                    {
                        'connection_id': connection_id,
                        'src_ip': stat.src_ip,
                        'dst_ip': stat.dst_ip,
                        'src_name': self._rdns_resolver.resolve(stat.src_ip),
                        'dst_name': self._rdns_resolver.resolve(stat.dst_ip),
                        'protocol': stat.protocol,
                        'port': stat.port,
                        'packets': stat.packets,
                        'bytes_per_sec': round(bytes_per_sec, 2),
                        'last_seen': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(stat.last_seen)),
                    }
                )

            for stale_key in stale_keys:
                del self._stats[stale_key]

        return payloads

    def metrics(self) -> dict:
        with self._lock:
            return {'total_packets': self._total_packets, 'active_connections': len(self._stats)}


async def run_websocket_server(host: str, port: int, aggregator: PacketAggregator, interval: float, agent_id: str, agent_name: str) -> None:
    clients: Set[ServerConnection] = set()

    async def handler(websocket: ServerConnection) -> None:
        clients.add(websocket)
        await websocket.send(
            json.dumps(
                {
                    'type': 'hello',
                    'payload': {
                        'message': 'FLEX packet agent connected',
                        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                        'agent_id': agent_id,
                        'agent_name': agent_name,
                    },
                }
            )
        )
        try:
            async for _ in websocket:
                pass
        finally:
            clients.discard(websocket)

    async def publisher() -> None:
        while True:
            await asyncio.sleep(interval)
            heartbeat = {
                'type': 'heartbeat',
                'payload': {
                    'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                    'agent_id': agent_id,
                    'agent_name': agent_name,
                    **aggregator.metrics(),
                },
            }
            body = json.dumps(heartbeat)
            for client in list(clients):
                try:
                    await client.send(body)
                except Exception:
                    clients.discard(client)

            for update in aggregator.snapshot(interval):
                payload = json.dumps({'type': 'connection_update', 'payload': update})
                for client in list(clients):
                    try:
                        await client.send(payload)
                    except Exception:
                        clients.discard(client)

    async with serve(handler, host, port):
        print(f'[FLEX agent] WebSocket listening on ws://{host}:{port}')
        await publisher()


async def run_upstream_client(upstream_url: str, aggregator: PacketAggregator, interval: float, agent_id: str, agent_name: str) -> None:
    print(f'[FLEX agent] Upstream mode: {upstream_url}')

    while True:
        try:
            async with connect(upstream_url) as websocket:
                await websocket.send(
                    json.dumps(
                        {
                            'type': 'hello',
                            'payload': {
                                'message': 'FLEX packet agent connected',
                                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                                'agent_id': agent_id,
                                'agent_name': agent_name,
                            },
                        }
                    )
                )

                while True:
                    await asyncio.sleep(interval)
                    await websocket.send(
                        json.dumps(
                            {
                                'type': 'heartbeat',
                                'payload': {
                                    'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                                    'agent_id': agent_id,
                                    'agent_name': agent_name,
                                    **aggregator.metrics(),
                                },
                            }
                        )
                    )

                    for update in aggregator.snapshot(interval):
                        await websocket.send(json.dumps({'type': 'connection_update', 'payload': update}))
        except Exception as err:  # noqa: BLE001
            print(f'[FLEX agent] Upstream disconnected: {err}')
            await asyncio.sleep(2)


def capture_loop(interface, bpf_filter: Optional[str], aggregator: PacketAggregator, stop_flag: threading.Event) -> None:
    kwargs = {'prn': aggregator.ingest_packet, 'store': False, 'timeout': 1}
    if interface:
        kwargs['iface'] = interface
    if bpf_filter:
        kwargs['filter'] = bpf_filter
    while not stop_flag.is_set():
        try:
            sniff(**kwargs)
        except Exception as exc:  # noqa: BLE001
            print(f'[FLEX agent] Capture error: {exc}')
            time.sleep(1)


def resolve_capture_interface(interface, upstream_url: str):
    if interface:
        return interface
    if os.name != 'nt':
        return None
    try:
        all_ifaces = [name for name in get_if_list() if name.startswith('\\Device\\NPF_')]
        if not all_ifaces:
            return None
        if upstream_url.startswith('ws://localhost') or upstream_url.startswith('ws://127.0.0.1'):
            loopback = [name for name in all_ifaces if 'Loopback' in name]
            if loopback:
                return loopback[0]
        return all_ifaces
    except Exception as exc:  # noqa: BLE001
        print(f'[FLEX agent] Interface auto-detect failed: {exc}')
        return None


def default_config_path() -> str:
    if os.name == 'nt':
        program_data = os.getenv('PROGRAMDATA', r'C:\ProgramData')
        return os.path.join(program_data, 'FLEX', 'agent-config.json')
    home_dir = os.path.expanduser('~')
    return os.path.join(home_dir, '.config', 'flex', 'agent-config.json')


def save_agent_config(config_path: str, config: dict) -> None:
    path = Path(config_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding='utf-8')


def load_agent_config(config_path: str) -> Optional[dict]:
    path = Path(config_path)
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding='utf-8'))


def post_json(url: str, body: dict) -> dict:
    req = request.Request(
        url,
        data=json.dumps(body).encode('utf-8'),
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    try:
        with request.urlopen(req, timeout=15) as response:
            return json.loads(response.read().decode('utf-8'))
    except error.HTTPError as exc:
        detail = exc.read().decode('utf-8', errors='ignore')
        raise RuntimeError(f'HTTP {exc.code}: {detail}') from exc


def configure_agent(args: argparse.Namespace) -> None:
    token = args.token.strip() if args.token else ''
    if not token:
        token = input('Enrollment token: ').strip()

    if not token:
        raise RuntimeError('token is required')

    registry_url = args.registry_url.rstrip('/')
    hostname = socket.gethostname()
    request_body = {
        'token': token,
        'agent_name': args.agent_name.strip() or hostname,
        'hostname': hostname,
        'platform': platform.platform(),
    }
    response = post_json(f'{registry_url}/api/register', request_body)

    config = {
        'version': 2,
        'registered_at': int(time.time()),
        'agent_id': response['agent_id'],
        'agent_name': response['agent_name'],
        'upstream_url': response['upstream_url'],
        'registry_url': registry_url,
    }
    save_agent_config(args.config_path, config)
    print(f"[FLEX agent] Registered '{config['agent_name']}' ({config['agent_id']})")
    print(f'[FLEX agent] Config saved: {args.config_path}')


def install_service(args: argparse.Namespace) -> None:
    script_path = Path(__file__).resolve()
    config_path = args.config_path
    python_bin = sys.executable

    if os.name == 'nt':
        service_name = args.service_name
        bin_path = f'\"{python_bin}\" \"{script_path}\" run --config-path \"{config_path}\"'
        subprocess.run(['sc.exe', 'create', service_name, f'binPath= {bin_path}', 'start= auto'], check=True)
        subprocess.run(['sc.exe', 'description', service_name, 'FLEX Packet Agent'], check=False)
        subprocess.run(['sc.exe', 'start', service_name], check=False)
        print(f'[FLEX agent] Windows service installed: {service_name}')
        return

    service_name = args.service_name
    service_file = Path(f'/etc/systemd/system/{service_name}.service')
    unit = f'''[Unit]
Description=FLEX Packet Agent
After=network.target

[Service]
Type=simple
ExecStart={python_bin} {script_path} run --config-path {config_path}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
'''
    service_file.write_text(unit, encoding='utf-8')
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', 'enable', '--now', service_name], check=True)
    print(f'[FLEX agent] systemd service installed: {service_name}')


def resolve_run_option(explicit_value, config: Optional[dict], config_key: str, fallback):
    if explicit_value is not None:
        return explicit_value
    if config and config_key in config:
        return config[config_key]
    return fallback


def resolve_agent_rdns_enabled(rdns_mode: str, upstream_url: str) -> bool:
    mode = (rdns_mode or 'auto').strip().lower()
    if mode in ('off', '0', 'false', 'no'):
        return False
    if mode in ('on', '1', 'true', 'yes'):
        return True
    return bool(upstream_url)


def parse_cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='FLEX packet capture agent')
    subparsers = parser.add_subparsers(dest='command')

    run_parser = subparsers.add_parser('run', help='Run packet capture agent')
    run_parser.add_argument('--iface', type=str, default=None)
    run_parser.add_argument('--host', type=str, default=None)
    run_parser.add_argument('--port', type=int, default=None)
    run_parser.add_argument('--interval', type=float, default=None)
    run_parser.add_argument('--idle-timeout', type=int, default=None)
    run_parser.add_argument('--bpf', type=str, default=None)
    run_parser.add_argument('--protocol-port-map', type=str, default=None)
    run_parser.add_argument('--endpoint-protocol-map', type=str, default=None)
    run_parser.add_argument('--agent-id', type=str, default=None)
    run_parser.add_argument('--agent-name', type=str, default=None)
    run_parser.add_argument('--upstream-url', type=str, default=None)
    run_parser.add_argument('--rdns-mode', type=str, default=None, choices=['auto', 'on', 'off'])
    run_parser.add_argument('--config-path', type=str, default=default_config_path())
    run_parser.add_argument('--skip-config', action='store_true')

    config_parser = subparsers.add_parser('config', help='Configure agent with enrollment token')
    config_parser.add_argument('--registry-url', type=str, default=os.getenv('FLEX_REGISTRY_URL', 'http://127.0.0.1:8780'))
    config_parser.add_argument('--token', type=str, default='')
    config_parser.add_argument('--agent-name', type=str, default=socket.gethostname())
    config_parser.add_argument('--config-path', type=str, default=default_config_path())

    register_parser = subparsers.add_parser('register', help='Alias of config')
    register_parser.add_argument('--registry-url', type=str, default=os.getenv('FLEX_REGISTRY_URL', 'http://127.0.0.1:8780'))
    register_parser.add_argument('--token', type=str, default='')
    register_parser.add_argument('--agent-name', type=str, default=socket.gethostname())
    register_parser.add_argument('--config-path', type=str, default=default_config_path())

    install_parser = subparsers.add_parser('install-service', help='Install as OS service')
    install_parser.add_argument('--service-name', type=str, default='FLEXAgent')
    install_parser.add_argument('--config-path', type=str, default=default_config_path())

    argv = sys.argv[1:]
    if not argv:
        argv = ['run']
    return parser.parse_args(argv)


def main() -> None:
    args = parse_cli_args()

    if args.command in ('config', 'register'):
        configure_agent(args)
        return

    if args.command == 'install-service':
        install_service(args)
        return

    config = None if args.skip_config else load_agent_config(args.config_path)

    host = resolve_run_option(args.host, config, 'host', '127.0.0.1')
    port = int(resolve_run_option(args.port, config, 'port', 8765))
    interval = float(resolve_run_option(args.interval, config, 'interval', 2.0))
    idle_timeout = int(resolve_run_option(args.idle_timeout, config, 'idle_timeout', 120))
    iface = resolve_run_option(args.iface, config, 'iface', None)
    bpf = resolve_run_option(args.bpf, config, 'bpf', 'tcp or udp')
    protocol_port_map_text = resolve_run_option(args.protocol_port_map, config, 'protocol_port_map', '')
    endpoint_protocol_map_text = resolve_run_option(args.endpoint_protocol_map, config, 'endpoint_protocol_map', '')
    agent_id = resolve_run_option(args.agent_id, config, 'agent_id', os.getenv('FLEX_AGENT_ID', 'agent-local'))
    agent_name = resolve_run_option(args.agent_name, config, 'agent_name', os.getenv('FLEX_AGENT_NAME', socket.gethostname()))
    upstream_url = resolve_run_option(args.upstream_url, config, 'upstream_url', os.getenv('FLEX_UPSTREAM_URL', ''))
    rdns_mode = resolve_run_option(args.rdns_mode, config, 'rdns_mode', os.getenv('FLEX_AGENT_RDNS_MODE', 'auto'))
    agent_rdns_enabled = resolve_agent_rdns_enabled(str(rdns_mode), str(upstream_url))
    iface = resolve_capture_interface(iface, str(upstream_url))

    protocol_port_map = dict(PROTOCOL_PORT_MAP)
    protocol_port_map.update(parse_protocol_port_map(protocol_port_map_text))
    endpoint_protocol_map = parse_endpoint_protocol_map(endpoint_protocol_map_text)
    rdns_resolver = ReverseDnsResolver(enabled=agent_rdns_enabled)

    aggregator = PacketAggregator(
        idle_timeout_seconds=idle_timeout,
        protocol_port_map=protocol_port_map,
        endpoint_protocol_map=endpoint_protocol_map,
        rdns_resolver=rdns_resolver,
    )

    stop_capture = threading.Event()
    capture_thread = threading.Thread(target=capture_loop, args=(iface, bpf, aggregator, stop_capture), daemon=True)

    print('[FLEX agent] Starting packet capture...')
    print(f'[FLEX agent] Capture interface: {iface if iface else "default"}')
    capture_thread.start()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    stop_event = asyncio.Event()

    def stop_handler(*_) -> None:
        stop_event.set()

    signal.signal(signal.SIGINT, stop_handler)
    signal.signal(signal.SIGTERM, stop_handler)

    async def runner() -> None:
        if upstream_url:
            task = asyncio.create_task(run_upstream_client(upstream_url, aggregator, interval, agent_id, agent_name))
        else:
            task = asyncio.create_task(run_websocket_server(host, port, aggregator, interval, agent_id, agent_name))

        await stop_event.wait()
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    try:
        loop.run_until_complete(runner())
    finally:
        print('[FLEX agent] Stopping packet capture...')
        stop_capture.set()
        capture_thread.join(timeout=3)
        loop.close()


if __name__ == '__main__':
    main()
