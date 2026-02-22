import argparse
import asyncio
import base64
import hashlib
import json
import os
import signal
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Dict, Optional, Set, Tuple
from urllib.parse import urlparse

from scapy.all import IP, TCP, UDP, sniff
from websockets.asyncio.client import connect
from websockets.asyncio.server import ServerConnection, serve


PROTOCOL_PORT_MAP = {
    502: "Modbus/TCP",
    44818: "EtherNet/IP",
    34964: "PROFINET",
    4840: "OPC UA",
    20000: "DNP3",
    2404: "IEC 104",
    47808: "BACnet/IP",
    443: "HTTPS",
    80: "HTTP",
    53: "DNS",
    123: "NTP",
    22: "SSH",
}


def parse_protocol_port_map(raw: str) -> Dict[int, str]:
    mapping: Dict[int, str] = {}
    if not raw:
        return mapping

    for item in raw.split(","):
        part = item.strip()
        if not part or ":" not in part:
            continue
        name, port_text = part.rsplit(":", 1)
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

    for item in raw.split(","):
        part = item.strip()
        if not part or ":" not in part:
            continue

        pair_text, name = part.rsplit(":", 1)
        name = name.strip()
        if not name or "-" not in pair_text:
            continue

        ip1, ip2 = [segment.strip() for segment in pair_text.split("-", 1)]
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


def infer_protocol(port: int, l4_protocol: str, protocol_port_map: Dict[int, str]) -> str:
    if port in protocol_port_map:
        return protocol_port_map[port]
    return f"{l4_protocol}/{port}"


class PacketAggregator:
    def __init__(
        self,
        idle_timeout_seconds: int = 120,
        protocol_port_map: Optional[Dict[int, str]] = None,
        endpoint_protocol_map: Optional[Dict[frozenset[str], str]] = None,
    ) -> None:
        self._stats: Dict[Tuple[str, str, str, int], ConnectionStat] = {}
        self._lock = threading.Lock()
        self._idle_timeout_seconds = idle_timeout_seconds
        self._total_packets = 0
        self._protocol_port_map = protocol_port_map or dict(PROTOCOL_PORT_MAP)
        self._endpoint_protocol_map = endpoint_protocol_map or {}

    def ingest_packet(self, packet) -> None:
        if IP not in packet:
            return

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        if TCP in packet:
            l4_protocol = "TCP"
            src_port = int(packet[TCP].sport)
            dst_port = int(packet[TCP].dport)
        elif UDP in packet:
            l4_protocol = "UDP"
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
                    f"{stat.src_ip}|{stat.dst_ip}|{stat.protocol}|{stat.port}".encode("utf-8")
                ).hexdigest()[:12]

                payloads.append(
                    {
                        "connection_id": connection_id,
                        "src_ip": stat.src_ip,
                        "dst_ip": stat.dst_ip,
                        "protocol": stat.protocol,
                        "port": stat.port,
                        "packets": stat.packets,
                        "bytes_per_sec": round(bytes_per_sec, 2),
                        "last_seen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stat.last_seen)),
                    }
                )

            for stale_key in stale_keys:
                del self._stats[stale_key]

        return payloads

    def metrics(self) -> dict:
        with self._lock:
            return {
                "total_packets": self._total_packets,
                "active_connections": len(self._stats),
            }


async def broadcast(clients: Set[ServerConnection], message: dict) -> None:
    if not clients:
        return

    body = json.dumps(message)
    disconnected: list[ServerConnection] = []

    for client in clients:
        try:
            await client.send(body)
        except Exception:
            disconnected.append(client)

    for client in disconnected:
        clients.discard(client)


async def run_websocket_server(
    host: str,
    port: int,
    aggregator: PacketAggregator,
    interval: float,
    agent_id: str,
    agent_name: str,
) -> None:
    clients: Set[ServerConnection] = set()

    async def handler(websocket: ServerConnection) -> None:
        clients.add(websocket)
        await websocket.send(
            json.dumps(
                {
                    "type": "hello",
                    "payload": {
                        "message": "FLEX packet agent connected",
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "agent_id": agent_id,
                        "agent_name": agent_name,
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
            await broadcast(
                clients,
                {
                    "type": "heartbeat",
                    "payload": {
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "agent_id": agent_id,
                        "agent_name": agent_name,
                        **aggregator.metrics(),
                    },
                },
            )
            updates = aggregator.snapshot(interval)
            for update in updates:
                await broadcast(
                    clients,
                    {
                        "type": "connection_update",
                        "payload": update,
                    },
                )

    async with serve(handler, host, port):
        print(f"[FLEX agent] WebSocket listening on ws://{host}:{port}")
        await publisher()


async def run_upstream_client(upstream_url: str, aggregator: PacketAggregator, interval: float, agent_id: str, agent_name: str) -> None:
    print(f"[FLEX agent] Upstream mode: {upstream_url}")

    while True:
        try:
            async with connect(upstream_url) as websocket:
                await websocket.send(
                    json.dumps(
                        {
                            "type": "hello",
                            "payload": {
                                "message": "FLEX packet agent connected",
                                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                                "agent_id": agent_id,
                                "agent_name": agent_name,
                            },
                        }
                    )
                )

                while True:
                    await asyncio.sleep(interval)
                    await websocket.send(
                        json.dumps(
                            {
                                "type": "heartbeat",
                                "payload": {
                                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                                    "agent_id": agent_id,
                                    "agent_name": agent_name,
                                    **aggregator.metrics(),
                                },
                            }
                        )
                    )

                    updates = aggregator.snapshot(interval)
                    for update in updates:
                        await websocket.send(
                            json.dumps(
                                {
                                    "type": "connection_update",
                                    "payload": update,
                                }
                            )
                        )
        except Exception as error:  # noqa: BLE001
            print(f"[FLEX agent] Upstream disconnected: {error}")
            await asyncio.sleep(2)


def capture_loop(interface: Optional[str], bpf_filter: Optional[str], aggregator: PacketAggregator, stop_flag: threading.Event) -> None:
    kwargs = {
        "prn": aggregator.ingest_packet,
        "store": False,
        "timeout": 1,
    }

    if interface:
        kwargs["iface"] = interface

    if bpf_filter:
        kwargs["filter"] = bpf_filter

    while not stop_flag.is_set():
        sniff(**kwargs)


def default_config_path() -> str:
    if os.name == "nt":
        program_data = os.getenv("PROGRAMDATA", r"C:\ProgramData")
        return os.path.join(program_data, "FLEX", "agent-config.json")

    home_dir = os.path.expanduser("~")
    return os.path.join(home_dir, ".config", "flex", "agent-config.json")


def parse_server_url(server_url: str) -> Tuple[str, int]:
    parsed = urlparse(server_url)
    if parsed.scheme not in ("ws", "wss"):
        raise ValueError("server_url must start with ws:// or wss://")
    if not parsed.hostname:
        raise ValueError("server_url must include hostname")

    if parsed.port is not None:
        return parsed.hostname, parsed.port

    if parsed.scheme == "wss":
        return parsed.hostname, 443

    return parsed.hostname, 80


def decode_register_token(token: str) -> dict:
    prefix = "flexreg.v1."
    if not token.startswith(prefix):
        raise ValueError("invalid token format")

    encoded = token[len(prefix) :]
    padding = "=" * ((4 - len(encoded) % 4) % 4)

    try:
        payload_bytes = base64.urlsafe_b64decode((encoded + padding).encode("utf-8"))
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception as error:  # noqa: BLE001
        raise ValueError("token decode failed") from error

    expires_at = int(payload.get("exp", 0))
    if expires_at <= int(time.time()):
        raise ValueError("token expired")

    server_url = payload.get("server_url")
    if not isinstance(server_url, str) or not server_url:
        raise ValueError("token missing server_url")

    return payload


def save_agent_config(config_path: str, config: dict) -> None:
    directory = os.path.dirname(config_path)
    if directory:
        os.makedirs(directory, exist_ok=True)

    with open(config_path, "w", encoding="utf-8") as file:
        json.dump(config, file, ensure_ascii=False, indent=2)


def load_agent_config(config_path: str) -> Optional[dict]:
    if not os.path.exists(config_path):
        return None

    with open(config_path, "r", encoding="utf-8") as file:
        return json.load(file)


def parse_cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="FLEX packet capture agent")
    subparsers = parser.add_subparsers(dest="command")

    run_parser = subparsers.add_parser("run", help="Run packet capture agent")
    run_parser.add_argument("--iface", type=str, default=None, help="Capture interface name")
    run_parser.add_argument("--host", type=str, default=None, help="WebSocket bind host")
    run_parser.add_argument("--port", type=int, default=None, help="WebSocket bind port")
    run_parser.add_argument("--interval", type=float, default=None, help="Publish interval seconds")
    run_parser.add_argument("--idle-timeout", type=int, default=None, help="Idle connection timeout seconds")
    run_parser.add_argument(
        "--bpf",
        type=str,
        default=None,
        help="Optional BPF filter, example: 'tcp port 502 or tcp port 44818'",
    )
    run_parser.add_argument(
        "--protocol-port-map",
        type=str,
        default=None,
        help="Extra protocol map, format: 'OPC UA:62557,MyProto:12345'",
    )
    run_parser.add_argument(
        "--endpoint-protocol-map",
        type=str,
        default=None,
        help="Endpoint protocol map, format: '192.168.1.50-192.168.1.100:OPC UA'",
    )
    run_parser.add_argument(
        "--agent-id",
        type=str,
        default=None,
        help="Unique agent identifier for multi-agent management",
    )
    run_parser.add_argument(
        "--agent-name",
        type=str,
        default=None,
        help="Display name for this agent",
    )
    run_parser.add_argument(
        "--config-path",
        type=str,
        default=default_config_path(),
        help="Agent config path for registered settings",
    )
    run_parser.add_argument(
        "--skip-config",
        action="store_true",
        help="Ignore saved config and use explicit run options only",
    )
    run_parser.add_argument(
        "--upstream-url",
        type=str,
        default=None,
        help="Registry websocket URL. When set, agent pushes events to upstream instead of serving ws locally.",
    )

    register_parser = subparsers.add_parser("register", help="Register agent settings from onboarding token")
    register_parser.add_argument("--token", type=str, required=True, help="Enrollment token from FLEX UI")
    register_parser.add_argument("--agent-name", type=str, required=True, help="Agent display name")
    register_parser.add_argument("--agent-id", type=str, default="", help="Optional fixed agent id")
    register_parser.add_argument("--server-url", type=str, default="", help="Optional override for token server url")
    register_parser.add_argument(
        "--config-path",
        type=str,
        default=default_config_path(),
        help="Agent config path",
    )

    argv = sys.argv[1:]
    if not argv or argv[0].startswith("-"):
        argv = ["run", *argv]

    return parser.parse_args(argv)


def register_agent(args: argparse.Namespace) -> None:
    token_payload = decode_register_token(args.token)
    server_url = args.server_url.strip() or str(token_payload["server_url"])

    agent_id = args.agent_id.strip() or f"agent-{uuid.uuid4().hex[:10]}"
    now = int(time.time())

    config = {
        "version": 1,
        "registered_at": now,
        "agent_id": agent_id,
        "agent_name": args.agent_name.strip(),
        "upstream_url": server_url,
    }

    save_agent_config(args.config_path, config)
    print(f"[FLEX agent] Registered agent '{config['agent_name']}' ({agent_id})")
    print(f"[FLEX agent] Config saved: {args.config_path}")
    print("[FLEX agent] Next: python agent.py run")


def resolve_run_option(explicit_value, config: Optional[dict], config_key: str, fallback):
    if explicit_value is not None:
        return explicit_value
    if config and config_key in config:
        return config[config_key]
    return fallback


def main() -> None:
    args = parse_cli_args()

    if args.command == "register":
        register_agent(args)
        return

    config = None if args.skip_config else load_agent_config(args.config_path)

    host = resolve_run_option(args.host, config, "host", "127.0.0.1")
    port = int(resolve_run_option(args.port, config, "port", 8765))
    interval = float(resolve_run_option(args.interval, config, "interval", 2.0))
    idle_timeout = int(resolve_run_option(args.idle_timeout, config, "idle_timeout", 120))
    iface = resolve_run_option(args.iface, config, "iface", None)
    bpf = resolve_run_option(args.bpf, config, "bpf", "tcp or udp")
    protocol_port_map_text = resolve_run_option(args.protocol_port_map, config, "protocol_port_map", "")
    endpoint_protocol_map_text = resolve_run_option(args.endpoint_protocol_map, config, "endpoint_protocol_map", "")
    agent_id = resolve_run_option(args.agent_id, config, "agent_id", os.getenv("FLEX_AGENT_ID", "agent-local"))
    agent_name = resolve_run_option(
        args.agent_name,
        config,
        "agent_name",
        os.getenv("FLEX_AGENT_NAME", "Local Packet Agent"),
    )
    upstream_url = resolve_run_option(args.upstream_url, config, "upstream_url", os.getenv("FLEX_UPSTREAM_URL", ""))

    protocol_port_map = dict(PROTOCOL_PORT_MAP)
    protocol_port_map.update(parse_protocol_port_map(protocol_port_map_text))
    endpoint_protocol_map = parse_endpoint_protocol_map(endpoint_protocol_map_text)

    aggregator = PacketAggregator(
        idle_timeout_seconds=idle_timeout,
        protocol_port_map=protocol_port_map,
        endpoint_protocol_map=endpoint_protocol_map,
    )
    stop_capture = threading.Event()
    capture_thread = threading.Thread(
        target=capture_loop,
        args=(iface, bpf, aggregator, stop_capture),
        daemon=True,
    )

    print("[FLEX agent] Starting packet capture...")
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
            server_task = asyncio.create_task(run_upstream_client(upstream_url, aggregator, interval, agent_id, agent_name))
        else:
            server_task = asyncio.create_task(
                run_websocket_server(
                    host,
                    port,
                    aggregator,
                    interval,
                    agent_id,
                    agent_name,
                )
            )
        await stop_event.wait()
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass

    try:
        loop.run_until_complete(runner())
    finally:
        print("[FLEX agent] Stopping packet capture...")
        stop_capture.set()
        capture_thread.join(timeout=3)
        loop.close()


if __name__ == "__main__":
    main()
