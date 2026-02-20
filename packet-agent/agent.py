import argparse
import asyncio
import hashlib
import json
import signal
import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional, Set, Tuple

from scapy.all import IP, TCP, UDP, sniff
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


def infer_protocol(port: int, l4_protocol: str) -> str:
    if port in PROTOCOL_PORT_MAP:
        return PROTOCOL_PORT_MAP[port]
    return f"{l4_protocol}/{port}"


class PacketAggregator:
    def __init__(self, idle_timeout_seconds: int = 120) -> None:
        self._stats: Dict[Tuple[str, str, str, int], ConnectionStat] = {}
        self._lock = threading.Lock()
        self._idle_timeout_seconds = idle_timeout_seconds
        self._total_packets = 0

    def ingest_packet(self, packet) -> None:
        if IP not in packet:
            return

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        if TCP in packet:
            l4_protocol = "TCP"
            dst_port = int(packet[TCP].dport)
        elif UDP in packet:
            l4_protocol = "UDP"
            dst_port = int(packet[UDP].dport)
        else:
            return

        protocol = infer_protocol(dst_port, l4_protocol)
        key = (src_ip, dst_ip, protocol, dst_port)
        now = time.time()
        packet_size = len(packet)

        with self._lock:
            self._total_packets += 1
            stat = self._stats.get(key)
            if stat is None:
                stat = ConnectionStat(src_ip=src_ip, dst_ip=dst_ip, protocol=protocol, port=dst_port)
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


async def run_websocket_server(host: str, port: int, aggregator: PacketAggregator, interval: float) -> None:
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="FLEX packet capture agent")
    parser.add_argument("--iface", type=str, default=None, help="Capture interface name")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="WebSocket bind host")
    parser.add_argument("--port", type=int, default=8765, help="WebSocket bind port")
    parser.add_argument("--interval", type=float, default=2.0, help="Publish interval seconds")
    parser.add_argument("--idle-timeout", type=int, default=120, help="Idle connection timeout seconds")
    parser.add_argument(
        "--bpf",
        type=str,
        default="tcp or udp",
        help="Optional BPF filter, example: 'tcp port 502 or tcp port 44818'",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    aggregator = PacketAggregator(idle_timeout_seconds=args.idle_timeout)
    stop_capture = threading.Event()
    capture_thread = threading.Thread(
        target=capture_loop,
        args=(args.iface, args.bpf, aggregator, stop_capture),
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
        server_task = asyncio.create_task(run_websocket_server(args.host, args.port, aggregator, args.interval))
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
