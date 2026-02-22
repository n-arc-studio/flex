import argparse
import asyncio
import json
import time
from typing import Dict, Set

from websockets.asyncio.server import ServerConnection, serve


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="FLEX agent registry")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8780)
    return parser.parse_args()


async def run_registry(host: str, port: int) -> None:
    agent_clients: Set[ServerConnection] = set()
    ui_clients: Set[ServerConnection] = set()
    agent_states: Dict[str, dict] = {}

    async def broadcast_ui(message: dict) -> None:
        if not ui_clients:
            return

        body = json.dumps(message)
        disconnected: list[ServerConnection] = []
        for client in ui_clients:
            try:
                await client.send(body)
            except Exception:
                disconnected.append(client)

        for client in disconnected:
            ui_clients.discard(client)

    async def handler(websocket: ServerConnection) -> None:
        path = "/"
        try:
            request = getattr(websocket, "request", None)
            if request is not None and getattr(request, "path", None):
                path = request.path
        except Exception:
            path = "/"

        if path == "/ui":
            ui_clients.add(websocket)
            await websocket.send(
                json.dumps(
                    {
                        "type": "registry_snapshot",
                        "payload": {
                            "agents": list(agent_states.values()),
                            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        },
                    }
                )
            )
            try:
                async for _ in websocket:
                    pass
            finally:
                ui_clients.discard(websocket)
            return

        if path != "/agent":
            await websocket.send(json.dumps({"type": "error", "payload": {"message": "unsupported path"}}))
            await websocket.close()
            return

        agent_clients.add(websocket)
        bound_agent_id: str | None = None

        try:
            async for raw in websocket:
                try:
                    message = json.loads(raw)
                except Exception:
                    continue

                msg_type = message.get("type")
                payload = message.get("payload", {})
                if not isinstance(payload, dict):
                    payload = {}

                agent_id = str(payload.get("agent_id", "")).strip() or bound_agent_id
                agent_name = str(payload.get("agent_name", "")).strip() or "Unknown Agent"

                if msg_type in ("hello", "heartbeat") and agent_id:
                    bound_agent_id = agent_id
                    state = {
                        "agent_id": agent_id,
                        "agent_name": agent_name,
                        "status": "connected",
                        "total_packets": int(payload.get("total_packets", 0) or 0),
                        "active_connections": int(payload.get("active_connections", 0) or 0),
                        "last_seen": payload.get("timestamp")
                        or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    }
                    agent_states[agent_id] = state
                    await broadcast_ui({"type": "registry_agent_update", "payload": state})

                if msg_type == "connection_update" and bound_agent_id:
                    enriched_payload = {
                        **payload,
                        "agent_id": bound_agent_id,
                        "agent_name": agent_states.get(bound_agent_id, {}).get("agent_name", "Unknown Agent"),
                    }
                    await broadcast_ui({"type": "connection_update", "payload": enriched_payload})
        finally:
            agent_clients.discard(websocket)
            if bound_agent_id and bound_agent_id in agent_states:
                state = {**agent_states[bound_agent_id], "status": "disconnected"}
                agent_states[bound_agent_id] = state
                await broadcast_ui({"type": "registry_agent_update", "payload": state})

    async with serve(handler, host, port):
        print(f"[FLEX registry] listening on ws://{host}:{port} (/agent, /ui)")
        await asyncio.Future()


def main() -> None:
    args = parse_args()
    asyncio.run(run_registry(args.host, args.port))


if __name__ == "__main__":
    main()
