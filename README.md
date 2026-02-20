# FLEX

Factory Link Explorer (FLEX) の可視化アプリです。設備接続グラフを表示し、`Mock` と `Live Packet Stream` を切り替えて接続変化を確認できます。

## 構成

- `src/` : React + Cytoscape の可視化UI
- `packet-agent/agent.py` : 実パケットを収集してWebSocket配信するエージェント

## 1) UI起動

```bash
npm install
npm run dev
```

画面: `http://localhost:5173`

## Dockerで同時起動（Frontend + Agent）

### 起動

```bash
docker compose up --build
```

- Frontend: `http://localhost:5173`
- Packet Agent WebSocket: `ws://localhost:8765`

必要なら `.env.example` を `.env` にコピーして値を調整します。

```bash
copy .env.example .env
```

カスタムポートやIPペアでプロトコル名を上書きしたい場合は `.env` に以下を設定できます。

```dotenv
FLEX_PROTOCOL_PORT_MAP=OPC UA:62557,MyProto:12000
FLEX_ENDPOINT_PROTOCOL_MAP=192.168.1.50-192.168.1.100:OPC UA
```

### 停止

```bash
docker compose down
```

## 2) 実パケット入力エージェント起動

### 前提

- Python 3.10+
- Windowsでは Npcap（WinPcap互換）
- パケット取得権限（管理者実行推奨）

### セットアップ

```bash
cd packet-agent
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

### 起動

```bash
python agent.py --host 127.0.0.1 --port 8765
```

必要に応じてインターフェース指定:

```bash
python agent.py --iface "Ethernet" --bpf "tcp or udp"
```

## 3) UIでLive接続

1. UIの `Mode` を `Live (Packet Agent)` に変更
2. `Agent URL` を `ws://127.0.0.1:8765` に設定
3. `Agent: Connected` になれば実パケット由来の接続が反映

## 注意事項（Windows + Docker）

- Windows上のDocker Desktopコンテナから、ホストの物理NICを直接スニッフィングできない場合があります。
- 実ネットワーク（SPAN/TAP）のパケット取得が必要な場合は、以下のどちらかを推奨します。
  - Linuxホストで`packet-agent`コンテナを実行
  - Windowsでは`packet-agent`をホストで直接実行し、FrontendのみDockerで実行

## エージェントが送るイベント形式

```json
{
  "type": "connection_update",
  "payload": {
    "connection_id": "a1b2c3d4e5f6",
    "src_ip": "192.168.10.11",
    "dst_ip": "192.168.10.21",
    "protocol": "Modbus/TCP",
    "port": 502,
    "packets": 182,
    "bytes_per_sec": 1468.5,
    "last_seen": "2026-02-20T14:22:10Z"
  }
}
```
