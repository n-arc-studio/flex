# FLEX

Factory Link Explorer (FLEX) の可視化アプリです。設備接続グラフを表示し、`Mock` と `Live` を切り替えて接続変化を確認できます。AgentはRegistryへ自発接続し、UIはRegistryを購読します（URL入力不要）。

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
- Agent Registry(UI): `ws://localhost:8780/ui`
- Agent Registry(Agent): `ws://localhost:8780/agent`

必要なら `.env.example` を `.env` にコピーして値を調整します。

```bash
copy .env.example .env
```

カスタムポートやIPペアでプロトコル名を上書きしたい場合は `.env` に以下を設定できます。

```dotenv
FLEX_PROTOCOL_PORT_MAP=OPC UA:62557,MyProto:12000
FLEX_ENDPOINT_PROTOCOL_MAP=192.168.1.50-192.168.1.100:OPC UA
FLEX_AGENT_ID=agent-docker
FLEX_AGENT_NAME=Docker Packet Agent
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

# エージェント識別情報を指定（推奨）
python agent.py --host 127.0.0.1 --port 8765 --agent-id line-a --agent-name "Line A Sensor"
```

必要に応じてインターフェース指定:

```bash
python agent.py --iface "Ethernet" --bpf "tcp or udp"
```

## 3) UIでLive接続

1. UIの `Mode` を `Live (Registry)` に変更
2. Agent側で `register` と `run` を実行
3. `Agents + Onboarding` タブにAgent状態が表示されれば接続完了

## 3.5) MVP: Self-hosted風の登録手順

GitHub Actions self-hosted runner登録に近い手順で、URL手入力なしの登録を行えます。

1. UIの `エージェント登録 (MVP)` で `登録先URL` / `エージェント名` / `トークン有効期限` を設定
2. `登録トークン生成` を押す
3. 表示された `登録コマンド` をWindowsホストの `packet-agent` ディレクトリで実行
4. 以降は `python agent.py run` で保存済み設定から起動

例:

```bash
python agent.py register --token "flexreg.v1.xxxxx" --agent-name "line-a-agent"
python agent.py run
```

保存先（既定）:

- Windows: `C:\ProgramData\FLEX\agent-config.json`
- Linux/macOS: `~/.config/flex/agent-config.json`

補足:

- `python agent.py` は `python agent.py run` と同義です
- `--skip-config` を付けると保存済み設定を無視できます

## 4) 複数エージェント管理（一覧）

- AgentはRegistryへ自発接続（GitHub runner型）
- UIはRegistryの状態を一覧表示（URL入力・手動Reconnect不要）
- `Agents + Onboarding` タブで登録トークン生成と登録コマンド表示
- 接続詳細にどのエージェント由来か (`Source Agent`) を表示

## 注意事項（Windows + Docker）

- Windows上のDocker Desktopコンテナから、ホストの物理NICを直接スニッフィングできない場合があります。
- 実ネットワーク（SPAN/TAP）のパケット取得が必要な場合は、以下のどちらかを推奨します。
  - Linuxホストで`packet-agent`コンテナを実行
  - Windowsでは`packet-agent`をホストで直接実行し、FrontendのみDockerで実行

## エージェントが送るイベント形式

`hello` / `heartbeat` は `agent_id` と `agent_name` を含めます。

```json
{
  "type": "hello",
  "payload": {
    "message": "FLEX packet agent connected",
    "timestamp": "2026-02-20T14:22:10Z",
    "agent_id": "line-a",
    "agent_name": "Line A Sensor"
  }
}
```

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
