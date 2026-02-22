# FLEX

Factory Link Explorer (FLEX) は、未知の工場ネットワークを受動観測して、設備接続のトポロジを可視化するツールです。

今回の実装で以下を追加しました。

- Agent Registry に SQLite 永続化を追加（再起動後も資産/接続/差分を保持）
- 接続差分イベント（新規フロー検出）を保存/配信
- 資産台帳（ラベル/役割/重要度）の編集 API
- UI を `Overview / Assets / Events / Onboarding` の運用向け構成に刷新

## 構成

- `src/` : React + Cytoscape の可視化 UI
- `agent-registry/registry.py` : Agent Registry（API + WS + SQLite）
- `packet-agent/agent.py` : パケット取得エージェント

## 起動

```bash
docker compose up --build
```

- Frontend: `http://localhost:5173`
- Registry API: `http://localhost:8780`
- Registry WS(UI): `ws://localhost:8780/ws/ui`
- Registry WS(Agent): `ws://localhost:8780/ws/agent`

Registry は `flex-registry-data` volume に `flex.db` を保存します。

## UI

### Overview
- 現在観測中の接続トポロジをグラフ表示
- Agent数/設備数/フロー数/パケット数/帯域の KPI 表示

### Assets
- 資産台帳（IP、ラベル、役割、重要度、最終観測時刻）
- 資産の手動メタデータ編集（ラベル、役割、重要度）
- 現在のフロー一覧

### Events
- 差分イベント一覧（新規フロー検出）

### Onboarding
- トークン発行
- Windows/Linux バンドルダウンロード
- `config` / `run` / `install-service` コマンド提示

## Agent Onboarding

1. UI の `Onboarding` でトークン発行
2. バンドルをダウンロード
3. エージェント側で設定

```bash
python agent.py config --registry-url "http://localhost:8780" --agent-name "line-a-agent" --token "<token>"
```

4. 収集開始

```bash
python agent.py run
```

5. サービス登録（任意）

```bash
python agent.py install-service
```

## 主要 API

- `POST /api/tokens` : Enrollment token 発行
- `POST /api/register` : Agent 登録
- `GET /api/topology/snapshot` : 既知の Agent/Asset/Connection/Diff 一括取得
- `GET /api/assets` : 資産一覧
- `PATCH /api/assets/{ip}` : 資産メタデータ更新
- `GET /api/diffs` : 差分イベント取得

## 永続化対象

- Agents
- Assets（台帳）
- Connections（最新状態）
- Diff Events（差分履歴）
- Enrollment Tokens（有効期限付き）

## 注意事項

- Windows の Docker Desktop コンテナから物理 NIC の直接スニッフィングが難しい場合があります。
- 実ネットワークの観測は、Linux ホストの agent 実行、または Windows ホストで `packet-agent` 直接実行を推奨します。

## 回帰テスト

バックエンド回帰テスト（認証、WSトークン保持、ループバック除外、署名Webhookリプレイ防止、運用API）を実行します。

```bash
python -m unittest discover -s agent-registry/tests -p "test_*.py"
```

Docker で実行する場合（依存関係込みで確実）:

```bash
docker compose build agent-registry
docker compose run --rm agent-registry python -m unittest discover -s /app/tests -p "test_*.py"
```
