# FLEX

Factory Link Explorer (FLEX) は、未知の工場ネットワークを受動観測して、設備接続のトポロジを可視化するツールです。

今回の実装で以下を追加しました。

- Agent Registry に SQLite 永続化を追加（再起動後も資産/接続/差分を保持）
- 接続差分イベント（新規フロー検出）を保存/配信
- 資産台帳（ラベル/役割/重要度）の編集 API
- UI を `Overview / Assets / Events / Operations / Onboarding` の運用向け構成に刷新

## 機能一覧（ネットワークに詳しくない方向け）

### まず用語（かんたん）

- Agent（エージェント）: 工場ネットワークの近くで動かして、通信を数える小さなプログラム
- Asset（資産）: 観測で見つかった機器（主にIPアドレス単位）
- Flow（フロー）: 「どの機器 → どの機器が、どのプロトコル/ポートで通信しているか」という通信のまとまり

### 観測・見える化

- 受動観測: 通信に割り込まずに“見て数える”方式（通信内容ではなく、相手/種類/量/時刻を中心に扱います）
- トポロジ可視化: 機器を点、通信を線としてグラフ表示
- ひと目の状況把握: Agent数/機器数/フロー数/パケット数/通信量の目安をKPIとして表示

### 資産台帳（現場向けに整備）

- 機器一覧: IP、ラベル（任意）、役割、重要度、最終観測時刻などを一覧化
- 手動で補正: 「このIPはPLC」「これは重要」などのメタ情報を後から編集可能

### 新規通信の検知（イベント）

- 新規フロー検知: これまで無かった通信が出たときにイベントとして記録
- 重大度/リスク: 工場系プロトコルや重要度などからリスクスコア（0〜100）と重大度を付与

### 運用（アラート・通知・監査）

- アラート管理: 高リスクのイベントをアラート化し、未対応/確認済み/解決済みで運用
- 通知（Webhook）: 一定以上のリスクのものを外部へ通知（URLと閾値を設定）
- 外部連携: 送信設定の管理、配信キューの再試行/状態確認、簡易メトリクス
- 監査ログ: 操作履歴を残し、監査レポート（JSON/CSV）として取得可能
- 保持期間: 接続/イベントの保持日数を設定し、古いデータを自動的に削除

### 導入（Onboarding）

- トークン発行: UIからエージェント導入用トークンを発行
- バンドル提供: Windows/Linux向けのダウンロードリンクを提示
- 実行ガイド: `config`（登録）→ `run`（収集）→ `install-service`（常駐）の流れを案内

## 構成

- `src/` : React + Cytoscape の可視化 UI
- `agent-registry/registry.py` : Agent Registry（API + WS + SQLite）
- `packet-agent/agent.py` : パケット取得エージェント

## 起動

```bash
docker compose up --build
```

初回起動（DBが空の状態）では管理者初期パスワードが必要です（12文字以上）。

- Bash: `FLEX_ADMIN_PASSWORD='YourStrongPasswordHere' docker compose up --build`
- PowerShell: `$env:FLEX_ADMIN_PASSWORD='YourStrongPasswordHere'; docker compose up --build`

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

### Operations
- アラート（未対応/確認済み/解決済み）
- 通知設定（Webhook）
- 外部連携（Integrations）
- 監査ログ/監査レポート

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

Packet Agent のユニットテスト（プロトコル推定、集計ロジック、エビクション等）:

```bash
python -m unittest discover -s packet-agent/tests -p "test_*.py"
```

Docker で実行する場合（依存関係込みで確実）:

```bash
docker compose build agent-registry
docker compose run --rm agent-registry python -m unittest discover -s /app/tests -p "test_*.py"
```

## E2Eスモーク（最小）

Docker Compose で起動して、health/login/snapshot/register の一連が通るかをチェックします。

```bash
FLEX_ADMIN_PASSWORD='RegressionAdmin#2026' docker compose up -d --build
ADMIN_PASSWORD='RegressionAdmin#2026' ADMIN_PASSWORD_NEW='RegressionAdminChanged#2026' node scripts/e2e_smoke.mjs
docker compose down -v
```
