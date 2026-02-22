import { useEffect, useMemo, useState } from 'react'
import CytoscapeComponent from 'react-cytoscapejs'
import './App.css'

type ConnectionStatus = 'confirmed' | 'unverified' | 'conflict'
type InputMode = 'mock' | 'live'
type Locale = 'ja' | 'en'
type MenuTab = 'overview' | 'agents' | 'settings'

type Connection = {
  id: string
  source: string
  target: string
  agentId: string
  agentName: string
  protocol: string
  port: number
  confidence: number
  basis: 'passive' | 'config' | 'hybrid'
  status: ConnectionStatus
  bandwidthKbps: number
  lastSeen: string
}

type DiffEvent = { id: string; timestamp: string; connectionId: string; message: string }
type AgentRuntime = { state: 'connected' | 'disconnected'; packetCount: number; lastHeartbeat: string | null }
type RegistryAgent = { id: string; name: string; status: 'connected' | 'disconnected' }

type LiveConnectionPayload = {
  connection_id: string
  agent_id: string
  agent_name: string
  src_ip: string
  dst_ip: string
  protocol: string
  port: number
  packets: number
  bytes_per_sec: number
  last_seen: string
}

type AgentMessage =
  | {
      type: 'registry_snapshot'
      payload: {
        agents: Array<{
          agent_id: string
          agent_name: string
          status: 'connected' | 'disconnected'
          total_packets: number
          active_connections: number
          last_seen: string
        }>
      }
    }
  | {
      type: 'registry_agent_update'
      payload: {
        agent_id: string
        agent_name: string
        status: 'connected' | 'disconnected'
        total_packets: number
        last_seen: string
      }
    }
  | { type: 'connection_update'; payload: LiveConnectionPayload }

type TokenIssueResponse = {
  token: string
  expires_at: number
  registry_http_url: string
  registry_ws_agent_url: string
  download: { windows: string; linux: string }
}

const REGISTRY_HTTP_URL = import.meta.env.VITE_REGISTRY_HTTP_URL ?? 'http://127.0.0.1:8780'
const REGISTRY_WS_URL = REGISTRY_HTTP_URL.replace(/^http/, 'ws') + '/ws/ui'

const textMap = {
  ja: {
    appSubtitle: 'Factory Link Explorer',
    input: '入力',
    mockData: 'モック',
    realPacketStream: 'Live',
    language: '言語',
    mode: 'モード',
    livePacketAgent: 'Live (Registry)',
    menu: 'メニュー',
    menuOverview: 'Overview',
    menuAgents: 'Agents + Onboarding',
    menuSettings: 'Settings',
    showSelfLoop: '自己ループ表示',
    agent: 'Agent',
    disconnected: '未接続',
    connected: '接続済み',
    packets: 'packet',
    connectedAgents: '接続Agent',
    equipmentConnectivityMap: '設備接続マップ',
    connectionDetails: '接続詳細',
    connectionDiffFeed: '接続差分フィード',
    agentManager: 'Agent一覧',
    issueToken: '① トークン発行',
    downloadBundle: '② エージェント一式ダウンロード',
    terminalConfig: '③ 端末でconfig実施',
    heartbeatStart: '④ ハートビート収集開始',
    serviceInstall: '⑤ サービス自動登録',
    tokenTtlMinutes: 'トークン有効期限(分)',
    generateToken: 'トークン発行',
    enrollmentToken: 'Enrollment Token',
    windowsBundle: 'Windows版をダウンロード',
    linuxBundle: 'Linux版をダウンロード',
    copy: 'コピー',
    configCommand: 'Configコマンド',
    runCommand: 'Runコマンド',
    installCommand: 'Service登録コマンド',
    noAgents: '接続中のAgentなし',
    waitingPacketEvents: 'イベント待機中...',
  },
  en: {
    appSubtitle: 'Factory Link Explorer',
    input: 'Input',
    mockData: 'Mock',
    realPacketStream: 'Live',
    language: 'Language',
    mode: 'Mode',
    livePacketAgent: 'Live (Registry)',
    menu: 'Menu',
    menuOverview: 'Overview',
    menuAgents: 'Agents + Onboarding',
    menuSettings: 'Settings',
    showSelfLoop: 'Show self-loop',
    agent: 'Agent',
    disconnected: 'Disconnected',
    connected: 'Connected',
    packets: 'packets',
    connectedAgents: 'Connected Agents',
    equipmentConnectivityMap: 'Connectivity Map',
    connectionDetails: 'Connection Details',
    connectionDiffFeed: 'Diff Feed',
    agentManager: 'Agents',
    issueToken: '① Issue token',
    downloadBundle: '② Download agent bundle',
    terminalConfig: '③ Run config in terminal',
    heartbeatStart: '④ Start heartbeat collection',
    serviceInstall: '⑤ Install auto service',
    tokenTtlMinutes: 'Token TTL (min)',
    generateToken: 'Issue token',
    enrollmentToken: 'Enrollment Token',
    windowsBundle: 'Download Windows bundle',
    linuxBundle: 'Download Linux bundle',
    copy: 'Copy',
    configCommand: 'Config command',
    runCommand: 'Run command',
    installCommand: 'Install service command',
    noAgents: 'No connected agents',
    waitingPacketEvents: 'Waiting for events...',
  },
} as const

function App() {
  const initialLocale: Locale =
    typeof navigator !== 'undefined' && navigator.language.toLowerCase().startsWith('ja') ? 'ja' : 'en'

  const [locale, setLocale] = useState<Locale>(initialLocale)
  const [mode, setMode] = useState<InputMode>('live')
  const [activeMenu, setActiveMenu] = useState<MenuTab>('agents')
  const [showSelfLoops, setShowSelfLoops] = useState<boolean>(true)
  const [liveConnections, setLiveConnections] = useState<Connection[]>([])
  const [diffEvents, setDiffEvents] = useState<DiffEvent[]>([])
  const [registryAgents, setRegistryAgents] = useState<RegistryAgent[]>([])
  const [agentRuntime, setAgentRuntime] = useState<Record<string, AgentRuntime>>({})
  const [ttlMinutes, setTtlMinutes] = useState<number>(15)
  const [tokenInfo, setTokenInfo] = useState<TokenIssueResponse | null>(null)

  const text = textMap[locale]
  const connectedAgents = useMemo(() => registryAgents.filter((agent) => agent.status === 'connected'), [registryAgents])
  const totalPackets = useMemo(
    () => connectedAgents.reduce((sum, agent) => sum + (agentRuntime[agent.id]?.packetCount ?? 0), 0),
    [connectedAgents, agentRuntime],
  )

  const visibleConnections = useMemo(
    () => (showSelfLoops ? liveConnections : liveConnections.filter((connection) => connection.source !== connection.target)),
    [liveConnections, showSelfLoops],
  )
  const selectedConnection = useMemo(() => visibleConnections[0], [visibleConnections])

  const agentStatusText = `${connectedAgents.length}/${registryAgents.length} ${text.connectedAgents} (${totalPackets} ${text.packets})`

  useEffect(() => {
    if (mode !== 'live') return

    let socket: WebSocket | null = null
    try {
      socket = new WebSocket(REGISTRY_WS_URL)
      socket.onmessage = (event) => {
        const parsed = JSON.parse(event.data as string) as AgentMessage

        if (parsed.type === 'registry_snapshot') {
          setRegistryAgents(parsed.payload.agents.map((agent) => ({ id: agent.agent_id, name: agent.agent_name, status: agent.status })))
          const runtime: Record<string, AgentRuntime> = {}
          parsed.payload.agents.forEach((agent) => {
            runtime[agent.agent_id] = { state: agent.status, packetCount: agent.total_packets, lastHeartbeat: agent.last_seen }
          })
          setAgentRuntime(runtime)
          return
        }

        if (parsed.type === 'registry_agent_update') {
          const payload = parsed.payload
          setRegistryAgents((previous) => {
            const index = previous.findIndex((agent) => agent.id === payload.agent_id)
            const nextItem: RegistryAgent = { id: payload.agent_id, name: payload.agent_name, status: payload.status }
            if (index === -1) return [nextItem, ...previous]
            const next = [...previous]
            next[index] = nextItem
            return next
          })
          setAgentRuntime((previous) => ({
            ...previous,
            [payload.agent_id]: { state: payload.status, packetCount: payload.total_packets, lastHeartbeat: payload.last_seen },
          }))
          return
        }

        if (parsed.type !== 'connection_update') return
        const payload = parsed.payload
        const id = `${payload.agent_id}:${payload.connection_id}`
        const nextConnection: Connection = {
          id,
          source: payload.src_ip,
          target: payload.dst_ip,
          agentId: payload.agent_id,
          agentName: payload.agent_name,
          protocol: payload.protocol,
          port: payload.port,
          confidence: Math.max(45, Math.min(99, Math.floor(55 + Math.log10(payload.packets + 1) * 20))),
          basis: 'passive',
          status: payload.packets > 20 ? 'confirmed' : 'unverified',
          bandwidthKbps: Math.max(1, Math.round((payload.bytes_per_sec * 8) / 1000)),
          lastSeen: payload.last_seen,
        }

        setLiveConnections((previous) => {
          const index = previous.findIndex((connection) => connection.id === id)
          if (index === -1) return [nextConnection, ...previous].slice(0, 500)
          const next = [...previous]
          next[index] = nextConnection
          return next
        })

        setDiffEvents((events) => [
          {
            id: `${id}-${Date.now()}`,
            timestamp: new Date().toLocaleTimeString(locale === 'ja' ? 'ja-JP' : 'en-US'),
            connectionId: id,
            message: `[${payload.agent_name}] ${payload.protocol} ${payload.src_ip} → ${payload.dst_ip}`,
          },
          ...events,
        ].slice(0, 50))
      }
    } catch {
      setRegistryAgents([])
    }

    return () => {
      if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) socket.close()
    }
  }, [mode, locale])

  const issueToken = async () => {
    const response = await fetch(`${REGISTRY_HTTP_URL}/api/tokens`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ttl_minutes: ttlMinutes }),
    })
    if (!response.ok) return
    const payload = (await response.json()) as TokenIssueResponse
    setTokenInfo(payload)
  }

  const configCommand = tokenInfo
    ? `python agent.py config --registry-url "${tokenInfo.registry_http_url}" --agent-name "my-agent" --token "${tokenInfo.token}"`
    : ''

  const runCommand = 'python agent.py run'
  const installCommand = 'python agent.py install-service'

  const menuItems: Array<{ key: MenuTab; label: string }> = [
    { key: 'overview', label: text.menuOverview },
    { key: 'agents', label: text.menuAgents },
    { key: 'settings', label: text.menuSettings },
  ]

  return (
    <div className="app">
      <header className="header">
        <div><h1>FLEX</h1><p>{text.appSubtitle}</p></div>
        <span className="badge">{text.input}: {mode === 'mock' ? text.mockData : text.realPacketStream}</span>
      </header>

      <div className="layout-shell">
        <aside className="card menu-card">
          <h2>{text.menu}</h2>
          <div className="menu-list">
            {menuItems.map((item) => (
              <button key={item.key} type="button" className={`menu-button ${activeMenu === item.key ? 'active' : ''}`} onClick={() => setActiveMenu(item.key)}>{item.label}</button>
            ))}
          </div>
          <div className="agent-status">{text.agent}: {agentStatusText}</div>
        </aside>

        <main className="main-panel">
          {activeMenu === 'settings' ? (
            <section className="card control-card resizable-card">
              <h2>Settings</h2>
              <div className="controls">
                <label>{text.language}
                  <select value={locale} onChange={(event) => setLocale(event.target.value as Locale)}>
                    <option value="ja">日本語</option><option value="en">English</option>
                  </select>
                </label>
                <label>{text.mode}
                  <select value={mode} onChange={(event) => setMode(event.target.value as InputMode)}>
                    <option value="live">{text.livePacketAgent}</option>
                    <option value="mock">{text.mockData}</option>
                  </select>
                </label>
                <label className="checkbox-label"><input type="checkbox" checked={showSelfLoops} onChange={(event) => setShowSelfLoops(event.target.checked)} />{text.showSelfLoop}</label>
              </div>
            </section>
          ) : null}

          {activeMenu === 'agents' ? (
            <section className="card agent-manager-card resizable-card">
              <h2>{text.agentManager}</h2>
              <table className="agent-table">
                <thead><tr><th>Name</th><th>Status</th><th>{text.packets}</th></tr></thead>
                <tbody>
                  {registryAgents.length === 0 ? <tr><td colSpan={3}>{text.noAgents}</td></tr> : registryAgents.map((agent) => (
                    <tr key={agent.id}><td>{agent.name}</td><td>{agent.status}</td><td>{agentRuntime[agent.id]?.packetCount ?? 0}</td></tr>
                  ))}
                </tbody>
              </table>

              <section className="card onboarding-card">
                <h2>{text.issueToken}</h2>
                <div className="onboarding-form">
                  <label>{text.tokenTtlMinutes}<input type="number" min={1} max={1440} value={ttlMinutes} onChange={(e) => setTtlMinutes(Number(e.target.value) || 15)} /></label>
                  <button type="button" onClick={issueToken}>{text.generateToken}</button>
                </div>

                {tokenInfo ? (
                  <div className="onboarding-result">
                    <label>{text.enrollmentToken}<textarea readOnly rows={3} value={tokenInfo.token} /></label>
                    <div className="onboarding-actions">
                      <a href={tokenInfo.download.windows} target="_blank" rel="noreferrer">{text.windowsBundle}</a>
                      <a href={tokenInfo.download.linux} target="_blank" rel="noreferrer">{text.linuxBundle}</a>
                    </div>
                    <label>{text.terminalConfig}<textarea readOnly rows={4} value={configCommand} /></label>
                    <label>{text.heartbeatStart}<textarea readOnly rows={2} value={runCommand} /></label>
                    <label>{text.serviceInstall}<textarea readOnly rows={2} value={installCommand} /></label>
                    <div className="onboarding-actions">
                      <button type="button" onClick={() => { void navigator.clipboard.writeText(configCommand) }}>{text.copy} ({text.configCommand})</button>
                      <button type="button" onClick={() => { void navigator.clipboard.writeText(runCommand) }}>{text.copy} ({text.runCommand})</button>
                      <button type="button" onClick={() => { void navigator.clipboard.writeText(installCommand) }}>{text.copy} ({text.installCommand})</button>
                    </div>
                  </div>
                ) : null}
              </section>
            </section>
          ) : null}

          {activeMenu === 'overview' ? (
            <>
              <section className="top-grid">
                <div className="card graph-card resizable-card">
                  <h2>{text.equipmentConnectivityMap}</h2>
                  <CytoscapeComponent
                    elements={visibleConnections.map((connection) => ({ data: { id: connection.id, source: connection.source, target: connection.target, label: `${connection.protocol}:${connection.port}` } }))}
                    style={{ width: '100%', height: 'clamp(420px, 56vh, 760px)' }}
                    layout={{ name: 'cose', fit: true, padding: 40, animate: false }}
                  />
                </div>
                <div className="card detail-card resizable-card">
                  <h2>{text.connectionDetails}</h2>
                  {selectedConnection ? <div>{selectedConnection.source} → {selectedConnection.target}</div> : <p>{text.waitingPacketEvents}</p>}
                </div>
              </section>
              <section className="card diff-card resizable-card">
                <h2>{text.connectionDiffFeed}</h2>
                <table><tbody>{diffEvents.slice(0, 20).map((event) => <tr key={event.id}><td>{event.timestamp}</td><td>{event.message}</td></tr>)}</tbody></table>
              </section>
            </>
          ) : null}
        </main>
      </div>
    </div>
  )
}

export default App
