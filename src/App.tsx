import { useEffect, useMemo, useState } from 'react'
import CytoscapeComponent from 'react-cytoscapejs'
import './App.css'

type Device = { id: string; name: string; role: string; zone: string }
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
        timestamp: string
      }
    }
  | {
      type: 'registry_agent_update'
      payload: {
        agent_id: string
        agent_name: string
        status: 'connected' | 'disconnected'
        total_packets: number
        active_connections: number
        last_seen: string
      }
    }
  | { type: 'connection_update'; payload: LiveConnectionPayload }

type EnrollmentTokenPayload = { server_url: string; exp: number; nonce: string }

const REGISTRY_WS_URL = import.meta.env.VITE_REGISTRY_WS_URL ?? 'ws://127.0.0.1:8780/ui'
const REGISTRY_AGENT_URL = REGISTRY_WS_URL.replace(/\/ui$/, '/agent')

function encodeEnrollmentToken(payload: EnrollmentTokenPayload): string {
  const encoded = btoa(JSON.stringify(payload)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
  return `flexreg.v1.${encoded}`
}

const devices: Device[] = [
  { id: 'plc-01', name: 'PLC-01', role: 'PLC', zone: 'Line-A' },
  { id: 'hmi-01', name: 'HMI-01', role: 'HMI', zone: 'Line-A' },
  { id: 'io-01', name: 'IO-01', role: 'Remote IO', zone: 'Line-A' },
  { id: 'scada-01', name: 'SCADA-01', role: 'SCADA', zone: 'Control' },
]

const initialConnections: Connection[] = [
  {
    id: 'c1',
    source: 'hmi-01',
    target: 'plc-01',
    agentId: 'mock-agent',
    agentName: 'Mock Agent',
    protocol: 'EtherNet/IP',
    port: 44818,
    confidence: 93,
    basis: 'hybrid',
    status: 'confirmed',
    bandwidthKbps: 480,
    lastSeen: new Date().toISOString(),
  },
  {
    id: 'c2',
    source: 'plc-01',
    target: 'io-01',
    agentId: 'mock-agent',
    agentName: 'Mock Agent',
    protocol: 'PROFINET',
    port: 34964,
    confidence: 88,
    basis: 'passive',
    status: 'confirmed',
    bandwidthKbps: 820,
    lastSeen: new Date().toISOString(),
  },
]

const textMap = {
  ja: {
    appSubtitle: 'Factory Link Explorer',
    input: '入力',
    mockData: 'モックデータ',
    realPacketStream: '実パケットストリーム',
    language: '言語',
    mode: 'モード',
    livePacketAgent: 'Live (Registry)',
    menu: 'メニュー',
    menuOverview: 'Overview',
    menuAgents: 'Agents + Onboarding',
    menuSettings: 'Settings',
    showSelfLoop: '自己ループを表示',
    agent: 'Agent',
    disconnected: '未接続',
    connected: '接続済み',
    packets: 'packet',
    connectionError: '接続エラー',
    connectedAgents: '接続Agent',
    equipmentConnectivityMap: '設備接続マップ',
    maximize: '最大化',
    restore: '元に戻す',
    connectionDetails: '接続詳細',
    connection: '接続',
    protocol: 'プロトコル',
    port: 'ポート',
    status: '状態',
    confidence: '信頼度',
    evidence: '根拠',
    bandwidth: '帯域',
    lastSeen: '最終検知',
    sourceAgent: '取得Agent',
    noConnectionSelected: '接続が選択されていません。',
    connectionDiffFeed: '接続差分フィード',
    time: '時刻',
    change: '変更',
    waitingPacketEvents: 'パケットイベント待機中...',
    waitingChanges: '変更待機中...',
    agentManager: 'Agents',
    onboarding: 'エージェント登録 (MVP)',
    tokenTtlMinutes: 'トークン有効期限(分)',
    generateToken: '登録トークン生成',
    enrollmentToken: '登録トークン',
    registerCommand: '登録コマンド',
    copy: 'コピー',
    tokenHint: 'Windowsで register を実行',
    noAgents: '接続中のAgentはありません',
    agentName: 'エージェント名',
  },
  en: {
    appSubtitle: 'Factory Link Explorer',
    input: 'Input',
    mockData: 'Mock Data',
    realPacketStream: 'Real Packet Stream',
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
    connectionError: 'Connection Error',
    connectedAgents: 'Connected Agents',
    equipmentConnectivityMap: 'Equipment Connectivity Map',
    maximize: 'Maximize',
    restore: 'Restore',
    connectionDetails: 'Connection Details',
    connection: 'Connection',
    protocol: 'Protocol',
    port: 'Port',
    status: 'Status',
    confidence: 'Confidence',
    evidence: 'Evidence',
    bandwidth: 'Bandwidth',
    lastSeen: 'Last Seen',
    sourceAgent: 'Source Agent',
    noConnectionSelected: 'No connection selected.',
    connectionDiffFeed: 'Connection Diff Feed',
    time: 'Time',
    change: 'Change',
    waitingPacketEvents: 'Waiting for packet events...',
    waitingChanges: 'Waiting for changes...',
    agentManager: 'Agents',
    onboarding: 'Agent Onboarding (MVP)',
    tokenTtlMinutes: 'Token TTL (min)',
    generateToken: 'Generate Token',
    enrollmentToken: 'Enrollment Token',
    registerCommand: 'Registration Command',
    copy: 'Copy',
    tokenHint: 'Run register on Windows host',
    noAgents: 'No connected agents',
    agentName: 'Agent Name',
  },
} as const

const statusLabelMap: Record<Locale, Record<ConnectionStatus, string>> = {
  ja: { confirmed: '確認済み', unverified: '未検証', conflict: '競合' },
  en: { confirmed: 'Confirmed', unverified: 'Unverified', conflict: 'Conflict' },
}

const basisLabelMap: Record<Locale, Record<Connection['basis'], string>> = {
  ja: { passive: '受動', config: '設定', hybrid: 'ハイブリッド' },
  en: { passive: 'passive', config: 'config', hybrid: 'hybrid' },
}

function App() {
  const initialLocale: Locale =
    typeof navigator !== 'undefined' && navigator.language.toLowerCase().startsWith('ja') ? 'ja' : 'en'

  const [locale, setLocale] = useState<Locale>(initialLocale)
  const [mode, setMode] = useState<InputMode>('mock')
  const [activeMenu, setActiveMenu] = useState<MenuTab>('overview')
  const [showSelfLoops, setShowSelfLoops] = useState<boolean>(true)
  const [isMapMaximized, setIsMapMaximized] = useState<boolean>(false)
  const [mockConnections, setMockConnections] = useState<Connection[]>(initialConnections)
  const [liveConnections, setLiveConnections] = useState<Connection[]>([])
  const [diffEvents, setDiffEvents] = useState<DiffEvent[]>([])
  const [selectedConnectionId, setSelectedConnectionId] = useState<string>(initialConnections[0].id)
  const [registryAgents, setRegistryAgents] = useState<RegistryAgent[]>([])
  const [agentRuntime, setAgentRuntime] = useState<Record<string, AgentRuntime>>({})
  const [onboardingAgentName, setOnboardingAgentName] = useState<string>('line-a-agent')
  const [onboardingTtlMinutes, setOnboardingTtlMinutes] = useState<number>(15)
  const [onboardingToken, setOnboardingToken] = useState<string>('')

  const text = textMap[locale]
  const statusLabel = statusLabelMap[locale]
  const basisLabel = basisLabelMap[locale]

  const connectedAgents = useMemo(() => registryAgents.filter((agent) => agent.status === 'connected'), [registryAgents])
  const totalPackets = useMemo(
    () => connectedAgents.reduce((sum, agent) => sum + (agentRuntime[agent.id]?.packetCount ?? 0), 0),
    [connectedAgents, agentRuntime],
  )

  const agentStatusText =
    mode === 'live'
      ? `${connectedAgents.length}/${registryAgents.length} ${text.connectedAgents} (${totalPackets} ${text.packets})`
      : text.disconnected

  const connections = mode === 'mock' ? mockConnections : liveConnections
  const visibleConnections = useMemo(
    () => (showSelfLoops ? connections : connections.filter((connection) => connection.source !== connection.target)),
    [connections, showSelfLoops],
  )

  const selectedConnection = useMemo(
    () => visibleConnections.find((connection) => connection.id === selectedConnectionId),
    [visibleConnections, selectedConnectionId],
  )

  const activeDevices = useMemo(() => {
    if (mode === 'mock') {
      return devices
    }
    const uniqueIds = new Set<string>()
    visibleConnections.forEach((connection) => {
      uniqueIds.add(connection.source)
      uniqueIds.add(connection.target)
    })
    return Array.from(uniqueIds).map((id) => ({ id, name: id, role: 'Endpoint', zone: 'Observed' }))
  }, [mode, visibleConnections])

  const elements = useMemo(
    () => [
      ...activeDevices.map((device) => ({ data: { id: device.id, label: device.name, role: device.role, zone: device.zone } })),
      ...visibleConnections.map((connection) => ({
        data: {
          id: connection.id,
          source: connection.source,
          target: connection.target,
          label: `${connection.protocol} : ${connection.port}`,
          status: connection.status,
        },
      })),
    ],
    [activeDevices, visibleConnections],
  )

  useEffect(() => {
    if (mode !== 'mock') return
    const timer = window.setInterval(() => {
      setMockConnections((previous) => {
        const index = Math.floor(Math.random() * previous.length)
        const next = [...previous]
        const target = next[index]
        const statuses: ConnectionStatus[] = ['confirmed', 'unverified', 'conflict']
        const status = statuses[Math.floor(Math.random() * statuses.length)]
        const updated: Connection = {
          ...target,
          status,
          confidence: Math.max(40, Math.min(99, target.confidence + (Math.floor(Math.random() * 11) - 5))),
          bandwidthKbps: Math.max(20, target.bandwidthKbps + (Math.floor(Math.random() * 101) - 50)),
          lastSeen: new Date().toISOString(),
        }
        next[index] = updated
        setDiffEvents((events) => [
          {
            id: `${updated.id}-${Date.now()}`,
            timestamp: new Date().toLocaleTimeString(locale === 'ja' ? 'ja-JP' : 'en-US'),
            connectionId: updated.id,
            message: `${updated.protocol} ${statusLabel[updated.status]} (${updated.confidence}%)`,
          },
          ...events,
        ].slice(0, 20))
        return next
      })
    }, 3000)
    return () => window.clearInterval(timer)
  }, [locale, mode, statusLabel])

  useEffect(() => {
    if (mode !== 'live') return

    let socket: WebSocket | null = null
    try {
      socket = new WebSocket(REGISTRY_WS_URL)
      socket.onmessage = (event) => {
        const parsed = JSON.parse(event.data as string) as AgentMessage

        if (parsed.type === 'registry_snapshot') {
          setRegistryAgents(
            parsed.payload.agents.map((agent) => ({ id: agent.agent_id, name: agent.agent_name, status: agent.status })),
          )
          const runtime: Record<string, AgentRuntime> = {}
          parsed.payload.agents.forEach((agent) => {
            runtime[agent.agent_id] = {
              state: agent.status,
              packetCount: agent.total_packets,
              lastHeartbeat: agent.last_seen,
            }
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
            [payload.agent_id]: {
              state: payload.status,
              packetCount: payload.total_packets,
              lastHeartbeat: payload.last_seen,
            },
          }))
          return
        }

        if (parsed.type !== 'connection_update') return

        const payload = parsed.payload
        const mergedConnectionId = `${payload.agent_id}:${payload.connection_id}`
        const nextConnection: Connection = {
          id: mergedConnectionId,
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
          const index = previous.findIndex((connection) => connection.id === nextConnection.id)
          if (index === -1) return [nextConnection, ...previous].slice(0, 500)
          const next = [...previous]
          next[index] = nextConnection
          return next
        })

        setDiffEvents((events) => [
          {
            id: `${mergedConnectionId}-${Date.now()}`,
            timestamp: new Date().toLocaleTimeString(locale === 'ja' ? 'ja-JP' : 'en-US'),
            connectionId: mergedConnectionId,
            message: `[${payload.agent_name}] ${payload.protocol} ${payload.src_ip} → ${payload.dst_ip} (${payload.bytes_per_sec.toFixed(1)} B/s)`,
          },
          ...events,
        ].slice(0, 30))
      }
    } catch {
      setRegistryAgents([])
    }

    return () => {
      if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) socket.close()
    }
  }, [mode, locale])

  const generateEnrollmentToken = () => {
    const now = Math.floor(Date.now() / 1000)
    setOnboardingToken(
      encodeEnrollmentToken({
        server_url: REGISTRY_AGENT_URL,
        exp: now + onboardingTtlMinutes * 60,
        nonce: Math.random().toString(36).slice(2, 10),
      }),
    )
  }

  const onboardingCommand = onboardingToken
    ? `python agent.py register --token "${onboardingToken}" --agent-name "${onboardingAgentName}"`
    : ''

  const menuItems: Array<{ key: MenuTab; label: string }> = [
    { key: 'overview', label: text.menuOverview },
    { key: 'agents', label: text.menuAgents },
    { key: 'settings', label: text.menuSettings },
  ]

  return (
    <div className="app">
      <header className="header">
        <div>
          <h1>FLEX</h1>
          <p>{text.appSubtitle}</p>
        </div>
        <span className="badge">{text.input}: {mode === 'mock' ? text.mockData : text.realPacketStream}</span>
      </header>

      <div className="layout-shell">
        <aside className="card menu-card">
          <h2>{text.menu}</h2>
          <div className="menu-list">
            {menuItems.map((item) => (
              <button
                key={item.key}
                type="button"
                className={`menu-button ${activeMenu === item.key ? 'active' : ''}`}
                onClick={() => setActiveMenu(item.key)}
              >
                {item.label}
              </button>
            ))}
          </div>
          <div className="agent-status">{text.agent}: {agentStatusText}</div>
        </aside>

        <main className="main-panel">
          {activeMenu === 'settings' ? (
            <section className="card control-card resizable-card">
              <h2>Settings</h2>
              <div className="controls">
                <label>
                  {text.language}
                  <select value={locale} onChange={(event) => setLocale(event.target.value as Locale)}>
                    <option value="ja">日本語</option>
                    <option value="en">English</option>
                  </select>
                </label>
                <label>
                  {text.mode}
                  <select value={mode} onChange={(event) => setMode(event.target.value as InputMode)}>
                    <option value="mock">{text.mockData}</option>
                    <option value="live">{text.livePacketAgent}</option>
                  </select>
                </label>
                <label className="checkbox-label">
                  <input type="checkbox" checked={showSelfLoops} onChange={(event) => setShowSelfLoops(event.target.checked)} />
                  {text.showSelfLoop}
                </label>
              </div>
            </section>
          ) : null}

          {activeMenu === 'agents' ? (
            <section className="card agent-manager-card resizable-card">
              <h2>{text.agentManager}</h2>
              <table className="agent-table">
                <thead>
                  <tr>
                    <th>{text.agentName}</th>
                    <th>{text.status}</th>
                    <th>{text.packets}</th>
                  </tr>
                </thead>
                <tbody>
                  {registryAgents.length === 0 ? (
                    <tr><td colSpan={3}>{text.noAgents}</td></tr>
                  ) : (
                    registryAgents.map((agent) => (
                      <tr key={agent.id}>
                        <td>{agent.name}</td>
                        <td>{agent.status === 'connected' ? text.connected : text.disconnected}</td>
                        <td>{agentRuntime[agent.id]?.packetCount ?? 0}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>

              <section className="card onboarding-card">
                <h2>{text.onboarding}</h2>
                <div className="onboarding-form">
                  <label>
                    {text.agentName}
                    <input type="text" value={onboardingAgentName} onChange={(event) => setOnboardingAgentName(event.target.value)} />
                  </label>
                  <label>
                    {text.tokenTtlMinutes}
                    <input
                      type="number"
                      min={1}
                      max={1440}
                      value={onboardingTtlMinutes}
                      onChange={(event) => setOnboardingTtlMinutes(Number(event.target.value) || 15)}
                    />
                  </label>
                  <button type="button" onClick={generateEnrollmentToken}>{text.generateToken}</button>
                </div>
                {onboardingToken ? (
                  <div className="onboarding-result">
                    <label>
                      {text.enrollmentToken}
                      <textarea value={onboardingToken} readOnly rows={3} />
                    </label>
                    <label>
                      {text.registerCommand}
                      <textarea value={onboardingCommand} readOnly rows={3} />
                    </label>
                    <div className="onboarding-actions">
                      <button type="button" onClick={() => { void navigator.clipboard.writeText(onboardingCommand) }}>{text.copy}</button>
                      <span>{text.tokenHint}</span>
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
                  <div className="graph-header">
                    <h2>{text.equipmentConnectivityMap}</h2>
                    <button type="button" className="graph-toggle" onClick={() => setIsMapMaximized((v) => !v)}>
                      {isMapMaximized ? text.restore : text.maximize}
                    </button>
                  </div>
                  <CytoscapeComponent
                    elements={elements}
                    style={{ width: '100%', height: isMapMaximized ? '82vh' : 'clamp(420px, 56vh, 760px)' }}
                    layout={{ name: activeDevices.length <= 12 ? 'circle' : 'cose', fit: true, padding: 40, animate: false }}
                    stylesheet={[
                      { selector: 'node', style: { label: 'data(label)', 'background-color': '#3f83f8', color: '#ffffff', 'font-size': '11px', width: 42, height: 42 } },
                      { selector: 'edge', style: { width: 3, label: 'data(label)', 'curve-style': 'bezier', 'target-arrow-shape': 'triangle', 'font-size': '9px', color: '#e2e8f0', 'line-color': '#60a5fa', 'target-arrow-color': '#60a5fa' } },
                      { selector: 'edge[status = "confirmed"]', style: { 'line-color': '#22c55e', 'target-arrow-color': '#22c55e' } },
                      { selector: 'edge[status = "unverified"]', style: { 'line-color': '#f59e0b', 'target-arrow-color': '#f59e0b' } },
                      { selector: 'edge[status = "conflict"]', style: { 'line-color': '#ef4444', 'target-arrow-color': '#ef4444' } },
                    ]}
                  />
                </div>

                <div className="card detail-card resizable-card">
                  <h2>{text.connectionDetails}</h2>
                  {selectedConnection ? (
                    <dl>
                      <div><dt>{text.connection}</dt><dd>{selectedConnection.source} → {selectedConnection.target}</dd></div>
                      <div><dt>{text.protocol}</dt><dd>{selectedConnection.protocol}</dd></div>
                      <div><dt>{text.sourceAgent}</dt><dd>{selectedConnection.agentName}</dd></div>
                      <div><dt>{text.port}</dt><dd>{selectedConnection.port}</dd></div>
                      <div><dt>{text.status}</dt><dd>{statusLabel[selectedConnection.status]}</dd></div>
                      <div><dt>{text.confidence}</dt><dd>{selectedConnection.confidence}%</dd></div>
                      <div><dt>{text.evidence}</dt><dd>{basisLabel[selectedConnection.basis]}</dd></div>
                      <div><dt>{text.bandwidth}</dt><dd>{selectedConnection.bandwidthKbps} kbps</dd></div>
                      <div><dt>{text.lastSeen}</dt><dd>{new Date(selectedConnection.lastSeen).toLocaleTimeString(locale === 'ja' ? 'ja-JP' : 'en-US')}</dd></div>
                    </dl>
                  ) : <p>{text.noConnectionSelected}</p>}
                </div>
              </section>

              <section className="card diff-card resizable-card">
                <h2>{text.connectionDiffFeed}</h2>
                <table>
                  <thead><tr><th>{text.time}</th><th>{text.connection}</th><th>{text.change}</th></tr></thead>
                  <tbody>
                    {diffEvents.length === 0 ? (
                      <tr><td colSpan={3}>{mode === 'live' ? text.waitingPacketEvents : text.waitingChanges}</td></tr>
                    ) : (
                      diffEvents.map((event) => (
                        <tr key={event.id} onClick={() => setSelectedConnectionId(event.connectionId)}>
                          <td>{event.timestamp}</td><td>{event.connectionId}</td><td>{event.message}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </section>
            </>
          ) : null}
        </main>
      </div>
    </div>
  )
}

export default App
