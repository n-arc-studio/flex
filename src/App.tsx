import { useEffect, useMemo, useState } from 'react'
import CytoscapeComponent from 'react-cytoscapejs'
import './App.css'

type Agent = {
  agent_id: string
  agent_name: string
  status: 'connected' | 'disconnected'
  total_packets: number
  active_connections: number
  first_seen: string
  last_seen: string
}

type Asset = {
  ip: string
  label: string | null
  role: string
  criticality: string
  first_seen: string
  last_seen: string
  last_agent_id: string | null
}

type Connection = {
  connection_key: string
  connection_id: string
  src_ip: string
  dst_ip: string
  protocol: string
  port: number
  packets: number
  bytes_per_sec: number
  first_seen: string
  last_seen: string
  last_agent_id: string
  last_agent_name: string
}

type DiffEvent = {
  id?: number
  event_type: string
  message: string
  connection_key: string
  src_ip: string
  dst_ip: string
  protocol: string
  port: number
  agent_id: string
  created_at: string
}

type SnapshotPayload = {
  agents: Agent[]
  assets: Asset[]
  connections: Connection[]
  diffs: DiffEvent[]
  timestamp: string
}

type TokenIssueResponse = {
  token: string
  expires_at: number
  registry_http_url: string
  registry_ws_agent_url: string
  download: { windows: string; linux: string }
}

type UiMessage =
  | { type: 'topology_snapshot'; payload: SnapshotPayload }
  | { type: 'registry_agent_update'; payload: Agent }
  | {
      type: 'connection_update'
      payload: {
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
    }
  | { type: 'connection_diff'; payload: DiffEvent }

const REGISTRY_HTTP_URL = import.meta.env.VITE_REGISTRY_HTTP_URL ?? 'http://127.0.0.1:8780'
const REGISTRY_WS_URL = REGISTRY_HTTP_URL.replace(/^http/, 'ws') + '/ws/ui'

type Tab = 'overview' | 'assets' | 'events' | 'onboarding'

function App() {
  const [tab, setTab] = useState<Tab>('overview')
  const [agents, setAgents] = useState<Agent[]>([])
  const [assets, setAssets] = useState<Asset[]>([])
  const [connections, setConnections] = useState<Connection[]>([])
  const [diffs, setDiffs] = useState<DiffEvent[]>([])
  const [selectedAssetIp, setSelectedAssetIp] = useState<string>('')
  const [assetLabel, setAssetLabel] = useState<string>('')
  const [assetRole, setAssetRole] = useState<string>('Unknown')
  const [assetCriticality, setAssetCriticality] = useState<string>('normal')
  const [ttlMinutes, setTtlMinutes] = useState<number>(30)
  const [tokenInfo, setTokenInfo] = useState<TokenIssueResponse | null>(null)

  const connectedAgents = useMemo(() => agents.filter((agent) => agent.status === 'connected').length, [agents])
  const totalPackets = useMemo(() => agents.reduce((sum, agent) => sum + agent.total_packets, 0), [agents])
  const totalBandwidth = useMemo(() => connections.reduce((sum, connection) => sum + connection.bytes_per_sec, 0), [connections])

  const assetMap = useMemo(() => {
    const map = new Map<string, Asset>()
    assets.forEach((asset) => map.set(asset.ip, asset))
    return map
  }, [assets])

  const graphElements = useMemo(() => {
    const nodeSet = new Set<string>()
    const nodes = assets.map((asset) => {
      nodeSet.add(asset.ip)
      return {
        data: {
          id: asset.ip,
          label: asset.label?.trim() ? `${asset.label} (${asset.ip})` : asset.ip,
          role: asset.role,
        },
      }
    })

    const edges = connections.map((connection) => {
      nodeSet.add(connection.src_ip)
      nodeSet.add(connection.dst_ip)
      return {
        data: {
          id: connection.connection_key,
          source: connection.src_ip,
          target: connection.dst_ip,
          label: `${connection.protocol}:${connection.port}`,
        },
      }
    })

    for (const ip of nodeSet) {
      if (nodes.find((node) => node.data.id === ip)) continue
      nodes.push({ data: { id: ip, label: ip, role: 'Unknown' } })
    }

    return [...nodes, ...edges]
  }, [assets, connections])

  const selectedAsset = useMemo(() => assets.find((asset) => asset.ip === selectedAssetIp) ?? null, [assets, selectedAssetIp])

  useEffect(() => {
    if (!selectedAsset) return
    setAssetLabel(selectedAsset.label ?? '')
    setAssetRole(selectedAsset.role)
    setAssetCriticality(selectedAsset.criticality)
  }, [selectedAsset])

  useEffect(() => {
    const loadSnapshot = async () => {
      const response = await fetch(`${REGISTRY_HTTP_URL}/api/topology/snapshot`)
      if (!response.ok) return
      const payload = (await response.json()) as SnapshotPayload
      setAgents(payload.agents)
      setAssets(payload.assets)
      setConnections(payload.connections)
      setDiffs(payload.diffs)
      if (payload.assets.length > 0) {
        setSelectedAssetIp((previous) => previous || payload.assets[0].ip)
      }
    }

    void loadSnapshot()

    const socket = new WebSocket(REGISTRY_WS_URL)
    socket.onmessage = (event) => {
      const message = JSON.parse(event.data as string) as UiMessage

      if (message.type === 'topology_snapshot') {
        setAgents(message.payload.agents)
        setAssets(message.payload.assets)
        setConnections(message.payload.connections)
        setDiffs(message.payload.diffs)
        if (message.payload.assets.length > 0) {
          setSelectedAssetIp((previous) => previous || message.payload.assets[0].ip)
        }
        return
      }

      if (message.type === 'registry_agent_update') {
        setAgents((previous) => {
          const index = previous.findIndex((agent) => agent.agent_id === message.payload.agent_id)
          if (index === -1) return [message.payload, ...previous]
          const next = [...previous]
          next[index] = message.payload
          return next
        })
        return
      }

      if (message.type === 'connection_update') {
        const payload = message.payload
        const key = `${payload.src_ip}|${payload.dst_ip}|${payload.protocol}|${payload.port}`
        const nextConnection: Connection = {
          connection_key: key,
          connection_id: payload.connection_id,
          src_ip: payload.src_ip,
          dst_ip: payload.dst_ip,
          protocol: payload.protocol,
          port: payload.port,
          packets: payload.packets,
          bytes_per_sec: payload.bytes_per_sec,
          first_seen: payload.last_seen,
          last_seen: payload.last_seen,
          last_agent_id: payload.agent_id,
          last_agent_name: payload.agent_name,
        }
        setConnections((previous) => {
          const index = previous.findIndex((connection) => connection.connection_key === key)
          if (index === -1) return [nextConnection, ...previous].slice(0, 3000)
          const next = [...previous]
          next[index] = { ...previous[index], ...nextConnection, first_seen: previous[index].first_seen }
          return next
        })
        return
      }

      if (message.type === 'connection_diff') {
        setDiffs((previous) => [message.payload, ...previous].slice(0, 500))
      }
    }

    return () => {
      if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING) {
        socket.close()
      }
    }
  }, [])

  const saveAsset = async () => {
    if (!selectedAssetIp) return
    const response = await fetch(`${REGISTRY_HTTP_URL}/api/assets/${encodeURIComponent(selectedAssetIp)}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ label: assetLabel, role: assetRole, criticality: assetCriticality }),
    })
    if (!response.ok) return
    const payload = (await response.json()) as { asset: Asset }
    setAssets((previous) => previous.map((item) => (item.ip === payload.asset.ip ? payload.asset : item)))
  }

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
    ? `python agent.py config --registry-url "${tokenInfo.registry_http_url}" --agent-name "line-a-agent" --token "${tokenInfo.token}"`
    : ''

  const runCommand = 'python agent.py run'
  const installCommand = 'python agent.py install-service'

  return (
    <div className="app">
      <header className="header card">
        <div>
          <h1>FLEX</h1>
          <p>Factory topology discovery for unknown equipment networks</p>
        </div>
        <div className="kpi-grid">
          <div className="kpi-item"><span>Agents</span><strong>{connectedAgents}/{agents.length}</strong></div>
          <div className="kpi-item"><span>Assets</span><strong>{assets.length}</strong></div>
          <div className="kpi-item"><span>Flows</span><strong>{connections.length}</strong></div>
          <div className="kpi-item"><span>Packets</span><strong>{totalPackets.toLocaleString()}</strong></div>
          <div className="kpi-item"><span>Throughput</span><strong>{Math.round((totalBandwidth * 8) / 1000)} kbps</strong></div>
        </div>
      </header>

      <nav className="tab-nav card">
        <button type="button" className={tab === 'overview' ? 'active' : ''} onClick={() => setTab('overview')}>Overview</button>
        <button type="button" className={tab === 'assets' ? 'active' : ''} onClick={() => setTab('assets')}>Assets</button>
        <button type="button" className={tab === 'events' ? 'active' : ''} onClick={() => setTab('events')}>Events</button>
        <button type="button" className={tab === 'onboarding' ? 'active' : ''} onClick={() => setTab('onboarding')}>Onboarding</button>
      </nav>

      {tab === 'overview' ? (
        <section className="card">
          <h2>Network Topology</h2>
          <CytoscapeComponent
            elements={graphElements}
            style={{ width: '100%', height: '62vh' }}
            layout={{ name: 'cose', fit: true, padding: 40, animate: false }}
            stylesheet={[
              { selector: 'node', style: { label: 'data(label)', 'background-color': '#334155', color: '#e2e8f0', 'font-size': 10 } },
              { selector: 'edge', style: { width: 2, label: 'data(label)', 'curve-style': 'bezier', 'line-color': '#64748b', color: '#cbd5e1', 'font-size': 9 } },
            ]}
          />
        </section>
      ) : null}

      {tab === 'assets' ? (
        <section className="assets-layout">
          <section className="card">
            <h2>Asset Registry</h2>
            <table className="table">
              <thead><tr><th>IP</th><th>Label</th><th>Role</th><th>Criticality</th><th>Last Seen</th></tr></thead>
              <tbody>
                {assets.length === 0 ? <tr><td colSpan={5}>No assets yet</td></tr> : assets.map((asset) => (
                  <tr key={asset.ip} className={asset.ip === selectedAssetIp ? 'selected' : ''} onClick={() => setSelectedAssetIp(asset.ip)}>
                    <td>{asset.ip}</td>
                    <td>{asset.label || '-'}</td>
                    <td>{asset.role}</td>
                    <td>{asset.criticality}</td>
                    <td>{new Date(asset.last_seen).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>

          <section className="card">
            <h2>Asset Detail</h2>
            {selectedAsset ? (
              <div className="form-grid">
                <label>IP<input value={selectedAsset.ip} readOnly /></label>
                <label>Name<input value={assetLabel} onChange={(event) => setAssetLabel(event.target.value)} placeholder="Line-A PLC" /></label>
                <label>Role<input value={assetRole} onChange={(event) => setAssetRole(event.target.value)} /></label>
                <label>Criticality
                  <select value={assetCriticality} onChange={(event) => setAssetCriticality(event.target.value)}>
                    <option value="normal">normal</option>
                    <option value="high">high</option>
                    <option value="critical">critical</option>
                  </select>
                </label>
                <label>Source Agent<input value={selectedAsset.last_agent_id ?? '-'} readOnly /></label>
                <button type="button" onClick={saveAsset}>Save</button>
              </div>
            ) : <p>Select asset from table</p>}
          </section>

          <section className="card">
            <h2>Current Flows</h2>
            <table className="table">
              <thead><tr><th>Path</th><th>Protocol</th><th>PPS</th><th>Agent</th><th>Last Seen</th></tr></thead>
              <tbody>
                {connections.length === 0 ? <tr><td colSpan={5}>No flow data</td></tr> : connections.slice(0, 200).map((connection) => (
                  <tr key={connection.connection_key}>
                    <td>{assetMap.get(connection.src_ip)?.label || connection.src_ip} → {assetMap.get(connection.dst_ip)?.label || connection.dst_ip}</td>
                    <td>{connection.protocol}:{connection.port}</td>
                    <td>{Math.round(connection.bytes_per_sec)}</td>
                    <td>{connection.last_agent_name}</td>
                    <td>{new Date(connection.last_seen).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        </section>
      ) : null}

      {tab === 'events' ? (
        <section className="card">
          <h2>Topology Diff Events</h2>
          <table className="table">
            <thead><tr><th>Time</th><th>Type</th><th>Message</th><th>Agent</th></tr></thead>
            <tbody>
              {diffs.length === 0 ? <tr><td colSpan={4}>No diff events</td></tr> : diffs.map((diff) => (
                <tr key={`${diff.connection_key}-${diff.created_at}-${diff.id ?? 0}`}>
                  <td>{new Date(diff.created_at).toLocaleString()}</td>
                  <td>{diff.event_type}</td>
                  <td>{diff.message}</td>
                  <td>{diff.agent_id}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      ) : null}

      {tab === 'onboarding' ? (
        <section className="card onboarding-grid">
          <h2>Agent Onboarding</h2>
          <div className="form-grid">
            <label>Token TTL (minutes)
              <input type="number" min={1} max={1440} value={ttlMinutes} onChange={(event) => setTtlMinutes(Number(event.target.value) || 30)} />
            </label>
            <button type="button" onClick={issueToken}>Issue token</button>
          </div>

          {tokenInfo ? (
            <div className="onboarding-result">
              <label>Enrollment token<textarea rows={3} readOnly value={tokenInfo.token} /></label>
              <div className="action-row">
                <a href={tokenInfo.download.windows} target="_blank" rel="noreferrer">Download Windows bundle</a>
                <a href={tokenInfo.download.linux} target="_blank" rel="noreferrer">Download Linux bundle</a>
              </div>
              <label>Config command<textarea rows={3} readOnly value={configCommand} /></label>
              <label>Run command<textarea rows={2} readOnly value={runCommand} /></label>
              <label>Install service command<textarea rows={2} readOnly value={installCommand} /></label>
            </div>
          ) : null}
        </section>
      ) : null}
    </div>
  )
}

export default App
