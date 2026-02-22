import { useEffect, useMemo, useRef, useState } from 'react'
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
  connection_retention_days: number
  event_retention_days: number
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

const roleColorMap: Record<string, string> = {
  'PLC/Controller Candidate': '#ef4444',
  'HMI/SCADA Candidate': '#3b82f6',
  'Infra Service': '#8b5cf6',
  'Service Endpoint': '#14b8a6',
  'Client Node': '#22c55e',
  Unknown: '#64748b',
}

const protocolColorMap: Record<string, string> = {
  'Modbus/TCP': '#f97316',
  'OPC UA': '#0ea5e9',
  PROFINET: '#10b981',
  'EtherNet/IP': '#eab308',
  DNP3: '#f43f5e',
  'IEC 104': '#a855f7',
  DNS: '#22c55e',
  NTP: '#06b6d4',
  HTTP: '#3b82f6',
  HTTPS: '#6366f1',
}

function App() {
  const cyRef = useRef<any>(null)
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
  const [eventRetentionDays, setEventRetentionDays] = useState<number>(14)
  const [tokenInfo, setTokenInfo] = useState<TokenIssueResponse | null>(null)
  const [selectedAssetIps, setSelectedAssetIps] = useState<string[]>([])
  const [selectedDiffIds, setSelectedDiffIds] = useState<number[]>([])

  const connectedAgents = useMemo(() => agents.filter((agent) => agent.status === 'connected').length, [agents])
  const totalPackets = useMemo(() => agents.reduce((sum, agent) => sum + agent.total_packets, 0), [agents])
  const totalBandwidth = useMemo(() => connections.reduce((sum, connection) => sum + connection.bytes_per_sec, 0), [connections])

  const topologyDensity = useMemo<'low' | 'medium' | 'high'>(() => {
    const nodeCount = assets.length
    const edgeCount = connections.length
    if (nodeCount >= 45 || edgeCount >= 80) return 'high'
    if (nodeCount >= 22 || edgeCount >= 30) return 'medium'
    return 'low'
  }, [assets.length, connections.length])

  const assetMap = useMemo(() => {
    const map = new Map<string, Asset>()
    assets.forEach((asset) => map.set(asset.ip, asset))
    return map
  }, [assets])

  const graphElements = useMemo(() => {
    const nodeSet = new Set<string>()
    const nodes = assets.map((asset) => {
      nodeSet.add(asset.ip)
      const baseColor = roleColorMap[asset.role] ?? roleColorMap.Unknown
      const borderColor = asset.criticality === 'critical' ? '#ef4444' : asset.criticality === 'high' ? '#f59e0b' : '#94a3b8'
      const nodeLabel =
        topologyDensity === 'high'
          ? asset.label?.trim() || ''
          : asset.label?.trim()
            ? `${asset.label} (${asset.ip})`
            : asset.ip
      return {
        data: {
          id: asset.ip,
          label: nodeLabel,
          role: asset.role,
          color: baseColor,
          borderColor,
        },
      }
    })

    const edges = connections.map((connection) => {
      nodeSet.add(connection.src_ip)
      nodeSet.add(connection.dst_ip)
      const edgeColor = protocolColorMap[connection.protocol] ?? '#64748b'
      const edgeLabel = topologyDensity === 'low' ? `${connection.protocol}:${connection.port}` : ''
      return {
        data: {
          id: connection.connection_key,
          source: connection.src_ip,
          target: connection.dst_ip,
          label: edgeLabel,
          edgeColor,
          width: Math.max(2, Math.min(7, Math.round(Math.log10(connection.packets + 1) * 2))),
        },
      }
    })

    for (const ip of nodeSet) {
      if (nodes.find((node) => node.data.id === ip)) continue
      nodes.push({ data: { id: ip, label: ip, role: 'Unknown', color: roleColorMap.Unknown, borderColor: '#94a3b8' } })
    }

    return [...nodes, ...edges]
  }, [assets, connections, topologyDensity])

  const topologyLayout = useMemo(() => {
    const nodeCount = graphElements.filter((element) => !('source' in element.data)).length
    if (nodeCount <= 1) {
      return { name: 'grid', fit: true, padding: 40, avoidOverlap: true }
    }
    if (topologyDensity === 'high') {
      return {
        name: 'cose',
        fit: true,
        padding: 48,
        animate: false,
        nodeRepulsion: 220000,
        idealEdgeLength: 140,
        edgeElasticity: 40,
      }
    }
    if (topologyDensity === 'medium') {
      return {
        name: 'cose',
        fit: true,
        padding: 36,
        animate: false,
        nodeRepulsion: 160000,
        idealEdgeLength: 100,
        edgeElasticity: 70,
      }
    }
    return { name: 'cose', fit: true, padding: 26, animate: false }
  }, [graphElements, topologyDensity])

  useEffect(() => {
    if (tab !== 'overview') return
    if (!cyRef.current) return

    const cy = cyRef.current
    const elements = cy.elements()
    if (!elements || elements.length === 0) return

    const padding = topologyDensity === 'high' ? 36 : topologyDensity === 'medium' ? 26 : 16
    const maxZoom = topologyDensity === 'high' ? 1.05 : topologyDensity === 'medium' ? 1.2 : 1.5

    const applyCamera = () => {
      cy.fit(elements, padding)
      if (cy.zoom() > maxZoom) cy.zoom(maxZoom)
      if (cy.zoom() < 0.35) cy.zoom(0.35)
      cy.center()
    }

    const timer = setTimeout(applyCamera, 30)
    return () => clearTimeout(timer)
  }, [tab, graphElements, topologyDensity])

  const selectedAsset = useMemo(() => assets.find((asset) => asset.ip === selectedAssetIp) ?? null, [assets, selectedAssetIp])
  const allAssetIps = useMemo(() => assets.map((asset) => asset.ip), [assets])
  const allDiffIds = useMemo(() => diffs.map((diff) => diff.id).filter((id): id is number => typeof id === 'number'), [diffs])

  const refreshSnapshot = async () => {
    const response = await fetch(`${REGISTRY_HTTP_URL}/api/topology/snapshot`)
    if (!response.ok) return
    const payload = (await response.json()) as SnapshotPayload
    setAgents(payload.agents)
    setAssets(payload.assets)
    setConnections(payload.connections)
    setDiffs(payload.diffs)
    setEventRetentionDays(payload.event_retention_days || 14)
    if (payload.assets.length > 0) {
      setSelectedAssetIp((previous) => previous || payload.assets[0].ip)
    }
  }

  useEffect(() => {
    if (!selectedAsset) return
    setAssetLabel(selectedAsset.label ?? '')
    setAssetRole(selectedAsset.role)
    setAssetCriticality(selectedAsset.criticality)
  }, [selectedAsset])

  useEffect(() => {
    void refreshSnapshot()

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

  useEffect(() => {
    setSelectedAssetIps((previous) => previous.filter((ip) => allAssetIps.includes(ip)))
  }, [allAssetIps])

  useEffect(() => {
    setSelectedDiffIds((previous) => previous.filter((id) => allDiffIds.includes(id)))
  }, [allDiffIds])

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

  const deleteSingleAsset = async (ip: string) => {
    const response = await fetch(`${REGISTRY_HTTP_URL}/api/assets/${encodeURIComponent(ip)}`, { method: 'DELETE' })
    if (!response.ok) return
    setSelectedAssetIps((previous) => previous.filter((item) => item !== ip))
    if (selectedAssetIp === ip) {
      setSelectedAssetIp('')
    }
    await refreshSnapshot()
  }

  const deleteSelectedAssets = async () => {
    if (selectedAssetIps.length === 0) return
    const response = await fetch(`${REGISTRY_HTTP_URL}/api/assets/delete-selected`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ips: selectedAssetIps }),
    })
    if (!response.ok) return
    if (selectedAssetIp && selectedAssetIps.includes(selectedAssetIp)) {
      setSelectedAssetIp('')
    }
    setSelectedAssetIps([])
    await refreshSnapshot()
  }

  const initializeAssets = async () => {
    const response = await fetch(`${REGISTRY_HTTP_URL}/api/assets/initialize`, { method: 'POST' })
    if (!response.ok) return
    await refreshSnapshot()
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

  const saveEventRetention = async () => {
    const response = await fetch(`${REGISTRY_HTTP_URL}/api/retention-policy`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ event_retention_days: eventRetentionDays }),
    })
    if (!response.ok) return
    await refreshSnapshot()
  }

  const clearPacketData = async (target: 'all' | 'connections' | 'diffs') => {
    const response = await fetch(`${REGISTRY_HTTP_URL}/api/packets/clear`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target }),
    })
    if (!response.ok) return
    setSelectedDiffIds([])
    await refreshSnapshot()
  }

  const deleteSelectedDiffs = async () => {
    if (selectedDiffIds.length === 0) return
    const response = await fetch(`${REGISTRY_HTTP_URL}/api/packets/delete-selected`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ connection_keys: [], diff_ids: selectedDiffIds }),
    })
    if (!response.ok) return
    setSelectedDiffIds([])
    await refreshSnapshot()
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
          <div className="legend-row">
            <span><i style={{ background: '#ef4444' }} />PLC</span>
            <span><i style={{ background: '#3b82f6' }} />HMI/SCADA</span>
            <span><i style={{ background: '#8b5cf6' }} />Infra</span>
            <span><i style={{ background: '#22c55e' }} />Client</span>
            <span><i style={{ background: '#f97316' }} />Modbus</span>
            <span><i style={{ background: '#0ea5e9' }} />OPC UA</span>
          </div>
          <CytoscapeComponent
            key={`topology-${graphElements.length}`}
            elements={graphElements}
            style={{ width: '100%', height: '62vh' }}
            layout={topologyLayout}
            cy={(cy) => {
              cyRef.current = cy
            }}
            stylesheet={[
              {
                selector: 'node',
                style: {
                  label: 'data(label)',
                  'background-color': 'data(color)',
                  'border-width': 2,
                  'border-color': 'data(borderColor)',
                  color: '#e2e8f0',
                  'font-size': topologyDensity === 'high' ? 8 : topologyDensity === 'medium' ? 9 : 10,
                  'text-wrap': 'wrap',
                  'text-max-width': topologyDensity === 'high' ? 80 : 120,
                  'text-background-opacity': topologyDensity === 'high' ? 0.28 : 0.55,
                  'text-background-color': '#0f172a',
                  'text-background-padding': 2,
                  'min-zoomed-font-size': topologyDensity === 'high' ? 12 : 8,
                },
              },
              {
                selector: 'edge',
                style: {
                  width: 'data(width)',
                  label: 'data(label)',
                  'curve-style': 'bezier',
                  'line-color': 'data(edgeColor)',
                  'target-arrow-shape': 'triangle',
                  'target-arrow-color': 'data(edgeColor)',
                  color: '#cbd5e1',
                  'font-size': topologyDensity === 'high' ? 7 : 9,
                  'text-background-opacity': topologyDensity === 'high' ? 0.2 : 0.45,
                  'text-background-color': '#0f172a',
                  'text-background-padding': 1,
                },
              },
            ] as any}
          />
        </section>
      ) : null}

      {tab === 'assets' ? (
        <section className="assets-layout">
          <section className="card">
            <h2>Asset Registry</h2>
            <div className="table-toolbar">
              <button type="button" onClick={() => setSelectedAssetIps(allAssetIps)}>Select All</button>
              <button type="button" onClick={() => setSelectedAssetIps([])}>Clear Select</button>
              <button type="button" onClick={deleteSelectedAssets} disabled={selectedAssetIps.length === 0}>Delete Selected ({selectedAssetIps.length})</button>
              <button type="button" className="danger-button" onClick={() => void initializeAssets()}>Initialize Registry</button>
            </div>
            <table className="table">
              <thead><tr><th>Select</th><th>IP</th><th>Label</th><th>Role</th><th>Criticality</th><th>Last Seen</th><th>Action</th></tr></thead>
              <tbody>
                {assets.length === 0 ? <tr><td colSpan={7}>No assets yet</td></tr> : assets.map((asset) => (
                  <tr key={asset.ip} className={asset.ip === selectedAssetIp ? 'selected' : ''} onClick={() => setSelectedAssetIp(asset.ip)}>
                    <td>
                      <input
                        type="checkbox"
                        checked={selectedAssetIps.includes(asset.ip)}
                        onChange={(event) => {
                          event.stopPropagation()
                          setSelectedAssetIps((previous) =>
                            event.target.checked
                              ? [...new Set([...previous, asset.ip])]
                              : previous.filter((ip) => ip !== asset.ip)
                          )
                        }}
                      />
                    </td>
                    <td>{asset.ip}</td>
                    <td>{asset.label || '-'}</td>
                    <td>{asset.role}</td>
                    <td>{asset.criticality}</td>
                    <td>{new Date(asset.last_seen).toLocaleString()}</td>
                    <td>
                      <button
                        type="button"
                        className="danger-button"
                        onClick={(event) => {
                          event.stopPropagation()
                          void deleteSingleAsset(asset.ip)
                        }}
                      >
                        Delete
                      </button>
                    </td>
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
            <div className="table-toolbar">
              <span>Flows are auto-maintained by retention policy.</span>
            </div>
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
          <div className="table-toolbar">
            <label>Event retention (days)
              <input type="number" min={1} max={3650} value={eventRetentionDays} onChange={(event) => setEventRetentionDays(Number(event.target.value) || 14)} />
            </label>
            <button type="button" onClick={saveEventRetention}>Save Retention</button>
            <button type="button" onClick={() => setSelectedDiffIds(allDiffIds)}>Select All</button>
            <button type="button" onClick={() => setSelectedDiffIds([])}>Clear Select</button>
            <button type="button" onClick={deleteSelectedDiffs} disabled={selectedDiffIds.length === 0}>Delete Selected ({selectedDiffIds.length})</button>
            <button type="button" className="danger-button" onClick={() => void clearPacketData('diffs')}>Clear All Diffs</button>
          </div>
          <table className="table">
            <thead><tr><th>Select</th><th>Time</th><th>Type</th><th>Message</th><th>Agent</th></tr></thead>
            <tbody>
              {diffs.length === 0 ? <tr><td colSpan={5}>No diff events</td></tr> : diffs.map((diff) => (
                <tr key={`${diff.connection_key}-${diff.created_at}-${diff.id ?? 0}`}>
                  <td>
                    <input
                      type="checkbox"
                      checked={typeof diff.id === 'number' ? selectedDiffIds.includes(diff.id) : false}
                      disabled={typeof diff.id !== 'number'}
                      onChange={(event) => {
                        if (typeof diff.id !== 'number') return
                        setSelectedDiffIds((previous) =>
                          event.target.checked
                            ? [...new Set([...previous, diff.id as number])]
                            : previous.filter((id) => id !== diff.id)
                        )
                      }}
                    />
                  </td>
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
