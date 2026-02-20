import { useEffect, useMemo, useState } from 'react'
import CytoscapeComponent from 'react-cytoscapejs'
import './App.css'

type Device = {
  id: string
  name: string
  role: string
  zone: string
}

type ConnectionStatus = 'confirmed' | 'unverified' | 'conflict'

type Connection = {
  id: string
  source: string
  target: string
  protocol: string
  port: number
  confidence: number
  basis: 'passive' | 'config' | 'hybrid'
  status: ConnectionStatus
  bandwidthKbps: number
  lastSeen: string
}

type DiffEvent = {
  id: string
  timestamp: string
  connectionId: string
  message: string
}

type InputMode = 'mock' | 'live'

type LiveConnectionPayload = {
  connection_id: string
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
      type: 'hello'
      payload: {
        message: string
        timestamp: string
      }
    }
  | {
      type: 'connection_update'
      payload: LiveConnectionPayload
    }
  | {
      type: 'heartbeat'
      payload: {
        timestamp: string
        total_packets: number
        active_connections: number
      }
    }

const devices: Device[] = [
  { id: 'plc-01', name: 'PLC-01', role: 'PLC', zone: 'Line-A' },
  { id: 'hmi-01', name: 'HMI-01', role: 'HMI', zone: 'Line-A' },
  { id: 'io-01', name: 'IO-01', role: 'Remote IO', zone: 'Line-A' },
  { id: 'scada-01', name: 'SCADA-01', role: 'SCADA', zone: 'Control' },
  { id: 'opc-01', name: 'OPC-Server', role: 'Server', zone: 'Control' },
  { id: 'hist-01', name: 'Historian', role: 'Server', zone: 'DMZ' },
]

const initialConnections: Connection[] = [
  {
    id: 'c1',
    source: 'hmi-01',
    target: 'plc-01',
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
    protocol: 'PROFINET',
    port: 34964,
    confidence: 88,
    basis: 'passive',
    status: 'confirmed',
    bandwidthKbps: 820,
    lastSeen: new Date().toISOString(),
  },
  {
    id: 'c3',
    source: 'scada-01',
    target: 'plc-01',
    protocol: 'Modbus/TCP',
    port: 502,
    confidence: 74,
    basis: 'config',
    status: 'unverified',
    bandwidthKbps: 220,
    lastSeen: new Date().toISOString(),
  },
  {
    id: 'c4',
    source: 'opc-01',
    target: 'plc-01',
    protocol: 'OPC UA',
    port: 4840,
    confidence: 81,
    basis: 'hybrid',
    status: 'confirmed',
    bandwidthKbps: 140,
    lastSeen: new Date().toISOString(),
  },
  {
    id: 'c5',
    source: 'hist-01',
    target: 'opc-01',
    protocol: 'HTTPS',
    port: 443,
    confidence: 68,
    basis: 'passive',
    status: 'unverified',
    bandwidthKbps: 90,
    lastSeen: new Date().toISOString(),
  },
]

const statusLabel: Record<ConnectionStatus, string> = {
  confirmed: 'Confirmed',
  unverified: 'Unverified',
  conflict: 'Conflict',
}

function App() {
  const [mode, setMode] = useState<InputMode>('mock')
  const [agentUrl, setAgentUrl] = useState<string>(import.meta.env.VITE_AGENT_URL ?? 'ws://127.0.0.1:8765')
  const [agentStatus, setAgentStatus] = useState<string>('Disconnected')
  const [reconnectToken, setReconnectToken] = useState<number>(0)
  const [mockConnections, setMockConnections] = useState<Connection[]>(initialConnections)
  const [liveConnections, setLiveConnections] = useState<Connection[]>([])
  const [diffEvents, setDiffEvents] = useState<DiffEvent[]>([])
  const [selectedConnectionId, setSelectedConnectionId] = useState<string>(initialConnections[0].id)

  const connections = mode === 'mock' ? mockConnections : liveConnections

  const selectedConnection = useMemo(
    () => connections.find((connection) => connection.id === selectedConnectionId),
    [connections, selectedConnectionId],
  )

  const activeDevices = useMemo<Device[]>(() => {
    if (mode === 'mock') {
      return devices
    }

    const uniqueIds = new Set<string>()
    liveConnections.forEach((connection) => {
      uniqueIds.add(connection.source)
      uniqueIds.add(connection.target)
    })

    return Array.from(uniqueIds).map((id) => ({
      id,
      name: id,
      role: 'Endpoint',
      zone: 'Observed',
    }))
  }, [mode, liveConnections])

  const elements = useMemo(
    () => [
      ...activeDevices.map((device) => ({
        data: {
          id: device.id,
          label: device.name,
          role: device.role,
          zone: device.zone,
        },
      })),
      ...connections.map((connection) => ({
        data: {
          id: connection.id,
          source: connection.source,
          target: connection.target,
          label: `${connection.protocol} : ${connection.port}`,
          status: connection.status,
          confidence: connection.confidence,
        },
      })),
    ],
    [activeDevices, connections],
  )

  useEffect(() => {
    if (mode !== 'mock') {
      return
    }

    const timer = window.setInterval(() => {
      setMockConnections((previous) => {
        const index = Math.floor(Math.random() * previous.length)
        const next = [...previous]
        const target = next[index]
        const statuses: ConnectionStatus[] = ['confirmed', 'unverified', 'conflict']
        const status = statuses[Math.floor(Math.random() * statuses.length)]
        const confidenceDelta = Math.floor(Math.random() * 11) - 5
        const bandwidthDelta = Math.floor(Math.random() * 101) - 50

        const updated: Connection = {
          ...target,
          status,
          confidence: Math.max(40, Math.min(99, target.confidence + confidenceDelta)),
          bandwidthKbps: Math.max(20, target.bandwidthKbps + bandwidthDelta),
          lastSeen: new Date().toISOString(),
        }

        next[index] = updated

        setDiffEvents((events) => [
          {
            id: `${updated.id}-${Date.now()}`,
            timestamp: new Date().toLocaleTimeString(),
            connectionId: updated.id,
            message: `${updated.protocol} ${statusLabel[updated.status]} (${updated.confidence}%)`,
          },
          ...events,
        ].slice(0, 20))

        return next
      })
    }, 3000)

    return () => window.clearInterval(timer)
  }, [mode])

  useEffect(() => {
    setDiffEvents([])
    setSelectedConnectionId('')
  }, [mode])

  useEffect(() => {
    if (mode !== 'live') {
      setAgentStatus('Disconnected')
      return
    }

    let socket: WebSocket | null = null

    try {
      socket = new WebSocket(agentUrl)
      setAgentStatus('Connecting...')

      socket.onopen = () => {
        setAgentStatus('Connected')
      }

      socket.onclose = () => {
        setAgentStatus('Disconnected')
      }

      socket.onerror = () => {
        setAgentStatus('Connection Error')
      }

      socket.onmessage = (event) => {
        const parsed = JSON.parse(event.data as string) as AgentMessage

        if (parsed.type === 'heartbeat') {
          setAgentStatus(`Connected (${parsed.payload.total_packets} packets)`)
          return
        }

        if (parsed.type !== 'connection_update') {
          return
        }

        const payload = parsed.payload

        const nextConnection: Connection = {
          id: payload.connection_id,
          source: payload.src_ip,
          target: payload.dst_ip,
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
          if (index === -1) {
            return [nextConnection, ...previous].slice(0, 300)
          }

          const next = [...previous]
          next[index] = nextConnection
          return next
        })

        setDiffEvents((events) => [
          {
            id: `${payload.connection_id}-${Date.now()}`,
            timestamp: new Date().toLocaleTimeString(),
            connectionId: payload.connection_id,
            message: `${payload.protocol} ${payload.src_ip} → ${payload.dst_ip} (${payload.bytes_per_sec.toFixed(1)} B/s)`,
          },
          ...events,
        ].slice(0, 30))

        setSelectedConnectionId((previous) => previous || payload.connection_id)
      }
    } catch {
      setAgentStatus('Connection Error')
    }

    return () => {
      if (socket && socket.readyState === WebSocket.OPEN) {
        socket.close()
      }
    }
  }, [mode, agentUrl, reconnectToken])

  return (
    <div className="app">
      <header className="header">
        <div>
          <h1>FLEX</h1>
          <p>Factory Link Explorer</p>
        </div>
        <span className="badge">Input: {mode === 'mock' ? 'Mock Data' : 'Real Packet Stream'}</span>
      </header>

      <section className="card control-card">
        <h2>Input Control</h2>
        <div className="controls">
          <label>
            Mode
            <select value={mode} onChange={(event) => setMode(event.target.value as InputMode)}>
              <option value="mock">Mock</option>
              <option value="live">Live (Packet Agent)</option>
            </select>
          </label>

          <label>
            Agent URL
            <input
              type="text"
              value={agentUrl}
              onChange={(event) => setAgentUrl(event.target.value)}
              placeholder="ws://127.0.0.1:8765"
              disabled={mode !== 'live'}
            />
          </label>

          <button type="button" onClick={() => setReconnectToken((value) => value + 1)} disabled={mode !== 'live'}>
            Reconnect
          </button>

          <div className="agent-status">Agent: {agentStatus}</div>
        </div>
      </section>

      <section className="top-grid">
        <div className="card graph-card">
          <h2>Equipment Connectivity Map</h2>
          <CytoscapeComponent
            elements={elements}
            style={{ width: '100%', height: '420px' }}
            layout={{ name: 'cose', fit: true, padding: 30 }}
            stylesheet={[
              {
                selector: 'node',
                style: {
                  label: 'data(label)',
                  'background-color': '#3f83f8',
                  color: '#ffffff',
                  'text-valign': 'center',
                  'text-halign': 'center',
                  'font-size': '11px',
                  width: 42,
                  height: 42,
                },
              },
              {
                selector: 'edge',
                style: {
                  width: 3,
                  label: 'data(label)',
                  'curve-style': 'bezier',
                  'target-arrow-shape': 'triangle',
                  'font-size': '9px',
                  'text-background-opacity': 1,
                  'text-background-color': '#0f172a',
                  'text-background-padding': '3px',
                  color: '#e2e8f0',
                  'line-color': '#60a5fa',
                  'target-arrow-color': '#60a5fa',
                },
              },
              {
                selector: 'edge[status = "confirmed"]',
                style: {
                  'line-color': '#22c55e',
                  'target-arrow-color': '#22c55e',
                },
              },
              {
                selector: 'edge[status = "unverified"]',
                style: {
                  'line-color': '#f59e0b',
                  'target-arrow-color': '#f59e0b',
                },
              },
              {
                selector: 'edge[status = "conflict"]',
                style: {
                  'line-color': '#ef4444',
                  'target-arrow-color': '#ef4444',
                },
              },
            ]}
          />
        </div>

        <div className="card detail-card">
          <h2>Connection Details</h2>
          {selectedConnection ? (
            <dl>
              <div>
                <dt>Connection</dt>
                <dd>{selectedConnection.source} → {selectedConnection.target}</dd>
              </div>
              <div>
                <dt>Protocol</dt>
                <dd>{selectedConnection.protocol}</dd>
              </div>
              <div>
                <dt>Port</dt>
                <dd>{selectedConnection.port}</dd>
              </div>
              <div>
                <dt>Status</dt>
                <dd>{statusLabel[selectedConnection.status]}</dd>
              </div>
              <div>
                <dt>Confidence</dt>
                <dd>{selectedConnection.confidence}%</dd>
              </div>
              <div>
                <dt>Evidence</dt>
                <dd>{selectedConnection.basis}</dd>
              </div>
              <div>
                <dt>Bandwidth</dt>
                <dd>{selectedConnection.bandwidthKbps} kbps</dd>
              </div>
              <div>
                <dt>Last Seen</dt>
                <dd>{new Date(selectedConnection.lastSeen).toLocaleTimeString()}</dd>
              </div>
            </dl>
          ) : (
            <p>No connection selected.</p>
          )}
        </div>
      </section>

      <section className="card">
        <h2>Connection Diff Feed</h2>
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Connection</th>
              <th>Change</th>
            </tr>
          </thead>
          <tbody>
            {diffEvents.length === 0 ? (
              <tr>
                <td colSpan={3}>{mode === 'live' ? 'Waiting for packet events...' : 'Waiting for changes...'}</td>
              </tr>
            ) : (
              diffEvents.map((event) => (
                <tr key={event.id} onClick={() => setSelectedConnectionId(event.connectionId)}>
                  <td>{event.timestamp}</td>
                  <td>{event.connectionId}</td>
                  <td>{event.message}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </section>
    </div>
  )
}

export default App
