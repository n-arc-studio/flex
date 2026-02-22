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
  severity?: 'low' | 'medium' | 'high' | 'critical'
  risk_score?: number
  triage_status?: 'open' | 'acknowledged' | 'resolved'
  connection_key: string
  src_ip: string
  dst_ip: string
  protocol: string
  port: number
  agent_id: string
  created_at: string
}

type AlertItem = {
  id: number
  diff_event_id: number
  severity: 'low' | 'medium' | 'high' | 'critical'
  status: 'open' | 'acknowledged' | 'resolved'
  assignee: string | null
  note: string | null
  created_at: string
  updated_at: string
  message?: string
  protocol?: string
  port?: number
  src_ip?: string
  dst_ip?: string
  risk_score?: number
}

type IntegrationItem = {
  id: number
  name: string
  provider: string
  endpoint_url: string
  api_key?: string | null
  inbound_mapping_json?: string
  outbound_mapping_json?: string
  direction: 'outbound' | 'inbound' | 'both'
  enabled: number
  last_status: string | null
  last_synced_at: string | null
}

type QueueItem = {
  id: number
  integration_id: number
  integration_name?: string
  event_type: string
  status: string
  attempt_count: number
  last_error: string | null
  updated_at: string
}

type QueueStat = {
  status: string
  count: number
}

type InboundEventItem = {
  id: number
  integration_id: number
  integration_name?: string
  source: string
  event_type: string
  external_id: string
  created_at: string
}

type IntegrationMetrics = {
  queue_status_counts: QueueStat[]
  processed_24h: number
  delivered_24h: number
  dead_24h: number
  inbound_24h: number
  success_rate_24h: number
}

type RunbookItem = {
  id: number
  name: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  owner: string | null
  steps: string
  escalation_minutes: number
}

type EscalationPolicyItem = {
  id: number
  severity: 'low' | 'medium' | 'high' | 'critical'
  threshold_minutes: number
  channel: string
  target: string
}

type AuditLogItem = {
  id: number
  actor: string
  action: string
  target: string
  details_json: string
  created_at: string
}

type SnapshotPayload = {
  agents: Agent[]
  assets: Asset[]
  connections: Connection[]
  diffs: DiffEvent[]
  alerts: AlertItem[]
  integrations: IntegrationItem[]
  runbooks: RunbookItem[]
  escalation_policies: EscalationPolicyItem[]
  audit_logs: AuditLogItem[]
  integration_queue_stats?: QueueStat[]
  integration_queue?: QueueItem[]
  inbound_events?: InboundEventItem[]
  timestamp: string
  connection_retention_days: number
  event_retention_days: number
  notification_webhook: string
  notification_min_risk: number
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
const REGISTRY_WS_BASE = REGISTRY_HTTP_URL.replace(/^http/, 'ws') + '/ws/ui'

type Tab = 'overview' | 'assets' | 'events' | 'operations' | 'onboarding'
type Locale = 'ja' | 'en'

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
  const [locale, setLocale] = useState<Locale>(() => (navigator.language?.toLowerCase().startsWith('ja') ? 'ja' : 'en'))
  const [authToken, setAuthToken] = useState<string>(() => localStorage.getItem('flex_auth_token') ?? '')
  const [loginUsername, setLoginUsername] = useState<string>('admin')
  const [loginPassword, setLoginPassword] = useState<string>('')
  const [loginError, setLoginError] = useState<string>('')
  const [mustChangePassword, setMustChangePassword] = useState<boolean>(false)
  const [changeCurrentPassword, setChangeCurrentPassword] = useState<string>('')
  const [changeNewPassword, setChangeNewPassword] = useState<string>('')
  const [tab, setTab] = useState<Tab>('overview')
  const [agents, setAgents] = useState<Agent[]>([])
  const [assets, setAssets] = useState<Asset[]>([])
  const [connections, setConnections] = useState<Connection[]>([])
  const [diffs, setDiffs] = useState<DiffEvent[]>([])
  const [alerts, setAlerts] = useState<AlertItem[]>([])
  const [integrations, setIntegrations] = useState<IntegrationItem[]>([])
  const [runbooks, setRunbooks] = useState<RunbookItem[]>([])
  const [policies, setPolicies] = useState<EscalationPolicyItem[]>([])
  const [auditLogs, setAuditLogs] = useState<AuditLogItem[]>([])
  const [selectedAssetIp, setSelectedAssetIp] = useState<string>('')
  const [assetLabel, setAssetLabel] = useState<string>('')
  const [assetRole, setAssetRole] = useState<string>('Unknown')
  const [assetCriticality, setAssetCriticality] = useState<string>('normal')
  const [ttlMinutes, setTtlMinutes] = useState<number>(30)
  const [eventRetentionDays, setEventRetentionDays] = useState<number>(14)
  const [tokenInfo, setTokenInfo] = useState<TokenIssueResponse | null>(null)
  const [selectedAssetIps, setSelectedAssetIps] = useState<string[]>([])
  const [selectedDiffIds, setSelectedDiffIds] = useState<number[]>([])
  const [notificationWebhook, setNotificationWebhook] = useState<string>('')
  const [notificationMinRisk, setNotificationMinRisk] = useState<number>(55)
  const [integrationName, setIntegrationName] = useState<string>('')
  const [integrationUrl, setIntegrationUrl] = useState<string>('')
  const [integrationProvider, setIntegrationProvider] = useState<string>('webhook')
  const [integrationDirection, setIntegrationDirection] = useState<'outbound' | 'inbound' | 'both'>('both')
  const [integrationApiKey, setIntegrationApiKey] = useState<string>('')
  const [integrationInboundMap, setIntegrationInboundMap] = useState<string>('{}')
  const [integrationOutboundMap, setIntegrationOutboundMap] = useState<string>('{}')
  const [queueItems, setQueueItems] = useState<QueueItem[]>([])
  const [queueStats, setQueueStats] = useState<QueueStat[]>([])
  const [inboundEvents, setInboundEvents] = useState<InboundEventItem[]>([])
  const [integrationMetrics, setIntegrationMetrics] = useState<IntegrationMetrics | null>(null)
  const [runbookName, setRunbookName] = useState<string>('')
  const [runbookSteps, setRunbookSteps] = useState<string>('')
  const [runbookSeverity, setRunbookSeverity] = useState<'low' | 'medium' | 'high' | 'critical'>('high')
  const [slaMttaSeconds, setSlaMttaSeconds] = useState<number>(0)
  const [slaMttrSeconds, setSlaMttrSeconds] = useState<number>(0)
  const [openBySeverityText, setOpenBySeverityText] = useState<string>('')

  const wsUrl = useMemo(() => {
    if (!authToken) return ''
    return `${REGISTRY_WS_BASE}?token=${encodeURIComponent(authToken)}`
  }, [authToken])

  const apiFetch = (path: string, init: RequestInit = {}) => {
    const headers = new Headers(init.headers || {})
    if (authToken) headers.set('Authorization', `Bearer ${authToken}`)
    return fetch(`${REGISTRY_HTTP_URL}${path}`, { ...init, headers })
  }

  const connectedAgents = useMemo(() => agents.filter((agent) => agent.status === 'connected').length, [agents])
  const totalPackets = useMemo(() => agents.reduce((sum, agent) => sum + agent.total_packets, 0), [agents])
  const totalBandwidth = useMemo(() => connections.reduce((sum, connection) => sum + connection.bytes_per_sec, 0), [connections])
  const uiLocale = locale === 'ja' ? 'ja-JP' : 'en-US'
  const tr = (en: string, ja: string) => (locale === 'ja' ? ja : en)

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
    const response = await apiFetch('/api/topology/snapshot')
    if (response.status === 401) {
      setAuthToken('')
      localStorage.removeItem('flex_auth_token')
      return
    }
    if (!response.ok) return
    const payload = (await response.json()) as SnapshotPayload
    setAgents(payload.agents)
    setAssets(payload.assets)
    setConnections(payload.connections)
    setDiffs(payload.diffs)
    setAlerts(payload.alerts || [])
    setIntegrations(payload.integrations || [])
    setQueueItems(payload.integration_queue || [])
    setQueueStats(payload.integration_queue_stats || [])
    setInboundEvents(payload.inbound_events || [])
    setRunbooks(payload.runbooks || [])
    setPolicies(payload.escalation_policies || [])
    setAuditLogs(payload.audit_logs || [])
    setNotificationWebhook(payload.notification_webhook || '')
    setNotificationMinRisk(payload.notification_min_risk || 55)
    setEventRetentionDays(payload.event_retention_days || 14)
    if (payload.assets.length > 0) {
      setSelectedAssetIp((previous) => previous || payload.assets[0].ip)
    }
  }

  const login = async () => {
    setLoginError('')
    const response = await fetch(`${REGISTRY_HTTP_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: loginUsername, password: loginPassword }),
    })
    if (!response.ok) {
      setLoginError(tr('Login failed', 'ログインに失敗しました'))
      return
    }
    const payload = (await response.json()) as { token: string; must_change_password?: boolean }
    setAuthToken(payload.token)
    localStorage.setItem('flex_auth_token', payload.token)
    setMustChangePassword(!!payload.must_change_password)
    setLoginPassword('')
  }

  const logout = async () => {
    await apiFetch('/api/auth/logout', { method: 'POST' })
    setAuthToken('')
    localStorage.removeItem('flex_auth_token')
  }

  const changePassword = async () => {
    const response = await apiFetch('/api/auth/change-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        current_password: changeCurrentPassword,
        new_password: changeNewPassword,
      }),
    })
    if (!response.ok) {
      setLoginError(tr('Password change failed', 'パスワード変更に失敗しました'))
      return
    }
    setMustChangePassword(false)
    setAuthToken('')
    localStorage.removeItem('flex_auth_token')
    setChangeCurrentPassword('')
    setChangeNewPassword('')
    setLoginError(tr('Password updated. Please login again.', 'パスワードを更新しました。再ログインしてください。'))
  }

  useEffect(() => {
    if (!selectedAsset) return
    setAssetLabel(selectedAsset.label ?? '')
    setAssetRole(selectedAsset.role)
    setAssetCriticality(selectedAsset.criticality)
  }, [selectedAsset])

  useEffect(() => {
    if (!authToken) return
    void refreshSnapshot()

    const socket = new WebSocket(wsUrl)
    socket.onmessage = (event) => {
      const message = JSON.parse(event.data as string) as UiMessage

      if (message.type === 'topology_snapshot') {
        setAgents(message.payload.agents)
        setAssets(message.payload.assets)
        setConnections(message.payload.connections)
        setDiffs(message.payload.diffs)
        setAlerts(message.payload.alerts || [])
        setIntegrations(message.payload.integrations || [])
        setQueueItems(message.payload.integration_queue || [])
        setQueueStats(message.payload.integration_queue_stats || [])
        setInboundEvents(message.payload.inbound_events || [])
        setRunbooks(message.payload.runbooks || [])
        setPolicies(message.payload.escalation_policies || [])
        setAuditLogs(message.payload.audit_logs || [])
        setNotificationWebhook(message.payload.notification_webhook || '')
        setNotificationMinRisk(message.payload.notification_min_risk || 55)
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
  }, [authToken, wsUrl])

  useEffect(() => {
    setSelectedAssetIps((previous) => previous.filter((ip) => allAssetIps.includes(ip)))
  }, [allAssetIps])

  useEffect(() => {
    setSelectedDiffIds((previous) => previous.filter((id) => allDiffIds.includes(id)))
  }, [allDiffIds])

  useEffect(() => {
    if (tab !== 'operations') return
    void fetchSlaSummary()
    void loadIntegrationQueue()
    void loadInboundEvents()
    void loadIntegrationMetrics()
  }, [tab])

  const saveAsset = async () => {
    if (!selectedAssetIp) return
    const response = await apiFetch(`/api/assets/${encodeURIComponent(selectedAssetIp)}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ label: assetLabel, role: assetRole, criticality: assetCriticality }),
    })
    if (!response.ok) return
    const payload = (await response.json()) as { asset: Asset }
    setAssets((previous) => previous.map((item) => (item.ip === payload.asset.ip ? payload.asset : item)))
  }

  const deleteSingleAsset = async (ip: string) => {
    const response = await apiFetch(`/api/assets/${encodeURIComponent(ip)}`, { method: 'DELETE' })
    if (!response.ok) return
    setSelectedAssetIps((previous) => previous.filter((item) => item !== ip))
    if (selectedAssetIp === ip) {
      setSelectedAssetIp('')
    }
    await refreshSnapshot()
  }

  const deleteSelectedAssets = async () => {
    if (selectedAssetIps.length === 0) return
    const response = await apiFetch('/api/assets/delete-selected', {
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
    const response = await apiFetch('/api/assets/initialize', { method: 'POST' })
    if (!response.ok) return
    await refreshSnapshot()
  }

  const issueToken = async () => {
    const response = await apiFetch('/api/tokens', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ttl_minutes: ttlMinutes }),
    })
    if (!response.ok) return
    const payload = (await response.json()) as TokenIssueResponse
    setTokenInfo(payload)
  }

  const saveEventRetention = async () => {
    const response = await apiFetch('/api/retention-policy', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ event_retention_days: eventRetentionDays }),
    })
    if (!response.ok) return
    await refreshSnapshot()
  }

  const updateDiffTriage = async (diffId: number, triageStatus: 'open' | 'acknowledged' | 'resolved') => {
    const response = await apiFetch(`/api/diffs/${diffId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ triage_status: triageStatus }),
    })
    if (!response.ok) return
    await refreshSnapshot()
  }

  const updateAlertStatus = async (alertId: number, status: 'open' | 'acknowledged' | 'resolved') => {
    const response = await apiFetch(`/api/alerts/${alertId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status }),
    })
    if (!response.ok) return
    await refreshSnapshot()
  }

  const saveNotificationSettings = async () => {
    const response = await apiFetch('/api/notification-settings', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        notification_webhook: notificationWebhook,
        notification_min_risk: notificationMinRisk,
      }),
    })
    if (!response.ok) return
    await refreshSnapshot()
  }

  const downloadAuditReport = (format: 'json' | 'csv') => {
    const url = `${REGISTRY_HTTP_URL}/api/reports/audit?days=30&format=${format}`
    window.open(url, '_blank', 'noopener,noreferrer')
  }

  const createIntegration = async () => {
    if (!integrationName || !integrationUrl) return
    let inboundMapping: Record<string, string> = {}
    let outboundMapping: Record<string, string> = {}
    try {
      inboundMapping = JSON.parse(integrationInboundMap || '{}')
      outboundMapping = JSON.parse(integrationOutboundMap || '{}')
    } catch {
      return
    }
    const response = await apiFetch('/api/integrations', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: integrationName,
        provider: integrationProvider,
        endpoint_url: integrationUrl,
        api_key: integrationApiKey,
        inbound_mapping: inboundMapping,
        outbound_mapping: outboundMapping,
        direction: integrationDirection,
        enabled: true,
      }),
    })
    if (!response.ok) return
    setIntegrationName('')
    setIntegrationUrl('')
    setIntegrationApiKey('')
    setIntegrationInboundMap('{}')
    setIntegrationOutboundMap('{}')
    await refreshSnapshot()
  }

  const loadIntegrationQueue = async () => {
    const response = await apiFetch('/api/integrations/queue?limit=200')
    if (!response.ok) return
    const payload = (await response.json()) as { queue: QueueItem[]; stats: QueueStat[] }
    setQueueItems(payload.queue || [])
    setQueueStats(payload.stats || [])
  }

  const retryIntegrationQueue = async (resetDead: boolean) => {
    const response = await apiFetch('/api/integrations/queue/retry', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reset_dead: resetDead }),
    })
    if (!response.ok) return
    await loadIntegrationQueue()
    await loadIntegrationMetrics()
  }

  const queueItemAction = async (id: number, action: 'hold' | 'cancel' | 'retry' | 'archive') => {
    const response = await apiFetch(`/api/integrations/queue/${id}/action`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action }),
    })
    if (!response.ok) return
    await loadIntegrationQueue()
    await loadIntegrationMetrics()
  }

  const archiveQueue = async () => {
    const response = await apiFetch('/api/integrations/queue/archive', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ older_than_hours: 24 }),
    })
    if (!response.ok) return
    await loadIntegrationQueue()
    await loadIntegrationMetrics()
  }

  const loadInboundEvents = async () => {
    const response = await apiFetch('/api/inbound/events?limit=200')
    if (!response.ok) return
    const payload = (await response.json()) as { events: InboundEventItem[] }
    setInboundEvents(payload.events || [])
  }

  const loadIntegrationMetrics = async () => {
    const response = await apiFetch('/api/integrations/metrics')
    if (!response.ok) return
    const payload = (await response.json()) as IntegrationMetrics
    setIntegrationMetrics(payload)
  }

  const testIntegration = async (id: number) => {
    const response = await apiFetch(`/api/integrations/${id}/test`, { method: 'POST' })
    if (!response.ok) return
    await refreshSnapshot()
  }

  const deleteIntegration = async (id: number) => {
    const response = await apiFetch(`/api/integrations/${id}`, { method: 'DELETE' })
    if (!response.ok) return
    await refreshSnapshot()
  }

  const createRunbook = async () => {
    if (!runbookName || !runbookSteps) return
    const response = await apiFetch('/api/runbooks', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: runbookName,
        severity: runbookSeverity,
        steps: runbookSteps,
        escalation_minutes: 30,
      }),
    })
    if (!response.ok) return
    setRunbookName('')
    setRunbookSteps('')
    await refreshSnapshot()
  }

  const fetchSlaSummary = async () => {
    const response = await apiFetch('/api/sla/summary')
    if (!response.ok) return
    const payload = (await response.json()) as {
      open_by_severity: Array<{ severity: string; count: number }>
      mtta_seconds: number
      mttr_seconds: number
    }
    setSlaMttaSeconds(payload.mtta_seconds)
    setSlaMttrSeconds(payload.mttr_seconds)
    setOpenBySeverityText((payload.open_by_severity || []).map((item) => `${item.severity}:${item.count}`).join(' | '))
  }

  const clearPacketData = async (target: 'all' | 'connections' | 'diffs') => {
    const response = await apiFetch('/api/packets/clear', {
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
    const response = await apiFetch('/api/packets/delete-selected', {
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

  if (!authToken) {
    return (
      <div className="app">
        <section className="card" style={{ maxWidth: 520, margin: '80px auto' }}>
          <h2>{tr('Sign in', 'サインイン')}</h2>
          <div className="form-grid">
            <label>{tr('Username', 'ユーザー名')}<input value={loginUsername} onChange={(event) => setLoginUsername(event.target.value)} /></label>
            <label>{tr('Password', 'パスワード')}<input type="password" value={loginPassword} onChange={(event) => setLoginPassword(event.target.value)} /></label>
            <button type="button" onClick={() => void login()}>{tr('Login', 'ログイン')}</button>
            {loginError ? <p>{loginError}</p> : null}
          </div>
        </section>
      </div>
    )
  }

  if (mustChangePassword) {
    return (
      <div className="app">
        <section className="card" style={{ maxWidth: 620, margin: '80px auto' }}>
          <h2>{tr('Password update required', '初回パスワード変更が必要です')}</h2>
          <div className="form-grid">
            <label>{tr('Current password', '現在のパスワード')}<input type="password" value={changeCurrentPassword} onChange={(event) => setChangeCurrentPassword(event.target.value)} /></label>
            <label>{tr('New password (12+ chars)', '新しいパスワード（12文字以上）')}<input type="password" value={changeNewPassword} onChange={(event) => setChangeNewPassword(event.target.value)} /></label>
            <button type="button" onClick={() => void changePassword()}>{tr('Change password', 'パスワード変更')}</button>
            <button type="button" className="danger-button" onClick={() => void logout()}>{tr('Logout', 'ログアウト')}</button>
            {loginError ? <p>{loginError}</p> : null}
          </div>
        </section>
      </div>
    )
  }

  return (
    <div className="app">
      <header className="header card">
        <div>
          <h1>FLEX</h1>
          <p>{tr('Factory topology discovery for unknown equipment networks', '未知設備ネットワーク向けファクトリトポロジ可視化')}</p>
        </div>
        <div className="header-side">
          <div className="lang-toggle">
            <button type="button" className={locale === 'ja' ? 'active' : ''} onClick={() => setLocale('ja')}>日本語</button>
            <button type="button" className={locale === 'en' ? 'active' : ''} onClick={() => setLocale('en')}>English</button>
            <button type="button" onClick={() => void logout()}>{tr('Logout', 'ログアウト')}</button>
          </div>
          <div className="kpi-grid">
            <div className="kpi-item"><span>{tr('Agents', 'エージェント')}</span><strong>{connectedAgents}/{agents.length}</strong></div>
            <div className="kpi-item"><span>{tr('Assets', '資産')}</span><strong>{assets.length}</strong></div>
            <div className="kpi-item"><span>{tr('Flows', 'フロー')}</span><strong>{connections.length}</strong></div>
            <div className="kpi-item"><span>{tr('Packets', 'パケット')}</span><strong>{totalPackets.toLocaleString(uiLocale)}</strong></div>
            <div className="kpi-item"><span>{tr('Throughput', 'スループット')}</span><strong>{Math.round((totalBandwidth * 8) / 1000)} kbps</strong></div>
          </div>
        </div>
      </header>

      <nav className="tab-nav card">
        <button type="button" className={tab === 'overview' ? 'active' : ''} onClick={() => setTab('overview')}>{tr('Overview', '概要')}</button>
        <button type="button" className={tab === 'assets' ? 'active' : ''} onClick={() => setTab('assets')}>{tr('Assets', '資産')}</button>
        <button type="button" className={tab === 'events' ? 'active' : ''} onClick={() => setTab('events')}>{tr('Events', 'イベント')}</button>
        <button type="button" className={tab === 'operations' ? 'active' : ''} onClick={() => setTab('operations')}>{tr('Operations', '運用')}</button>
        <button type="button" className={tab === 'onboarding' ? 'active' : ''} onClick={() => setTab('onboarding')}>{tr('Onboarding', '導入')}</button>
      </nav>

      {tab === 'overview' ? (
        <section className="card">
          <h2>{tr('Network Topology', 'ネットワークトポロジ')}</h2>
          <div className="legend-row">
            <span><i style={{ background: '#ef4444' }} />{tr('PLC', 'PLC')}</span>
            <span><i style={{ background: '#3b82f6' }} />{tr('HMI/SCADA', 'HMI/SCADA')}</span>
            <span><i style={{ background: '#8b5cf6' }} />{tr('Infra', '基盤')}</span>
            <span><i style={{ background: '#22c55e' }} />{tr('Client', 'クライアント')}</span>
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
            <h2>{tr('Asset Registry', '資産台帳')}</h2>
            <div className="table-toolbar">
              <button type="button" onClick={() => setSelectedAssetIps(allAssetIps)}>{tr('Select All', '全選択')}</button>
              <button type="button" onClick={() => setSelectedAssetIps([])}>{tr('Clear Select', '選択解除')}</button>
              <button type="button" onClick={deleteSelectedAssets} disabled={selectedAssetIps.length === 0}>{tr('Delete Selected', '選択削除')} ({selectedAssetIps.length})</button>
              <button type="button" className="danger-button" onClick={() => void initializeAssets()}>{tr('Initialize Registry', '台帳を初期化')}</button>
            </div>
            <table className="table">
              <thead><tr><th>{tr('Select', '選択')}</th><th>IP</th><th>{tr('Label', '名称')}</th><th>{tr('Role', '役割')}</th><th>{tr('Criticality', '重要度')}</th><th>{tr('Last Seen', '最終検知')}</th><th>{tr('Action', '操作')}</th></tr></thead>
              <tbody>
                {assets.length === 0 ? <tr><td colSpan={7}>{tr('No assets yet', '資産はまだありません')}</td></tr> : assets.map((asset) => (
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
                    <td>{new Date(asset.last_seen).toLocaleString(uiLocale)}</td>
                    <td>
                      <button
                        type="button"
                        className="danger-button"
                        onClick={(event) => {
                          event.stopPropagation()
                          void deleteSingleAsset(asset.ip)
                        }}
                      >
                        {tr('Delete', '削除')}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>

          <section className="card">
            <h2>{tr('Asset Detail', '資産詳細')}</h2>
            {selectedAsset ? (
              <div className="form-grid">
                <label>IP<input value={selectedAsset.ip} readOnly /></label>
                <label>{tr('Name', '名称')}<input value={assetLabel} onChange={(event) => setAssetLabel(event.target.value)} placeholder={tr('Line-A PLC', 'ラインA PLC')} /></label>
                <label>{tr('Role', '役割')}<input value={assetRole} onChange={(event) => setAssetRole(event.target.value)} /></label>
                <label>{tr('Criticality', '重要度')}
                  <select value={assetCriticality} onChange={(event) => setAssetCriticality(event.target.value)}>
                    <option value="normal">{tr('normal', '通常')}</option>
                    <option value="high">{tr('high', '高')}</option>
                    <option value="critical">{tr('critical', '重大')}</option>
                  </select>
                </label>
                <label>{tr('Source Agent', '送信元エージェント')}<input value={selectedAsset.last_agent_id ?? '-'} readOnly /></label>
                <button type="button" onClick={saveAsset}>{tr('Save', '保存')}</button>
              </div>
            ) : <p>{tr('Select asset from table', '表から資産を選択してください')}</p>}
          </section>

          <section className="card">
            <h2>{tr('Current Flows', '現在のフロー')}</h2>
            <div className="table-toolbar">
              <span>{tr('Flows are auto-maintained by retention policy.', 'フローは保持ポリシーにより自動管理されます。')}</span>
            </div>
            <table className="table">
              <thead><tr><th>{tr('Path', '経路')}</th><th>{tr('Protocol', 'プロトコル')}</th><th>PPS</th><th>{tr('Agent', 'エージェント')}</th><th>{tr('Last Seen', '最終検知')}</th></tr></thead>
              <tbody>
                {connections.length === 0 ? <tr><td colSpan={5}>{tr('No flow data', 'フローデータがありません')}</td></tr> : connections.slice(0, 200).map((connection) => (
                  <tr key={connection.connection_key}>
                    <td>{assetMap.get(connection.src_ip)?.label || connection.src_ip} → {assetMap.get(connection.dst_ip)?.label || connection.dst_ip}</td>
                    <td>{connection.protocol}:{connection.port}</td>
                    <td>{Math.round(connection.bytes_per_sec)}</td>
                    <td>{connection.last_agent_name}</td>
                    <td>{new Date(connection.last_seen).toLocaleString(uiLocale)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        </section>
      ) : null}

      {tab === 'events' ? (
        <section className="assets-layout">
          <section className="card">
            <h2>{tr('Notification & Audit', '通知と監査')}</h2>
            <div className="form-grid">
              <label>{tr('Webhook URL', 'Webhook URL')}
                <input
                  value={notificationWebhook}
                  onChange={(event) => setNotificationWebhook(event.target.value)}
                  placeholder="https://example.com/webhook"
                />
              </label>
              <label>{tr('Notify min risk', '通知最小リスク')}
                <input
                  type="number"
                  min={0}
                  max={100}
                  value={notificationMinRisk}
                  onChange={(event) => setNotificationMinRisk(Number(event.target.value) || 55)}
                />
              </label>
              <label>{tr('Event retention (days)', 'イベント保持期間（日）')}
                <input type="number" min={1} max={3650} value={eventRetentionDays} onChange={(event) => setEventRetentionDays(Number(event.target.value) || 14)} />
              </label>
              <button type="button" onClick={saveNotificationSettings}>{tr('Save Notification', '通知設定を保存')}</button>
              <button type="button" onClick={saveEventRetention}>{tr('Save Retention', '保持期間を保存')}</button>
              <button type="button" onClick={() => downloadAuditReport('json')}>{tr('Open Audit JSON', '監査JSONを開く')}</button>
              <button type="button" onClick={() => downloadAuditReport('csv')}>{tr('Download Audit CSV', '監査CSVをDL')}</button>
            </div>
          </section>

          <section className="card">
            <h2>{tr('Alerts', 'アラート')}</h2>
            <table className="table">
              <thead><tr><th>{tr('Time', '時刻')}</th><th>{tr('Severity', '重大度')}</th><th>{tr('Risk', 'リスク')}</th><th>{tr('Status', '状態')}</th><th>{tr('Message', 'メッセージ')}</th><th>{tr('Action', '操作')}</th></tr></thead>
              <tbody>
                {alerts.length === 0 ? <tr><td colSpan={6}>{tr('No alerts', 'アラートはありません')}</td></tr> : alerts.map((alert) => (
                  <tr key={alert.id}>
                    <td>{new Date(alert.created_at).toLocaleString(uiLocale)}</td>
                    <td>{alert.severity}</td>
                    <td>{alert.risk_score ?? '-'}</td>
                    <td>{alert.status}</td>
                    <td>{alert.message}</td>
                    <td>
                      <button type="button" onClick={() => void updateAlertStatus(alert.id, 'acknowledged')}>{tr('Acknowledge', '確認済みにする')}</button>
                      <button type="button" onClick={() => void updateAlertStatus(alert.id, 'resolved')}>{tr('Resolve', '解決済みにする')}</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>

          <section className="card">
            <h2>{tr('Topology Diff Events', 'トポロジ差分イベント')}</h2>
            <div className="table-toolbar">
              <button type="button" onClick={() => setSelectedDiffIds(allDiffIds)}>{tr('Select All', '全選択')}</button>
              <button type="button" onClick={() => setSelectedDiffIds([])}>{tr('Clear Select', '選択解除')}</button>
              <button type="button" onClick={deleteSelectedDiffs} disabled={selectedDiffIds.length === 0}>{tr('Delete Selected', '選択削除')} ({selectedDiffIds.length})</button>
              <button type="button" className="danger-button" onClick={() => void clearPacketData('diffs')}>{tr('Clear All Diffs', '差分を全削除')}</button>
            </div>
            <table className="table">
              <thead><tr><th>{tr('Select', '選択')}</th><th>{tr('Time', '時刻')}</th><th>{tr('Severity', '重大度')}</th><th>{tr('Risk', 'リスク')}</th><th>{tr('Status', '状態')}</th><th>{tr('Message', 'メッセージ')}</th><th>{tr('Action', '操作')}</th></tr></thead>
              <tbody>
                {diffs.length === 0 ? <tr><td colSpan={7}>{tr('No diff events', '差分イベントはありません')}</td></tr> : diffs.map((diff) => (
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
                    <td>{new Date(diff.created_at).toLocaleString(uiLocale)}</td>
                    <td>{diff.severity ?? 'low'}</td>
                    <td>{diff.risk_score ?? 0}</td>
                    <td>{diff.triage_status ?? 'open'}</td>
                    <td>{diff.message}</td>
                    <td>
                      {typeof diff.id === 'number' ? (
                        <>
                          <button type="button" onClick={() => void updateDiffTriage(diff.id as number, 'acknowledged')}>{tr('Ack', '確認')}</button>
                          <button type="button" onClick={() => void updateDiffTriage(diff.id as number, 'resolved')}>{tr('Resolve', '解決')}</button>
                        </>
                      ) : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        </section>
      ) : null}

      {tab === 'operations' ? (
        <section className="assets-layout">
          <section className="card">
            <h2>{tr('Integration Metrics', '連携メトリクス')}</h2>
            <div className="kpi-grid">
              <div className="kpi-item"><span>{tr('24h Processed', '24h処理件数')}</span><strong>{integrationMetrics?.processed_24h ?? 0}</strong></div>
              <div className="kpi-item"><span>{tr('24h Delivered', '24h配信成功')}</span><strong>{integrationMetrics?.delivered_24h ?? 0}</strong></div>
              <div className="kpi-item"><span>{tr('24h Dead', '24h Dead')}</span><strong>{integrationMetrics?.dead_24h ?? 0}</strong></div>
              <div className="kpi-item"><span>{tr('24h Inbound', '24h取り込み')}</span><strong>{integrationMetrics?.inbound_24h ?? 0}</strong></div>
              <div className="kpi-item"><span>{tr('Success Rate', '成功率')}</span><strong>{(integrationMetrics?.success_rate_24h ?? 0).toFixed(2)}%</strong></div>
              <div className="kpi-item"><span>{tr('Queue Status', 'キュー状態')}</span><strong>{queueStats.map((s) => `${s.status}:${s.count}`).join(' | ') || '-'}</strong></div>
            </div>
            <div className="table-toolbar">
              <button type="button" onClick={() => void loadIntegrationMetrics()}>{tr('Refresh Metrics', 'メトリクス更新')}</button>
            </div>
          </section>

          <section className="card">
            <h2>{tr('SLA Summary', 'SLAサマリー')}</h2>
            <div className="kpi-grid">
              <div className="kpi-item"><span>MTTA</span><strong>{Math.round(slaMttaSeconds / 60)} min</strong></div>
              <div className="kpi-item"><span>MTTR</span><strong>{Math.round(slaMttrSeconds / 60)} min</strong></div>
              <div className="kpi-item"><span>{tr('Open Alerts', '未対応アラート')}</span><strong>{openBySeverityText || '-'}</strong></div>
            </div>
            <div className="table-toolbar">
              <button type="button" onClick={() => void fetchSlaSummary()}>{tr('Refresh SLA', 'SLA更新')}</button>
            </div>
          </section>

          <section className="card">
            <h2>{tr('Integrations', '外部連携')}</h2>
            <div className="form-grid">
              <label>{tr('Name', '名称')}<input value={integrationName} onChange={(event) => setIntegrationName(event.target.value)} /></label>
              <label>{tr('Provider', 'プロバイダ')}<input value={integrationProvider} onChange={(event) => setIntegrationProvider(event.target.value)} /></label>
              <label>URL<input value={integrationUrl} onChange={(event) => setIntegrationUrl(event.target.value)} placeholder="https://..." /></label>
              <label>{tr('Direction', '方向')}
                <select value={integrationDirection} onChange={(event) => setIntegrationDirection(event.target.value as 'outbound' | 'inbound' | 'both')}>
                  <option value="outbound">outbound</option>
                  <option value="inbound">inbound</option>
                  <option value="both">both</option>
                </select>
              </label>
              <label>{tr('API Key (for signed webhook)', 'APIキー（署名Webhook用）')}<input value={integrationApiKey} onChange={(event) => setIntegrationApiKey(event.target.value)} /></label>
              <label>{tr('Inbound Mapping JSON', 'InboundマッピングJSON')}<textarea rows={4} value={integrationInboundMap} onChange={(event) => setIntegrationInboundMap(event.target.value)} /></label>
              <label>{tr('Outbound Mapping JSON', 'OutboundマッピングJSON')}<textarea rows={4} value={integrationOutboundMap} onChange={(event) => setIntegrationOutboundMap(event.target.value)} /></label>
              <button type="button" onClick={() => void createIntegration()}>{tr('Add Integration', '連携追加')}</button>
            </div>
            <table className="table">
              <thead><tr><th>ID</th><th>{tr('Name', '名称')}</th><th>{tr('Direction', '方向')}</th><th>{tr('Status', '状態')}</th><th>{tr('Action', '操作')}</th></tr></thead>
              <tbody>
                {integrations.length === 0 ? <tr><td colSpan={5}>{tr('No integrations', '連携なし')}</td></tr> : integrations.map((item) => (
                  <tr key={item.id}>
                    <td>{item.id}</td>
                    <td>{item.name}</td>
                    <td>{item.direction}</td>
                    <td>{item.last_status || '-'}</td>
                    <td>
                      <button type="button" onClick={() => void testIntegration(item.id)}>{tr('Test', 'テスト')}</button>
                      <button type="button" className="danger-button" onClick={() => void deleteIntegration(item.id)}>{tr('Delete', '削除')}</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>

          <section className="card">
            <h2>{tr('Delivery Queue', '配信キュー')}</h2>
            <div className="table-toolbar">
              <button type="button" onClick={() => void loadIntegrationQueue()}>{tr('Refresh Queue', 'キュー更新')}</button>
              <button type="button" onClick={() => void retryIntegrationQueue(false)}>{tr('Retry Due', '期限到来を再送')}</button>
              <button type="button" onClick={() => void retryIntegrationQueue(true)}>{tr('Retry Dead', 'Deadを再送')}</button>
              <button type="button" onClick={() => void archiveQueue()}>{tr('Archive Old', '古い履歴をアーカイブ')}</button>
            </div>
            <table className="table">
              <thead><tr><th>ID</th><th>{tr('Integration', '連携')}</th><th>{tr('Event', 'イベント')}</th><th>{tr('Status', '状態')}</th><th>{tr('Attempt', '試行')}</th><th>{tr('Error', 'エラー')}</th><th>{tr('Action', '操作')}</th></tr></thead>
              <tbody>
                {queueItems.length === 0 ? <tr><td colSpan={7}>{tr('No queue items', 'キューなし')}</td></tr> : queueItems.slice(0, 200).map((item) => (
                  <tr key={item.id}>
                    <td>{item.id}</td>
                    <td>{item.integration_name || item.integration_id}</td>
                    <td>{item.event_type}</td>
                    <td>{item.status}</td>
                    <td>{item.attempt_count}</td>
                    <td>{item.last_error || '-'}</td>
                    <td>
                      <button type="button" onClick={() => void queueItemAction(item.id, 'retry')}>{tr('Retry', '再送')}</button>
                      <button type="button" onClick={() => void queueItemAction(item.id, 'hold')}>{tr('Hold', '保留')}</button>
                      <button type="button" onClick={() => void queueItemAction(item.id, 'cancel')}>{tr('Cancel', '取消')}</button>
                      <button type="button" onClick={() => void queueItemAction(item.id, 'archive')}>{tr('Archive', 'アーカイブ')}</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>

          <section className="card">
            <h2>{tr('Inbound Events', '取り込みイベント')}</h2>
            <div className="table-toolbar">
              <button type="button" onClick={() => void loadInboundEvents()}>{tr('Refresh Inbound', '取り込み更新')}</button>
            </div>
            <table className="table">
              <thead><tr><th>ID</th><th>{tr('Time', '時刻')}</th><th>{tr('Integration', '連携')}</th><th>{tr('Source', 'ソース')}</th><th>{tr('Type', '種別')}</th><th>{tr('External ID', '外部ID')}</th></tr></thead>
              <tbody>
                {inboundEvents.length === 0 ? <tr><td colSpan={6}>{tr('No inbound events', '取り込みイベントなし')}</td></tr> : inboundEvents.slice(0, 200).map((item) => (
                  <tr key={item.id}>
                    <td>{item.id}</td>
                    <td>{new Date(item.created_at).toLocaleString(uiLocale)}</td>
                    <td>{item.integration_name || item.integration_id}</td>
                    <td>{item.source}</td>
                    <td>{item.event_type}</td>
                    <td>{item.external_id}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>

          <section className="card">
            <h2>{tr('Runbooks', 'Runbook')}</h2>
            <div className="form-grid">
              <label>{tr('Name', '名称')}<input value={runbookName} onChange={(event) => setRunbookName(event.target.value)} /></label>
              <label>{tr('Severity', '重大度')}
                <select value={runbookSeverity} onChange={(event) => setRunbookSeverity(event.target.value as 'low' | 'medium' | 'high' | 'critical')}>
                  <option value="low">low</option>
                  <option value="medium">medium</option>
                  <option value="high">high</option>
                  <option value="critical">critical</option>
                </select>
              </label>
              <label>{tr('Steps', '手順')}<textarea rows={4} value={runbookSteps} onChange={(event) => setRunbookSteps(event.target.value)} /></label>
              <button type="button" onClick={() => void createRunbook()}>{tr('Add Runbook', 'Runbook追加')}</button>
            </div>
            <table className="table">
              <thead><tr><th>ID</th><th>{tr('Name', '名称')}</th><th>{tr('Severity', '重大度')}</th><th>{tr('Escalation', 'エスカレーション')}</th></tr></thead>
              <tbody>
                {runbooks.length === 0 ? <tr><td colSpan={4}>{tr('No runbooks', 'Runbookなし')}</td></tr> : runbooks.map((item) => (
                  <tr key={item.id}>
                    <td>{item.id}</td>
                    <td>{item.name}</td>
                    <td>{item.severity}</td>
                    <td>{item.escalation_minutes} min</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>

          <section className="card">
            <h2>{tr('Escalation Policies', 'エスカレーションポリシー')}</h2>
            <table className="table">
              <thead><tr><th>{tr('Severity', '重大度')}</th><th>{tr('Threshold', '閾値(分)')}</th><th>{tr('Channel', '通知先')}</th><th>{tr('Target', '宛先')}</th></tr></thead>
              <tbody>
                {policies.length === 0 ? <tr><td colSpan={4}>{tr('No policies', 'ポリシーなし')}</td></tr> : policies.map((item) => (
                  <tr key={item.id}>
                    <td>{item.severity}</td>
                    <td>{item.threshold_minutes}</td>
                    <td>{item.channel}</td>
                    <td>{item.target}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>

          <section className="card">
            <h2>{tr('Audit Logs', '監査ログ')}</h2>
            <table className="table">
              <thead><tr><th>{tr('Time', '時刻')}</th><th>{tr('Actor', '実行者')}</th><th>{tr('Action', '操作')}</th><th>{tr('Target', '対象')}</th></tr></thead>
              <tbody>
                {auditLogs.length === 0 ? <tr><td colSpan={4}>{tr('No logs', 'ログなし')}</td></tr> : auditLogs.slice(0, 120).map((item) => (
                  <tr key={item.id}>
                    <td>{new Date(item.created_at).toLocaleString(uiLocale)}</td>
                    <td>{item.actor}</td>
                    <td>{item.action}</td>
                    <td>{item.target}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        </section>
      ) : null}

      {tab === 'onboarding' ? (
        <section className="card onboarding-grid">
          <h2>{tr('Agent Onboarding', 'エージェント導入')}</h2>
          <div className="form-grid">
            <label>{tr('Token TTL (minutes)', 'トークン有効期限（分）')}
              <input type="number" min={1} max={1440} value={ttlMinutes} onChange={(event) => setTtlMinutes(Number(event.target.value) || 30)} />
            </label>
            <button type="button" onClick={issueToken}>{tr('Issue token', 'トークン発行')}</button>
          </div>

          {tokenInfo ? (
            <div className="onboarding-result">
              <label>{tr('Enrollment token', '登録トークン')}<textarea rows={3} readOnly value={tokenInfo.token} /></label>
              <div className="action-row">
                <a href={`${tokenInfo.download.windows}?token=${encodeURIComponent(authToken)}`} target="_blank" rel="noreferrer">{tr('Download Windows bundle', 'Windowsバンドルをダウンロード')}</a>
                <a href={`${tokenInfo.download.linux}?token=${encodeURIComponent(authToken)}`} target="_blank" rel="noreferrer">{tr('Download Linux bundle', 'Linuxバンドルをダウンロード')}</a>
              </div>
              <label>{tr('Config command', '設定コマンド')}<textarea rows={3} readOnly value={configCommand} /></label>
              <label>{tr('Run command', '実行コマンド')}<textarea rows={2} readOnly value={runCommand} /></label>
              <label>{tr('Install service command', 'サービス登録コマンド')}<textarea rows={2} readOnly value={installCommand} /></label>
            </div>
          ) : null}
        </section>
      ) : null}
    </div>
  )
}

export default App
