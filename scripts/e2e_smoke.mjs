const REGISTRY_HTTP_URL = process.env.REGISTRY_HTTP_URL ?? 'http://localhost:8780'
const FRONTEND_URL = process.env.FRONTEND_URL ?? 'http://localhost:5173'

const ADMIN_USERNAME = process.env.ADMIN_USERNAME ?? 'admin'
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD ?? ''
const ADMIN_PASSWORD_NEW = process.env.ADMIN_PASSWORD_NEW ?? 'RegressionAdminChanged#2026'

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

async function fetchJson(url, init = {}, timeoutMs = 5000) {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const res = await fetch(url, { ...init, signal: controller.signal })
    const text = await res.text()
    let json
    try {
      json = text ? JSON.parse(text) : null
    } catch {
      json = null
    }
    return { res, json, text }
  } finally {
    clearTimeout(timeout)
  }
}

async function waitForHealth({ attempts = 60, delayMs = 1000 } = {}) {
  const url = `${REGISTRY_HTTP_URL}/api/health`
  for (let i = 0; i < attempts; i++) {
    try {
      const { res, json } = await fetchJson(url, {}, 2000)
      if (res.ok && json?.status === 'ok') return
    } catch {
      // ignore
    }
    await sleep(delayMs)
  }
  throw new Error(`Registry health check failed: ${url}`)
}

async function smokeFrontend() {
  const res = await fetch(FRONTEND_URL, { redirect: 'follow' })
  if (!res.ok) throw new Error(`Frontend not reachable: ${FRONTEND_URL} status=${res.status}`)
}

async function login(password) {
  const { res, json, text } = await fetchJson(
    `${REGISTRY_HTTP_URL}/api/auth/login`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: ADMIN_USERNAME, password }),
    },
    5000,
  )
  if (!res.ok) {
    throw new Error(`Login failed status=${res.status} body=${text.slice(0, 500)}`)
  }
  if (!json?.token) throw new Error('Login response missing token')
  return json
}

async function changePassword(token, currentPassword, newPassword) {
  const { res, json, text } = await fetchJson(
    `${REGISTRY_HTTP_URL}/api/auth/change-password`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    },
    5000,
  )
  if (!res.ok) throw new Error(`Change-password failed status=${res.status} body=${text.slice(0, 500)}`)
  if (json?.ok === true) return
  if (json?.status === 'password_changed_relogin_required') return
  throw new Error(`Change-password response not ok: ${text.slice(0, 500)}`)
}

async function getSnapshot(token) {
  const { res, json, text } = await fetchJson(
    `${REGISTRY_HTTP_URL}/api/topology/snapshot`,
    { headers: { Authorization: `Bearer ${token}` } },
    5000,
  )
  if (!res.ok) throw new Error(`Snapshot failed status=${res.status} body=${text.slice(0, 500)}`)
  if (!json || !Array.isArray(json.agents) || !Array.isArray(json.connections)) {
    throw new Error('Snapshot missing agents/connections')
  }
  return json
}

async function issueEnrollmentToken(token) {
  const { res, json, text } = await fetchJson(
    `${REGISTRY_HTTP_URL}/api/tokens`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ ttl_minutes: 5 }),
    },
    5000,
  )
  if (!res.ok) throw new Error(`Issue token failed status=${res.status} body=${text.slice(0, 500)}`)
  if (!json?.token) throw new Error('Issue token response missing token')
  return json.token
}

async function registerAgent(enrollmentToken) {
  const { res, json, text } = await fetchJson(
    `${REGISTRY_HTTP_URL}/api/register`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token: enrollmentToken,
        agent_name: 'ci-smoke-agent',
        hostname: 'ci-host',
        platform: 'linux',
      }),
    },
    5000,
  )
  if (!res.ok) throw new Error(`Register agent failed status=${res.status} body=${text.slice(0, 500)}`)
  if (!json?.agent_id || !json?.upstream_url) throw new Error('Register response missing agent_id/upstream_url')
  if (!String(json.upstream_url).includes('/ws/agent')) throw new Error('Register response upstream_url looks invalid')
  return json.agent_id
}

async function main() {
  if (!ADMIN_PASSWORD) {
    throw new Error('ADMIN_PASSWORD is required (set to the same value as FLEX_ADMIN_PASSWORD for first startup)')
  }

  await waitForHealth()
  await smokeFrontend()

  let password = ADMIN_PASSWORD
  let auth
  try {
    auth = await login(password)
  } catch (err) {
    // On reruns, the admin password may have already been rotated.
    password = ADMIN_PASSWORD_NEW
    auth = await login(password)
  }

  if (auth.must_change_password) {
    await changePassword(auth.token, password, ADMIN_PASSWORD_NEW)
    password = ADMIN_PASSWORD_NEW
    auth = await login(password)
  }

  await getSnapshot(auth.token)
  const enrollmentToken = await issueEnrollmentToken(auth.token)
  const agentId = await registerAgent(enrollmentToken)
  const snapshotAfter = await getSnapshot(auth.token)

  const found = snapshotAfter.agents.some((a) => a?.agent_id === agentId)
  if (!found) throw new Error('Registered agent not found in snapshot')

  process.stdout.write('E2E smoke OK\n')
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
