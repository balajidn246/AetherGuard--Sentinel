import axios from 'axios'

const BASE_URL = 'http://localhost:8000'

const api = axios.create({
  baseURL: BASE_URL,
  timeout: 30000,
})

// Attach JWT token automatically
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('ag_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

// Handle 401 globally
api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem('ag_token')
      localStorage.removeItem('ag_user')
      window.location.href = '/login'
    }
    return Promise.reject(err)
  }
)

// ── Auth ──────────────────────────────────────────────────────────────────────
export const authApi = {
  login: (username, password) => api.post('/api/auth/login', { username, password }),
  me: () => api.get('/api/auth/me'),
  logout: () => api.post('/api/auth/logout'),
}

// ── Dashboard ────────────────────────────────────────────────────────────────
export const dashboardApi = {
  stats: () => api.get('/api/dashboard/stats'),
  epsHistory: () => api.get('/api/dashboard/eps-history'),
  topAttackers: () => api.get('/api/dashboard/top-attackers'),
  topTargets: () => api.get('/api/dashboard/top-targets'),
  mitreCoverage: () => api.get('/api/dashboard/mitre-coverage'),
  geoAttacks: () => api.get('/api/dashboard/geo-attacks'),
  recentAlerts: () => api.get('/api/dashboard/recent-alerts'),
  severityTimeline: () => api.get('/api/dashboard/severity-timeline'),
}

// ── Logs ──────────────────────────────────────────────────────────────────────
export const logsApi = {
  search: (params) => api.get('/api/logs/search', { params }),
  stats: () => api.get('/api/logs/stats'),
  live: (limit = 50) => api.get('/api/logs/live', { params: { limit } }),
  sources: () => api.get('/api/logs/sources'),
}

// ── Alerts ────────────────────────────────────────────────────────────────────
export const alertsApi = {
  list: (params) => api.get('/api/alerts/', { params }),
  get: (id) => api.get(`/api/alerts/${id}`),
  acknowledge: (id, notes = '') => api.post(`/api/alerts/${id}/acknowledge`, { notes }),
  escalate: (id) => api.post(`/api/alerts/${id}/escalate`),
  summary: () => api.get('/api/alerts/stats/summary'),
}

// ── Incidents ────────────────────────────────────────────────────────────────
export const incidentsApi = {
  list: (params) => api.get('/api/incidents/', { params }),
  get: (id) => api.get(`/api/incidents/${id}`),
  create: (data) => api.post('/api/incidents/', data),
  update: (id, data) => api.put(`/api/incidents/${id}`, data),
  transition: (id, status) => api.post(`/api/incidents/${id}/transition`, null, { params: { new_status: status } }),
  addNote: (id, content) => api.post(`/api/incidents/${id}/notes`, { content }),
  stats: () => api.get('/api/incidents/stats'),
}

// ── Threat Intel ─────────────────────────────────────────────────────────────
export const threatIntelApi = {
  iocs: (params) => api.get('/api/threat-intel/iocs', { params }),
  createIoc: (data) => api.post('/api/threat-intel/iocs', data),
  deleteIoc: (id) => api.delete(`/api/threat-intel/iocs/${id}`),
  ipReputation: (ip) => api.get(`/api/threat-intel/ip-reputation/${ip}`),
  checkHash: (hash) => api.get(`/api/threat-intel/hash/${hash}`),
  feeds: () => api.get('/api/threat-intel/feeds'),
  blocklist: () => api.get('/api/threat-intel/blocklist'),
  syncFeeds: () => api.post('/api/threat-intel/sync'),
}

// ── Cases ────────────────────────────────────────────────────────────────────
export const casesApi = {
  list: (params) => api.get('/api/cases/', { params }),
  get: (id) => api.get(`/api/cases/${id}`),
  create: (data) => api.post('/api/cases/', data),
  update: (id, data) => api.patch(`/api/cases/${id}`, data),
  addNote: (id, content) => api.post(`/api/cases/${id}/notes`, { content }),
  attachSignal: (id, signalId) => api.post(`/api/cases/${id}/signals`, null, { params: { signal_id: signalId } }),
}

// ── Detection Rules ──────────────────────────────────────────────────────────
export const rulesApi = {
  list: (params) => api.get('/api/rules/', { params }),
  get: (id) => api.get(`/api/rules/${id}`),
  create: (data) => api.post('/api/rules/', data),
  toggle: (id, enabled) => api.patch(`/api/rules/${id}/enable`, { enabled }),
  test: (id, event) => api.post(`/api/rules/${id}/test`, { event }),
}

// ── Audit Logs ───────────────────────────────────────────────────────────────
export const auditApi = {
  list: (params) => api.get('/api/audit/', { params }),
  actions: () => api.get('/api/audit/actions'),
}

// ── Reports ──────────────────────────────────────────────────────────────────
export const reportsApi = {
  exportLogsCsv: () => `${BASE_URL}/api/reports/logs/csv`,
  exportAlertsCsv: () => `${BASE_URL}/api/reports/alerts/csv`,
  exportIncidentsCsv: () => `${BASE_URL}/api/reports/incidents/csv`,
  summary: () => api.get('/api/reports/summary'),
}

// ── UEBA ──────────────────────────────────────────────────────────────────────
export const uebaApi = {
  users: () => api.get('/api/ueba/users'),
  user: (username) => api.get(`/api/ueba/user/${username}`),
}

// ── Signals & AI ─────────────────────────────────────────────────────────────
export const signalsApi = {
  investigate: (id) => api.post(`/api/signals/${id}/investigate`),
  health: () => api.get('/api/signals/ai-health'),
}

// ── Health ────────────────────────────────────────────────────────────────────
export const healthApi = {
  check: () => api.get('/api/health'),
}

// ── Entity Graph ──────────────────────────────────────────────────────────────
export const entityApi = {
  nodes: (params) => api.get('/api/entities/nodes', { params }),
  node: (id) => api.get(`/api/entities/nodes/${id}`),
  nodeGraph: (id, depth = 1) => api.get(`/api/entities/nodes/${id}/graph`, { params: { depth } }),
  relationships: (params) => api.get('/api/entities/relationships', { params }),
  summary: () => api.get('/api/entities/summary'),
  search: (q, limit = 20) => api.get('/api/entities/search', { params: { q, limit } }),
}

// ── SOAR ─────────────────────────────────────────────────────────────────────
export const soarApi = {
  execute: (data) => api.post('/api/soar/execute', data),
  history: () => api.get('/api/soar/history'),
}

export default api


