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

// ── Health ────────────────────────────────────────────────────────────────────
export const healthApi = {
  check: () => api.get('/api/health'),
}

export default api
