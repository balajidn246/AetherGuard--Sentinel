export const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  info: '#64748b',
}

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']

export const LOG_SOURCE_LABELS = {
  windows_event: 'Windows Event',
  linux_syslog: 'Linux Syslog',
  firewall: 'Firewall',
  ids_ips: 'IDS/IPS',
  web_server: 'Web Server',
  auth_log: 'Auth Log',
  netflow: 'NetFlow',
  dns: 'DNS',
  endpoint: 'Endpoint',
}

export const INCIDENT_STATUSES = ['open', 'investigating', 'contained', 'resolved', 'closed']

export const STATUS_COLORS = {
  open: '#ef4444',
  investigating: '#f97316',
  contained: '#3b82f6',
  resolved: '#10b981',
  closed: '#64748b',
}

export const ALERT_LIFECYCLE_STATUSES = [
  'NEW',
  'TRIAGING',
  'INVESTIGATING',
  'ESCALATED',
  'CONTAINED',
  'RESOLVED',
  'CLOSED'
]

export const MITRE_TACTICS = {
  'T1046': 'Discovery',
  'T1078': 'Initial Access',
  'T1110': 'Credential Access',
  'T1059': 'Execution',
  'T1055': 'Defense Evasion',
  'T1041': 'Exfiltration',
  'T1071': 'Command & Control',
  'T1190': 'Initial Access',
  'T1486': 'Impact',
  'T1098': 'Persistence',
  'T1134': 'Privilege Escalation',
  'T1027': 'Defense Evasion',
  'T1140': 'Defense Evasion',
  'T1021': 'Lateral Movement',
  'T1210': 'Lateral Movement',
  'T1498': 'Impact',
  'T1566': 'Initial Access',
}

export function formatBytes(bytes) {
  if (!bytes) return '0 B'
  const k = 1000
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`
}

export function formatTime(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

export function formatDateTime(value) {
  if (!value) return '—'

  const normalized = String(value).trim()

  // Handle ClickHouse values such as:
  // 2026-09-07 06:43:02.880
  // by converting them to an ISO-like format.
  const isoValue = normalized.includes(' ') && !normalized.includes('T')
    ? normalized.replace(' ', 'T')
    : normalized

  const d = new Date(isoValue)

  if (Number.isNaN(d.getTime())) {
    return '—'
  }

  return d.toLocaleString('en-US', {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  })
}

export function timeAgo(iso) {
  if (!iso) return '—'
  const diff = Date.now() - new Date(iso).getTime()
  const s = Math.floor(diff / 1000)
  if (s < 60) return `${s}s ago`
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  return `${Math.floor(s / 86400)}d ago`
}

export function severityBadgeClass(severity) {
  return `badge badge-${severity?.toLowerCase() || 'info'}`
}

export function getRiskColor(score) {
  if (score >= 80) return '#ef4444'
  if (score >= 60) return '#f97316'
  if (score >= 40) return '#eab308'
  if (score >= 20) return '#3b82f6'
  return '#10b981'
}
