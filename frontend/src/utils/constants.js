export const SEVERITY_COLORS = {
  critical: '#ff3366',
  high: '#ff6b35',
  medium: '#ffaa00',
  low: '#3b82f6',
  info: '#6b7280',
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
  open: '#ff3366',
  investigating: '#ffaa00',
  contained: '#3b82f6',
  resolved: '#00ff88',
  closed: '#6b7280',
}

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

export function formatDateTime(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  return d.toLocaleString('en-US', {
    month: 'short', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
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
  if (score >= 80) return '#ff3366'
  if (score >= 60) return '#ff6b35'
  if (score >= 40) return '#ffaa00'
  if (score >= 20) return '#3b82f6'
  return '#6b7280'
}
