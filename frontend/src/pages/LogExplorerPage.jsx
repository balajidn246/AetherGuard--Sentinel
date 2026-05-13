import { useState, useEffect, useCallback } from 'react'
import { logsApi } from '../services/api'
import { Search, Download, RefreshCw, Filter, X } from 'lucide-react'
import { formatDateTime, SEVERITY_COLORS, LOG_SOURCE_LABELS, severityBadgeClass } from '../utils/constants'
import { reportsApi } from '../services/api'

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']
const LOG_SOURCES = ['windows_event', 'linux_syslog', 'firewall', 'ids_ips', 'web_server', 'auth_log', 'netflow']

function LogDetailModal({ log, onClose }) {
  if (!log) return null
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ background: 'rgba(0,0,0,0.7)' }}>
      <div className="glass-card w-full max-w-2xl max-h-[80vh] overflow-auto" style={{ border: '1px solid #1f2937' }}>
        <div className="flex items-center justify-between p-4" style={{ borderBottom: '1px solid #1f2937' }}>
          <span className="font-bold text-sm text-white">Log Event Detail</span>
          <button onClick={onClose} className="text-gray-500 hover:text-white"><X size={16} /></button>
        </div>
        <div className="p-4 space-y-3">
          {Object.entries(log).filter(([k]) => !['_id'].includes(k)).map(([k, v]) => (
            <div key={k} className="grid grid-cols-3 gap-2">
              <span className="text-xs text-gray-500 font-mono">{k}</span>
              <span className="col-span-2 text-xs text-gray-200 font-mono break-all">
                {Array.isArray(v) ? v.join(', ') : String(v ?? '—')}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

export default function LogExplorerPage() {
  const [logs, setLogs] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(false)
  const [selectedLog, setSelectedLog] = useState(null)
  const [page, setPage] = useState(0)
  const limit = 100

  const [filters, setFilters] = useState({
    q: '', severity: '', hostname: '', source_ip: '', event_type: '', log_source: ''
  })
  const [appliedFilters, setAppliedFilters] = useState({})

  const fetchLogs = useCallback(async (f = appliedFilters, pg = page) => {
    setLoading(true)
    try {
      const params = { limit, skip: pg * limit, ...f }
      Object.keys(params).forEach(k => !params[k] && delete params[k])
      const res = await logsApi.search(params)
      setLogs(res.data.logs)
      setTotal(res.data.total)
    } catch (e) { console.error(e) }
    finally { setLoading(false) }
  }, [appliedFilters, page])

  useEffect(() => { fetchLogs() }, [page])

  const applySearch = () => {
    setPage(0)
    setAppliedFilters(filters)
    fetchLogs(filters, 0)
  }

  const clearFilters = () => {
    const empty = { q: '', severity: '', hostname: '', source_ip: '', event_type: '', log_source: '' }
    setFilters(empty)
    setAppliedFilters({})
    fetchLogs({}, 0)
  }

  const hasFilters = Object.values(filters).some(Boolean)

  return (
    <div className="flex flex-col h-full gap-4 animate-fade-in">
      {/* Search Bar */}
      <div className="glass-card p-4 flex-shrink-0">
        <div className="flex items-center gap-3 mb-3">
          <div className="flex-1 relative">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
            <input
              className="cyber-input w-full pl-9"
              placeholder='Search logs... (keyword, IP, hostname, message)'
              value={filters.q}
              onChange={e => setFilters(f => ({ ...f, q: e.target.value }))}
              onKeyDown={e => e.key === 'Enter' && applySearch()}
            />
          </div>
          <button className="btn-cyber btn-cyber-primary" onClick={applySearch}>
            <Search size={12} /> Search
          </button>
          {hasFilters && (
            <button className="btn-cyber btn-cyber-danger" onClick={clearFilters}>
              <X size={12} /> Clear
            </button>
          )}
          <button className="btn-cyber btn-cyber-primary" onClick={() => fetchLogs()}>
            <RefreshCw size={12} /> Refresh
          </button>
          <a
            href={`${reportsApi.exportLogsCsv()}?token=${localStorage.getItem('ag_token')}`}
            target="_blank" rel="noreferrer"
          >
            <button className="btn-cyber btn-cyber-success">
              <Download size={12} /> Export CSV
            </button>
          </a>
        </div>

        {/* Filter Row */}
        <div className="flex items-center gap-2 flex-wrap">
          <Filter size={12} className="text-gray-500" />
          <select className="cyber-input text-xs" value={filters.severity} onChange={e => setFilters(f => ({ ...f, severity: e.target.value }))}>
            <option value="">All Severity</option>
            {SEVERITIES.map(s => <option key={s} value={s}>{s.toUpperCase()}</option>)}
          </select>
          <select className="cyber-input text-xs" value={filters.log_source} onChange={e => setFilters(f => ({ ...f, log_source: e.target.value }))}>
            <option value="">All Sources</option>
            {LOG_SOURCES.map(s => <option key={s} value={s}>{LOG_SOURCE_LABELS[s] || s}</option>)}
          </select>
          <input className="cyber-input text-xs" placeholder="Hostname" value={filters.hostname}
            onChange={e => setFilters(f => ({ ...f, hostname: e.target.value }))} style={{ width: 130 }} />
          <input className="cyber-input text-xs" placeholder="Source IP" value={filters.source_ip}
            onChange={e => setFilters(f => ({ ...f, source_ip: e.target.value }))} style={{ width: 130 }} />
          <span className="text-xs text-gray-500 ml-auto">{total.toLocaleString()} results</span>
        </div>
      </div>

      {/* Table */}
      <div className="flex-1 glass-card overflow-hidden flex flex-col">
        <div className="overflow-auto flex-1">
          <table className="cyber-table">
            <thead className="sticky top-0 z-10">
              <tr>
                <th>Time</th>
                <th>Severity</th>
                <th>Source</th>
                <th>Hostname</th>
                <th>Source IP</th>
                <th>Event Type</th>
                <th className="w-1/3">Message</th>
                <th>MITRE</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={8} className="text-center py-12 text-gray-500">Loading logs...</td></tr>
              ) : logs.length === 0 ? (
                <tr><td colSpan={8} className="text-center py-12 text-gray-600">No logs found</td></tr>
              ) : logs.map((log, i) => (
                <tr
                  key={log._id || i}
                  onClick={() => setSelectedLog(log)}
                  className="cursor-pointer"
                >
                  <td className="font-mono text-xs text-gray-400 whitespace-nowrap">{formatDateTime(log.created_at)}</td>
                  <td><span className={severityBadgeClass(log.severity)}>{log.severity}</span></td>
                  <td className="text-xs" style={{ color: '#00d4ff' }}>{LOG_SOURCE_LABELS[log.log_source] || log.log_source}</td>
                  <td className="font-mono text-xs text-amber-400">{log.hostname || '—'}</td>
                  <td className="font-mono text-xs" style={{ color: '#a855f7' }}>{log.source_ip || '—'}</td>
                  <td className="text-xs text-gray-400">{log.event_type?.replace(/_/g, ' ')}</td>
                  <td className="text-xs text-gray-300 max-w-xs">
                    <div className="truncate">{log.message || log.raw_log || '—'}</div>
                  </td>
                  <td>
                    <div className="flex flex-wrap gap-0.5">
                      {(log.mitre_techniques || []).slice(0, 2).map(t => (
                        <span key={t} className="text-xs px-1.5 rounded font-mono"
                          style={{ background: '#1f2937', color: '#ffaa00', fontSize: '0.6rem' }}>
                          {t}
                        </span>
                      ))}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div className="flex items-center justify-between px-4 py-2 flex-shrink-0" style={{ borderTop: '1px solid #1f2937' }}>
          <span className="text-xs text-gray-500">
            Page {page + 1} — {Math.min((page + 1) * limit, total).toLocaleString()} of {total.toLocaleString()} events
          </span>
          <div className="flex gap-2">
            <button className="btn-cyber btn-cyber-primary" onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0}>
              ← Prev
            </button>
            <button className="btn-cyber btn-cyber-primary" onClick={() => setPage(p => p + 1)} disabled={(page + 1) * limit >= total}>
              Next →
            </button>
          </div>
        </div>
      </div>

      {selectedLog && <LogDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} />}
    </div>
  )
}
