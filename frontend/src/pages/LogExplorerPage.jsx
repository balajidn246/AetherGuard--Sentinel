import { useState, useEffect, useCallback } from 'react'
import { useSearchParams } from 'react-router-dom'
import { logsApi, reportsApi } from '../services/api'
import EntityChip from '../components/EntityChip'
import {
  Search, Download, RefreshCw, Filter, X, ChevronRight,
  Clock, Server, Globe, Shield, Tag, FileText, Code, Cpu, ExternalLink,
  ChevronLeft, Copy, Check
} from 'lucide-react'
import { formatDateTime, SEVERITY_COLORS, LOG_SOURCE_LABELS, severityBadgeClass } from '../utils/constants'
import { toast } from 'react-toastify'

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']
const LOG_SOURCES = ['windows_event', 'linux_syslog', 'firewall', 'ids_ips', 'web_server', 'auth_log', 'netflow']

export default function LogExplorerPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const initialQuery = searchParams.get('q') || ''

  const [logs, setLogs] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(false)
  const [selectedLog, setSelectedLog] = useState(null)
  const [activeTab, setActiveTab] = useState('summary') // 'summary' | 'ocsf' | 'raw' | 'entities' | 'mitre'
  const [copiedRaw, setCopiedRaw] = useState(false)
  const [page, setPage] = useState(0)
  const limit = 100

  const [filters, setFilters] = useState({
    q: initialQuery,
    severity: '',
    hostname: '',
    source_ip: '',
    event_type: '',
    log_source: ''
  })
  const [appliedFilters, setAppliedFilters] = useState({ q: initialQuery })

  const fetchLogs = useCallback(async (f = appliedFilters, pg = page) => {
    setLoading(true)
    try {
      const params = { limit, skip: pg * limit, ...f }
      Object.keys(params).forEach(k => !params[k] && delete params[k])
      const res = await logsApi.search(params)
      setLogs(res.data.logs || [])
      setTotal(res.data.total || 0)
    } catch (e) {
      console.error('Log search error:', e)
      toast.error('Failed to fetch telemetry from ClickHouse')
    } finally {
      setLoading(false)
    }
  }, [appliedFilters, page])

  useEffect(() => {
    fetchLogs(appliedFilters, page)
  }, [fetchLogs, page, appliedFilters])

  // Sync with searchParams if url changes
  useEffect(() => {
    const qParam = searchParams.get('q')
    if (qParam !== null && qParam !== filters.q) {
      setFilters(prev => ({ ...prev, q: qParam }))
      setAppliedFilters(prev => ({ ...prev, q: qParam }))
      setPage(0)
    }
  }, [searchParams])

  const applySearch = () => {
    setPage(0)
    setAppliedFilters(filters)
    if (filters.q) {
      setSearchParams({ q: filters.q })
    } else {
      setSearchParams({})
    }
  }

  const clearFilters = () => {
    const empty = { q: '', severity: '', hostname: '', source_ip: '', event_type: '', log_source: '' }
    setFilters(empty)
    setAppliedFilters({})
    setSearchParams({})
    setPage(0)
  }

  const copyRawLog = (text) => {
    navigator.clipboard?.writeText(text)
    setCopiedRaw(true)
    toast.info('Raw event copied to clipboard', { autoClose: 1500 })
    setTimeout(() => setCopiedRaw(false), 2000)
  }

  const hasFilters = Object.values(filters).some(Boolean)

  return (
    <div className="flex flex-col h-full gap-3 animate-fade-in relative overflow-hidden">
      {/* Search & Query Control Bar */}
      <div className="soc-card p-3 flex-shrink-0 space-y-2.5">
        <div className="flex items-center gap-2">
          <div className="flex-1 relative">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              className="soc-input w-full pl-9 text-xs"
              placeholder='Query telemetry... (e.g. "failed login", IP:198.51.100.42, hostname:DC01, brute)'
              value={filters.q}
              onChange={e => setFilters(f => ({ ...f, q: e.target.value }))}
              onKeyDown={e => e.key === 'Enter' && applySearch()}
            />
          </div>
          <button className="soc-btn soc-btn-primary" onClick={applySearch}>
            <Search size={12} /> Execute Query
          </button>
          {hasFilters && (
            <button className="soc-btn soc-btn-danger" onClick={clearFilters} title="Clear filters">
              <X size={12} /> Clear
            </button>
          )}
          <button className="soc-btn soc-btn-secondary" onClick={() => fetchLogs()} title="Refresh">
            <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
          </button>
          <a
            href={`${reportsApi.exportLogsCsv()}?token=${localStorage.getItem('ag_token')}`}
            target="_blank"
            rel="noreferrer"
          >
            <button className="soc-btn soc-btn-secondary">
              <Download size={12} /> Export CSV
            </button>
          </a>
        </div>

        {/* Structured Filter Row */}
        <div className="flex items-center gap-2 flex-wrap text-xs">
          <div className="flex items-center gap-1.5 text-slate-500 font-mono text-[11px]">
            <Filter size={12} />
            <span>FILTERS:</span>
          </div>
          <select
            className="soc-input text-xs py-1"
            value={filters.severity}
            onChange={e => {
              setFilters(f => ({ ...f, severity: e.target.value }))
              setAppliedFilters(f => ({ ...f, severity: e.target.value }))
            }}
          >
            <option value="">All Severity</option>
            {SEVERITIES.map(s => <option key={s} value={s}>{s.toUpperCase()}</option>)}
          </select>
          <select
            className="soc-input text-xs py-1"
            value={filters.log_source}
            onChange={e => {
              setFilters(f => ({ ...f, log_source: e.target.value }))
              setAppliedFilters(f => ({ ...f, log_source: e.target.value }))
            }}
          >
            <option value="">All Log Sources</option>
            {LOG_SOURCES.map(s => <option key={s} value={s}>{LOG_SOURCE_LABELS[s] || s}</option>)}
          </select>
          <input
            className="soc-input text-xs py-1 w-32 font-mono"
            placeholder="Hostname..."
            value={filters.hostname}
            onChange={e => setFilters(f => ({ ...f, hostname: e.target.value }))}
            onKeyDown={e => e.key === 'Enter' && applySearch()}
          />
          <input
            className="soc-input text-xs py-1 w-32 font-mono"
            placeholder="Source IP..."
            value={filters.source_ip}
            onChange={e => setFilters(f => ({ ...f, source_ip: e.target.value }))}
            onKeyDown={e => e.key === 'Enter' && applySearch()}
          />

          <span className="text-xs text-slate-400 font-mono ml-auto">
            {total.toLocaleString()} ClickHouse records
          </span>
        </div>
      </div>

      {/* Main Investigation Split Table & Side Inspector */}
      <div className="flex-1 flex gap-3 min-h-0 overflow-hidden">
        {/* Telemetry Table Container */}
        <div className="flex-1 soc-card overflow-hidden flex flex-col min-w-0">
          <div className="overflow-auto flex-1">
            <table className="soc-table">
              <thead className="sticky top-0 z-10">
                <tr>
                  <th className="w-40">Timestamp</th>
                  <th className="w-20">Severity</th>
                  <th className="w-28">Log Source</th>
                  <th className="w-32">Hostname</th>
                  <th className="w-36">Source IP</th>
                  <th className="w-28">Event Type</th>
                  <th>Message / Telemetry Snippet</th>
                  <th className="w-28">MITRE</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr>
                    <td colSpan={8} className="text-center py-16 text-slate-500 font-mono text-xs">
                      Querying ClickHouse events...
                    </td>
                  </tr>
                ) : logs.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="text-center py-16 text-slate-500 font-mono text-xs">
                      No events match query criteria in ClickHouse buffer
                    </td>
                  </tr>
                ) : (
                  logs.map((log, i) => {
                    const isSelected = selectedLog?.id === log.id || selectedLog?._id === log._id
                    return (
                      <tr
                        key={log.id || log._id || i}
                        onClick={() => setSelectedLog(log)}
                        className={`cursor-pointer transition-colors ${
                          isSelected ? 'bg-sky-950/40 border-l-2 border-sky-400' : ''
                        }`}
                      >
                        <td className="font-mono text-[11px] text-slate-400 whitespace-nowrap">
                          {formatDateTime(log.time || log.created_at || log.timestamp)}
                        </td>
                        <td>
                          <span className={severityBadgeClass(log.severity)}>{log.severity}</span>
                        </td>
                        <td className="text-xs text-sky-400 truncate">
                          {LOG_SOURCE_LABELS[log.log_source] || log.log_source || 'OCSF'}
                        </td>
                        <td>
                          <EntityChip type="host" value={log.hostname || log.host_name} />
                        </td>
                        <td>
                          <EntityChip type="ip" value={log.source_ip || log.src_ip} />
                        </td>
                        <td className="text-xs text-slate-400 font-mono truncate">
                          {log.event_type || log.class_name || 'event'}
                        </td>
                        <td className="text-xs text-slate-300 max-w-md">
                          <div className="truncate font-sans">{log.message || log.raw_log || log.raw_data || '—'}</div>
                        </td>
                        <td>
                          <div className="flex flex-wrap gap-1">
                            {(log.mitre_techniques || []).slice(0, 1).map(t => (
                              <span
                                key={t}
                                className="text-[10px] font-mono px-1 py-0.5 rounded bg-slate-800 text-amber-300 border border-slate-700"
                              >
                                {t}
                              </span>
                            ))}
                          </div>
                        </td>
                      </tr>
                    )
                  })
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination Footer */}
          <div className="flex items-center justify-between px-3 py-2 border-t border-slate-800 bg-slate-950/60 flex-shrink-0 text-xs">
            <span className="text-slate-400 font-mono text-[11px]">
              Page {page + 1} • Rows {page * limit + 1}–{Math.min((page + 1) * limit, total)} of {total.toLocaleString()}
            </span>
            <div className="flex items-center gap-1.5">
              <button
                className="soc-btn soc-btn-secondary text-xs py-1 px-2.5"
                onClick={() => setPage(p => Math.max(0, p - 1))}
                disabled={page === 0}
              >
                <ChevronLeft size={12} /> Prev
              </button>
              <button
                className="soc-btn soc-btn-secondary text-xs py-1 px-2.5"
                onClick={() => setPage(p => p + 1)}
                disabled={(page + 1) * limit >= total}
              >
                Next <ChevronRight size={12} />
              </button>
            </div>
          </div>
        </div>

        {/* Sliding Contextual Side Inspector */}
        {selectedLog && (
          <div className="w-[440px] soc-card flex flex-col flex-shrink-0 overflow-hidden animate-fade-in border-l border-slate-800">
            {/* Inspector Header */}
            <div className="p-3 border-b border-slate-800 bg-slate-950 flex items-center justify-between flex-shrink-0">
              <div className="flex items-center gap-2">
                <FileText size={14} className="text-sky-400" />
                <span className="text-xs font-bold text-slate-100 uppercase tracking-wider">Event Inspector</span>
              </div>
              <button
                onClick={() => setSelectedLog(null)}
                className="p-1 text-slate-400 hover:text-white rounded"
                title="Close Inspector"
              >
                <X size={14} />
              </button>
            </div>

            {/* Tab Navigation */}
            <div className="flex border-b border-slate-800 bg-slate-900/80 px-2 text-[11px] font-medium text-slate-400">
              {[
                { id: 'summary', label: 'Summary' },
                { id: 'ocsf', label: 'Normalized OCSF' },
                { id: 'raw', label: 'Raw Log' },
                { id: 'entities', label: 'Entities' },
                { id: 'mitre', label: 'MITRE ATT&CK' },
              ].map(tab => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`px-2.5 py-2 border-b-2 transition-colors ${
                    activeTab === tab.id
                      ? 'border-sky-400 text-sky-300 font-semibold'
                      : 'border-transparent hover:text-slate-200'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            {/* Tab Body */}
            <div className="flex-1 overflow-y-auto p-3 text-xs space-y-3">
              {/* Tab 1: Summary */}
              {activeTab === 'summary' && (
                <div className="space-y-3">
                  <div className="p-2.5 rounded bg-slate-900 border border-slate-800 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] uppercase font-mono text-slate-500">Event Class</span>
                      <span className={severityBadgeClass(selectedLog.severity)}>{selectedLog.severity}</span>
                    </div>
                    <div className="text-sm font-semibold text-slate-100">
                      {selectedLog.event_type || selectedLog.class_name || 'Security Event'}
                    </div>
                    <div className="text-[11px] font-mono text-slate-400">
                      {formatDateTime(selectedLog.time || selectedLog.created_at || selectedLog.timestamp)}
                    </div>
                  </div>

                  <div>
                    <div className="text-[11px] font-semibold text-slate-400 mb-1">Message Content</div>
                    <div className="p-2.5 rounded bg-slate-950 border border-slate-800 text-slate-200 font-mono text-[11px] leading-relaxed break-all">
                      {selectedLog.message || selectedLog.raw_data || '—'}
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div className="p-2 rounded bg-slate-900 border border-slate-800">
                      <span className="text-[10px] text-slate-500 block">Source IP</span>
                      <EntityChip type="ip" value={selectedLog.source_ip || selectedLog.src_ip} />
                    </div>
                    <div className="p-2 rounded bg-slate-900 border border-slate-800">
                      <span className="text-[10px] text-slate-500 block">Destination IP</span>
                      <EntityChip type="ip" value={selectedLog.dest_ip || selectedLog.dst_ip} />
                    </div>
                    <div className="p-2 rounded bg-slate-900 border border-slate-800">
                      <span className="text-[10px] text-slate-500 block">Host Name</span>
                      <EntityChip type="host" value={selectedLog.hostname || selectedLog.host_name} />
                    </div>
                    <div className="p-2 rounded bg-slate-900 border border-slate-800">
                      <span className="text-[10px] text-slate-500 block">User Name</span>
                      <EntityChip type="user" value={selectedLog.username || selectedLog.user_name} />
                    </div>
                  </div>
                </div>
              )}

              {/* Tab 2: Normalized OCSF */}
              {activeTab === 'ocsf' && (
                <div className="space-y-1 font-mono text-[11px]">
                  {Object.entries(selectedLog)
                    .filter(([k]) => !['_id', 'raw_data', 'raw_log'].includes(k))
                    .map(([k, v]) => (
                      <div key={k} className="p-1.5 rounded bg-slate-900/60 border border-slate-800/80 flex items-start gap-2">
                        <span className="text-slate-400 w-32 flex-shrink-0 truncate">{k}:</span>
                        <span className="text-slate-200 flex-1 break-all">
                          {Array.isArray(v) ? v.join(', ') : String(v ?? '—')}
                        </span>
                      </div>
                    ))}
                </div>
              )}

              {/* Tab 3: Raw Log */}
              {activeTab === 'raw' && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-[11px] text-slate-400">
                    <span>Original Telemetry String</span>
                    <button
                      onClick={() => copyRawLog(selectedLog.raw_data || selectedLog.raw_log || selectedLog.message || '')}
                      className="soc-btn soc-btn-secondary text-[10px] py-0.5 px-2"
                    >
                      {copiedRaw ? <Check size={10} className="text-emerald-400" /> : <Copy size={10} />}
                      <span>{copiedRaw ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                  <pre className="p-2.5 rounded bg-slate-950 border border-slate-800 text-slate-200 font-mono text-[11px] whitespace-pre-wrap break-all leading-relaxed max-h-96 overflow-y-auto">
                    {selectedLog.raw_data || selectedLog.raw_log || selectedLog.message || JSON.stringify(selectedLog, null, 2)}
                  </pre>
                </div>
              )}

              {/* Tab 4: Entities */}
              {activeTab === 'entities' && (
                <div className="space-y-2.5">
                  <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                    <div className="text-[11px] font-semibold text-slate-300 mb-2 flex items-center gap-1.5">
                      <Globe size={13} className="text-indigo-400" />
                      <span>Network Identifiers</span>
                    </div>
                    <div className="space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-slate-500">Source:</span>
                        <EntityChip type="ip" value={selectedLog.source_ip || selectedLog.src_ip} />
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-slate-500">Destination:</span>
                        <EntityChip type="ip" value={selectedLog.dest_ip || selectedLog.dst_ip} />
                      </div>
                      <div className="flex items-center justify-between text-[11px] font-mono">
                        <span className="text-slate-500">Port Mapping:</span>
                        <span className="text-slate-300">
                          {selectedLog.source_port || selectedLog.src_port || 0} → {selectedLog.dest_port || selectedLog.dst_port || 0}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                    <div className="text-[11px] font-semibold text-slate-300 mb-2 flex items-center gap-1.5">
                      <Server size={13} className="text-amber-400" />
                      <span>Asset & Identity Context</span>
                    </div>
                    <div className="space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-slate-500">Endpoint Host:</span>
                        <EntityChip type="host" value={selectedLog.hostname || selectedLog.host_name} />
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-slate-500">Account Username:</span>
                        <EntityChip type="user" value={selectedLog.username || selectedLog.user_name} />
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Tab 5: MITRE ATT&CK */}
              {activeTab === 'mitre' && (
                <div className="space-y-2">
                  <div className="text-[11px] font-semibold text-slate-400">Associated Techniques</div>
                  {(selectedLog.mitre_techniques || []).length === 0 ? (
                    <div className="p-4 text-center text-slate-500 text-xs">
                      No MITRE techniques mapped to this specific event.
                    </div>
                  ) : (
                    selectedLog.mitre_techniques.map(tech => (
                      <div key={tech} className="p-2.5 rounded bg-slate-900 border border-slate-800 flex items-center justify-between">
                        <span className="font-mono text-amber-300 font-bold text-xs">{tech}</span>
                        <a
                          href={`https://attack.mitre.org/techniques/${tech}/`}
                          target="_blank"
                          rel="noreferrer"
                          className="text-sky-400 hover:text-sky-300 flex items-center gap-1 text-[11px]"
                        >
                          <span>MITRE Reference</span>
                          <ExternalLink size={10} />
                        </a>
                      </div>
                    ))
                  )}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
