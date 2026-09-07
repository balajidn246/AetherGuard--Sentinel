import { useRef, useEffect, useState } from 'react'
import useStore from '../store/useStore'
import { Terminal, Pause, Play, ChevronDown } from 'lucide-react'
import { formatTime, SEVERITY_COLORS } from '../utils/constants'

const SEV_LABEL = { critical: 'CRIT', high: 'HIGH', medium: 'MED', low: 'LOW', info: 'INFO' }

function LogRow({ log }) {
  const color = SEVERITY_COLORS[log.severity] || '#64748b'
  return (
    <div
      className="flex items-start gap-3 px-3 py-1 hover:bg-slate-800/40 transition-colors font-mono text-[11px] border-b border-slate-900/60"
    >
      <span className="text-slate-500 flex-shrink-0 w-16">{formatTime(log.created_at || log.time)}</span>
      <span
        className="flex-shrink-0 w-10 font-bold text-center rounded px-1 text-[10px]"
        style={{ color, background: `${color}18`, border: `1px solid ${color}33` }}
      >
        {SEV_LABEL[log.severity] || 'INFO'}
      </span>
      <span className="flex-shrink-0 w-24 truncate text-sky-400 font-sans text-xs">
        {log.log_source?.replace('_', ' ').toUpperCase() || 'TELEMETRY'}
      </span>
      <span className="flex-shrink-0 w-28 truncate text-amber-300/90">{log.hostname || '—'}</span>
      <span className="flex-shrink-0 w-28 truncate text-indigo-300">{log.source_ip || log.src_ip || '—'}</span>
      <span className="flex-1 truncate text-slate-300">{log.message || log.raw_log || '—'}</span>
    </div>
  )
}

export default function LiveLogFeed({ maxHeight = '100%' }) {
  const liveLogs = useStore(s => s.liveLogs)
  const bottomRef = useRef(null)
  const containerRef = useRef(null)
  const [paused, setPaused] = useState(false)
  const [filter, setFilter] = useState('')
  const [severityFilter, setSeverityFilter] = useState('')

  // Auto-scroll to bottom unless paused
  useEffect(() => {
    if (!paused && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [liveLogs, paused])

  const filtered = liveLogs.filter(l => {
    const matchSev = !severityFilter || l.severity === severityFilter
    const matchText = !filter ||
      l.message?.toLowerCase().includes(filter.toLowerCase()) ||
      (l.source_ip || l.src_ip)?.includes(filter) ||
      l.hostname?.toLowerCase().includes(filter.toLowerCase())
    return matchSev && matchText
  })

  return (
    <div className="flex flex-col h-full bg-slate-950 border border-slate-800 rounded-lg overflow-hidden" style={{ maxHeight }}>
      {/* Header */}
      <div
        className="flex items-center justify-between px-3 py-2 border-b border-slate-800 bg-slate-900/90 flex-shrink-0"
      >
        <div className="flex items-center gap-2">
          <Terminal size={13} className="text-sky-400" />
          <span className="text-xs font-bold text-slate-200 uppercase tracking-wider">Live Telemetry Ingestion</span>
          <div className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse ml-1" />
          <span className="text-[11px] font-mono text-slate-400">({liveLogs.length} buffered)</span>
        </div>
        <div className="flex items-center gap-2">
          <input
            className="soc-input text-xs py-0.5 px-2 bg-slate-950"
            placeholder="Filter stream..."
            value={filter}
            onChange={e => setFilter(e.target.value)}
            style={{ width: 140 }}
          />
          <select
            className="soc-input text-xs py-0.5 px-2 bg-slate-950"
            value={severityFilter}
            onChange={e => setSeverityFilter(e.target.value)}
          >
            <option value="">All Severity</option>
            {['critical','high','medium','low','info'].map(s => (
              <option key={s} value={s}>{s.toUpperCase()}</option>
            ))}
          </select>
          <button
            onClick={() => setPaused(p => !p)}
            className={`soc-btn text-xs py-1 px-2.5 ${paused ? 'soc-btn-success' : 'soc-btn-secondary'}`}
          >
            {paused ? <Play size={11} /> : <Pause size={11} />}
            <span>{paused ? 'Resume' : 'Pause'}</span>
          </button>
        </div>
      </div>

      {/* Column headers */}
      <div
        className="flex items-center gap-3 px-3 py-1.5 flex-shrink-0 bg-slate-950/80 font-mono text-[10px] text-slate-500 font-semibold border-b border-slate-800/80 tracking-wider"
      >
        <span className="w-16">TIME</span>
        <span className="w-10">SEV</span>
        <span className="w-24">SOURCE</span>
        <span className="w-28">HOSTNAME</span>
        <span className="w-28">SRC IP</span>
        <span className="flex-1">MESSAGE / RAW TELEMETRY</span>
      </div>

      {/* Log rows */}
      <div
        ref={containerRef}
        className="flex-1 overflow-y-auto bg-slate-950/60 divide-y divide-slate-900/40"
      >
        {filtered.length === 0 ? (
          <div className="flex items-center justify-center h-24 text-slate-600 text-xs font-mono">
            Awaiting streaming events from ClickHouse / Syslog...
          </div>
        ) : (
          [...filtered].reverse().map((log, i) => <LogRow key={log._id || i} log={log} />)
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  )
}
