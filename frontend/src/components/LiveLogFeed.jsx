import { useRef, useEffect, useState } from 'react'
import useStore from '../store/useStore'
import { Terminal, Pause, Play, ChevronDown } from 'lucide-react'
import { formatTime, SEVERITY_COLORS } from '../utils/constants'

const SEV_LABEL = { critical: 'CRIT', high: 'HIGH', medium: 'MED', low: 'LOW', info: 'INFO' }

function LogRow({ log }) {
  const color = SEVERITY_COLORS[log.severity] || '#6b7280'
  return (
    <div
      className="flex items-start gap-3 px-3 py-1 hover:bg-white/5 transition-colors rounded animate-fade-in"
      style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.7rem', borderBottom: '1px solid rgba(31,41,55,0.4)' }}
    >
      <span className="text-gray-500 flex-shrink-0 w-16">{formatTime(log.created_at)}</span>
      <span
        className="flex-shrink-0 w-10 font-bold text-center rounded px-1"
        style={{ color, background: `${color}22`, fontSize: '0.6rem' }}
      >
        {SEV_LABEL[log.severity] || 'INFO'}
      </span>
      <span className="flex-shrink-0 w-20 truncate" style={{ color: '#00d4ff' }}>
        {log.log_source?.replace('_', ' ').toUpperCase()}
      </span>
      <span className="flex-shrink-0 w-28 truncate text-amber-400">{log.hostname || '—'}</span>
      <span className="flex-shrink-0 w-28 truncate" style={{ color: '#a855f7' }}>{log.source_ip || '—'}</span>
      <span className="flex-1 truncate text-gray-300">{log.message || log.raw_log || '—'}</span>
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
      l.source_ip?.includes(filter) ||
      l.hostname?.toLowerCase().includes(filter.toLowerCase())
    return matchSev && matchText
  })

  return (
    <div className="flex flex-col h-full" style={{ maxHeight }}>
      {/* Header */}
      <div
        className="flex items-center justify-between px-4 py-2.5 flex-shrink-0"
        style={{ background: '#0d1117', borderBottom: '1px solid #1f2937' }}
      >
        <div className="flex items-center gap-2">
          <Terminal size={14} color="#00d4ff" />
          <span className="text-xs font-bold text-white">LIVE LOG STREAM</span>
          <div className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse ml-1" />
          <span className="text-xs text-gray-500">{liveLogs.length} events</span>
        </div>
        <div className="flex items-center gap-2">
          <input
            className="cyber-input text-xs"
            placeholder="Filter logs..."
            value={filter}
            onChange={e => setFilter(e.target.value)}
            style={{ width: 160, padding: '3px 10px' }}
          />
          <select
            className="cyber-input text-xs"
            value={severityFilter}
            onChange={e => setSeverityFilter(e.target.value)}
            style={{ padding: '3px 8px' }}
          >
            <option value="">All Severity</option>
            {['critical','high','medium','low','info'].map(s => (
              <option key={s} value={s}>{s.toUpperCase()}</option>
            ))}
          </select>
          <button
            onClick={() => setPaused(p => !p)}
            className={`btn-cyber ${paused ? 'btn-cyber-success' : 'btn-cyber-primary'}`}
            style={{ padding: '3px 10px' }}
          >
            {paused ? <Play size={11} /> : <Pause size={11} />}
            <span>{paused ? 'Resume' : 'Pause'}</span>
          </button>
        </div>
      </div>

      {/* Column headers */}
      <div
        className="flex items-center gap-3 px-3 py-1.5 flex-shrink-0"
        style={{
          background: '#0a0e18',
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: '0.6rem',
          color: '#4b5563',
          letterSpacing: '0.08em',
          borderBottom: '1px solid #1f2937',
        }}
      >
        <span className="w-16">TIME</span>
        <span className="w-10">SEV</span>
        <span className="w-20">SOURCE</span>
        <span className="w-28">HOST</span>
        <span className="w-28">SRC IP</span>
        <span className="flex-1">MESSAGE</span>
      </div>

      {/* Log rows */}
      <div
        ref={containerRef}
        className="flex-1 overflow-y-auto scanline"
        style={{ background: '#030712' }}
      >
        {filtered.length === 0 ? (
          <div className="flex items-center justify-center h-32 text-gray-600 text-xs terminal">
            Waiting for log events...
          </div>
        ) : (
          [...filtered].reverse().map((log, i) => <LogRow key={log._id || i} log={log} />)
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  )
}
