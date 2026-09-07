import { useState, useRef, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Globe, Server, User, Copy, Check, ExternalLink, ShieldAlert, FileText, Activity } from 'lucide-react'
import { toast } from 'react-toastify'

export default function EntityChip({
  type = 'ip', // 'ip' | 'host' | 'user'
  value,
  className = '',
  showActions = true,
}) {
  const [open, setOpen] = useState(false)
  const [copied, setCopied] = useState(false)
  const menuRef = useRef(null)
  const navigate = useNavigate()

  useEffect(() => {
    function handleClickOutside(e) {
      if (menuRef.current && !menuRef.current.contains(e.target)) {
        setOpen(false)
      }
    }
    if (open) {
      document.addEventListener('mousedown', handleClickOutside)
    }
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [open])

  if (!value || value === '—' || value === 'unknown') {
    return <span className="text-gray-500 font-mono text-xs">—</span>
  }

  const handleCopy = (e) => {
    e.stopPropagation()
    navigator.clipboard?.writeText(value)
    setCopied(true)
    toast.info(`Copied ${value}`, { autoClose: 1500 })
    setTimeout(() => setCopied(false), 2000)
  }

  const pivotLogExplorer = (e) => {
    e.stopPropagation()
    setOpen(false)
    navigate(`/logs?q=${encodeURIComponent(value)}`)
  }

  const pivotThreatIntel = (e) => {
    e.stopPropagation()
    setOpen(false)
    navigate(`/threat-intel?ip=${encodeURIComponent(value)}`)
  }

  const pivotUEBA = (e) => {
    e.stopPropagation()
    setOpen(false)
    navigate(`/ueba?user=${encodeURIComponent(value)}`)
  }

  const pivotSOAR = (e) => {
    e.stopPropagation()
    setOpen(false)
    navigate(`/soar?target=${encodeURIComponent(value)}&type=${type}`)
  }

  const getIcon = () => {
    if (type === 'host') return <Server size={11} className="text-amber-400 flex-shrink-0" />
    if (type === 'user') return <User size={11} className="text-sky-400 flex-shrink-0" />
    return <Globe size={11} className="text-indigo-400 flex-shrink-0" />
  }

  return (
    <div className={`relative inline-block font-mono text-xs ${className}`} ref={menuRef}>
      <button
        type="button"
        onClick={(e) => {
          if (!showActions) return
          e.stopPropagation()
          setOpen(!open)
        }}
        className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded border transition-all select-none
          ${open ? 'border-sky-500 bg-sky-950/30' : 'border-slate-800 hover:border-slate-700 bg-slate-900/80 hover:bg-slate-800/80'}
          text-slate-200 cursor-pointer`}
        title={showActions ? `Pivot on ${value}` : value}
      >
        {getIcon()}
        <span className="truncate max-w-[140px]">{value}</span>
      </button>

      {/* Context Menu Dropdown */}
      {open && (
        <div
          className="absolute left-0 mt-1 w-56 rounded-md shadow-2xl z-50 overflow-hidden text-xs
                     bg-slate-900 border border-slate-700 py-1 divide-y divide-slate-800 animate-fade-in"
          onClick={(e) => e.stopPropagation()}
        >
          <div className="px-3 py-1.5 bg-slate-950/50 flex items-center justify-between">
            <span className="text-[10px] uppercase font-bold text-slate-400">
              Entity: {type}
            </span>
            <button
              onClick={handleCopy}
              className="text-slate-400 hover:text-white flex items-center gap-1 text-[10px]"
              title="Copy to clipboard"
            >
              {copied ? <Check size={10} className="text-emerald-400" /> : <Copy size={10} />}
              {copied ? 'Copied' : 'Copy'}
            </button>
          </div>

          <div className="py-1">
            <button
              onClick={pivotLogExplorer}
              className="w-full text-left px-3 py-1.5 hover:bg-slate-800 text-slate-300 hover:text-white flex items-center gap-2"
            >
              <FileText size={12} className="text-sky-400" />
              <span>Query in Log Explorer</span>
            </button>

            {type === 'ip' && (
              <button
                onClick={pivotThreatIntel}
                className="w-full text-left px-3 py-1.5 hover:bg-slate-800 text-slate-300 hover:text-white flex items-center gap-2"
              >
                <ShieldAlert size={12} className="text-indigo-400" />
                <span>Check Threat Intel</span>
              </button>
            )}

            {type === 'user' && (
              <button
                onClick={pivotUEBA}
                className="w-full text-left px-3 py-1.5 hover:bg-slate-800 text-slate-300 hover:text-white flex items-center gap-2"
              >
                <Activity size={12} className="text-amber-400" />
                <span>View User UEBA Profile</span>
              </button>
            )}

            <button
              onClick={pivotSOAR}
              className="w-full text-left px-3 py-1.5 hover:bg-slate-800 text-rose-300 hover:text-rose-200 flex items-center gap-2"
            >
              <ShieldAlert size={12} className="text-rose-400" />
              <span>Trigger SOAR Playbook</span>
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
