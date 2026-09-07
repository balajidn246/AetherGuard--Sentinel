import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Search, LayoutDashboard, FileText, Bell, AlertTriangle, Shield,
  Users, BarChart3, Settings, FolderGit2, ShieldCheck, History,
  Zap, ArrowRight, CornerDownLeft, ExternalLink, X
} from 'lucide-react'

const STATIC_ROUTES = [
  { id: 'dash', title: 'Command Center', subtitle: 'Live SOC Overview & Telemetry', route: '/dashboard', icon: LayoutDashboard, category: 'Navigation' },
  { id: 'logs', title: 'Log Explorer', subtitle: 'Query and analyze all events in ClickHouse', route: '/logs', icon: FileText, category: 'Navigation' },
  { id: 'alerts', title: 'Security Signals & Alerts', subtitle: 'Active threat alerts and AI investigations', route: '/alerts', icon: Bell, category: 'Navigation' },
  { id: 'cases', title: 'Case Management', subtitle: 'Investigation workflows, notes & evidence', route: '/cases', icon: FolderGit2, category: 'Navigation' },
  { id: 'incidents', title: 'Incident Response', subtitle: 'Incident lifecycle and tracking', route: '/incidents', icon: AlertTriangle, category: 'Navigation' },
  { id: 'rules', title: 'Detection Rules', subtitle: 'Sigma, Python, and YAML detection engine', route: '/rules', icon: ShieldCheck, category: 'Navigation' },
  { id: 'soar', title: 'SOAR Automation', subtitle: 'Containment playbooks with approval gates', route: '/soar', icon: Zap, category: 'Navigation' },
  { id: 'threat-intel', title: 'Threat Intelligence', subtitle: 'IOC lookup, reputation & feeds', route: '/threat-intel', icon: Shield, category: 'Navigation' },
  { id: 'ueba', title: 'UEBA Analytics', subtitle: 'User and entity behavior anomalies', route: '/ueba', icon: Users, category: 'Navigation' },
  { id: 'audit', title: 'Audit Trail', subtitle: 'Immutable compliance and activity history', route: '/audit', icon: History, category: 'Navigation' },
  { id: 'reports', title: 'Reports & Export', subtitle: 'Export telemetry data and executive summaries', route: '/reports', icon: BarChart3, category: 'Navigation' },
  { id: 'settings', title: 'Platform Settings', subtitle: 'Service health, tenants & configuration', route: '/settings', icon: Settings, category: 'Navigation' },
]

export default function CommandPalette({ isOpen, onClose }) {
  const [query, setQuery] = useState('')
  const [selectedIndex, setSelectedIndex] = useState(0)
  const inputRef = useRef(null)
  const navigate = useNavigate()

  useEffect(() => {
    if (isOpen) {
      setQuery('')
      setSelectedIndex(0)
      setTimeout(() => inputRef.current?.focus(), 50)
    }
  }, [isOpen])

  useEffect(() => {
    function handleKeyDown(e) {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        if (isOpen) onClose()
        else {
          // Trigger open via custom event or prop
          window.dispatchEvent(new CustomEvent('open-command-palette'))
        }
      }
      if (!isOpen) return

      if (e.key === 'Escape') {
        e.preventDefault()
        onClose()
      } else if (e.key === 'ArrowDown') {
        e.preventDefault()
        setSelectedIndex((prev) => (prev + 1) % filteredItems.length)
      } else if (e.key === 'ArrowUp') {
        e.preventDefault()
        setSelectedIndex((prev) => (prev - 1 + filteredItems.length) % (filteredItems.length || 1))
      } else if (e.key === 'Enter') {
        e.preventDefault()
        if (filteredItems[selectedIndex]) {
          handleSelect(filteredItems[selectedIndex])
        }
      }
    }

    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  })

  // Dynamic items based on query
  const q = query.trim().toLowerCase()
  let filteredItems = STATIC_ROUTES.filter((r) =>
    r.title.toLowerCase().includes(q) || r.subtitle.toLowerCase().includes(q)
  )

  // If query looks like an IP or keyword search, add dynamic search option
  if (q.length > 0) {
    filteredItems.unshift({
      id: `search-${q}`,
      title: `Search logs for "${query}"`,
      subtitle: 'Execute full-text query in Log Explorer',
      route: `/logs?q=${encodeURIComponent(query)}`,
      icon: Search,
      category: 'Quick Actions',
    })

    // If matches IP format
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(q)) {
      filteredItems.splice(1, 0, {
        id: `ip-${q}`,
        title: `Check IP reputation: ${query}`,
        subtitle: 'Lookup IP in Threat Intelligence database',
        route: `/threat-intel?ip=${encodeURIComponent(query)}`,
        icon: Shield,
        category: 'Quick Actions',
      })
    }
  }

  const handleSelect = (item) => {
    onClose()
    if (item.route) {
      navigate(item.route)
    }
  }

  if (!isOpen) return null

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-24 px-4 bg-black/70 backdrop-blur-xs animate-fade-in"
      onClick={onClose}
    >
      <div
        className="w-full max-w-xl bg-slate-900 border border-slate-700 rounded-xl shadow-2xl overflow-hidden flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Search Input Bar */}
        <div className="flex items-center gap-3 px-4 py-3.5 border-b border-slate-800 bg-slate-950/60">
          <Search size={18} className="text-slate-400 flex-shrink-0" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value)
              setSelectedIndex(0)
            }}
            placeholder="Type a command, route, or search query (e.g. 198.51.100.42, brute force)..."
            className="w-full bg-transparent text-sm text-slate-100 placeholder-slate-500 outline-none font-sans"
          />
          <kbd className="hidden sm:inline-flex items-center gap-0.5 px-2 py-0.5 text-[10px] font-mono text-slate-400 bg-slate-800 border border-slate-700 rounded">
            ESC
          </kbd>
        </div>

        {/* Results List */}
        <div className="max-h-80 overflow-y-auto p-2 divide-y divide-slate-800/40">
          {filteredItems.length === 0 ? (
            <div className="py-8 text-center text-xs text-slate-500">
              No matching commands or routes found for "{query}"
            </div>
          ) : (
            filteredItems.map((item, idx) => {
              const Icon = item.icon
              const isSelected = idx === selectedIndex
              return (
                <div
                  key={item.id}
                  onClick={() => handleSelect(item)}
                  onMouseEnter={() => setSelectedIndex(idx)}
                  className={`flex items-center gap-3 px-3 py-2.5 rounded-lg cursor-pointer transition-colors ${
                    isSelected ? 'bg-sky-950/60 text-white' : 'text-slate-300 hover:bg-slate-800/50'
                  }`}
                >
                  <div
                    className={`w-7 h-7 rounded-md flex items-center justify-center flex-shrink-0 border ${
                      isSelected
                        ? 'bg-sky-600/20 border-sky-500/40 text-sky-400'
                        : 'bg-slate-800 border-slate-700 text-slate-400'
                    }`}
                  >
                    <Icon size={14} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="text-xs font-semibold truncate flex items-center gap-2">
                      <span>{item.title}</span>
                      <span className="text-[10px] font-normal text-slate-500 uppercase tracking-wider font-mono">
                        {item.category}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-400 truncate">{item.subtitle}</div>
                  </div>
                  {isSelected && (
                    <CornerDownLeft size={13} className="text-sky-400 flex-shrink-0" />
                  )}
                </div>
              )
            })
          )}
        </div>

        {/* Footer info */}
        <div className="px-4 py-2 border-t border-slate-800 bg-slate-950/40 text-[11px] text-slate-500 flex items-center justify-between font-mono">
          <div className="flex items-center gap-3">
            <span>↑↓ to navigate</span>
            <span>↵ to execute</span>
          </div>
          <span>AetherGuard Omnibar</span>
        </div>
      </div>
    </div>
  )
}
