import { useState } from 'react'
import { useLocation } from 'react-router-dom'
import useStore from '../store/useStore'
import { Bell, Wifi, WifiOff, Activity, Search, X, ChevronRight, Sun, Moon, Cpu, Shield } from 'lucide-react'
import { formatDateTime, severityBadgeClass } from '../utils/constants'

const PAGE_TITLES = {
  '/dashboard':    { title: 'Command Center',         sub: 'Real-time security operations & telemetry posture' },
  '/logs':         { title: 'Log Explorer',           sub: 'Interactive ClickHouse telemetry investigation workbench' },
  '/alerts':       { title: 'Security Signals',       sub: 'Active threat alerts, detections & AI triage' },
  '/cases':        { title: 'Case Management',        sub: 'Investigation workflows, evidence & analyst notes' },
  '/incidents':    { title: 'Incident Response',      sub: 'Incident lifecycle, containment & remediation' },
  '/rules':        { title: 'Detection Rules',        sub: 'Stateful Python, Sigma & YAML detection engineering' },
  '/soar':         { title: 'SOAR Playbooks',         sub: 'Automated containment actions with approval gates' },
  '/threat-intel': { title: 'Threat Intelligence',    sub: 'IOC reputation database, feed sync & blocklists' },
  '/ueba':         { title: 'UEBA Analytics',         sub: 'User & entity behavioral baseline anomaly detection' },
  '/audit':        { title: 'Audit Trail',            sub: 'Immutable compliance trail & administrative actions' },
  '/reports':      { title: 'Reports & Export',       sub: 'Executive summaries & CSV data exports' },
  '/settings':     { title: 'Platform Settings',      sub: 'Service health, tenants & configuration' },
}

export default function TopNav({ onOpenCommandPalette }) {
  const location = useLocation()
  const { wsConnected, eps, unreadAlerts, liveAlerts, toggleNotif, notifOpen, clearUnread, theme, toggleTheme } = useStore()
  const page = PAGE_TITLES[location.pathname] || { title: 'AetherGuard Sentinel', sub: 'Enterprise SOC' }

  return (
    <header
      className="flex items-center justify-between px-5 h-14 flex-shrink-0 relative z-10 select-none bg-slate-950 border-b border-slate-800"
    >
      {/* Left: Page title & Tenant */}
      <div className="flex items-center gap-4">
        <div>
          <h1 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <span>{page.title}</span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700 font-normal">
              TENANT: DEFAULT
            </span>
          </h1>
          <p className="text-[11px] text-slate-400 hidden sm:block">{page.sub}</p>
        </div>
      </div>

      {/* Middle/Right: Omnibar Launcher & Status indicators */}
      <div className="flex items-center gap-3">
        {/* Global Command Bar Button */}
        <button
          onClick={onOpenCommandPalette}
          className="hidden md:flex items-center gap-3 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-700 transition-colors text-xs"
          title="Search commands, routes, IPs, rules (Ctrl+K)"
        >
          <div className="flex items-center gap-1.5">
            <Search size={13} className="text-slate-400" />
            <span>Search or command...</span>
          </div>
          <kbd className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300">
            Ctrl K
          </kbd>
        </button>

        {/* Ingestion EPS Spark */}
        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800" title="Live Ingestion Events Per Second">
          <Activity size={12} className="text-emerald-400 animate-pulse" />
          <span className="text-xs font-mono font-bold text-emerald-400">{eps}</span>
          <span className="text-[10px] text-slate-400 font-mono">EPS</span>
        </div>

        {/* AI Engine Status */}
        <div className="hidden lg:flex items-center gap-1.5 px-2 py-1 rounded-md bg-slate-900 border border-slate-800 text-xs" title="Ollama llama3.2:1b Local Security Engine">
          <Cpu size={12} className="text-indigo-400" />
          <span className="text-[11px] font-mono text-indigo-300">llama3.2:1b</span>
        </div>

        {/* WebSocket Connection Status */}
        <div
          className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 text-xs"
          title={wsConnected ? 'WebSocket live stream connected' : 'WebSocket disconnected - reconnecting'}
        >
          {wsConnected ? (
            <>
              <div className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              <Wifi size={12} className="text-emerald-400" />
              <span className="text-[10px] font-mono text-emerald-400 font-bold">ONLINE</span>
            </>
          ) : (
            <>
              <div className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-pulse" />
              <WifiOff size={12} className="text-rose-400" />
              <span className="text-[10px] font-mono text-rose-400 font-bold">OFFLINE</span>
            </>
          )}
        </div>

        {/* Theme Toggle */}
        <button
          onClick={toggleTheme}
          className="p-2 rounded-md bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-100 hover:border-slate-700 transition-colors"
          title={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
        >
          {theme === 'dark' ? <Sun size={14} /> : <Moon size={14} />}
        </button>

        {/* Notification Bell */}
        <button
          onClick={() => { toggleNotif(); clearUnread() }}
          className="relative p-2 rounded-md bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-100 hover:border-slate-700 transition-colors"
          title="Live Threat Alerts"
        >
          <Bell size={14} />
          {unreadAlerts > 0 && (
            <span
              className="absolute -top-1 -right-1 w-4 h-4 rounded-full flex items-center justify-center text-white font-bold font-mono text-[9px] bg-rose-500"
            >
              {unreadAlerts > 9 ? '9+' : unreadAlerts}
            </span>
          )}
        </button>
      </div>

      {/* Notifications Drawer */}
      {notifOpen && (
        <div
          className="absolute right-4 top-16 w-96 rounded-xl shadow-2xl z-50 overflow-hidden bg-slate-900 border border-slate-700 animate-fade-in"
        >
          <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800 bg-slate-950">
            <div className="flex items-center gap-2">
              <Bell size={13} className="text-sky-400" />
              <span className="text-xs font-bold text-white uppercase tracking-wider">Recent Threat Signals</span>
            </div>
            <button onClick={toggleNotif} className="text-slate-500 hover:text-white">
              <X size={14} />
            </button>
          </div>
          <div className="max-h-80 overflow-y-auto divide-y divide-slate-800">
            {liveAlerts.length === 0 ? (
              <div className="p-6 text-center text-slate-500 text-xs">No active threat signals logged</div>
            ) : (
              liveAlerts.slice(0, 15).map((alert, i) => (
                <div
                  key={alert._id || i}
                  className="flex items-start gap-3 px-4 py-2.5 hover:bg-slate-800/60 transition-colors cursor-pointer"
                >
                  <span className={severityBadgeClass(alert.severity)}>{alert.severity}</span>
                  <div className="flex-1 min-w-0">
                    <div className="text-xs font-semibold text-slate-200 truncate">{alert.title}</div>
                    <div className="text-[10px] text-slate-500 font-mono mt-0.5">{formatDateTime(alert.created_at)}</div>
                  </div>
                  <ChevronRight size={12} className="text-slate-600 flex-shrink-0 mt-1" />
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </header>
  )
}
