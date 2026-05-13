import { useState } from 'react'
import { useLocation } from 'react-router-dom'
import useStore from '../store/useStore'
import { Bell, Wifi, WifiOff, Activity, Search, X, ChevronRight } from 'lucide-react'
import { formatDateTime, severityBadgeClass } from '../utils/constants'

const PAGE_TITLES = {
  '/dashboard':    { title: 'Live Dashboard',        sub: 'Real-time threat monitoring' },
  '/logs':         { title: 'Log Explorer',           sub: 'Search and query all events' },
  '/alerts':       { title: 'Alert Center',           sub: 'Active threat alerts' },
  '/incidents':    { title: 'Incident Management',    sub: 'IR workflow & tracking' },
  '/threat-intel': { title: 'Threat Intelligence',    sub: 'IOC management & feeds' },
  '/attack-map':   { title: 'Attack Map',             sub: 'Global attack visualization' },
  '/ueba':         { title: 'UEBA Analytics',         sub: 'User behavior analysis' },
  '/reports':      { title: 'Reports & Export',       sub: 'Analysis & reporting' },
  '/settings':     { title: 'System Settings',        sub: 'Configuration & administration' },
}

export default function TopNav() {
  const location = useLocation()
  const { wsConnected, eps, unreadAlerts, liveAlerts, toggleNotif, notifOpen, clearUnread } = useStore()
  const page = PAGE_TITLES[location.pathname] || { title: 'AetherGuard', sub: '' }

  return (
    <header
      className="flex items-center justify-between px-6 h-14 flex-shrink-0 relative z-10"
      style={{ background: '#0d1117', borderBottom: '1px solid #1f2937' }}
    >
      {/* Left: Page title */}
      <div>
        <h1 className="text-sm font-bold text-white">{page.title}</h1>
        <p className="text-xs text-gray-500">{page.sub}</p>
      </div>

      {/* Right: Status indicators */}
      <div className="flex items-center gap-4">
        {/* EPS Counter */}
        <div className="flex items-center gap-1.5 px-3 py-1 rounded-lg" style={{ background: '#111827', border: '1px solid #1f2937' }}>
          <Activity size={12} color="#00ff88" className="animate-pulse" />
          <span className="text-xs font-mono font-bold" style={{ color: '#00ff88' }}>{eps}</span>
          <span className="text-xs text-gray-500">EPS</span>
        </div>

        {/* WS Connection */}
        <div className="flex items-center gap-1.5" title={wsConnected ? 'Connected to backend' : 'Disconnected'}>
          {wsConnected ? (
            <>
              <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
              <Wifi size={13} color="#00ff88" />
            </>
          ) : (
            <>
              <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
              <WifiOff size={13} color="#ff3366" />
            </>
          )}
          <span className="text-xs" style={{ color: wsConnected ? '#00ff88' : '#ff3366' }}>
            {wsConnected ? 'LIVE' : 'OFFLINE'}
          </span>
        </div>

        {/* Notifications */}
        <button
          onClick={() => { toggleNotif(); clearUnread() }}
          className="relative p-2 rounded-lg text-gray-400 hover:text-white transition-colors"
          style={{ background: '#111827', border: '1px solid #1f2937' }}
        >
          <Bell size={16} />
          {unreadAlerts > 0 && (
            <span
              className="absolute -top-1 -right-1 w-4 h-4 rounded-full flex items-center justify-center text-white font-bold"
              style={{ background: '#ff3366', fontSize: '0.6rem' }}
            >
              {unreadAlerts > 9 ? '9+' : unreadAlerts}
            </span>
          )}
        </button>
      </div>

      {/* Notification Panel */}
      {notifOpen && (
        <div
          className="absolute right-4 top-16 w-96 rounded-xl shadow-2xl z-50 overflow-hidden animate-fade-in"
          style={{ background: '#111827', border: '1px solid #1f2937' }}
        >
          <div className="flex items-center justify-between px-4 py-3" style={{ borderBottom: '1px solid #1f2937' }}>
            <div className="flex items-center gap-2">
              <Bell size={14} color="#00d4ff" />
              <span className="text-sm font-semibold text-white">Recent Alerts</span>
            </div>
            <button onClick={toggleNotif} className="text-gray-500 hover:text-white">
              <X size={14} />
            </button>
          </div>
          <div className="max-h-80 overflow-y-auto">
            {liveAlerts.length === 0 ? (
              <div className="p-6 text-center text-gray-500 text-sm">No alerts yet</div>
            ) : (
              liveAlerts.slice(0, 15).map((alert, i) => (
                <div
                  key={alert._id || i}
                  className="flex items-start gap-3 px-4 py-3 hover:bg-white/5 transition-colors"
                  style={{ borderBottom: '1px solid #1f2937' }}
                >
                  <span className={severityBadgeClass(alert.severity)}>{alert.severity}</span>
                  <div className="flex-1 min-w-0">
                    <div className="text-xs font-medium text-gray-200 truncate">{alert.title}</div>
                    <div className="text-xs text-gray-500 mt-0.5">{formatDateTime(alert.created_at)}</div>
                  </div>
                  <ChevronRight size={12} className="text-gray-600 flex-shrink-0 mt-1" />
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </header>
  )
}
