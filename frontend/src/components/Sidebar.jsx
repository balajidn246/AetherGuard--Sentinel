import { NavLink, useNavigate } from 'react-router-dom'
import useStore from '../store/useStore'
import {
  LayoutDashboard, FileText, Bell, AlertTriangle, Shield,
  Map, Users, BarChart3, Settings, ChevronLeft, ChevronRight,
  LogOut, Activity, Database, Zap
} from 'lucide-react'

const NAV_ITEMS = [
  { to: '/dashboard',    icon: LayoutDashboard, label: 'Dashboard',      desc: 'Live Overview' },
  { to: '/logs',         icon: FileText,        label: 'Log Explorer',   desc: 'Search & Query' },
  { to: '/alerts',       icon: Bell,            label: 'Alerts',         desc: 'Active Threats' },
  { to: '/incidents',    icon: AlertTriangle,   label: 'Incidents',      desc: 'IR Workflow' },
  { to: '/threat-intel', icon: Shield,          label: 'Threat Intel',   desc: 'IOC & Feeds' },
  { to: '/attack-map',   icon: Map,             label: 'Attack Map',     desc: 'Geo Visualization' },
  { to: '/ueba',         icon: Users,           label: 'UEBA',           desc: 'Behavior Analytics' },
  { to: '/reports',      icon: BarChart3,       label: 'Reports',        desc: 'Export & Analysis' },
  { to: '/settings',     icon: Settings,        label: 'Settings',       desc: 'System Config' },
]

export default function Sidebar() {
  const { sidebarCollapsed, toggleSidebar, user, logout, unreadAlerts } = useStore()
  const navigate = useNavigate()

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  return (
    <aside
      className="flex flex-col h-full transition-all duration-300 relative z-20"
      style={{
        width: sidebarCollapsed ? '64px' : '220px',
        minWidth: sidebarCollapsed ? '64px' : '220px',
        background: 'linear-gradient(180deg, #0d1117 0%, #030712 100%)',
        borderRight: '1px solid #1f2937',
      }}
    >
      {/* Logo */}
      <div className="flex items-center gap-3 px-4 py-5" style={{ borderBottom: '1px solid #1f2937' }}>
        <div className="flex-shrink-0 relative">
          <div
            className="w-8 h-8 rounded-lg flex items-center justify-center"
            style={{ background: 'linear-gradient(135deg, #00d4ff22, #a855f722)', border: '1px solid #00d4ff44' }}
          >
            <Zap size={16} color="#00d4ff" />
          </div>
          <div className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-green-400 border-2 border-gray-950 animate-pulse" />
        </div>
        {!sidebarCollapsed && (
          <div className="overflow-hidden">
            <div className="text-sm font-bold tracking-wide text-white whitespace-nowrap">AetherGuard</div>
            <div className="text-xs text-cyan-400 whitespace-nowrap" style={{ color: '#00d4ff', fontSize: '0.65rem' }}>SENTINEL v1.0</div>
          </div>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-3 overflow-x-hidden">
        {NAV_ITEMS.map(({ to, icon: Icon, label, desc }) => (
          <NavLink
            key={to}
            to={to}
            title={sidebarCollapsed ? label : undefined}
            className={({ isActive }) =>
              `flex items-center gap-3 px-4 py-2.5 mx-2 rounded-lg mb-0.5 transition-all duration-200 relative group
               ${isActive
                 ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                 : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'
               }`
            }
          >
            {({ isActive }) => (
              <>
                <div className="relative flex-shrink-0">
                  <Icon size={17} />
                  {to === '/alerts' && unreadAlerts > 0 && (
                    <span
                      className="absolute -top-1.5 -right-1.5 min-w-[14px] h-3.5 rounded-full flex items-center justify-center text-white font-bold"
                      style={{ background: '#ff3366', fontSize: '0.55rem', padding: '0 3px' }}
                    >
                      {unreadAlerts > 99 ? '99+' : unreadAlerts}
                    </span>
                  )}
                </div>
                {!sidebarCollapsed && (
                  <div className="overflow-hidden">
                    <div className="text-sm font-medium leading-none">{label}</div>
                    {isActive && <div className="text-xs mt-0.5 opacity-60">{desc}</div>}
                  </div>
                )}
                {isActive && (
                  <div
                    className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-5 rounded-r"
                    style={{ background: '#00d4ff' }}
                  />
                )}
              </>
            )}
          </NavLink>
        ))}
      </nav>

      {/* User + Collapse */}
      <div style={{ borderTop: '1px solid #1f2937' }}>
        {/* User info */}
        {!sidebarCollapsed && user && (
          <div className="px-4 py-3">
            <div className="flex items-center gap-2">
              <div
                className="w-7 h-7 rounded-lg flex items-center justify-center text-xs font-bold flex-shrink-0"
                style={{ background: '#1f2937', color: '#00d4ff' }}
              >
                {user.username?.[0]?.toUpperCase() || 'A'}
              </div>
              <div className="overflow-hidden">
                <div className="text-xs font-medium text-gray-200 truncate">{user.username}</div>
                <div className="text-xs capitalize" style={{ color: '#00d4ff', fontSize: '0.65rem' }}>{user.role}</div>
              </div>
              <button
                onClick={handleLogout}
                className="ml-auto text-gray-500 hover:text-red-400 transition-colors"
                title="Logout"
              >
                <LogOut size={14} />
              </button>
            </div>
          </div>
        )}

        {/* Collapse toggle */}
        <button
          onClick={toggleSidebar}
          className="w-full flex items-center justify-center py-3 text-gray-500 hover:text-gray-300 transition-colors"
          style={{ borderTop: '1px solid #1f2937' }}
        >
          {sidebarCollapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
        </button>
      </div>
    </aside>
  )
}
