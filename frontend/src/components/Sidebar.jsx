import { NavLink, useNavigate } from 'react-router-dom'
import useStore from '../store/useStore'
import {
  LayoutDashboard, FileText, Bell, AlertTriangle, Shield,
  Users, BarChart3, Settings, ChevronLeft, ChevronRight,
  LogOut, Activity, Database, Zap, FolderGit2, ShieldCheck, History,
  Network, Globe
} from 'lucide-react'

const WORKFLOW_GROUPS = [
  {
    category: 'COMMAND',
    items: [
      { to: '/dashboard', icon: LayoutDashboard, label: 'Command Center', desc: 'Live Telemetry' },
    ]
  },
  {
    category: 'DETECT',
    items: [
      { to: '/rules', icon: ShieldCheck, label: 'Detection Rules', desc: 'Sigma & Stateful' },
    ]
  },
  {
    category: 'INVESTIGATE',
    items: [
      { to: '/logs', icon: FileText, label: 'Log Explorer', desc: 'ClickHouse Query' },
      { to: '/alerts', icon: Bell, label: 'Security Signals', desc: 'Threat Alerts' },
      { to: '/cases', icon: FolderGit2, label: 'Cases', desc: 'Investigations' },
      { to: '/entity-graph', icon: Network, label: 'Entity Graph', desc: 'Security Graph' },
    ]
  },
  {
    category: 'RESPOND',
    items: [
      { to: '/incidents', icon: AlertTriangle, label: 'Incidents', desc: 'IR Lifecycle' },
      { to: '/soar', icon: Zap, label: 'SOAR Playbooks', desc: 'Containment Gates' },
    ]
  },
  {
    category: 'INTELLIGENCE',
    items: [
      { to: '/threat-intel', icon: Shield, label: 'Threat Intel', desc: 'IOCs & Feeds' },
      { to: '/attack-map', icon: Globe, label: 'Attack Map', desc: 'Geo Telemetry' },
    ]
  },
  {
    category: 'BEHAVIOR',
    items: [
      { to: '/ueba', icon: Users, label: 'UEBA Analytics', desc: 'Entity Anomaly' },
    ]
  },
  {
    category: 'GOVERNANCE',
    items: [
      { to: '/audit', icon: History, label: 'Audit Trail', desc: 'Compliance Logs' },
      { to: '/reports', icon: BarChart3, label: 'Reports', desc: 'Data Exports' },
    ]
  },
  {
    category: 'SYSTEM',
    items: [
      { to: '/settings', icon: Settings, label: 'Platform Settings', desc: 'Health & Config' },
    ]
  },
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
      className="flex flex-col h-full transition-all duration-200 relative z-20 select-none"
      style={{
        width: sidebarCollapsed ? '64px' : '230px',
        minWidth: sidebarCollapsed ? '64px' : '230px',
        background: '#090f1b',
        borderRight: '1px solid #1e293b',
      }}
    >
      {/* Brand Header */}
      <div className="flex items-center gap-3 px-4 py-3.5 border-b border-slate-800 h-14 flex-shrink-0">
        <div className="flex-shrink-0 relative">
          <div
            className="w-7 h-7 rounded-md flex items-center justify-center bg-sky-500/10 border border-sky-500/30 text-sky-400"
          >
            <Shield size={16} />
          </div>
          <div className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-emerald-400 border border-slate-900" />
        </div>
        {!sidebarCollapsed && (
          <div className="overflow-hidden">
            <div className="text-xs font-bold tracking-wider text-slate-100 uppercase">AetherGuard</div>
            <div className="text-[10px] font-mono tracking-widest text-sky-400 uppercase">SENTINEL SOC</div>
          </div>
        )}
      </div>

      {/* Navigation Workflows */}
      <nav className="flex-1 overflow-y-auto py-2 overflow-x-hidden space-y-3">
        {WORKFLOW_GROUPS.map((group) => (
          <div key={group.category} className="px-2">
            {!sidebarCollapsed && (
              <div className="px-2 mb-1 text-[10px] font-bold text-slate-500 tracking-wider font-mono">
                {group.category}
              </div>
            )}
            <div className="space-y-0.5">
              {group.items.map(({ to, icon: Icon, label, desc }) => (
                <NavLink
                  key={to}
                  to={to}
                  title={sidebarCollapsed ? label : undefined}
                  className={({ isActive }) =>
                    `flex items-center gap-2.5 px-2.5 py-1.5 rounded-md transition-colors relative group text-xs
                     ${isActive
                       ? 'bg-sky-500/15 text-sky-300 font-semibold border border-sky-500/25'
                       : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40 border border-transparent'
                     }`
                  }
                >
                  {({ isActive }) => (
                    <>
                      <div className="relative flex-shrink-0">
                        <Icon size={15} className={isActive ? 'text-sky-400' : 'text-slate-400 group-hover:text-slate-300'} />
                        {to === '/alerts' && unreadAlerts > 0 && (
                          <span
                            className="absolute -top-1.5 -right-2 min-w-[14px] h-3.5 rounded-full flex items-center justify-center text-white font-bold font-mono"
                            style={{ background: '#ef4444', fontSize: '0.55rem', padding: '0 3px' }}
                          >
                            {unreadAlerts > 99 ? '99+' : unreadAlerts}
                          </span>
                        )}
                      </div>
                      {!sidebarCollapsed && (
                        <div className="overflow-hidden flex-1 min-w-0">
                          <div className="truncate leading-none">{label}</div>
                        </div>
                      )}
                      {isActive && (
                        <div className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-3.5 rounded-r bg-sky-400" />
                      )}
                    </>
                  )}
                </NavLink>
              ))}
            </div>
          </div>
        ))}
      </nav>

      {/* User & Collapse Footer */}
      <div className="border-t border-slate-800 bg-slate-950/40 flex-shrink-0">
        {!sidebarCollapsed && user && (
          <div className="px-3 py-2.5 flex items-center gap-2">
            <div className="w-6 h-6 rounded bg-slate-800 border border-slate-700 flex items-center justify-center text-[10px] font-mono font-bold text-sky-400 flex-shrink-0">
              {user.username?.[0]?.toUpperCase() || 'A'}
            </div>
            <div className="overflow-hidden flex-1 min-w-0">
              <div className="text-xs font-medium text-slate-200 truncate leading-none">{user.username}</div>
              <div className="text-[10px] text-slate-500 capitalize font-mono mt-0.5">{user.role}</div>
            </div>
            <button
              onClick={handleLogout}
              className="p-1 rounded text-slate-500 hover:text-rose-400 hover:bg-slate-800 transition-colors"
              title="Sign Out"
            >
              <LogOut size={13} />
            </button>
          </div>
        )}

        <button
          onClick={toggleSidebar}
          className="w-full flex items-center justify-center py-2 text-slate-500 hover:text-slate-300 hover:bg-slate-800/30 transition-colors border-t border-slate-800/60"
          title={sidebarCollapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
        >
          {sidebarCollapsed ? <ChevronRight size={14} /> : <ChevronLeft size={14} />}
        </button>
      </div>
    </aside>
  )
}
