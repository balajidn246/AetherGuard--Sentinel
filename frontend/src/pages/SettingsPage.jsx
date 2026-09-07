import { useState, useEffect } from 'react'
import { healthApi, rulesApi } from '../services/api'
import useStore from '../store/useStore'
import { Settings, Server, Database, Shield, Activity, Wifi, User, Info, CheckCircle, XCircle } from 'lucide-react'

function ServiceRow({ label, data, icon: Icon, color }) {
  const isHealthy = typeof data === 'string'
    ? data === 'healthy'
    : typeof data === 'object' && data !== null
      ? Object.values(data).every(v => v === 'healthy')
      : !!data
  return (
    <div className="flex items-center gap-3 p-3 rounded-lg" style={{ background: '#1f2937' }}>
      <Icon size={14} color={color} />
      <span className="text-xs text-gray-400 flex-1">{label}</span>
      {isHealthy
        ? <CheckCircle size={13} color="#00ff88" />
        : <XCircle size={13} color="#ff3366" />
      }
      <span className="text-xs font-bold capitalize" style={{ color: isHealthy ? '#00ff88' : '#ff3366' }}>
        {typeof data === 'object' && data !== null ? 'healthy' : String(data || 'unknown')}
      </span>
    </div>
  )
}

export default function SettingsPage() {
  const { user } = useStore()
  const [health, setHealth] = useState(null)
  const [rules, setRules] = useState([])
  const [rulesLoading, setRulesLoading] = useState(false)

  useEffect(() => {
    // Poll health
    const fetchHealth = () =>
      healthApi.check().then(r => setHealth(r.data)).catch(() => {})
    fetchHealth()
    const interval = setInterval(fetchHealth, 10000)

    // Fetch live detection rules
    setRulesLoading(true)
    rulesApi.list({ limit: 20 })
      .then(r => setRules(r.data?.rules || r.data || []))
      .catch(() => {})
      .finally(() => setRulesLoading(false))

    return () => clearInterval(interval)
  }, [])

  return (
    <div className="flex flex-col gap-4 h-full animate-fade-in">
      <div className="grid grid-cols-12 gap-4">

        {/* System Health */}
        <div className="col-span-6 glass-card p-4">
          <div className="flex items-center gap-2 mb-4">
            <Server size={14} color="#00d4ff" />
            <span className="text-sm font-bold text-white">System Health</span>
            <div className={`w-2 h-2 rounded-full ml-auto ${health?.status === 'healthy' ? 'bg-green-400 animate-pulse' : 'bg-red-500'}`} />
          </div>
          <div className="space-y-3">
            <ServiceRow label="API Status"       data={health?.status}              icon={Activity} color="#00ff88" />
            <ServiceRow label="PostgreSQL"        data={health?.database?.postgres}  icon={Database} color="#00d4ff" />
            <ServiceRow label="ClickHouse"        data={health?.database?.clickhouse} icon={Database} color="#a855f7" />
            <ServiceRow label="Redis"             data={health?.redis}               icon={Database} color="#ffaa00" />
            <ServiceRow label="AI Engine"         data={health?.ai}                  icon={Activity} color="#ff3366" />
            <div className="flex items-center gap-3 p-3 rounded-lg" style={{ background: '#1f2937' }}>
              <Wifi size={14} color="#ffaa00" />
              <span className="text-xs text-gray-400 flex-1">WebSocket Clients</span>
              <span className="text-xs font-bold" style={{ color: '#ffaa00' }}>
                {health?.websocket_clients ?? '—'}
              </span>
            </div>
          </div>
        </div>

        {/* User Info */}
        <div className="col-span-6 glass-card p-4">
          <div className="flex items-center gap-2 mb-4">
            <User size={14} color="#a855f7" />
            <span className="text-sm font-bold text-white">Current Session</span>
          </div>
          <div className="space-y-3">
            {[
              { label: 'Username',   value: user?.username },
              { label: 'Role',       value: user?.role },
              { label: 'Full Name',  value: user?.full_name || '—' },
              { label: 'Department', value: user?.department || '—' },
              { label: 'Email',      value: user?.email || '—' },
            ].map(({ label, value }) => (
              <div key={label} className="flex items-center justify-between py-1.5" style={{ borderBottom: '1px solid #1f2937' }}>
                <span className="text-xs text-gray-500">{label}</span>
                <span className="text-xs text-gray-200 capitalize">{value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Platform Info */}
        <div className="col-span-12 glass-card p-4">
          <div className="flex items-center gap-2 mb-4">
            <Info size={14} color="#00d4ff" />
            <span className="text-sm font-bold text-white">Platform Information</span>
          </div>
          <div className="grid grid-cols-3 gap-6 text-xs">
            {[
              { label: 'Platform',    value: 'AetherGuard--Sentinel' },
              { label: 'Version',     value: '1.0.0' },
              { label: 'Build',       value: 'Open-Source SIEM' },
              { label: 'Backend',     value: 'FastAPI + Python 3.13' },
              { label: 'Frontend',    value: 'React 19 + Vite 8 + Tailwind CSS 3' },
              { label: 'Database',    value: 'PostgreSQL 16 + ClickHouse' },
              { label: 'Queue',       value: 'Redis 7.2' },
              { label: 'ML Engine',   value: 'IsolationForest UEBA (sklearn)' },
              { label: 'AI',          value: 'Ollama llama3.2:1b (local)' },
            ].map(({ label, value }) => (
              <div key={label} className="flex flex-col gap-1">
                <span className="text-gray-500">{label}</span>
                <span className="text-gray-200 font-medium">{value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Active Detection Rules — live from API */}
        <div className="col-span-12 glass-card p-4">
          <div className="flex items-center gap-2 mb-4">
            <Shield size={14} color="#00ff88" />
            <span className="text-sm font-bold text-white">Active Detection Rules</span>
            <span className="ml-2 text-xs text-gray-500">
              {rulesLoading ? 'Loading...' : `${rules.filter(r => r.enabled).length} of ${rules.length} enabled`}
            </span>
          </div>
          {rules.length === 0 && !rulesLoading ? (
            <p className="text-xs text-gray-600">No rules loaded — check backend connectivity.</p>
          ) : (
            <div className="grid grid-cols-2 gap-x-6 gap-y-1">
              {rules.map(rule => (
                <div key={rule.id} className="flex items-center gap-2 py-1.5" style={{ borderBottom: '1px solid #1f2937' }}>
                  <div className={`w-1.5 h-1.5 rounded-full ${rule.enabled ? 'bg-green-400' : 'bg-gray-600'}`} />
                  <span className="text-xs text-gray-300 flex-1 truncate">{rule.name}</span>
                  <span
                    className="text-xs px-2 py-0.5 rounded"
                    style={{
                      background: rule.enabled ? '#00ff8815' : '#1f2937',
                      color: rule.enabled ? '#00ff88' : '#6b7280',
                    }}
                  >
                    {rule.enabled ? 'ACTIVE' : 'DISABLED'}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

      </div>
    </div>
  )
}
