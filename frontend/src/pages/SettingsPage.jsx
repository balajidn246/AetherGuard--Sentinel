import { useState, useEffect } from 'react'
import { healthApi } from '../services/api'
import useStore from '../store/useStore'
import { Settings, Server, Database, Shield, Activity, Wifi, User, Info } from 'lucide-react'

export default function SettingsPage() {
  const { user } = useStore()
  const [health, setHealth] = useState(null)

  useEffect(() => {
    healthApi.check().then(r => setHealth(r.data)).catch(() => {})
    const interval = setInterval(() => {
      healthApi.check().then(r => setHealth(r.data)).catch(() => {})
    }, 10000)
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
            {[
              { label: 'API Status', value: health?.status || 'Unknown', color: health?.status === 'healthy' ? '#00ff88' : '#ff3366', icon: Activity },
              { label: 'Database', value: health?.database || 'Unknown', color: '#00d4ff', icon: Database },
              { label: 'WebSocket Clients', value: health?.websocket_clients || 0, color: '#ffaa00', icon: Wifi },
            ].map(({ label, value, color, icon: Icon }) => (
              <div key={label} className="flex items-center gap-3 p-3 rounded-lg" style={{ background: '#1f2937' }}>
                <Icon size={14} color={color} />
                <span className="text-xs text-gray-400 flex-1">{label}</span>
                <span className="text-xs font-bold capitalize" style={{ color }}>{String(value)}</span>
              </div>
            ))}
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
              { label: 'Username', value: user?.username },
              { label: 'Role', value: user?.role },
              { label: 'Full Name', value: user?.full_name || '—' },
              { label: 'Department', value: user?.department || '—' },
              { label: 'Email', value: user?.email || '—' },
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
              { label: 'Platform', value: 'AetherGuard Sentinel' },
              { label: 'Version', value: '1.0.0' },
              { label: 'Build', value: 'Enterprise Edition' },
              { label: 'Backend', value: 'FastAPI + Python 3.13' },
              { label: 'Frontend', value: 'React 18 + Tailwind CSS' },
              { label: 'Database', value: health?.database === 'mongodb' ? 'MongoDB' : 'TinyDB (Fallback)' },
              { label: 'ML Engine', value: 'scikit-learn IsolationForest' },
              { label: 'WebSocket', value: 'FastAPI Native WS' },
              { label: 'Auth', value: 'JWT + bcrypt' },
            ].map(({ label, value }) => (
              <div key={label} className="flex flex-col gap-1">
                <span className="text-gray-500">{label}</span>
                <span className="text-gray-200 font-medium">{value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Detection Rules */}
        <div className="col-span-6 glass-card p-4">
          <div className="flex items-center gap-2 mb-4">
            <Shield size={14} color="#00ff88" />
            <span className="text-sm font-bold text-white">Active Detection Rules</span>
          </div>
          <div className="space-y-2">
            {[
              'Brute Force Login Detection',
              'Port Scan Detection',
              'Privilege Escalation Detection',
              'Suspicious PowerShell Activity',
              'Impossible Travel Login',
              'Data Exfiltration Detection',
              'Malware Indicator Detection',
              'C2 Beaconing Detection',
            ].map((rule, i) => (
              <div key={i} className="flex items-center gap-2 py-1.5" style={{ borderBottom: '1px solid #1f2937' }}>
                <div className="w-1.5 h-1.5 rounded-full bg-green-400" />
                <span className="text-xs text-gray-300">{rule}</span>
                <span className="ml-auto text-xs px-2 py-0.5 rounded" style={{ background: '#00ff8815', color: '#00ff88' }}>ACTIVE</span>
              </div>
            ))}
          </div>
        </div>

        {/* Attack Simulator */}
        <div className="col-span-6 glass-card p-4">
          <div className="flex items-center gap-2 mb-4">
            <Activity size={14} color="#ff3366" />
            <span className="text-sm font-bold text-white">Attack Simulation Campaigns</span>
          </div>
          <div className="space-y-2">
            {[
              'SSH Brute Force', 'RDP Brute Force', 'Port Scanning', 'DDoS HTTP Flood',
              'Malware Execution', 'Data Exfiltration', 'Reverse Shell', 'Privilege Escalation',
              'Impossible Travel', 'PowerShell Attack',
            ].map((campaign, i) => (
              <div key={i} className="flex items-center gap-2 py-1.5" style={{ borderBottom: '1px solid #1f2937' }}>
                <div className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse" />
                <span className="text-xs text-gray-300">{campaign}</span>
                <span className="ml-auto text-xs px-2 py-0.5 rounded" style={{ background: '#ff336615', color: '#ff3366' }}>RUNNING</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
