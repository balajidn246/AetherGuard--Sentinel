import { useState, useEffect, useCallback } from 'react'
import { alertsApi } from '../services/api'
import AlertCard from '../components/AlertCard'
import { RefreshCw, Filter, Bell, Check, AlertTriangle } from 'lucide-react'
import { SEVERITY_COLORS } from '../utils/constants'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'

export default function AlertsPage() {
  const [alerts, setAlerts] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(false)
  const [summary, setSummary] = useState(null)
  const [filters, setFilters] = useState({ severity: '', acknowledged: '' })

  const fetchAlerts = useCallback(async () => {
    setLoading(true)
    try {
      const params = { limit: 200 }
      if (filters.severity) params.severity = filters.severity
      if (filters.acknowledged !== '') params.acknowledged = filters.acknowledged === 'true'
      const [alertsRes, summaryRes] = await Promise.all([
        alertsApi.list(params),
        alertsApi.summary(),
      ])
      setAlerts(alertsRes.data.alerts)
      setTotal(alertsRes.data.total)
      setSummary(summaryRes.data)
    } catch (e) { console.error(e) }
    finally { setLoading(false) }
  }, [filters])

  useEffect(() => { fetchAlerts() }, [filters])
  useEffect(() => {
    const interval = setInterval(fetchAlerts, 10000)
    return () => clearInterval(interval)
  }, [fetchAlerts])

  const sevData = summary ? Object.entries(summary.by_severity || {}).map(([k, v]) => ({
    name: k, value: v, color: SEVERITY_COLORS[k] || '#6b7280'
  })) : []

  return (
    <div className="flex flex-col gap-4 h-full animate-fade-in">
      {/* Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 flex-shrink-0">
        {[
          { label: 'Total Alerts', value: total, color: '#00d4ff' },
          { label: 'Unacknowledged', value: summary?.unacknowledged || 0, color: '#ff3366' },
          { label: 'Critical', value: summary?.critical || 0, color: '#ff3366' },
          { label: 'High', value: (summary?.by_severity?.high || 0), color: '#ff6b35' },
        ].map(s => (
          <div key={s.label} className="glass-card p-4">
            <div className="text-xs text-gray-500 mb-1">{s.label}</div>
            <div className="text-2xl font-bold" style={{ color: s.color }}>
              {(s.value || 0).toLocaleString()}
            </div>
          </div>
        ))}
      </div>

      <div className="flex-1 grid grid-cols-12 gap-4 min-h-0">
        {/* Left: Alert list */}
        <div className="col-span-8 flex flex-col gap-3">
          {/* Toolbar */}
          <div className="glass-card p-3 flex items-center gap-3 flex-shrink-0">
            <Bell size={14} color="#ff3366" />
            <span className="text-xs font-bold text-white">{total} ALERTS</span>
            <div className="ml-auto flex items-center gap-2">
              <select
                className="cyber-input text-xs"
                value={filters.severity}
                onChange={e => setFilters(f => ({ ...f, severity: e.target.value }))}
              >
                <option value="">All Severity</option>
                {['critical','high','medium','low'].map(s => (
                  <option key={s} value={s}>{s.toUpperCase()}</option>
                ))}
              </select>
              <select
                className="cyber-input text-xs"
                value={filters.acknowledged}
                onChange={e => setFilters(f => ({ ...f, acknowledged: e.target.value }))}
              >
                <option value="">All Status</option>
                <option value="false">Unacknowledged</option>
                <option value="true">Acknowledged</option>
              </select>
              <button className="btn-cyber btn-cyber-primary" onClick={fetchAlerts}>
                <RefreshCw size={12} /> Refresh
              </button>
            </div>
          </div>

          <div className="flex-1 glass-card p-4 overflow-y-auto">
            {loading ? (
              <div className="flex items-center justify-center h-32 text-gray-500 text-sm">Loading alerts...</div>
            ) : alerts.length === 0 ? (
              <div className="flex items-center justify-center h-32 text-gray-600">
                <div className="text-center">
                  <Check size={32} className="mx-auto mb-2 opacity-30" />
                  <p className="text-sm">No alerts match your filters</p>
                </div>
              </div>
            ) : (
              alerts.map((alert, i) => (
                <AlertCard key={alert._id || i} alert={alert} onUpdate={fetchAlerts} />
              ))
            )}
          </div>
        </div>

        {/* Right: Severity Bar Chart */}
        <div className="col-span-4 flex flex-col gap-4">
          <div className="glass-card p-4">
            <div className="text-xs font-bold text-white mb-3">Alerts by Severity</div>
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={sevData} layout="vertical" barSize={14}>
                <XAxis type="number" tick={{ fill: '#4b5563', fontSize: 10 }} />
                <YAxis type="category" dataKey="name" tick={{ fill: '#9ca3af', fontSize: 10 }} width={55} />
                <Tooltip contentStyle={{ background: '#111827', border: '1px solid #1f2937', borderRadius: 8, color: '#f9fafb', fontSize: 11 }} />
                <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                  {sevData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Unacked alert highlight */}
          <div className="glass-card p-4" style={{ borderLeft: '3px solid #ff3366' }}>
            <div className="flex items-center gap-2 mb-2">
              <AlertTriangle size={14} color="#ff3366" />
              <span className="text-xs font-bold text-white">Action Required</span>
            </div>
            <div className="text-2xl font-bold mb-1" style={{ color: '#ff3366' }}>
              {summary?.unacknowledged || 0}
            </div>
            <p className="text-xs text-gray-500">Unacknowledged alerts pending analyst review</p>
          </div>
        </div>
      </div>
    </div>
  )
}
