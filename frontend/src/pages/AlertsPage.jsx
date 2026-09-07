import { useState, useEffect, useCallback } from 'react'
import { alertsApi } from '../services/api'
import AlertCard from '../components/AlertCard'
import { RefreshCw, Filter, Bell, Check, AlertTriangle, ShieldCheck, Layers } from 'lucide-react'
import { SEVERITY_COLORS, ALERT_LIFECYCLE_STATUSES } from '../utils/constants'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'
import { toast } from 'react-toastify'

export default function AlertsPage() {
  const [alerts, setAlerts] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(false)
  const [summary, setSummary] = useState(null)
  const [filters, setFilters] = useState({ severity: '', acknowledged: '', status: '' })

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
      setAlerts(alertsRes.data.alerts || [])
      setTotal(alertsRes.data.total || 0)
      setSummary(summaryRes.data)
    } catch (e) {
      console.error('Error fetching alerts:', e)
    } finally {
      setLoading(false)
    }
  }, [filters])

  useEffect(() => {
    fetchAlerts()
  }, [fetchAlerts])

  const sevData = summary ? Object.entries(summary.by_severity || {}).map(([k, v]) => ({
    name: k, value: v, color: SEVERITY_COLORS[k] || '#64748b'
  })) : []

  return (
    <div className="flex flex-col gap-3 h-full animate-fade-in overflow-hidden">
      {/* Posture summary metrics */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-2.5 flex-shrink-0">
        {[
          { label: 'Active Signals', value: total, color: '#38bdf8', icon: Bell },
          { label: 'Unacknowledged', value: summary?.unacknowledged || 0, color: '#ef4444', icon: AlertTriangle },
          { label: 'Critical Severity', value: summary?.critical || 0, color: '#f97316', icon: ShieldCheck },
          { label: 'High Severity', value: summary?.by_severity?.high || 0, color: '#eab308', icon: Layers },
        ].map(s => {
          const Icon = s.icon
          return (
            <div key={s.label} className="soc-card p-3 flex items-center justify-between">
              <div>
                <div className="text-[11px] text-slate-400 font-medium">{s.label}</div>
                <div className="text-xl font-bold font-mono mt-0.5" style={{ color: s.color }}>
                  {(s.value || 0).toLocaleString()}
                </div>
              </div>
              <div className="p-2 rounded bg-slate-900 border border-slate-800 text-slate-400">
                <Icon size={16} style={{ color: s.color }} />
              </div>
            </div>
          )
        })}
      </div>

      {/* Main split: Alert Queue + Severity Profile */}
      <div className="flex-1 grid grid-cols-12 gap-3 min-h-0 overflow-hidden">
        {/* Left 8 Cols: Alert Queue */}
        <div className="col-span-12 lg:col-span-8 flex flex-col gap-2 min-h-0">
          {/* Controls Bar */}
          <div className="soc-card p-2.5 flex items-center gap-2 flex-shrink-0 text-xs flex-wrap">
            <div className="flex items-center gap-1.5 font-bold text-slate-200 uppercase font-mono text-[11px]">
              <Bell size={13} className="text-rose-400" />
              <span>{total} SIGNALS</span>
            </div>

            <div className="ml-auto flex items-center gap-2">
              <select
                className="soc-input text-xs py-1"
                value={filters.severity}
                onChange={e => setFilters(f => ({ ...f, severity: e.target.value }))}
              >
                <option value="">All Severities</option>
                {['critical','high','medium','low'].map(s => (
                  <option key={s} value={s}>{s.toUpperCase()}</option>
                ))}
              </select>

              <select
                className="soc-input text-xs py-1"
                value={filters.acknowledged}
                onChange={e => setFilters(f => ({ ...f, acknowledged: e.target.value }))}
              >
                <option value="">All Acknowledgement</option>
                <option value="false">Unacknowledged Only</option>
                <option value="true">Acknowledged Only</option>
              </select>

              <button
                className="soc-btn soc-btn-secondary text-xs py-1 px-2.5"
                onClick={fetchAlerts}
                title="Refresh queue"
              >
                <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
                <span>Refresh</span>
              </button>
            </div>
          </div>

          {/* Alert List Container */}
          <div className="flex-1 soc-card p-2.5 overflow-y-auto min-h-0 space-y-2">
            {loading && alerts.length === 0 ? (
              <div className="flex items-center justify-center h-48 text-slate-500 text-xs font-mono">
                Loading security signals from PostgreSQL...
              </div>
            ) : alerts.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-48 text-slate-500 text-xs p-6 text-center">
                <Check size={28} className="mb-2 text-emerald-400 opacity-60" />
                <div className="font-semibold text-slate-300">No active signals found</div>
                <div className="text-[11px] text-slate-500 mt-0.5">
                  Filters match zero signals or all threats have been acknowledged
                </div>
              </div>
            ) : (
              alerts.map((alert, i) => (
                <AlertCard key={alert.id || alert._id || i} alert={alert} onUpdate={fetchAlerts} />
              ))
            )}
          </div>
        </div>

        {/* Right 4 Cols: Analytics & Required Action Highlight */}
        <div className="col-span-12 lg:col-span-4 flex flex-col gap-3 min-h-0">
          {/* Severity Bar Chart */}
          <div className="soc-card p-3 flex-shrink-0">
            <div className="text-xs font-bold text-slate-200 uppercase tracking-wider mb-2 font-mono">
              Signal Severity Profile
            </div>
            <ResponsiveContainer width="100%" height={160}>
              <BarChart data={sevData} layout="vertical" barSize={12}>
                <XAxis type="number" tick={{ fill: '#64748b', fontSize: 10 }} />
                <YAxis type="category" dataKey="name" tick={{ fill: '#94a3b8', fontSize: 10 }} width={55} />
                <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: 6, fontSize: 11 }} />
                <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                  {sevData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Action Required Banner */}
          <div className="soc-card p-3.5 border-l-4 border-l-rose-500 bg-rose-950/10">
            <div className="flex items-center gap-2 mb-1.5 text-rose-400">
              <AlertTriangle size={15} />
              <span className="text-xs font-bold uppercase tracking-wider font-mono">Triage Backlog</span>
            </div>
            <div className="text-2xl font-bold font-mono text-rose-400">
              {summary?.unacknowledged || 0}
            </div>
            <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">
              Unacknowledged security signals require immediate analyst triage and evidence assessment.
            </p>
          </div>

          {/* Operational Workflow Reference */}
          <div className="soc-card p-3 flex-1 flex flex-col justify-between text-xs space-y-2">
            <div className="text-xs font-bold text-slate-200 uppercase tracking-wider font-mono">
              Analyst Playbook Guidance
            </div>
            <div className="space-y-1.5 text-[11px] text-slate-400">
              <div className="flex items-start gap-2">
                <span className="w-4 h-4 rounded bg-slate-800 text-sky-400 flex items-center justify-center font-mono font-bold text-[10px] flex-shrink-0">1</span>
                <span>Click <strong>AI Triage</strong> to run local Ollama analysis for grounded verdict.</span>
              </div>
              <div className="flex items-start gap-2">
                <span className="w-4 h-4 rounded bg-slate-800 text-sky-400 flex items-center justify-center font-mono font-bold text-[10px] flex-shrink-0">2</span>
                <span>Use <strong>+ Case</strong> to bundle signal telemetry into an investigation.</span>
              </div>
              <div className="flex items-start gap-2">
                <span className="w-4 h-4 rounded bg-slate-800 text-sky-400 flex items-center justify-center font-mono font-bold text-[10px] flex-shrink-0">3</span>
                <span>Execute <strong>SOAR</strong> containment with explicit approval gate.</span>
              </div>
            </div>
            <div className="p-2 rounded bg-slate-900 border border-slate-800 text-[10px] text-slate-500 font-mono">
              Audit log automatically tracks all triage, notes, and containment decisions.
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
