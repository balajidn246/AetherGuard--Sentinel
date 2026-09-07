import { useEffect, useState, useCallback } from 'react'
import { dashboardApi, healthApi } from '../services/api'
import LiveLogFeed from '../components/LiveLogFeed'
import AlertCard from '../components/AlertCard'
import EntityChip from '../components/EntityChip'
import useStore from '../store/useStore'
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, PieChart, Pie, Cell
} from 'recharts'
import {
  Shield, AlertTriangle, Activity, Database,
  TrendingUp, Globe, Eye, Server, RefreshCw, Cpu, Layers, CheckCircle, XCircle
} from 'lucide-react'
import { SEVERITY_COLORS, formatDateTime } from '../utils/constants'

function SectionHeader({ title, subtitle, badge }) {
  return (
    <div className="flex items-center justify-between mb-2">
      <div>
        <h2 className="text-xs font-bold text-slate-200 uppercase tracking-wider">{title}</h2>
        {subtitle && <p className="text-[11px] text-slate-400">{subtitle}</p>}
      </div>
      {badge && (
        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
          {badge}
        </span>
      )}
    </div>
  )
}

export default function DashboardPage() {
  const [stats, setStats] = useState(null)
  const [epsHistory, setEpsHistory] = useState([])
  const [topAttackers, setTopAttackers] = useState([])
  const [topTargets, setTopTargets] = useState([])
  const [severityTimeline, setSeverityTimeline] = useState([])
  const [mitreCoverage, setMitreCoverage] = useState([])
  const [health, setHealth] = useState(null)
  const [loading, setLoading] = useState(true)
  const liveAlerts = useStore(s => s.liveAlerts)
  const eps = useStore(s => s.eps)

  const fetchData = useCallback(async () => {
    try {
      const [statsRes, epsRes, attackersRes, targetsRes, timelineRes, mitreRes, healthRes] = await Promise.all([
        dashboardApi.stats(),
        dashboardApi.epsHistory(),
        dashboardApi.topAttackers(),
        dashboardApi.topTargets(),
        dashboardApi.severityTimeline(),
        dashboardApi.mitreCoverage(),
        healthApi.check(),
      ])
      setStats(statsRes.data)
      setEpsHistory(epsRes.data)
      setTopAttackers(attackersRes.data.slice(0, 8))
      setTopTargets(targetsRes.data?.slice(0, 8) || [])
      setSeverityTimeline(timelineRes.data.slice(-12))
      setMitreCoverage(mitreRes.data.slice(0, 8))
      setHealth(healthRes.data)
    } catch (e) {
      console.error('Dashboard fetch error:', e)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 12000)
    return () => clearInterval(interval)
  }, [fetchData])

  const sevBreakdown = stats ? Object.entries(stats.severity_breakdown || {}).map(([k, v]) => ({
    name: k, value: v, color: SEVERITY_COLORS[k] || '#64748b'
  })) : []

  return (
    <div className="h-full flex flex-col gap-3 animate-fade-in overflow-y-auto">
      {/* Top Security Posture Bar */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-2.5 flex-shrink-0">
        <div className="soc-card p-3 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-[11px] font-medium">Telemetry (24h)</span>
            <Database size={14} className="text-sky-400" />
          </div>
          <div className="text-xl font-bold font-mono text-slate-100 mt-1">
            {(stats?.total_logs || 0).toLocaleString()}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">ClickHouse indexed events</div>
        </div>

        <div className="soc-card p-3 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-[11px] font-medium">Detection Pressure</span>
            <Shield size={14} className="text-rose-400" />
          </div>
          <div className="text-xl font-bold font-mono text-rose-400 mt-1">
            {stats?.total_alerts || 0}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">Active security signals</div>
        </div>

        <div className="soc-card p-3 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-[11px] font-medium">Critical Threats</span>
            <AlertTriangle size={14} className="text-orange-400" />
          </div>
          <div className="text-xl font-bold font-mono text-orange-400 mt-1">
            {stats?.critical_alerts || 0}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">Requiring analyst action</div>
        </div>

        <div className="soc-card p-3 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-[11px] font-medium">Open Incidents</span>
            <Layers size={14} className="text-amber-400" />
          </div>
          <div className="text-xl font-bold font-mono text-amber-400 mt-1">
            {stats?.open_incidents || 0}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">In active response cycle</div>
        </div>

        <div className="soc-card p-3 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-[11px] font-medium">Investigating</span>
            <Eye size={14} className="text-indigo-400" />
          </div>
          <div className="text-xl font-bold font-mono text-indigo-400 mt-1">
            {stats?.investigating || 0}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">Active triage cases</div>
        </div>

        <div className="soc-card p-3 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-[11px] font-medium">Ingestion Rate</span>
            <Activity size={14} className="text-emerald-400" />
          </div>
          <div className="text-xl font-bold font-mono text-emerald-400 mt-1">
            {eps} <span className="text-xs font-normal text-slate-400">EPS</span>
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">Live syslog & HTTP rate</div>
        </div>
      </div>

      {/* Infrastructure Health Strip */}
      {health && (
        <div className="soc-card px-3.5 py-1.5 flex items-center gap-6 flex-shrink-0 text-xs">
          <div className="flex items-center gap-1.5 text-slate-400 font-medium font-mono text-[11px]">
            <Server size={12} className="text-slate-400" />
            <span>CORE SERVICES:</span>
          </div>
          {[
            { label: 'PostgreSQL', status: health.database?.postgres },
            { label: 'ClickHouse', status: health.database?.clickhouse },
            { label: 'Redis',      status: health.redis },
            { label: 'Ollama AI',  status: health.ai },
          ].map(({ label, status }) => (
            <div key={label} className="flex items-center gap-1.5">
              <div className={`w-1.5 h-1.5 rounded-full ${status === 'healthy' ? 'bg-emerald-400' : 'bg-rose-500'}`} />
              <span className="text-slate-300">{label}</span>
              <span className={`text-[10px] font-mono uppercase ${status === 'healthy' ? 'text-emerald-400' : 'text-rose-400'}`}>
                {status || 'down'}
              </span>
            </div>
          ))}
          <div className="ml-auto flex items-center gap-2 text-slate-500 font-mono text-[11px]">
            <span>{health.websocket_clients || 0} WS Client(s)</span>
            <button
              onClick={fetchData}
              className="p-1 text-slate-400 hover:text-white"
              title="Refresh telemetry"
            >
              <RefreshCw size={12} />
            </button>
          </div>
        </div>
      )}

      {/* Main Grid: Charts & Feeds */}
      <div className="grid grid-cols-12 gap-3 min-h-[420px]">
        {/* Left 8 Cols: Charts + Threat Entities */}
        <div className="col-span-12 lg:col-span-8 flex flex-col gap-3">
          {/* EPS Area Chart */}
          <div className="soc-card p-3.5 flex-1">
            <SectionHeader
              title="Telemetry Ingestion Velocity"
              subtitle="Events per second (EPS) moving window across all ingest interfaces"
              badge="CLICKHOUSE BUFFER"
            />
            <ResponsiveContainer width="100%" height={140}>
              <AreaChart data={epsHistory}>
                <defs>
                  <linearGradient id="epsGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#0284c7" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#0284c7" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" tick={{ fill: '#64748b', fontSize: 10 }} interval={9} />
                <YAxis tick={{ fill: '#64748b', fontSize: 10 }} />
                <Tooltip
                  contentStyle={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: 6, fontSize: 11 }}
                  labelStyle={{ color: '#94a3b8' }}
                />
                <Area type="monotone" dataKey="eps" stroke="#38bdf8" strokeWidth={1.5} fill="url(#epsGrad)" dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {/* Severity Timeline */}
          <div className="soc-card p-3.5 flex-1">
            <SectionHeader
              title="24-Hour Severity Telemetry Distribution"
              subtitle="Aggregated event distribution classified by normalized security severity"
            />
            <ResponsiveContainer width="100%" height={130}>
              <BarChart data={severityTimeline} barSize={12}>
                <XAxis dataKey="hour" tick={{ fill: '#64748b', fontSize: 10 }} />
                <YAxis tick={{ fill: '#64748b', fontSize: 10 }} />
                <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: 6, fontSize: 11 }} />
                <Bar dataKey="critical" stackId="a" fill="#ef4444" />
                <Bar dataKey="high"     stackId="a" fill="#f97316" />
                <Bar dataKey="medium"   stackId="a" fill="#eab308" />
                <Bar dataKey="low"      stackId="a" fill="#3b82f6" />
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Bottom Row: Top Attackers & MITRE ATT&CK */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {/* Top Attacker IPs */}
            <div className="soc-card p-3">
              <SectionHeader title="Top Threat Actor IPs" subtitle="Click entity chip to pivot or contain" />
              <div className="space-y-1.5 mt-2">
                {topAttackers.length === 0 ? (
                  <div className="text-center py-6 text-slate-500 text-xs">No active external attacker IPs recorded</div>
                ) : (
                  topAttackers.slice(0, 5).map((a, i) => (
                    <div key={a.ip} className="flex items-center gap-2 text-xs">
                      <span className="font-mono text-slate-500 w-3">{i + 1}</span>
                      <div className="flex-1 min-w-0">
                        <EntityChip type="ip" value={a.ip} />
                      </div>
                      <div className="w-20">
                        <div className="h-1.5 rounded-full bg-slate-800">
                          <div
                            className="h-full rounded-full bg-rose-500"
                            style={{
                              width: `${Math.min(100, (a.count / (topAttackers[0]?.count || 1)) * 100)}%`,
                            }}
                          />
                        </div>
                      </div>
                      <span className="font-mono text-slate-400 w-10 text-right">{a.count}</span>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* MITRE Coverage */}
            <div className="soc-card p-3">
              <SectionHeader title="MITRE ATT&CK Detections" subtitle="Active tactics matched by detection engine" />
              <div className="space-y-1.5 mt-2">
                {mitreCoverage.length === 0 ? (
                  <div className="text-center py-6 text-slate-500 text-xs">No MITRE techniques matched in current window</div>
                ) : (
                  mitreCoverage.slice(0, 5).map(m => (
                    <div key={m.technique} className="flex items-center gap-2 text-xs">
                      <span
                        className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-amber-300 border border-slate-700 flex-shrink-0"
                      >
                        {m.technique}
                      </span>
                      <div className="flex-1">
                        <div className="h-1.5 rounded-full bg-slate-800">
                          <div
                            className="h-full rounded-full bg-amber-500"
                            style={{
                              width: `${Math.min(100, (m.count / (mitreCoverage[0]?.count || 1)) * 100)}%`,
                            }}
                          />
                        </div>
                      </div>
                      <span className="font-mono text-slate-400 text-xs">{m.count} hits</span>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Right 4 Cols: Live Alerts Stream + Severity Donut */}
        <div className="col-span-12 lg:col-span-4 flex flex-col gap-3">
          {/* Severity Donut */}
          <div className="soc-card p-3 flex-shrink-0">
            <SectionHeader title="Severity Breakdown" />
            {sevBreakdown.length > 0 ? (
              <div className="flex items-center gap-3">
                <ResponsiveContainer width={130} height={120}>
                  <PieChart>
                    <Pie
                      data={sevBreakdown}
                      cx="50%" cy="50%"
                      innerRadius={36}
                      outerRadius={54}
                      paddingAngle={2}
                      dataKey="value"
                    >
                      {sevBreakdown.map((entry, i) => (
                        <Cell key={i} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: 6, fontSize: 10 }} />
                  </PieChart>
                </ResponsiveContainer>
                <div className="flex-1 space-y-1">
                  {sevBreakdown.map(s => (
                    <div key={s.name} className="flex items-center justify-between text-xs">
                      <div className="flex items-center gap-1.5">
                        <div className="w-2 h-2 rounded-full" style={{ background: s.color }} />
                        <span className="text-slate-400 capitalize">{s.name}</span>
                      </div>
                      <span className="font-mono font-bold" style={{ color: s.color }}>{s.value}</span>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="h-24 flex items-center justify-center text-slate-600 text-xs font-mono">
                Calculating breakdown...
              </div>
            )}
          </div>

          {/* Live Security Signals */}
          <div className="soc-card flex-1 flex flex-col min-h-[300px] overflow-hidden">
            <div className="px-3 py-2 border-b border-slate-800 bg-slate-900/60 flex items-center justify-between flex-shrink-0">
              <div className="flex items-center gap-2">
                <Shield size={13} className="text-rose-400" />
                <span className="text-xs font-bold text-slate-200 uppercase tracking-wider">Active Signals Queue</span>
              </div>
              <span className="text-[10px] font-mono text-slate-400 bg-slate-800 px-1.5 py-0.5 rounded">
                {liveAlerts.length} buffered
              </span>
            </div>
            <div className="flex-1 overflow-y-auto p-2 space-y-2">
              {liveAlerts.length === 0 ? (
                <div className="h-40 flex flex-col items-center justify-center text-slate-500 text-xs text-center p-4">
                  <Shield size={24} className="mb-2 text-slate-600" />
                  <p>All clear — detection engine active</p>
                  <p className="text-[11px] text-slate-600 mt-1">Signals will appear here upon rule match</p>
                </div>
              ) : (
                liveAlerts.slice(0, 15).map((alert, i) => (
                  <AlertCard key={alert._id || i} alert={alert} onUpdate={fetchData} />
                ))
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Bottom: Docked Live Log Stream */}
      <div className="h-56 flex-shrink-0">
        <LiveLogFeed />
      </div>
    </div>
  )
}
