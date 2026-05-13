import { useEffect, useState, useCallback } from 'react'
import { dashboardApi } from '../services/api'
import StatWidget from '../components/StatWidget'
import LiveLogFeed from '../components/LiveLogFeed'
import AlertCard from '../components/AlertCard'
import useStore from '../store/useStore'
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, PieChart, Pie, Cell, LineChart, Line
} from 'recharts'
import {
  Shield, AlertTriangle, Activity, Database,
  Zap, TrendingUp, Globe, Eye
} from 'lucide-react'
import { SEVERITY_COLORS, formatDateTime } from '../utils/constants'

const COLORS = ['#ff3366', '#ff6b35', '#ffaa00', '#3b82f6', '#6b7280']

function SectionHeader({ title, subtitle }) {
  return (
    <div className="mb-3">
      <h2 className="text-sm font-bold text-white">{title}</h2>
      {subtitle && <p className="text-xs text-gray-500">{subtitle}</p>}
    </div>
  )
}

function MiniCard({ children, className = '' }) {
  return (
    <div className={`glass-card p-4 ${className}`}>{children}</div>
  )
}

export default function DashboardPage() {
  const [stats, setStats] = useState(null)
  const [epsHistory, setEpsHistory] = useState([])
  const [topAttackers, setTopAttackers] = useState([])
  const [severityTimeline, setSeverityTimeline] = useState([])
  const [mitreCoverage, setMitreCoverage] = useState([])
  const [loading, setLoading] = useState(true)
  const liveAlerts = useStore(s => s.liveAlerts)
  const eps = useStore(s => s.eps)

  const fetchData = useCallback(async () => {
    try {
      const [statsRes, epsRes, attackersRes, timelineRes, mitreRes] = await Promise.all([
        dashboardApi.stats(),
        dashboardApi.epsHistory(),
        dashboardApi.topAttackers(),
        dashboardApi.severityTimeline(),
        dashboardApi.mitreCoverage(),
      ])
      setStats(statsRes.data)
      setEpsHistory(epsRes.data)
      setTopAttackers(attackersRes.data.slice(0, 8))
      setSeverityTimeline(timelineRes.data.slice(-12))
      setMitreCoverage(mitreRes.data.slice(0, 8))
    } catch (e) {
      console.error('Dashboard fetch error:', e)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 15000)
    return () => clearInterval(interval)
  }, [fetchData])

  const sevBreakdown = stats ? Object.entries(stats.severity_breakdown || {}).map(([k, v]) => ({
    name: k, value: v, color: SEVERITY_COLORS[k] || '#6b7280'
  })) : []

  return (
    <div className="h-full flex flex-col gap-4 animate-fade-in">
      {/* Stat Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3 flex-shrink-0">
        <StatWidget label="Total Events"    value={stats?.total_logs || 0}        icon={Database}      color="#00d4ff" />
        <StatWidget label="Active Alerts"   value={stats?.total_alerts || 0}       icon={Bell}          color="#ff3366" />
        <StatWidget label="Open Incidents"  value={stats?.open_incidents || 0}     icon={AlertTriangle} color="#ffaa00" />
        <StatWidget label="Critical Alerts" value={stats?.critical_alerts || 0}    icon={Shield}        color="#ff3366" />
        <StatWidget label="Investigating"   value={stats?.investigating || 0}      icon={Eye}           color="#a855f7" />
        <StatWidget label="Live EPS"        value={eps}                            icon={Activity}      color="#00ff88" subtitle="Events/sec" />
      </div>

      {/* Main content grid */}
      <div className="flex-1 grid grid-cols-12 gap-4 min-h-0">

        {/* Left: EPS Chart + Severity Timeline */}
        <div className="col-span-8 flex flex-col gap-4">

          {/* EPS Area Chart */}
          <MiniCard>
            <SectionHeader title="Events Per Second — Live" subtitle="Real-time ingestion rate" />
            <ResponsiveContainer width="100%" height={140}>
              <AreaChart data={epsHistory}>
                <defs>
                  <linearGradient id="epsGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#00d4ff" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#00d4ff" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" tick={{ fill: '#4b5563', fontSize: 10 }} interval={9} />
                <YAxis tick={{ fill: '#4b5563', fontSize: 10 }} />
                <Tooltip
                  contentStyle={{ background: '#111827', border: '1px solid #1f2937', borderRadius: 8, color: '#f9fafb', fontSize: 11 }}
                  labelStyle={{ color: '#9ca3af' }}
                />
                <Area type="monotone" dataKey="eps" stroke="#00d4ff" strokeWidth={2} fill="url(#epsGrad)" dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          </MiniCard>

          {/* Severity Timeline Stacked Bar */}
          <MiniCard>
            <SectionHeader title="Event Severity — 24h Timeline" />
            <ResponsiveContainer width="100%" height={150}>
              <BarChart data={severityTimeline} barSize={14}>
                <XAxis dataKey="hour" tick={{ fill: '#4b5563', fontSize: 10 }} />
                <YAxis tick={{ fill: '#4b5563', fontSize: 10 }} />
                <Tooltip contentStyle={{ background: '#111827', border: '1px solid #1f2937', borderRadius: 8, color: '#f9fafb', fontSize: 11 }} />
                <Bar dataKey="critical" stackId="a" fill="#ff3366" />
                <Bar dataKey="high"     stackId="a" fill="#ff6b35" />
                <Bar dataKey="medium"   stackId="a" fill="#ffaa00" />
                <Bar dataKey="low"      stackId="a" fill="#3b82f6" />
              </BarChart>
            </ResponsiveContainer>
          </MiniCard>

          {/* Bottom: Top Attackers + MITRE */}
          <div className="grid grid-cols-2 gap-4">
            {/* Top Attackers */}
            <MiniCard>
              <SectionHeader title="Top Attacker IPs" />
              <div className="space-y-2">
                {topAttackers.slice(0, 6).map((a, i) => (
                  <div key={a.ip} className="flex items-center gap-2">
                    <span className="text-xs text-gray-600 w-4">{i + 1}</span>
                    <span className="font-mono text-xs flex-1 truncate" style={{ color: '#a855f7' }}>{a.ip}</span>
                    <div className="flex-1 max-w-24">
                      <div className="h-1.5 rounded-full bg-gray-800">
                        <div
                          className="h-full rounded-full"
                          style={{
                            width: `${Math.min(100, (a.count / (topAttackers[0]?.count || 1)) * 100)}%`,
                            background: '#ff3366',
                          }}
                        />
                      </div>
                    </div>
                    <span className="text-xs text-gray-400 w-8 text-right">{a.count}</span>
                  </div>
                ))}
              </div>
            </MiniCard>

            {/* MITRE Coverage */}
            <MiniCard>
              <SectionHeader title="MITRE ATT&CK Coverage" />
              <div className="space-y-1.5">
                {mitreCoverage.slice(0, 6).map(m => (
                  <div key={m.technique} className="flex items-center gap-2">
                    <span
                      className="text-xs font-mono px-1.5 py-0.5 rounded flex-shrink-0"
                      style={{ background: '#1f2937', color: '#ffaa00', fontSize: '0.65rem' }}
                    >
                      {m.technique}
                    </span>
                    <div className="flex-1">
                      <div className="h-1.5 rounded-full bg-gray-800">
                        <div
                          className="h-full rounded-full"
                          style={{
                            width: `${Math.min(100, (m.count / (mitreCoverage[0]?.count || 1)) * 100)}%`,
                            background: '#ffaa00',
                          }}
                        />
                      </div>
                    </div>
                    <span className="text-xs text-gray-500">{m.count}</span>
                  </div>
                ))}
              </div>
            </MiniCard>
          </div>
        </div>

        {/* Right panel: Severity Donut + Live Alerts */}
        <div className="col-span-4 flex flex-col gap-4">
          {/* Severity Donut */}
          <MiniCard>
            <SectionHeader title="Severity Distribution" />
            {sevBreakdown.length > 0 ? (
              <>
                <ResponsiveContainer width="100%" height={160}>
                  <PieChart>
                    <Pie
                      data={sevBreakdown}
                      cx="50%" cy="50%"
                      innerRadius={45}
                      outerRadius={70}
                      paddingAngle={3}
                      dataKey="value"
                    >
                      {sevBreakdown.map((entry, i) => (
                        <Cell key={i} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ background: '#111827', border: '1px solid #1f2937', borderRadius: 8, color: '#f9fafb', fontSize: 11 }} />
                  </PieChart>
                </ResponsiveContainer>
                <div className="grid grid-cols-2 gap-1.5">
                  {sevBreakdown.map(s => (
                    <div key={s.name} className="flex items-center gap-1.5">
                      <div className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: s.color }} />
                      <span className="text-xs text-gray-400 capitalize">{s.name}</span>
                      <span className="text-xs font-bold ml-auto" style={{ color: s.color }}>{s.value}</span>
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <div className="h-32 flex items-center justify-center text-gray-600 text-xs">Loading...</div>
            )}
          </MiniCard>

          {/* Live Alert Feed */}
          <div className="flex-1 glass-card overflow-hidden flex flex-col">
            <div className="px-4 py-2.5 flex-shrink-0" style={{ borderBottom: '1px solid #1f2937' }}>
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full animate-pulse" style={{ background: '#ff3366' }} />
                <span className="text-xs font-bold text-white">LIVE ALERTS</span>
                <span className="text-xs text-gray-500 ml-auto">{liveAlerts.length} total</span>
              </div>
            </div>
            <div className="flex-1 overflow-y-auto p-3">
              {liveAlerts.length === 0 ? (
                <div className="flex items-center justify-center h-24 text-gray-600 text-xs">
                  Monitoring for threats...
                </div>
              ) : (
                liveAlerts.slice(0, 20).map((alert, i) => (
                  <AlertCard key={alert._id || i} alert={alert} />
                ))
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Bottom: Live Log Feed */}
      <div className="glass-card overflow-hidden flex-shrink-0" style={{ height: '240px' }}>
        <LiveLogFeed />
      </div>
    </div>
  )
}

function Bell(props) {
  return <AlertTriangle {...props} />
}
