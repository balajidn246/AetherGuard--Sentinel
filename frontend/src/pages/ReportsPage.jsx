import { useState, useEffect } from 'react'
import { reportsApi } from '../services/api'
import { Download, FileText, BarChart3, AlertTriangle, RefreshCw } from 'lucide-react'
import { formatDateTime } from '../utils/constants'
import { toast } from 'react-toastify'

export default function ReportsPage() {
  const [summary, setSummary] = useState(null)
  const [loading, setLoading] = useState(false)

  const fetchSummary = async () => {
    setLoading(true)
    try {
      const res = await reportsApi.summary()
      setSummary(res.data)
    } catch (e) { console.error(e) }
    finally { setLoading(false) }
  }

  useEffect(() => { fetchSummary() }, [])

  const downloadCsv = (url) => {
    const token = localStorage.getItem('ag_token')
    // Open with token as query param — backend accepts Bearer via header but
    // direct browser downloads can't set headers, so we temporarily bypass
    // by building a link with Authorization embedded via fetch+blob download.
    fetch(`http://localhost:8000${url}`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then(res => {
        if (!res.ok) throw new Error('Export failed')
        return res.blob()
      })
      .then(blob => {
        const filename = url.split('/').pop().replace('csv', '') + `${Date.now()}.csv`
        const a = document.createElement('a')
        a.href = URL.createObjectURL(blob)
        a.download = filename
        a.click()
        URL.revokeObjectURL(a.href)
        toast.success('Download started')
      })
      .catch(() => toast.error('Export failed — check connection'))
  }

  const EXPORTS = [
    { label: 'Export Logs CSV', desc: 'Last 1000 log events', icon: FileText, url: '/api/reports/logs/csv', color: '#00d4ff' },
    { label: 'Export Alerts CSV', desc: 'All alert records', icon: AlertTriangle, url: '/api/reports/alerts/csv', color: '#ff3366' },
    { label: 'Export Incidents CSV', desc: 'All incidents', icon: BarChart3, url: '/api/reports/incidents/csv', color: '#ffaa00' },
  ]

  return (
    <div className="flex flex-col gap-4 h-full animate-fade-in">
      {/* Summary Cards */}
      {summary && (
        <div className="grid grid-cols-4 gap-3 flex-shrink-0">
          {[
            { label: 'Total Log Events', value: summary.statistics?.total_logs, color: '#00d4ff' },
            { label: 'Total Alerts', value: summary.statistics?.total_alerts, color: '#ff3366' },
            { label: 'Open Incidents', value: summary.statistics?.open_incidents, color: '#ffaa00' },
            { label: 'Critical Alerts', value: summary.statistics?.critical_alerts, color: '#ff3366' },
          ].map(({ label, value, color }) => (
            <div key={label} className="glass-card p-4">
              <div className="text-xs text-gray-500 mb-1">{label}</div>
              <div className="text-2xl font-bold" style={{ color }}>{(value || 0).toLocaleString()}</div>
            </div>
          ))}
        </div>
      )}

      <div className="flex-1 grid grid-cols-12 gap-4 min-h-0">
        {/* Export Cards */}
        <div className="col-span-5 flex flex-col gap-3">
          <div className="glass-card p-4">
            <div className="flex items-center gap-2 mb-4">
              <Download size={14} color="#00d4ff" />
              <span className="text-sm font-bold text-white">Data Export</span>
            </div>
            <div className="space-y-3">
              {EXPORTS.map(({ label, desc, icon: Icon, url, color }) => (
                <div
                  key={url}
                  className="flex items-center justify-between p-4 rounded-xl transition-all hover:scale-[1.01]"
                  style={{ background: '#1f2937', border: `1px solid ${color}22` }}
                >
                  <div className="flex items-center gap-3">
                    <div className="w-9 h-9 rounded-lg flex items-center justify-center" style={{ background: `${color}18`, border: `1px solid ${color}33` }}>
                      <Icon size={16} color={color} />
                    </div>
                    <div>
                      <div className="text-sm font-medium text-gray-200">{label}</div>
                      <div className="text-xs text-gray-500">{desc}</div>
                    </div>
                  </div>
                  <button
                    onClick={() => downloadCsv(url)}
                    className="btn-cyber"
                    style={{ background: `${color}15`, color, border: `1px solid ${color}44`, padding: '6px 14px' }}
                  >
                    <Download size={12} /> CSV
                  </button>
                </div>
              ))}
            </div>
          </div>

          {/* Report generation info */}
          <div className="glass-card p-4">
            <div className="text-xs font-bold text-white mb-3">Report Info</div>
            {summary && (
              <div className="space-y-2 text-xs">
                <div className="flex justify-between">
                  <span className="text-gray-500">Generated at</span>
                  <span className="text-gray-300">{formatDateTime(summary.generated_at)}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Generated by</span>
                  <span className="text-gray-300">{summary.generated_by}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Period</span>
                  <span className="text-gray-300">{summary.report_period}</span>
                </div>
              </div>
            )}
            <button className="btn-cyber btn-cyber-primary mt-3 w-full justify-center" onClick={fetchSummary}>
              <RefreshCw size={12} /> Refresh Report
            </button>
          </div>
        </div>

        {/* Severity breakdown */}
        <div className="col-span-7 glass-card p-4">
          <div className="text-sm font-bold text-white mb-4">Alert Severity Breakdown</div>
          {summary?.severity_breakdown ? (
            <div className="space-y-4">
              {Object.entries(summary.severity_breakdown).map(([sev, count]) => {
                const colors = { critical: '#ff3366', high: '#ff6b35', medium: '#ffaa00', low: '#3b82f6', info: '#6b7280' }
                const total = Object.values(summary.severity_breakdown).reduce((a, b) => a + b, 0)
                const pct = total > 0 ? Math.round((count / total) * 100) : 0
                const color = colors[sev] || '#6b7280'
                return (
                  <div key={sev}>
                    <div className="flex justify-between text-xs mb-1.5">
                      <span className="capitalize text-gray-300 font-medium">{sev}</span>
                      <span style={{ color }}>{count.toLocaleString()} ({pct}%)</span>
                    </div>
                    <div className="h-2.5 rounded-full bg-gray-800 overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all duration-500"
                        style={{ width: `${pct}%`, background: `linear-gradient(90deg, ${color}, ${color}88)` }}
                      />
                    </div>
                  </div>
                )
              })}
            </div>
          ) : (
            <div className="flex items-center justify-center h-full text-gray-600 text-sm">
              {loading ? 'Loading...' : 'No data available'}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
