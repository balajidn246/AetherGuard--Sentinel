import { useState, useEffect } from 'react'
import { auditApi } from '../services/api'
import { ShieldCheck, Search, Filter, History, User, Activity, ArrowUpDown } from 'lucide-react'

export default function AuditPage() {
  const [logs, setLogs] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [actionFilter, setActionFilter] = useState('')
  const [actorFilter, setActorFilter] = useState('')
  const [availableActions, setAvailableActions] = useState([])

  const fetchLogs = async () => {
    setLoading(true)
    try {
      const params = { limit: 100 }
      if (actionFilter) params.action = actionFilter
      if (actorFilter) params.actor = actorFilter
      const res = await auditApi.list(params)
      setLogs(res.data.audit_logs || [])
      setTotal(res.data.total || 0)
    } catch (err) {
      console.error('Error fetching audit logs:', err)
    } finally {
      setLoading(false)
    }
  }

  const fetchActions = async () => {
    try {
      const res = await auditApi.actions()
      setAvailableActions(res.data.actions || [])
    } catch (err) {
      console.error('Error fetching actions:', err)
    }
  }

  useEffect(() => {
    fetchActions()
  }, [])

  useEffect(() => {
    fetchLogs()
  }, [actionFilter, actorFilter])

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <History className="text-cyan-400" size={22} />
            Compliance & Audit Trails
          </h1>
          <p className="text-xs text-gray-400 mt-0.5">
            Immutable, cryptographically verifiable log of all administrative actions and security responses ({total} total)
          </p>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="flex flex-wrap items-center gap-3 p-3 glass-card">
        <div className="flex items-center gap-2 text-xs text-gray-400">
          <Filter size={14} />
          <span>Filters:</span>
        </div>
        <select
          value={actionFilter}
          onChange={(e) => setActionFilter(e.target.value)}
          className="cyber-input text-xs py-1"
        >
          <option value="">All Actions</option>
          {availableActions.map((act) => (
            <option key={act} value={act}>
              {act}
            </option>
          ))}
        </select>
        <input
          type="text"
          value={actorFilter}
          onChange={(e) => setActorFilter(e.target.value)}
          placeholder="Filter by actor (e.g. admin)..."
          className="cyber-input text-xs py-1"
        />
      </div>

      {/* Audit Log Table */}
      <div className="glass-card overflow-hidden">
        <table className="cyber-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Actor</th>
              <th>Action</th>
              <th>Resource / ID</th>
              <th>Details</th>
              <th>IP Address</th>
              <th>Result</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={7} className="text-center py-8 text-gray-500">
                  Loading audit logs...
                </td>
              </tr>
            ) : logs.length === 0 ? (
              <tr>
                <td colSpan={7} className="text-center py-8 text-gray-500">
                  No audit trail records found.
                </td>
              </tr>
            ) : (
              logs.map((item) => (
                <tr key={item.id} className="transition-colors hover:bg-gray-800/30">
                  <td className="font-mono text-xs text-gray-400">
                    {item.timestamp ? new Date(item.timestamp).toLocaleString() : '—'}
                  </td>
                  <td>
                    <div className="flex items-center gap-1.5 font-semibold text-gray-200 text-xs">
                      <User size={12} className="text-cyan-400" />
                      <span>{item.actor}</span>
                    </div>
                  </td>
                  <td>
                    <span className="font-mono text-xs text-purple-300 bg-purple-950/30 px-2 py-0.5 rounded border border-purple-800/40">
                      {item.action}
                    </span>
                  </td>
                  <td>
                    <div className="text-xs text-gray-300 font-medium">{item.resource}</div>
                    {item.resource_id && (
                      <div className="text-[10px] text-gray-500 font-mono">{item.resource_id.slice(0, 8)}...</div>
                    )}
                  </td>
                  <td>
                    <div className="text-xs text-gray-400 max-w-xs truncate font-mono">
                      {JSON.stringify(item.details)}
                    </div>
                  </td>
                  <td className="text-xs font-mono text-gray-400">
                    {item.ip_address || 'local'}
                  </td>
                  <td>
                    <span className={`badge ${item.result === 'success' ? 'badge-low text-green-400 border-green-500/30 bg-green-950/20' : 'badge-critical'}`}>
                      {item.result}
                    </span>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
