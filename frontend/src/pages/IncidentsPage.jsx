import { useState, useEffect, useCallback } from 'react'
import { incidentsApi } from '../services/api'
import { Plus, RefreshCw, ChevronRight, Clock, User, Tag, X, Send } from 'lucide-react'
import { formatDateTime, STATUS_COLORS, INCIDENT_STATUSES, severityBadgeClass } from '../utils/constants'
import { toast } from 'react-toastify'

function StatusBadge({ status }) {
  const color = STATUS_COLORS[status] || '#6b7280'
  return (
    <span
      className="badge"
      style={{ background: `${color}22`, color, border: `1px solid ${color}44` }}
    >
      {status}
    </span>
  )
}

function IncidentModal({ incident, onClose, onUpdate }) {
  const [notes, setNotes] = useState('')
  const [noteLoading, setNoteLoading] = useState(false)

  const transitions = {
    open: ['investigating', 'closed'],
    investigating: ['contained', 'resolved', 'open'],
    contained: ['resolved', 'investigating'],
    resolved: ['closed', 'investigating'],
    closed: [],
  }

  const doTransition = async (status) => {
    try {
      await incidentsApi.transition(incident._id, status)
      toast.success(`Status → ${status}`)
      onUpdate()
      onClose()
    } catch (e) { toast.error('Transition failed') }
  }

  const addNote = async () => {
    if (!notes.trim()) return
    setNoteLoading(true)
    try {
      await incidentsApi.addNote(incident._id, notes)
      toast.success('Note added')
      setNotes('')
      onUpdate()
    } catch { toast.error('Failed to add note') }
    finally { setNoteLoading(false) }
  }

  const available = transitions[incident.status] || []

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ background: 'rgba(0,0,0,0.8)' }}>
      <div className="glass-card w-full max-w-2xl max-h-[85vh] flex flex-col" style={{ border: '1px solid #1f2937' }}>
        <div className="flex items-center justify-between p-4 flex-shrink-0" style={{ borderBottom: '1px solid #1f2937' }}>
          <div className="flex items-center gap-2">
            <StatusBadge status={incident.status} />
            <span className="font-bold text-sm text-white truncate max-w-xs">{incident.title}</span>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-white"><X size={16} /></button>
        </div>

        <div className="overflow-y-auto flex-1 p-4 space-y-4">
          {/* Details */}
          <div className="grid grid-cols-2 gap-3">
            <div><span className="text-xs text-gray-500">Severity</span><div className="mt-1"><span className={severityBadgeClass(incident.severity)}>{incident.severity}</span></div></div>
            <div><span className="text-xs text-gray-500">Assigned To</span><div className="text-sm text-white mt-1">{incident.assigned_to || '—'}</div></div>
            <div><span className="text-xs text-gray-500">Created</span><div className="text-xs text-gray-300 mt-1">{formatDateTime(incident.created_at)}</div></div>
            <div><span className="text-xs text-gray-500">Source IP</span><div className="text-xs font-mono mt-1" style={{ color: '#a855f7' }}>{incident.source_ip || '—'}</div></div>
          </div>

          <div>
            <span className="text-xs text-gray-500">Description</span>
            <p className="text-sm text-gray-300 mt-1">{incident.description}</p>
          </div>

          {incident.mitre_techniques?.length > 0 && (
            <div>
              <span className="text-xs text-gray-500">MITRE ATT&CK</span>
              <div className="flex flex-wrap gap-1.5 mt-1">
                {incident.mitre_techniques.map(t => (
                  <span key={t} className="text-xs px-2 py-0.5 rounded font-mono" style={{ background: '#1f2937', color: '#ffaa00' }}>{t}</span>
                ))}
              </div>
            </div>
          )}

          {/* Timeline */}
          {incident.timeline?.length > 0 && (
            <div>
              <span className="text-xs text-gray-500 block mb-2">Timeline</span>
              <div className="space-y-2">
                {incident.timeline.map((t, i) => (
                  <div key={i} className="flex gap-3 text-xs">
                    <span className="text-gray-600 whitespace-nowrap">{formatDateTime(t.ts)}</span>
                    <span className="text-gray-400">{t.note}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Notes */}
          {incident.notes?.length > 0 && (
            <div>
              <span className="text-xs text-gray-500 block mb-2">Analyst Notes</span>
              {incident.notes.map((n, i) => (
                <div key={i} className="p-3 rounded-lg mb-2 text-xs" style={{ background: '#1f2937' }}>
                  <div className="flex items-center gap-2 mb-1">
                    <User size={10} color="#00d4ff" />
                    <span style={{ color: '#00d4ff' }}>{n.author}</span>
                    <span className="text-gray-500">{formatDateTime(n.ts)}</span>
                  </div>
                  <p className="text-gray-300">{n.content}</p>
                </div>
              ))}
            </div>
          )}

          {/* Add note */}
          <div>
            <span className="text-xs text-gray-500 block mb-1.5">Add Note</span>
            <div className="flex gap-2">
              <textarea
                className="cyber-input flex-1 text-xs resize-none"
                rows={2}
                placeholder="Add analyst note..."
                value={notes}
                onChange={e => setNotes(e.target.value)}
              />
              <button className="btn-cyber btn-cyber-primary self-end" onClick={addNote} disabled={noteLoading}>
                <Send size={12} />
              </button>
            </div>
          </div>
        </div>

        {/* Workflow transitions */}
        {available.length > 0 && (
          <div className="p-4 flex-shrink-0 flex items-center gap-2" style={{ borderTop: '1px solid #1f2937' }}>
            <span className="text-xs text-gray-500">Transition:</span>
            {available.map(s => (
              <button
                key={s}
                onClick={() => doTransition(s)}
                className="btn-cyber"
                style={{ background: `${STATUS_COLORS[s]}22`, color: STATUS_COLORS[s], border: `1px solid ${STATUS_COLORS[s]}44`, padding: '4px 12px' }}
              >
                → {s}
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

function CreateIncidentModal({ onClose, onCreated }) {
  const [form, setForm] = useState({ title: '', description: '', severity: 'medium', assigned_to: '' })
  const [loading, setLoading] = useState(false)

  const submit = async () => {
    if (!form.title) { toast.error('Title required'); return }
    setLoading(true)
    try {
      await incidentsApi.create(form)
      toast.success('Incident created')
      onCreated()
      onClose()
    } catch { toast.error('Failed to create') }
    finally { setLoading(false) }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ background: 'rgba(0,0,0,0.8)' }}>
      <div className="glass-card w-full max-w-md" style={{ border: '1px solid #1f2937' }}>
        <div className="flex items-center justify-between p-4" style={{ borderBottom: '1px solid #1f2937' }}>
          <span className="font-bold text-sm text-white">Create Incident</span>
          <button onClick={onClose} className="text-gray-500 hover:text-white"><X size={16} /></button>
        </div>
        <div className="p-4 space-y-3">
          <div>
            <label className="text-xs text-gray-400 block mb-1">Title *</label>
            <input className="cyber-input w-full" value={form.title} onChange={e => setForm(f => ({ ...f, title: e.target.value }))} placeholder="Incident title" />
          </div>
          <div>
            <label className="text-xs text-gray-400 block mb-1">Description</label>
            <textarea className="cyber-input w-full resize-none" rows={3} value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-gray-400 block mb-1">Severity</label>
              <select className="cyber-input w-full" value={form.severity} onChange={e => setForm(f => ({ ...f, severity: e.target.value }))}>
                {['critical','high','medium','low'].map(s => <option key={s} value={s}>{s.toUpperCase()}</option>)}
              </select>
            </div>
            <div>
              <label className="text-xs text-gray-400 block mb-1">Assign To</label>
              <input className="cyber-input w-full" value={form.assigned_to} onChange={e => setForm(f => ({ ...f, assigned_to: e.target.value }))} placeholder="analyst" />
            </div>
          </div>
          <button className="btn-cyber btn-cyber-primary w-full justify-center" onClick={submit} disabled={loading}>
            Create Incident
          </button>
        </div>
      </div>
    </div>
  )
}

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState([])
  const [stats, setStats] = useState(null)
  const [selectedIncident, setSelectedIncident] = useState(null)
  const [showCreate, setShowCreate] = useState(false)
  const [statusFilter, setStatusFilter] = useState('')
  const [loading, setLoading] = useState(false)

  const fetchIncidents = useCallback(async () => {
    setLoading(true)
    try {
      const params = { limit: 200 }
      if (statusFilter) params.status = statusFilter
      const [incRes, statsRes] = await Promise.all([
        incidentsApi.list(params),
        incidentsApi.stats(),
      ])
      setIncidents(incRes.data.incidents)
      setStats(statsRes.data)
    } catch (e) { console.error(e) }
    finally { setLoading(false) }
  }, [statusFilter])

  useEffect(() => { fetchIncidents() }, [fetchIncidents])

  return (
    <div className="flex flex-col gap-4 h-full animate-fade-in">
      {/* Status bar */}
      <div className="grid grid-cols-5 gap-3 flex-shrink-0">
        {INCIDENT_STATUSES.map(s => (
          <button
            key={s}
            onClick={() => setStatusFilter(statusFilter === s ? '' : s)}
            className="glass-card p-3 text-left transition-all hover:scale-[1.02]"
            style={{
              borderLeft: `3px solid ${STATUS_COLORS[s]}`,
              opacity: statusFilter && statusFilter !== s ? 0.5 : 1,
            }}
          >
            <div className="text-xs text-gray-400 capitalize mb-1">{s}</div>
            <div className="text-xl font-bold" style={{ color: STATUS_COLORS[s] }}>
              {stats?.by_status?.[s] || 0}
            </div>
          </button>
        ))}
      </div>

      {/* Toolbar */}
      <div className="flex items-center gap-3 flex-shrink-0">
        <span className="text-sm font-bold text-white">{incidents.length} Incidents</span>
        <button className="btn-cyber btn-cyber-primary ml-auto" onClick={fetchIncidents}>
          <RefreshCw size={12} /> Refresh
        </button>
        <button className="btn-cyber btn-cyber-success" onClick={() => setShowCreate(true)}>
          <Plus size={12} /> New Incident
        </button>
      </div>

      {/* Incidents Table */}
      <div className="flex-1 glass-card overflow-hidden">
        <div className="overflow-auto h-full">
          <table className="cyber-table">
            <thead className="sticky top-0">
              <tr>
                <th>Title</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Assigned To</th>
                <th>Source IP</th>
                <th>Created</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={7} className="text-center py-12 text-gray-500">Loading...</td></tr>
              ) : incidents.length === 0 ? (
                <tr><td colSpan={7} className="text-center py-12 text-gray-600">No incidents found</td></tr>
              ) : incidents.map((inc, i) => (
                <tr key={inc._id || i} className="cursor-pointer" onClick={() => setSelectedIncident(inc)}>
                  <td className="max-w-xs">
                    <div className="text-xs font-medium text-gray-200 truncate">{inc.title}</div>
                    {inc.mitre_techniques?.length > 0 && (
                      <div className="flex gap-1 mt-1">
                        {inc.mitre_techniques.slice(0, 2).map(t => (
                          <span key={t} className="text-xs px-1 rounded font-mono" style={{ background: '#1f2937', color: '#ffaa00', fontSize: '0.6rem' }}>{t}</span>
                        ))}
                      </div>
                    )}
                  </td>
                  <td><span className={severityBadgeClass(inc.severity)}>{inc.severity}</span></td>
                  <td><StatusBadge status={inc.status} /></td>
                  <td><span className="text-xs text-gray-300">{inc.assigned_to || '—'}</span></td>
                  <td className="font-mono text-xs" style={{ color: '#a855f7' }}>{inc.source_ip || '—'}</td>
                  <td className="text-xs text-gray-500 whitespace-nowrap">{formatDateTime(inc.created_at)}</td>
                  <td><ChevronRight size={14} className="text-gray-600" /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {selectedIncident && (
        <IncidentModal
          incident={selectedIncident}
          onClose={() => setSelectedIncident(null)}
          onUpdate={fetchIncidents}
        />
      )}
      {showCreate && (
        <CreateIncidentModal
          onClose={() => setShowCreate(false)}
          onCreated={fetchIncidents}
        />
      )}
    </div>
  )
}
