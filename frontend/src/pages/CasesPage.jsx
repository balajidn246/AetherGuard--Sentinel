import { useState, useEffect } from 'react'
import { casesApi, alertsApi } from '../services/api'
import { FolderGit2, Plus, Search, Filter, MessageSquare, ShieldAlert, CheckCircle, Clock } from 'lucide-react'

export default function CasesPage() {
  const [cases, setCases] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [statusFilter, setStatusFilter] = useState('')
  const [priorityFilter, setPriorityFilter] = useState('')
  const [selectedCase, setSelectedCase] = useState(null)
  const [newNote, setNewNote] = useState('')
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [newTitle, setNewTitle] = useState('')
  const [newDesc, setNewDesc] = useState('')
  const [newPriority, setNewPriority] = useState('medium')

  const fetchCases = async () => {
    setLoading(true)
    try {
      const params = {}
      if (statusFilter) params.status = statusFilter
      if (priorityFilter) params.priority = priorityFilter
      const res = await casesApi.list(params)
      setCases(res.data.cases || [])
      setTotal(res.data.total || 0)
    } catch (err) {
      console.error('Error fetching cases:', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchCases()
  }, [statusFilter, priorityFilter])

  const handleCreateCase = async (e) => {
    e.preventDefault()
    if (!newTitle.trim()) return
    try {
      await casesApi.create({
        title: newTitle,
        description: newDesc,
        priority: newPriority,
      })
      setShowCreateModal(false)
      setNewTitle('')
      setNewDesc('')
      fetchCases()
    } catch (err) {
      console.error('Error creating case:', err)
    }
  }

  const handleAddNote = async (caseId) => {
    if (!newNote.trim()) return
    try {
      await casesApi.addNote(caseId, newNote)
      setNewNote('')
      // Refresh selected case
      const res = await casesApi.get(caseId)
      setSelectedCase(res.data)
      fetchCases()
    } catch (err) {
      console.error('Error adding note:', err)
    }
  }

  const handleStatusChange = async (caseId, newStatus) => {
    try {
      await casesApi.update(caseId, { status: newStatus })
      const res = await casesApi.get(caseId)
      setSelectedCase(res.data)
      fetchCases()
    } catch (err) {
      console.error('Error updating status:', err)
    }
  }

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <FolderGit2 className="text-cyan-400" size={22} />
            Case Management
          </h1>
          <p className="text-xs text-gray-400 mt-0.5">
            Structured SOC investigations, evidence preservation, and response tracking ({total} total)
          </p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="btn-cyber btn-cyber-primary"
        >
          <Plus size={15} />
          New Investigation Case
        </button>
      </div>

      {/* Filter Bar */}
      <div className="flex flex-wrap items-center gap-3 p-3 glass-card">
        <div className="flex items-center gap-2 text-xs text-gray-400">
          <Filter size={14} />
          <span>Filters:</span>
        </div>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="cyber-input text-xs py-1"
        >
          <option value="">All Statuses</option>
          <option value="open">Open</option>
          <option value="investigating">Investigating</option>
          <option value="contained">Contained</option>
          <option value="resolved">Resolved</option>
          <option value="closed">Closed</option>
        </select>
        <select
          value={priorityFilter}
          onChange={(e) => setPriorityFilter(e.target.value)}
          className="cyber-input text-xs py-1"
        >
          <option value="">All Priorities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>

      {/* Main Grid: Cases List + Detail Drawer */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Table / List */}
        <div className="lg:col-span-2 glass-card overflow-hidden">
          <table className="cyber-table">
            <thead>
              <tr>
                <th>Title / ID</th>
                <th>Priority</th>
                <th>Status</th>
                <th>Owner</th>
                <th>Evidence</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={6} className="text-center py-8 text-gray-500">
                    Loading cases...
                  </td>
                </tr>
              ) : cases.length === 0 ? (
                <tr>
                  <td colSpan={6} className="text-center py-8 text-gray-500">
                    No investigation cases found matching filters.
                  </td>
                </tr>
              ) : (
                cases.map((c) => (
                  <tr
                    key={c.id}
                    onClick={() => setSelectedCase(c)}
                    className={`cursor-pointer transition-colors ${selectedCase?.id === c.id ? 'bg-cyan-500/10' : ''}`}
                  >
                    <td>
                      <div className="font-semibold text-gray-200 text-sm">{c.title}</div>
                      <div className="text-xs text-gray-500 font-mono">{c.id.slice(0, 8)}...</div>
                    </td>
                    <td>
                      <span className={`badge badge-${c.priority}`}>
                        {c.priority}
                      </span>
                    </td>
                    <td>
                      <span className="text-xs font-mono uppercase text-gray-300">
                        {c.status}
                      </span>
                    </td>
                    <td className="text-xs text-gray-400">{c.owner_id || 'Unassigned'}</td>
                    <td className="text-xs font-mono text-cyan-400">
                      {c.evidence_refs?.length || 0} items
                    </td>
                    <td className="text-xs text-gray-500">
                      {c.created_at ? new Date(c.created_at).toLocaleDateString() : '—'}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Detail Panel */}
        <div className="glass-card p-4 flex flex-col h-full">
          {selectedCase ? (
            <div className="space-y-4 flex-1 flex flex-col">
              <div className="flex items-start justify-between border-b border-gray-800 pb-3">
                <div>
                  <h3 className="font-bold text-white text-base leading-snug">{selectedCase.title}</h3>
                  <div className="text-xs text-gray-500 font-mono mt-0.5">{selectedCase.id}</div>
                </div>
                <span className={`badge badge-${selectedCase.priority}`}>
                  {selectedCase.priority}
                </span>
              </div>

              {/* Status Switcher */}
              <div className="flex items-center gap-2">
                <span className="text-xs text-gray-400">Status:</span>
                <select
                  value={selectedCase.status}
                  onChange={(e) => handleStatusChange(selectedCase.id, e.target.value)}
                  className="cyber-input text-xs py-1 flex-1"
                >
                  <option value="open">Open</option>
                  <option value="investigating">Investigating</option>
                  <option value="contained">Contained</option>
                  <option value="resolved">Resolved</option>
                  <option value="closed">Closed</option>
                </select>
              </div>

              {/* Description */}
              <div>
                <div className="text-xs text-gray-400 font-medium mb-1">Description</div>
                <p className="text-xs text-gray-300 bg-black/30 p-2.5 rounded border border-gray-800">
                  {selectedCase.description || 'No description provided.'}
                </p>
              </div>

              {/* Evidence Refs */}
              <div>
                <div className="text-xs text-gray-400 font-medium mb-1">
                  Evidence Telemetry ({selectedCase.evidence_refs?.length || 0})
                </div>
                <div className="max-h-28 overflow-y-auto space-y-1 bg-black/30 p-2 rounded border border-gray-800 font-mono text-[11px] text-gray-400">
                  {selectedCase.evidence_refs?.length > 0 ? (
                    selectedCase.evidence_refs.map((ref, idx) => (
                      <div key={idx} className="truncate text-cyan-400/80">
                        {ref}
                      </div>
                    ))
                  ) : (
                    <div className="text-gray-600">No raw event references linked yet.</div>
                  )}
                </div>
              </div>

              {/* Notes & Timeline */}
              <div className="flex-1 flex flex-col min-h-0">
                <div className="text-xs text-gray-400 font-medium mb-1">Analyst Notes</div>
                <div className="flex-1 overflow-y-auto space-y-2 max-h-44 pr-1">
                  {selectedCase.notes?.map((n, i) => (
                    <div key={i} className="text-xs bg-gray-900/60 p-2 rounded border border-gray-800">
                      <div className="flex items-center justify-between text-[10px] text-gray-500 mb-0.5">
                        <span className="font-semibold text-cyan-400">{n.author}</span>
                        <span>{n.ts ? new Date(n.ts).toLocaleTimeString() : ''}</span>
                      </div>
                      <div className="text-gray-300">{n.content}</div>
                    </div>
                  ))}
                </div>
                <div className="mt-2 flex gap-2">
                  <input
                    type="text"
                    value={newNote}
                    onChange={(e) => setNewNote(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && handleAddNote(selectedCase.id)}
                    placeholder="Add an analyst observation..."
                    className="cyber-input text-xs flex-1"
                  />
                  <button
                    onClick={() => handleAddNote(selectedCase.id)}
                    className="btn-cyber btn-cyber-primary text-xs px-3"
                  >
                    Post
                  </button>
                </div>
              </div>
            </div>
          ) : (
            <div className="flex-1 flex flex-col items-center justify-center text-center text-gray-500 py-12">
              <FolderGit2 size={36} className="mb-2 opacity-40 text-cyan-400" />
              <p className="text-xs">Select an investigation case on the left to inspect evidence and notes.</p>
            </div>
          )}
        </div>
      </div>

      {/* Create Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="glass-card max-w-md w-full p-5 border border-cyan-500/30">
            <h2 className="text-lg font-bold text-white mb-3 flex items-center gap-2">
              <Plus size={18} className="text-cyan-400" />
              Create Investigation Case
            </h2>
            <form onSubmit={handleCreateCase} className="space-y-3">
              <div>
                <label className="block text-xs text-gray-400 mb-1">Case Title</label>
                <input
                  type="text"
                  required
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  placeholder="e.g. Lateral Movement on DC01"
                  className="cyber-input w-full text-xs"
                />
              </div>
              <div>
                <label className="block text-xs text-gray-400 mb-1">Priority</label>
                <select
                  value={newPriority}
                  onChange={(e) => setNewPriority(e.target.value)}
                  className="cyber-input w-full text-xs"
                >
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>
              <div>
                <label className="block text-xs text-gray-400 mb-1">Description</label>
                <textarea
                  rows={3}
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  placeholder="Detailed summary of observed signals and initial hypothesis..."
                  className="cyber-input w-full text-xs resize-none"
                />
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="btn-cyber bg-gray-800 text-gray-300 hover:bg-gray-700"
                >
                  Cancel
                </button>
                <button type="submit" className="btn-cyber btn-cyber-primary">
                  Create Case
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
