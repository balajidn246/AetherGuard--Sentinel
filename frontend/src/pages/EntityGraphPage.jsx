import { useState, useEffect, useCallback } from 'react'
import { entityApi } from '../services/api'
import EntityChip from '../components/EntityChip'
import {
  Network, Search, Activity, Shield, Globe, Server, User, Hash,
  AlertTriangle, ChevronRight, X, RefreshCw
} from 'lucide-react'
import { toast } from 'react-toastify'

const ENTITY_ICONS = {
  ip: Globe,
  user: User,
  host: Server,
  domain: Globe,
  process: Activity,
  file_hash: Hash,
}

const RISK_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
}

function EntityNodeCard({ node, onSelect, selected }) {
  const Icon = ENTITY_ICONS[node.entity_type] || Shield
  const riskColor = RISK_COLORS[node.risk_level] || '#6b7280'
  const isSelected = selected?.id === node.id

  return (
    <div
      onClick={() => onSelect(node)}
      className="glass-card p-3 cursor-pointer transition-all hover:scale-[1.01]"
      style={{
        border: isSelected ? `1px solid ${riskColor}` : '1px solid rgba(255,255,255,0.06)',
        boxShadow: isSelected ? `0 0 12px ${riskColor}33` : undefined,
      }}
    >
      <div className="flex items-center gap-3">
        <div
          className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
          style={{ background: `${riskColor}18`, border: `1px solid ${riskColor}33` }}
        >
          <Icon size={15} color={riskColor} />
        </div>
        <div className="min-w-0 flex-1">
          <div className="text-xs font-mono truncate" style={{ color: '#e5e7eb' }}>
            {node.canonical_value}
          </div>
          <div className="flex items-center gap-2 mt-0.5">
            <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: `${riskColor}22`, color: riskColor }}>
              {node.entity_type}
            </span>
            {node.risk_level && (
              <span className="text-[10px] text-gray-500 uppercase">{node.risk_level}</span>
            )}
          </div>
        </div>
        {node.current_risk_score != null && (
          <div className="text-right flex-shrink-0">
            <div className="text-sm font-bold" style={{ color: riskColor }}>
              {Math.round(node.current_risk_score)}
            </div>
            <div className="text-[10px] text-gray-600">risk</div>
          </div>
        )}
      </div>
    </div>
  )
}

function GraphCanvas({ graph }) {
  if (!graph) {
    return (
      <div className="h-full flex items-center justify-center text-gray-600 text-sm">
        Select an entity to view its relationship graph
      </div>
    )
  }

  const { nodes, edges, focal_node_id } = graph

  // Simple force-layout approximation: place focal in center, neighbors in a ring
  const cx = 50, cy = 50
  const radius = 32
  const nonFocal = nodes.filter(n => n.id !== focal_node_id)
  const positions = {}
  positions[focal_node_id] = { x: cx, y: cy }
  nonFocal.forEach((n, i) => {
    const angle = (2 * Math.PI * i) / Math.max(nonFocal.length, 1)
    positions[n.id] = {
      x: cx + radius * Math.cos(angle),
      y: cy + radius * Math.sin(angle),
    }
  })

  return (
    <div className="relative h-full w-full" style={{ background: 'linear-gradient(135deg, #030a18 0%, #050d20 100%)' }}>
      <svg className="absolute inset-0 w-full h-full">
        {/* Edges */}
        {edges.map(e => {
          const src = positions[e.source]
          const tgt = positions[e.target]
          if (!src || !tgt) return null
          return (
            <g key={e.id}>
              <line
                x1={`${src.x}%`} y1={`${src.y}%`}
                x2={`${tgt.x}%`} y2={`${tgt.y}%`}
                stroke="#374151" strokeWidth="1.5" strokeDasharray="4 2"
              />
              {/* edge label */}
              <text
                x={`${(src.x + tgt.x) / 2}%`}
                y={`${(src.y + tgt.y) / 2}%`}
                fill="#6b7280" fontSize="7" textAnchor="middle" dominantBaseline="middle"
              >
                {e.relation_type}
              </text>
            </g>
          )
        })}

        {/* Nodes */}
        {nodes.map(n => {
          const pos = positions[n.id]
          if (!pos) return null
          const isFocal = n.id === focal_node_id
          const riskColor = RISK_COLORS[n.risk_level] || '#6b7280'
          return (
            <g key={n.id}>
              <circle
                cx={`${pos.x}%`} cy={`${pos.y}%`}
                r={isFocal ? 16 : 11}
                fill={`${riskColor}22`}
                stroke={riskColor}
                strokeWidth={isFocal ? 2 : 1}
              />
              {isFocal && (
                <circle cx={`${pos.x}%`} cy={`${pos.y}%`} r={20} fill="none"
                  stroke={riskColor} strokeWidth="0.5" strokeDasharray="3 2" opacity={0.4}
                >
                  <animate attributeName="r" values="16;22;16" dur="2s" repeatCount="indefinite" />
                  <animate attributeName="opacity" values="0.4;0.1;0.4" dur="2s" repeatCount="indefinite" />
                </circle>
              )}
              <text
                x={`${pos.x}%`} y={`${pos.y + (isFocal ? 3.5 : 2.5)}%`}
                fill={riskColor} fontSize={isFocal ? 7 : 6}
                textAnchor="middle" dominantBaseline="middle"
                style={{ fontFamily: 'JetBrains Mono, monospace' }}
              >
                {n.canonical_value.length > 15 ? n.canonical_value.slice(0, 14) + '…' : n.canonical_value}
              </text>
              <text
                x={`${pos.x}%`} y={`${pos.y - (isFocal ? 3 : 2)}%`}
                fill="#6b7280" fontSize="5.5"
                textAnchor="middle" dominantBaseline="middle"
              >
                {n.entity_type}
              </text>
            </g>
          )
        })}
      </svg>

      {/* Graph legend */}
      <div className="absolute bottom-3 right-3 glass-card p-2 text-[10px] text-gray-500">
        <div className="mb-1 font-bold text-gray-400">LEGEND</div>
        {Object.entries(RISK_COLORS).map(([level, color]) => (
          <div key={level} className="flex items-center gap-1.5">
            <div className="w-2 h-2 rounded-full" style={{ background: color }} />
            <span className="capitalize">{level}</span>
          </div>
        ))}
      </div>

      {/* Edge count */}
      <div className="absolute top-3 right-3 glass-card px-2 py-1 text-[10px] text-gray-400">
        {nodes.length} nodes · {edges.length} edges
      </div>
    </div>
  )
}

export default function EntityGraphPage() {
  const [nodes, setNodes] = useState([])
  const [summary, setSummary] = useState(null)
  const [selectedNode, setSelectedNode] = useState(null)
  const [graph, setGraph] = useState(null)
  const [graphLoading, setGraphLoading] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [searchResults, setSearchResults] = useState([])
  const [searching, setSearching] = useState(false)
  const [entityTypeFilter, setEntityTypeFilter] = useState('')
  const [loading, setLoading] = useState(true)

  const loadNodes = useCallback(async () => {
    setLoading(true)
    try {
      const [nodesRes, summaryRes] = await Promise.all([
        entityApi.nodes({ entity_type: entityTypeFilter || undefined, limit: 50 }),
        entityApi.summary(),
      ])
      setNodes(nodesRes.data)
      setSummary(summaryRes.data)
    } catch (err) {
      toast.error('Failed to load entities')
    } finally {
      setLoading(false)
    }
  }, [entityTypeFilter])

  useEffect(() => { loadNodes() }, [loadNodes])

  const handleSelectNode = async (node) => {
    setSelectedNode(node)
    setGraphLoading(true)
    try {
      const res = await entityApi.nodeGraph(node.id, 1)
      setGraph(res.data)
    } catch {
      toast.error('Failed to load entity graph')
      setGraph(null)
    } finally {
      setGraphLoading(false)
    }
  }

  const handleSearch = async (e) => {
    e.preventDefault()
    if (!searchQuery.trim() || searchQuery.length < 2) return
    setSearching(true)
    try {
      const res = await entityApi.search(searchQuery.trim())
      setSearchResults(res.data)
    } catch {
      toast.error('Search failed')
    } finally {
      setSearching(false)
    }
  }

  const displayNodes = searchResults.length > 0 ? searchResults : nodes

  return (
    <div className="flex flex-col gap-4 h-full animate-fade-in">
      {/* Summary bar */}
      {summary && (
        <div className="grid grid-cols-5 gap-3 flex-shrink-0">
          <div className="glass-card p-3 col-span-1">
            <div className="text-xs text-gray-500 mb-1">Total Entities</div>
            <div className="text-2xl font-bold text-cyan-400">{summary.total_nodes}</div>
          </div>
          {Object.entries(summary.by_type || {}).slice(0, 4).map(([type, count]) => {
            const Icon = ENTITY_ICONS[type] || Shield
            const color = '#6b7280'
            return (
              <div
                key={type}
                className="glass-card p-3 cursor-pointer"
                style={{ borderColor: entityTypeFilter === type ? '#60a5fa' : undefined }}
                onClick={() => setEntityTypeFilter(prev => prev === type ? '' : type)}
              >
                <div className="flex items-center gap-2 mb-1">
                  <Icon size={12} className="text-gray-400" />
                  <span className="text-xs text-gray-500 capitalize">{type}</span>
                </div>
                <div className="text-xl font-bold text-gray-200">{count}</div>
              </div>
            )
          })}
        </div>
      )}

      {/* Main layout */}
      <div className="flex flex-1 gap-4 min-h-0">
        {/* Left panel: node list */}
        <div className="w-80 flex flex-col gap-3 flex-shrink-0">
          {/* Search */}
          <form onSubmit={handleSearch} className="flex gap-2">
            <input
              type="text"
              value={searchQuery}
              onChange={e => { setSearchQuery(e.target.value); if (!e.target.value) setSearchResults([]) }}
              placeholder="Search entities…"
              className="flex-1 input-dark text-xs py-2"
            />
            <button type="submit" disabled={searching}
              className="btn-secondary px-3 py-2 text-xs flex items-center gap-1">
              <Search size={13} />
            </button>
            {searchResults.length > 0 && (
              <button type="button" onClick={() => { setSearchResults([]); setSearchQuery('') }}
                className="btn-ghost px-2">
                <X size={13} />
              </button>
            )}
          </form>

          {/* Node list */}
          <div className="flex-1 overflow-y-auto space-y-2">
            {loading ? (
              <div className="text-center text-gray-600 text-xs py-8">Loading entities…</div>
            ) : displayNodes.length === 0 ? (
              <div className="text-center text-gray-600 text-xs py-8">
                No entities tracked yet. Ingest telemetry to populate the graph.
              </div>
            ) : (
              displayNodes.map(node => (
                <EntityNodeCard
                  key={node.id}
                  node={node}
                  onSelect={handleSelectNode}
                  selected={selectedNode}
                />
              ))
            )}
          </div>
        </div>

        {/* Right panel: graph + detail */}
        <div className="flex-1 flex flex-col gap-3 min-w-0">
          {/* Graph canvas */}
          <div className="flex-1 glass-card overflow-hidden relative">
            {graphLoading ? (
              <div className="h-full flex items-center justify-center">
                <RefreshCw size={20} className="text-cyan-500 animate-spin" />
              </div>
            ) : (
              <GraphCanvas graph={graph} />
            )}
          </div>

          {/* Selected node detail */}
          {selectedNode && (
            <div className="glass-card p-4 flex-shrink-0">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  {(() => { const Icon = ENTITY_ICONS[selectedNode.entity_type] || Shield; return <Icon size={16} className="text-cyan-400" /> })()}
                  <span className="text-sm font-bold text-gray-200">{selectedNode.canonical_value}</span>
                  <span className="text-xs px-2 py-0.5 rounded" style={{ background: '#0e7490', color: '#a5f3fc' }}>
                    {selectedNode.entity_type}
                  </span>
                </div>
                <button onClick={() => { setSelectedNode(null); setGraph(null) }} className="btn-ghost p-1">
                  <X size={14} />
                </button>
              </div>
              <div className="grid grid-cols-4 gap-3 text-xs text-gray-400">
                <div>
                  <div className="text-gray-600">Risk Score</div>
                  <div className="font-bold" style={{ color: RISK_COLORS[selectedNode.risk_level] || '#9ca3af' }}>
                    {selectedNode.current_risk_score != null ? Math.round(selectedNode.current_risk_score) : '—'}
                  </div>
                </div>
                <div>
                  <div className="text-gray-600">Risk Level</div>
                  <div className="font-medium capitalize">{selectedNode.risk_level || '—'}</div>
                </div>
                <div>
                  <div className="text-gray-600">First Seen</div>
                  <div>{selectedNode.first_seen ? new Date(selectedNode.first_seen).toLocaleDateString() : '—'}</div>
                </div>
                <div>
                  <div className="text-gray-600">Last Seen</div>
                  <div>{selectedNode.last_seen ? new Date(selectedNode.last_seen).toLocaleDateString() : '—'}</div>
                </div>
              </div>
              {graph && (
                <div className="mt-3 pt-3 border-t border-gray-800 text-xs text-gray-500">
                  <span className="font-bold text-gray-400">{graph.edges.length}</span> relationships ·{' '}
                  <span className="font-bold text-gray-400">{graph.nodes.length - 1}</span> neighbours
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
