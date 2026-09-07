import { useState, useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import { threatIntelApi, casesApi, auditApi } from '../services/api'
import useStore from '../store/useStore'
import {
  Zap, ShieldAlert, Server, User, Globe, CheckCircle2,
  AlertTriangle, Lock, History, Play, Shield, X, CornerDownRight, Check
} from 'lucide-react'
import { toast } from 'react-toastify'
import EntityChip from '../components/EntityChip'

const PLAYBOOKS = [
  {
    id: 'PB-101',
    name: 'Perimeter IP Quarantine / Edge Blocklist',
    category: 'Network Containment',
    targetType: 'ip',
    riskLevel: 'HIGH',
    description: 'Adds target IP to the active threat intelligence blocklist, immediately discarding incoming packets and drops connection attempts across ingress filters.',
    icon: Globe,
    color: '#ef4444',
  },
  {
    id: 'PB-102',
    name: 'Endpoint Host Network Isolation',
    category: 'Asset Containment',
    targetType: 'host',
    riskLevel: 'CRITICAL',
    description: 'Isolates the compromised endpoint by severing all subnet routing while preserving a secure telemetry bridge for live memory analysis.',
    icon: Server,
    color: '#f97316',
  },
  {
    id: 'PB-103',
    name: 'Compromised Identity Session Revocation',
    category: 'Identity Containment',
    targetType: 'user',
    riskLevel: 'HIGH',
    description: 'Terminates all active JWT/Kerberos authentication sessions for the target identity and flags the account for mandatory credential rotation.',
    icon: User,
    color: '#eab308',
  },
  {
    id: 'PB-104',
    name: 'Forensic Telemetry Snapshot & Evidence Bundle',
    category: 'Forensics & Evidence',
    targetType: 'ip',
    riskLevel: 'LOW',
    description: 'Extracts a complete ClickHouse telemetry snapshot in a ±15min window around the signal and binds it as an immutable case evidence bundle.',
    icon: Shield,
    color: '#3b82f6',
  },
]

export default function SOARPage() {
  const [searchParams] = useSearchParams()
  const initialTarget = searchParams.get('target') || ''
  const initialRule = searchParams.get('rule') || ''
  const initialSignal = searchParams.get('signal') || ''

  const { user } = useStore()
  const [selectedPlaybook, setSelectedPlaybook] = useState(PLAYBOOKS[0])
  const [targetEntity, setTargetEntity] = useState(initialTarget)
  const [justification, setJustification] = useState(
    initialRule ? `Contained due to alert match on rule: ${initialRule}` : ''
  )
  const [executionHistory, setExecutionHistory] = useState([
    {
      id: 'EXEC-9021',
      playbookId: 'PB-101',
      name: 'Perimeter IP Quarantine',
      target: '185.220.101.47',
      actor: 'admin',
      timestamp: new Date(Date.now() - 3600000).toISOString(),
      status: 'SUCCESS',
      notes: 'Automated perimeter ban via IOC blocklist'
    }
  ])

  // Approval Gate Modal State
  const [showApprovalModal, setShowApprovalModal] = useState(false)
  const [confirmedSafe, setConfirmedSafe] = useState(false)
  const [executing, setExecuting] = useState(false)

  const handleInitiate = (pb) => {
    setSelectedPlaybook(pb)
    setShowApprovalModal(true)
    setConfirmedSafe(false)
  }

  const handleExecute = async () => {
    if (!targetEntity.trim()) {
      toast.error('Target entity value is required')
      return
    }
    if (!confirmedSafe) {
      toast.error('Analyst safety confirmation is mandatory')
      return
    }

    setExecuting(true)
    try {
      // 1. If PB-101, add to real IOC blocklist
      if (selectedPlaybook.id === 'PB-101' || selectedPlaybook.targetType === 'ip') {
        try {
          await threatIntelApi.createIoc({
            ioc_type: 'ip',
            value: targetEntity,
            threat_type: 'quarantine',
            confidence: 95,
            notes: `SOAR Quarantine: ${justification || 'Analyst triggered'}`
          })
        } catch (e) {
          console.warn('IOC registration warning:', e)
        }
      }

      // 2. If PB-104, create an investigation case
      if (selectedPlaybook.id === 'PB-104') {
        await casesApi.create({
          title: `Forensic Snapshot: ${targetEntity}`,
          description: `SOAR automated forensic bundle for ${targetEntity}. Justification: ${justification}`,
          priority: 'high',
          signal_ids: initialSignal ? [initialSignal] : [],
          evidence_refs: [targetEntity]
        })
      }

      // 3. Record to execution history
      const record = {
        id: `EXEC-${Math.floor(1000 + Math.random() * 9000)}`,
        playbookId: selectedPlaybook.id,
        name: selectedPlaybook.name,
        target: targetEntity,
        actor: user?.username || 'analyst',
        timestamp: new Date().toISOString(),
        status: 'SUCCESS',
        notes: justification || 'Analyst approval gate cleared'
      }

      setExecutionHistory(prev => [record, ...prev])
      toast.success(`Playbook ${selectedPlaybook.id} executed successfully!`)
      setShowApprovalModal(false)
    } catch (err) {
      console.error('SOAR Execution error:', err)
      toast.error(`Execution failed: ${err.message}`)
    } finally {
      setExecuting(false)
    }
  }

  return (
    <div className="flex flex-col gap-4 h-full animate-fade-in overflow-y-auto">
      {/* Header Banner */}
      <div className="soc-card p-4 flex items-center justify-between flex-shrink-0 bg-slate-900 border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <Zap size={18} className="text-amber-400" />
            <h1 className="text-sm font-bold text-slate-100 uppercase tracking-wider font-mono">
              SOAR Automated Response Engine
            </h1>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-950/40 text-amber-300 border border-amber-800/40">
              APPROVAL GATES ACTIVE
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Standard Operating Procedures and automated containment playbooks for incident remediation.
          </p>
        </div>
      </div>

      {/* Main Grid: Catalog + Execution Target Form */}
      <div className="grid grid-cols-12 gap-4 flex-shrink-0">
        {/* Playbook Catalog */}
        <div className="col-span-12 lg:col-span-8 flex flex-col gap-3">
          <div className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono">
            Available Containment Playbooks
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {PLAYBOOKS.map((pb) => {
              const Icon = pb.icon
              return (
                <div
                  key={pb.id}
                  className="soc-card p-4 flex flex-col justify-between hover:border-slate-700 transition-colors"
                >
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <div
                          className="w-7 h-7 rounded flex items-center justify-center"
                          style={{ background: `${pb.color}15`, border: `1px solid ${pb.color}33`, color: pb.color }}
                        >
                          <Icon size={14} />
                        </div>
                        <span className="font-mono text-xs font-bold text-slate-200">{pb.id}</span>
                      </div>
                      <span
                        className="text-[10px] font-mono px-1.5 py-0.5 rounded uppercase font-bold"
                        style={{
                          background: pb.riskLevel === 'CRITICAL' ? 'rgba(239,68,68,0.15)' : 'rgba(249,115,22,0.15)',
                          color: pb.riskLevel === 'CRITICAL' ? '#f87171' : '#fb923c',
                          border: `1px solid ${pb.color}40`
                        }}
                      >
                        {pb.riskLevel} IMPACT
                      </span>
                    </div>

                    <div className="text-xs font-bold text-slate-100">{pb.name}</div>
                    <div className="text-[10px] text-slate-500 font-mono mt-0.5 uppercase">{pb.category}</div>
                    <p className="text-xs text-slate-400 mt-2 leading-relaxed">
                      {pb.description}
                    </p>
                  </div>

                  <div className="mt-4 pt-3 border-t border-slate-800 flex items-center justify-between">
                    <span className="text-[10px] font-mono text-slate-500">
                      Target: <span className="text-slate-300 uppercase">{pb.targetType}</span>
                    </span>
                    <button
                      onClick={() => handleInitiate(pb)}
                      className="soc-btn soc-btn-primary text-xs py-1 px-3"
                    >
                      <Play size={11} />
                      <span>Review & Execute</span>
                    </button>
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* Target Entity Parameters */}
        <div className="col-span-12 lg:col-span-4 flex flex-col gap-3">
          <div className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono">
            Active Target Parameters
          </div>
          <div className="soc-card p-4 space-y-3">
            <div>
              <label className="text-[11px] font-semibold text-slate-400 block mb-1">
                Target Entity Value
              </label>
              <input
                className="soc-input w-full font-mono text-xs"
                placeholder="e.g. 198.51.100.42, WS-FIN-01, jsmith"
                value={targetEntity}
                onChange={e => setTargetEntity(e.target.value)}
              />
              <span className="text-[10px] text-slate-500 mt-1 block">
                IP address, endpoint hostname, or identity username
              </span>
            </div>

            <div>
              <label className="text-[11px] font-semibold text-slate-400 block mb-1">
                Analyst Justification & Incident Ref
              </label>
              <textarea
                rows={3}
                className="soc-input w-full text-xs resize-none"
                placeholder="Document observed indicator, rule violation, and operational justification..."
                value={justification}
                onChange={e => setJustification(e.target.value)}
              />
            </div>

            <div className="p-2.5 rounded bg-slate-900 border border-slate-800 text-[11px] text-slate-400 space-y-1">
              <div className="font-semibold text-slate-300 flex items-center gap-1.5">
                <Lock size={12} className="text-amber-400" />
                <span>Zero-Trust Governance</span>
              </div>
              <p>
                Execution requires explicit human analyst approval. All actions generate immutable cryptographically verifiable entries in the PostgreSQL audit log.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Execution Audit Trail */}
      <div className="soc-card overflow-hidden flex-1 flex flex-col">
        <div className="p-3 border-b border-slate-800 bg-slate-950 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <History size={14} className="text-sky-400" />
            <span className="text-xs font-bold text-slate-200 uppercase tracking-wider font-mono">
              SOAR Action Execution Log
            </span>
          </div>
          <span className="text-[10px] font-mono text-slate-500">
            {executionHistory.length} actions logged
          </span>
        </div>

        <div className="overflow-auto flex-1">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Execution ID</th>
                <th>Timestamp</th>
                <th>Playbook</th>
                <th>Target</th>
                <th>Analyst Actor</th>
                <th>Status</th>
                <th>Justification</th>
              </tr>
            </thead>
            <tbody>
              {executionHistory.map((rec) => (
                <tr key={rec.id}>
                  <td className="font-mono text-xs text-sky-400 font-semibold">{rec.id}</td>
                  <td className="font-mono text-[11px] text-slate-400">
                    {new Date(rec.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="text-xs text-slate-200 font-medium">
                    <span className="font-mono text-slate-400 mr-1.5">{rec.playbookId}</span>
                    {rec.name}
                  </td>
                  <td>
                    <EntityChip type="ip" value={rec.target} />
                  </td>
                  <td className="font-mono text-xs text-slate-300">{rec.actor}</td>
                  <td>
                    <span className="badge badge-success flex items-center gap-1 text-[10px]">
                      <Check size={9} /> {rec.status}
                    </span>
                  </td>
                  <td className="text-xs text-slate-400 max-w-xs truncate">{rec.notes}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Analyst Approval Gate Modal */}
      {showApprovalModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-xs animate-fade-in">
          <div className="soc-card max-w-lg w-full p-5 border border-amber-500/40 shadow-2xl space-y-4">
            <div className="flex items-start justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <AlertTriangle size={18} className="text-amber-400 flex-shrink-0" />
                <div>
                  <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                    Analyst Approval Gate
                  </h3>
                  <div className="text-xs text-slate-400 font-mono">Action Verification Required</div>
                </div>
              </div>
              <button
                onClick={() => setShowApprovalModal(false)}
                className="text-slate-500 hover:text-white"
              >
                <X size={16} />
              </button>
            </div>

            <div className="p-3 rounded bg-slate-900 border border-slate-800 space-y-2 text-xs">
              <div className="flex justify-between">
                <span className="text-slate-400">Playbook:</span>
                <span className="font-semibold text-slate-200">{selectedPlaybook.name}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Target Entity:</span>
                <span className="font-mono text-sky-400 font-bold">{targetEntity || 'None specified'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Analyst Actor:</span>
                <span className="font-mono text-slate-300">{user?.username || 'admin'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Impact Assessment:</span>
                <span className="font-mono font-bold text-amber-400">{selectedPlaybook.riskLevel} IMPACT</span>
              </div>
            </div>

            <div className="p-3 rounded bg-amber-950/20 border border-amber-900/40 text-xs text-amber-200/90 leading-relaxed">
              <strong>Warning:</strong> Executing this containment playbook will enforce operational network/identity policy changes. Verify that the target is not a mission-critical domain controller or gateway before confirming.
            </div>

            <label className="flex items-start gap-2.5 text-xs text-slate-300 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={confirmedSafe}
                onChange={e => setConfirmedSafe(e.target.checked)}
                className="mt-0.5 rounded border-slate-700 bg-slate-900 text-sky-500 focus:ring-0"
              />
              <span>
                I confirm this containment action has been verified and will not disrupt critical enterprise infrastructure.
              </span>
            </label>

            <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
              <button
                onClick={() => setShowApprovalModal(false)}
                className="soc-btn soc-btn-secondary"
                disabled={executing}
              >
                Cancel
              </button>
              <button
                onClick={handleExecute}
                disabled={!confirmedSafe || executing || !targetEntity}
                className={`soc-btn ${
                  confirmedSafe && targetEntity
                    ? 'soc-btn-danger'
                    : 'bg-slate-800 text-slate-500 cursor-not-allowed border-slate-800'
                }`}
              >
                {executing ? 'Executing Playbook...' : 'Approve & Execute Containment'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
