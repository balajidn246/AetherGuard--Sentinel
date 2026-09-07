import { severityBadgeClass, formatDateTime } from '../utils/constants'
import { Bell, Check, ArrowUpRight, BrainCircuit, FolderPlus, ShieldAlert, Zap } from 'lucide-react'
import { alertsApi, signalsApi, casesApi } from '../services/api'
import useStore from '../store/useStore'
import EntityChip from './EntityChip'
import { useNavigate } from 'react-router-dom'
import { toast } from 'react-toastify'
import { useState } from 'react'

const SEV_BORDER = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  info: '#64748b',
}

const VERDICT_STYLES = {
  MALICIOUS: { bg: 'rgba(239, 68, 68, 0.15)', border: 'rgba(239, 68, 68, 0.4)', text: '#f87171' },
  SUSPICIOUS: { bg: 'rgba(234, 179, 8, 0.15)', border: 'rgba(234, 179, 8, 0.4)', text: '#facc15' },
  BENIGN: { bg: 'rgba(16, 185, 129, 0.15)', border: 'rgba(16, 185, 129, 0.4)', text: '#34d399' },
  INSUFFICIENT_EVIDENCE: { bg: 'rgba(100, 116, 139, 0.15)', border: 'rgba(100, 116, 139, 0.4)', text: '#94a3b8' },
}

export default function AlertCard({ alert, onUpdate }) {
  const [loading, setLoading] = useState(false)
  const [investigating, setInvestigating] = useState(false)
  const [creatingCase, setCreatingCase] = useState(false)
  const navigate = useNavigate()

  const aiInvestigation = useStore(
    s => s.aiInvestigations[alert.id || alert._id]
  )

  const alertId = alert.id || alert._id

  const ack = async () => {
    setLoading(true)
    try {
      await alertsApi.acknowledge(alertId)
      toast.success('Signal acknowledged')
      onUpdate?.()
    } catch {
      toast.error('Failed to acknowledge')
    } finally {
      setLoading(false)
    }
  }

  const investigate = async () => {
    setInvestigating(true)
    try {
      await signalsApi.investigate(alertId)
      toast.info(
        'AI investigation queued. Local Ollama (llama3.2:1b) analyzing...',
        { autoClose: 3500 }
      )
    } catch (err) {
      toast.error('AI Investigation Failed')
    } finally {
      setInvestigating(false)
    }
  }

  const createCaseFromAlert = async () => {
    setCreatingCase(true)
    try {
      await casesApi.create({
        title: `Case: ${alert.title}`,
        description: alert.description || `Generated from signal ${alertId}`,
        priority: alert.severity || 'medium',
        signal_ids: [alertId],
        evidence_refs: alert.evidence_refs || [alert.log_id || alertId],
      })
      toast.success('Investigation case created!')
      onUpdate?.()
    } catch {
      toast.error('Failed to create case')
    } finally {
      setCreatingCase(false)
    }
  }

  const triggerSOAR = () => {
    const targetIp = alert.source_ip || alert.src_ip || ''
    navigate(`/soar?target=${encodeURIComponent(targetIp)}&rule=${encodeURIComponent(alert.rule_name || alert.title)}&signal=${alertId}`)
  }

  const border = SEV_BORDER[alert.severity] || '#64748b'
  const aiReport = aiInvestigation || (alert.ai_analysis ? {
    verdict: alert.ai_verdict || 'UNKNOWN',
    confidence: alert.ai_confidence
      ? (typeof alert.ai_confidence === 'number'
          ? `${Math.round(alert.ai_confidence * 100)}%`
          : (parseFloat(alert.ai_confidence) <= 1.0 && !isNaN(alert.ai_confidence)
              ? `${Math.round(parseFloat(alert.ai_confidence) * 100)}%`
              : alert.ai_confidence))
      : '—',
    provider: 'ollama/llama3.2:1b',
    summary: alert.ai_analysis,
    observed_facts: [
      (alert.source_ip || alert.src_ip) && `Source IP: ${alert.source_ip || alert.src_ip}`,
      (alert.hostname || alert.host_name) && `Host: ${alert.hostname || alert.host_name}`,
      (alert.username || alert.user_name) && `User: ${alert.username || alert.user_name}`,
      alert.attack_type && `Attack type: ${alert.attack_type}`,
      alert.rule_name && `Triggered Rule: ${alert.rule_name}`,
    ].filter(Boolean),
    mitre_attack: alert.mitre_techniques || [],
    recommended_actions: alert.recommended_actions || [
      "Review source IP telemetry history and related host activity."
    ],
    evidence_refs: alert.evidence_refs || [alert.log_id || alertId],
  } : null)

  const effectiveVerdict = aiReport?.verdict || alert.ai_verdict
  const verdictStyle = effectiveVerdict ? (VERDICT_STYLES[effectiveVerdict.toUpperCase()] || VERDICT_STYLES.SUSPICIOUS) : null

  return (
    <div
      className="soc-card p-3 mb-2 transition-all animate-fade-in"
      style={{
        borderLeft: `3px solid ${border}`,
      }}
    >
      <div className="flex items-start justify-between gap-3">
        {/* Left: Signal metadata & details */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={severityBadgeClass(alert.severity)}>{alert.severity}</span>
            <span className="text-xs font-bold text-slate-100 truncate">{alert.title}</span>

            {/* AI Verdict Badge */}
            {verdictStyle && (
              <span
                className="px-2 py-0.5 rounded text-[10px] font-bold font-mono uppercase"
                style={{
                  background: verdictStyle.bg,
                  border: `1px solid ${verdictStyle.border}`,
                  color: verdictStyle.text,
                }}
              >
                AI: {effectiveVerdict}
              </span>
            )}
          </div>

          <div className="text-xs text-slate-400 mt-1 leading-relaxed">
            {alert.description}
          </div>

          {/* Grounded AI Investigation Card */}
          {aiReport && (
            <div
              className="mt-2.5 p-3 rounded-lg border bg-indigo-950/20 border-indigo-900/40 text-xs space-y-2"
            >
              <div className="flex items-center justify-between pb-1 border-b border-indigo-900/30">
                <span className="font-bold text-indigo-300 flex items-center gap-1.5 font-mono text-[11px]">
                  <BrainCircuit size={13} className="text-indigo-400" />
                  AI OPERATIONAL TRIAGE
                </span>
                <span className="text-[10px] font-mono text-indigo-400">
                  {aiReport.provider || 'ollama/llama3.2:1b'}
                </span>
              </div>

              <div className="grid grid-cols-3 gap-2">
                <div>
                  <div className="text-[10px] text-slate-500 font-mono">VERDICT</div>
                  <div className="font-bold text-slate-100">{aiReport.verdict || 'UNKNOWN'}</div>
                </div>
                <div>
                  <div className="text-[10px] text-slate-500 font-mono">CONFIDENCE</div>
                  <div className="font-bold text-slate-100">
                    {typeof aiReport.confidence === 'number'
                      ? `${Math.round(aiReport.confidence * 100)}%`
                      : aiReport.confidence || '—'}
                  </div>
                </div>
                <div>
                  <div className="text-[10px] text-slate-500 font-mono">SIGNAL ID</div>
                  <div className="font-mono text-[11px] text-slate-300 truncate">
                    {alertId?.slice?.(0, 10) || alertId}
                  </div>
                </div>
              </div>

              {aiReport.summary && (
                <div>
                  <div className="text-[10px] text-slate-500 font-mono mb-0.5">EXECUTIVE ANALYSIS</div>
                  <div className="text-slate-300 leading-relaxed text-[11px]">
                    {aiReport.summary}
                  </div>
                </div>
              )}

              {aiReport.observed_facts?.length > 0 && (
                <div>
                  <div className="text-[10px] text-slate-500 font-mono mb-0.5">OBSERVED FACTS</div>
                  <div className="space-y-0.5">
                    {aiReport.observed_facts.map((fact, i) => (
                      <div key={i} className="text-slate-300 text-[11px]">
                        • {fact}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {aiReport.mitre_attack?.length > 0 && (
                <div>
                  <div className="text-[10px] text-slate-500 font-mono mb-1">MITRE ATT&CK TECHNIQUES</div>
                  <div className="flex flex-wrap gap-1">
                    {aiReport.mitre_attack.map((technique) => (
                      <span
                        key={technique}
                        className="text-[10px] px-1.5 py-0.5 rounded font-mono bg-slate-900 text-amber-300 border border-slate-800"
                      >
                        {technique}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {aiReport.recommended_actions?.length > 0 && (
                <div>
                  <div className="text-[10px] text-slate-500 font-mono mb-0.5">RECOMMENDED ACTIONS</div>
                  <div className="space-y-0.5">
                    {aiReport.recommended_actions.map((act, i) => (
                      <div key={i} className="text-slate-300 text-[11px]">
                        {i + 1}. {act}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {aiReport.evidence_refs?.length > 0 && (
                <div>
                  <div className="text-[10px] text-slate-500 font-mono mb-1">LINKED EVIDENCE REFS</div>
                  <div className="flex flex-wrap gap-1 font-mono text-[10px] text-slate-400">
                    {aiReport.evidence_refs.map((ref, i) => (
                      <span key={i} className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800">
                        {ref}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Entity & Context Strip */}
          <div className="flex items-center gap-2.5 mt-2 flex-wrap text-xs">
            {(alert.source_ip || alert.src_ip) && (
              <EntityChip type="ip" value={alert.source_ip || alert.src_ip} />
            )}
            {(alert.hostname || alert.host_name) && (
              <EntityChip type="host" value={alert.hostname || alert.host_name} />
            )}
            {(alert.username || alert.user_name) && (
              <EntityChip type="user" value={alert.username || alert.user_name} />
            )}
            {alert.mitre_techniques?.slice(0, 2).map(t => (
              <span
                key={t}
                className="text-[10px] px-1.5 py-0.5 rounded font-mono bg-slate-900 text-amber-300 border border-slate-800"
              >
                {t}
              </span>
            ))}
            <span className="text-[11px] font-mono text-slate-500 ml-auto">
              {formatDateTime(alert.created_at)}
            </span>
          </div>
        </div>

        {/* Right: Operational Actions */}
        <div className="flex flex-col items-end gap-1.5 flex-shrink-0">
          <div className="flex items-center gap-1.5">
            <button
              onClick={investigate}
              disabled={investigating}
              className="soc-btn text-xs py-1 px-2.5 bg-indigo-950/40 text-indigo-300 border-indigo-800/60 hover:bg-indigo-900/40"
              title="Run local Ollama investigation"
            >
              <BrainCircuit size={12} />
              <span>{investigating ? 'Analyzing...' : 'AI Triage'}</span>
            </button>

            <button
              onClick={createCaseFromAlert}
              disabled={creatingCase}
              className="soc-btn text-xs py-1 px-2.5 bg-sky-950/40 text-sky-300 border-sky-800/60 hover:bg-sky-900/40"
              title="Open investigation case in Case Management"
            >
              <FolderPlus size={12} />
              <span>{creatingCase ? 'Creating...' : '+ Case'}</span>
            </button>

            <button
              onClick={triggerSOAR}
              className="soc-btn text-xs py-1 px-2.5 bg-rose-950/40 text-rose-300 border-rose-800/60 hover:bg-rose-900/40"
              title="Open SOAR containment playbook"
            >
              <Zap size={12} />
              <span>SOAR</span>
            </button>
          </div>

          {alert.acknowledged ? (
            <span className="badge badge-low flex items-center gap-1 text-[10px]">
              <Check size={10} /> ACKNOWLEDGED
            </span>
          ) : (
            <button
              onClick={ack}
              disabled={loading}
              className="soc-btn soc-btn-secondary text-xs py-1 px-2.5"
            >
              <Check size={12} /> Acknowledge
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
