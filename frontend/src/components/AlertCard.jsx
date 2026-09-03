import { severityBadgeClass, formatDateTime } from '../utils/constants'
import { Bell, Check, ArrowUpRight, BrainCircuit } from 'lucide-react'
import { alertsApi, signalsApi } from '../services/api'
import { toast } from 'react-toastify'
import { useState } from 'react'

const SEV_BORDER = {
  critical: '#ff3366',
  high: '#ff6b35',
  medium: '#ffaa00',
  low: '#3b82f6',
  info: '#4b5563',
}

export default function AlertCard({ alert, onUpdate }) {
  const [loading, setLoading] = useState(false)
  const [investigating, setInvestigating] = useState(false)

  const ack = async () => {
    setLoading(true)
    try {
      await alertsApi.acknowledge(alert._id)
      toast.success('Alert acknowledged')
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
      await signalsApi.investigate(alert._id)
      toast.info('AI Investigation Started (Local Ollama)')
    } catch (err) {
      toast.error('AI Investigation Failed')
    } finally {
      setInvestigating(false)
    }
  }

  const border = SEV_BORDER[alert.severity] || '#4b5563'

  return (
    <div
      className="rounded-lg p-3 mb-2 transition-all hover:scale-[1.01] animate-fade-in"
      style={{
        background: '#111827',
        borderLeft: `3px solid ${border}`,
        border: `1px solid ${border}33`,
        borderLeftWidth: '3px',
      }}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-start gap-2 flex-1 min-w-0">
          <Bell size={13} color={border} className="mt-0.5 flex-shrink-0" />
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className={severityBadgeClass(alert.severity)}>{alert.severity}</span>
              <span className="text-xs font-semibold text-gray-200 truncate">{alert.title}</span>
            </div>
            <div className="text-xs text-gray-500 mt-1 line-clamp-2">{alert.description}</div>
            <div className="flex items-center gap-3 mt-1.5 flex-wrap">
              {alert.source_ip && (
                <span className="text-xs font-mono" style={{ color: '#a855f7' }}>
                  {alert.source_ip}
                </span>
              )}
              {alert.hostname && (
                <span className="text-xs" style={{ color: '#00d4ff' }}>{alert.hostname}</span>
              )}
              {alert.mitre_techniques?.slice(0, 3).map(t => (
                <span
                  key={t}
                  className="text-xs px-1.5 py-0.5 rounded font-mono"
                  style={{ background: '#1f2937', color: '#ffaa00', fontSize: '0.6rem' }}
                >
                  {t}
                </span>
              ))}
              <span className="text-xs text-gray-600">{formatDateTime(alert.created_at)}</span>
            </div>
          </div>
        </div>

        <div className="flex flex-col items-end gap-1 flex-shrink-0">
          <button
            onClick={investigate}
            disabled={investigating}
            className="btn-cyber flex items-center gap-1 hover:bg-purple-900/30"
            style={{ padding: '3px 10px', fontSize: '0.7rem', border: '1px solid #8b5cf6', color: '#8b5cf6' }}
            title="Analyze with local AI"
          >
            <BrainCircuit size={10} /> {investigating ? 'Analyzing...' : 'Investigate'}
          </button>
          
          {alert.acknowledged ? (
            <span className="badge badge-low flex items-center gap-1">
              <Check size={9} /> ACK
            </span>
          ) : (
            <button
              onClick={ack}
              disabled={loading}
              className="btn-cyber btn-cyber-primary"
              style={{ padding: '3px 10px', fontSize: '0.7rem' }}
            >
              <Check size={10} /> Ack
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
