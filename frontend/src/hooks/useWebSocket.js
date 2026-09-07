import { useEffect } from 'react'
import wsService from '../services/websocket'
import useStore from '../store/useStore'
import { toast } from 'react-toastify'

export function useWebSocket() {
  const addLog = useStore(s => s.addLog)
  const addAlert = useStore(s => s.addAlert)
  const setWsConnected = useStore(s => s.setWsConnected)
  const setEps = useStore(s => s.setEps)
  const setAIInvestigation = useStore(s => s.setAIInvestigation)

  useEffect(() => {
    wsService.connect()

    const offLog = wsService.on('log', addLog)
    const offAlert = wsService.on('alert', (alert) => {
      addAlert(alert)
      const sev = alert.severity || 'info'
      if (sev === 'critical' || sev === 'high') {
        toast.error(`🚨 ${alert.title}`, { autoClose: 6000 })
      }
    })
    const offStats = wsService.on('stats', (data) => {
      if (data?.eps !== undefined) setEps(data.eps)
    })
    const offAI = wsService.on('AI_INVESTIGATION_COMPLETE', (data) => {
      if (!data?.signal_id) return

      setAIInvestigation(data.signal_id, data)

      toast.success(
        `AI investigation complete: ${data.verdict || 'UNKNOWN'}`,
        { autoClose: 5000 }
      )
    })
    const offConn = wsService.on('connected', () => setWsConnected(true))
    const offDisc = wsService.on('disconnected', () => setWsConnected(false))

    return () => {
      offLog()
      offAlert()
      offStats()
      offAI()
      offConn()
      offDisc()
    }
  }, [])
}
