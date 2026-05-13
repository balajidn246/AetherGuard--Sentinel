/**
 * WebSocket service — connects to AetherGuard backend and
 * dispatches log/alert/incident/stats events to the Zustand store.
 */

const WS_URL = 'ws://localhost:8000/ws'

class WebSocketService {
  constructor() {
    this.ws = null
    this.reconnectDelay = 2000
    this.maxReconnectDelay = 30000
    this.reconnectAttempts = 0
    this.handlers = { log: [], alert: [], incident: [], stats: [], connected: [], disconnected: [] }
    this._epsCounter = 0
    this._epsInterval = null
  }

  connect() {
    if (this.ws?.readyState === WebSocket.OPEN) return

    try {
      this.ws = new WebSocket(WS_URL)

      this.ws.onopen = () => {
        console.log('[WS] Connected to AetherGuard Sentinel')
        this.reconnectAttempts = 0
        this.reconnectDelay = 2000
        this._emit('connected')
        this._startEpsCounter()
        // Heartbeat ping every 20s
        this._pingInterval = setInterval(() => {
          if (this.ws?.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify({ type: 'ping' }))
          }
        }, 20000)
      }

      this.ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data)
          if (msg.type === 'pong') return
          this._epsCounter++
          this._emit(msg.type, msg.data)
        } catch (e) {
          // ignore parse errors
        }
      }

      this.ws.onclose = () => {
        console.log('[WS] Disconnected. Reconnecting...')
        this._emit('disconnected')
        clearInterval(this._pingInterval)
        this._scheduleReconnect()
      }

      this.ws.onerror = (err) => {
        console.warn('[WS] Error:', err)
      }
    } catch (e) {
      this._scheduleReconnect()
    }
  }

  _scheduleReconnect() {
    this.reconnectAttempts++
    const delay = Math.min(this.reconnectDelay * Math.pow(1.5, Math.min(this.reconnectAttempts, 8)), this.maxReconnectDelay)
    console.log(`[WS] Reconnecting in ${Math.round(delay / 1000)}s...`)
    setTimeout(() => this.connect(), delay)
  }

  _startEpsCounter() {
    clearInterval(this._epsInterval)
    this._epsInterval = setInterval(() => {
      const eps = this._epsCounter
      this._epsCounter = 0
      this._emit('stats', { eps })
    }, 1000)
  }

  on(event, handler) {
    if (this.handlers[event]) {
      this.handlers[event].push(handler)
    }
    return () => this.off(event, handler)
  }

  off(event, handler) {
    if (this.handlers[event]) {
      this.handlers[event] = this.handlers[event].filter(h => h !== handler)
    }
  }

  _emit(event, data) {
    this.handlers[event]?.forEach(h => h(data))
  }

  disconnect() {
    clearInterval(this._epsInterval)
    clearInterval(this._pingInterval)
    this.ws?.close()
  }
}

export const wsService = new WebSocketService()
export default wsService
