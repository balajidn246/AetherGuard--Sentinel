import { create } from 'zustand'

const useStore = create((set, get) => ({
  // Auth
  user: null,
  token: null,
  setAuth: (user, token) => {
    localStorage.setItem('ag_token', token)
    localStorage.setItem('ag_user', JSON.stringify(user))
    set({ user, token })
  },
  logout: () => {
    localStorage.removeItem('ag_token')
    localStorage.removeItem('ag_user')
    set({ user: null, token: null })
  },
  initAuth: () => {
    const token = localStorage.getItem('ag_token')
    const userStr = localStorage.getItem('ag_user')
    if (token && userStr) {
      try {
        const user = JSON.parse(userStr)
        set({ user, token })
        return true
      } catch {
        return false
      }
    }
    return false
  },

  // Live logs buffer (last 500)
  liveLogs: [],
  addLog: (log) => set((s) => ({
    liveLogs: [log, ...s.liveLogs].slice(0, 500),
  })),

  // Live alerts buffer (last 100)
  liveAlerts: [],
  addAlert: (alert) => set((s) => ({
    liveAlerts: [alert, ...s.liveAlerts].slice(0, 100),
    unreadAlerts: s.unreadAlerts + 1,
  })),
  unreadAlerts: 0,
  clearUnread: () => set({ unreadAlerts: 0 }),

  // Notifications panel
  notifOpen: false,
  toggleNotif: () => set((s) => ({ notifOpen: !s.notifOpen })),

  // Sidebar collapsed
  sidebarCollapsed: false,
  toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),

  // WebSocket status
  wsConnected: false,
  setWsConnected: (v) => set({ wsConnected: v }),

  // EPS
  eps: 0,
  setEps: (v) => set({ eps: v }),
}))

export default useStore
