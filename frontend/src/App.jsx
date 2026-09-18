import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { useEffect, useState } from 'react'
import useStore from './store/useStore'
import { useWebSocket } from './hooks/useWebSocket'
import Sidebar from './components/Sidebar'
import TopNav from './components/TopNav'
import CommandPalette from './components/CommandPalette'

import LoginPage from './pages/LoginPage'
import DashboardPage from './pages/DashboardPage'
import LogExplorerPage from './pages/LogExplorerPage'
import AlertsPage from './pages/AlertsPage'
import IncidentsPage from './pages/IncidentsPage'
import ThreatIntelPage from './pages/ThreatIntelPage'
import AttackMapPage from './pages/AttackMapPage'
import UEBAPage from './pages/UEBAPage'
import ReportsPage from './pages/ReportsPage'
import SettingsPage from './pages/SettingsPage'
import CasesPage from './pages/CasesPage'
import DetectionRulesPage from './pages/DetectionRulesPage'
import AuditPage from './pages/AuditPage'
import SOARPage from './pages/SOARPage'
import EntityGraphPage from './pages/EntityGraphPage'

function Layout({ children, onOpenCommandPalette }) {
  useWebSocket()
  return (
    <div className="flex h-screen overflow-hidden" style={{ background: 'var(--bg-primary)' }}>
      <Sidebar />
      <div className="flex flex-col flex-1 min-w-0 overflow-hidden">
        <TopNav onOpenCommandPalette={onOpenCommandPalette} />
        <main className="flex-1 overflow-auto p-4" style={{ background: 'var(--bg-primary)' }}>
          {children}
        </main>
      </div>
    </div>
  )
}

function ProtectedRoute({ children }) {
  const token = useStore(s => s.token)
  if (!token) return <Navigate to="/login" replace />
  return children
}

function AppRoutes({ onOpenCommandPalette }) {
  const initAuth = useStore(s => s.initAuth)
  const initTheme = useStore(s => s.initTheme)
  useEffect(() => { initAuth(); initTheme() }, [])

  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/" element={<Navigate to="/dashboard" replace />} />
      <Route path="/dashboard" element={
        <ProtectedRoute><Layout onOpenCommandPalette={onOpenCommandPalette}><DashboardPage /></Layout></ProtectedRoute>
      } />
      <Route path="/logs" element={
        <ProtectedRoute><Layout onOpenCommandPalette={onOpenCommandPalette}><LogExplorerPage /></Layout></ProtectedRoute>
      } />
      <Route path="/alerts" element={
        <ProtectedRoute><Layout onOpenCommandPalette={onOpenCommandPalette}><AlertsPage /></Layout></ProtectedRoute>
      } />
      <Route path="/cases" element={
        <ProtectedRoute><Layout onOpenCommandPalette={onOpenCommandPalette}><CasesPage /></Layout></ProtectedRoute>
      } />
      <Route path="/incidents" element={
        <ProtectedRoute><Layout onOpenCommandPalette={onOpenCommandPalette}><IncidentsPage /></Layout></ProtectedRoute>
      } />
      <Route path="/rules" element={
        <ProtectedRoute><Layout onOpenCommandPalette={onOpenCommandPalette}><DetectionRulesPage /></Layout></ProtectedRoute>
      } />
      <Route path="/soar" element={
        <ProtectedRoute><Layout onOpenCommandPalette={onOpenCommandPalette}><SOARPage /></Layout></ProtectedRoute>
      } />
      <Route path="/threat-intel" element={
        <ProtectedRoute><Layout onOpenCommandPalette={onOpenCommandPalette}><ThreatIntelPage /></Layout></ProtectedRoute>
      } />
      <Route path="/ueba" element={
        <ProtectedRoute><Layout onOpenCommandPalette={onOpenCommandPalette}><UEBAPage /></Layout></ProtectedRoute>
      } />
      <Route path="/audit" element={
        <ProtectedRoute><Layout onOpenCommandPalette={onOpenCommandPalette}><AuditPage /></Layout></ProtectedRoute>
      } />
      <Route path="/reports" element={
        <ProtectedRoute><Layout onOpenCommandPalette={onOpenCommandPalette}><ReportsPage /></Layout></ProtectedRoute>
      } />
      <Route path="/settings" element={
        <ProtectedRoute><Layout onOpenCommandPalette={onOpenCommandPalette}><SettingsPage /></Layout></ProtectedRoute>
      } />
      <Route path="/attack-map" element={
        <ProtectedRoute><Layout onOpenCommandPalette={onOpenCommandPalette}><AttackMapPage /></Layout></ProtectedRoute>
      } />
      <Route path="/entity-graph" element={
        <ProtectedRoute><Layout onOpenCommandPalette={onOpenCommandPalette}><EntityGraphPage /></Layout></ProtectedRoute>
      } />
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  )
}

export default function App() {
  const [paletteOpen, setPaletteOpen] = useState(false)

  useEffect(() => {
    function handleCustomOpen() {
      setPaletteOpen(true)
    }
    window.addEventListener('open-command-palette', handleCustomOpen)
    return () => window.removeEventListener('open-command-palette', handleCustomOpen)
  }, [])

  return (
    <BrowserRouter>
      <CommandPalette isOpen={paletteOpen} onClose={() => setPaletteOpen(false)} />
      <AppRoutes onOpenCommandPalette={() => setPaletteOpen(true)} />
    </BrowserRouter>
  )
}
