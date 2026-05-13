import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { useEffect } from 'react'
import useStore from './store/useStore'
import { useWebSocket } from './hooks/useWebSocket'
import Sidebar from './components/Sidebar'
import TopNav from './components/TopNav'

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

function Layout({ children }) {
  useWebSocket()
  return (
    <div className="flex h-screen overflow-hidden" style={{ background: '#030712' }}>
      <Sidebar />
      <div className="flex flex-col flex-1 min-w-0 overflow-hidden">
        <TopNav />
        <main className="flex-1 overflow-auto p-5" style={{ background: '#030712' }}>
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

function AppRoutes() {
  const initAuth = useStore(s => s.initAuth)
  useEffect(() => { initAuth() }, [])

  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/" element={<Navigate to="/dashboard" replace />} />
      <Route path="/dashboard" element={
        <ProtectedRoute><Layout><DashboardPage /></Layout></ProtectedRoute>
      } />
      <Route path="/logs" element={
        <ProtectedRoute><Layout><LogExplorerPage /></Layout></ProtectedRoute>
      } />
      <Route path="/alerts" element={
        <ProtectedRoute><Layout><AlertsPage /></Layout></ProtectedRoute>
      } />
      <Route path="/incidents" element={
        <ProtectedRoute><Layout><IncidentsPage /></Layout></ProtectedRoute>
      } />
      <Route path="/threat-intel" element={
        <ProtectedRoute><Layout><ThreatIntelPage /></Layout></ProtectedRoute>
      } />
      <Route path="/attack-map" element={
        <ProtectedRoute><Layout><AttackMapPage /></Layout></ProtectedRoute>
      } />
      <Route path="/ueba" element={
        <ProtectedRoute><Layout><UEBAPage /></Layout></ProtectedRoute>
      } />
      <Route path="/reports" element={
        <ProtectedRoute><Layout><ReportsPage /></Layout></ProtectedRoute>
      } />
      <Route path="/settings" element={
        <ProtectedRoute><Layout><SettingsPage /></Layout></ProtectedRoute>
      } />
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <AppRoutes />
    </BrowserRouter>
  )
}
