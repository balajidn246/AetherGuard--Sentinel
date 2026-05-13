import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { authApi } from '../services/api'
import useStore from '../store/useStore'
import { Zap, Eye, EyeOff, Shield, AlertTriangle, Activity } from 'lucide-react'
import { toast } from 'react-toastify'

export default function LoginPage() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [loading, setLoading] = useState(false)
  const { setAuth } = useStore()
  const navigate = useNavigate()

  const handleLogin = async (e) => {
    e.preventDefault()
    if (!username || !password) { toast.error('Enter credentials'); return }
    setLoading(true)
    try {
      const res = await authApi.login(username, password)
      setAuth(res.data.user, res.data.access_token)
      toast.success(`Welcome, ${res.data.user.username}!`)
      navigate('/dashboard')
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  const fillDemo = (u, p) => { setUsername(u); setPassword(p) }

  return (
    <div
      className="min-h-screen flex items-center justify-center relative overflow-hidden"
      style={{ background: 'linear-gradient(135deg, #030712 0%, #0a0e18 50%, #030712 100%)' }}
    >
      {/* Background grid */}
      <div
        className="absolute inset-0 pointer-events-none opacity-10"
        style={{
          backgroundImage: 'linear-gradient(#1f2937 1px, transparent 1px), linear-gradient(90deg, #1f2937 1px, transparent 1px)',
          backgroundSize: '40px 40px',
        }}
      />

      {/* Animated glow orbs */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 rounded-full opacity-5 animate-pulse"
          style={{ background: 'radial-gradient(circle, #00d4ff, transparent)', filter: 'blur(60px)' }} />
        <div className="absolute bottom-1/4 right-1/4 w-96 h-96 rounded-full opacity-5 animate-pulse"
          style={{ background: 'radial-gradient(circle, #a855f7, transparent)', filter: 'blur(60px)', animationDelay: '1s' }} />
      </div>

      <div className="relative z-10 w-full max-w-md px-6">
        {/* Logo */}
        <div className="text-center mb-10">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl mb-4 relative"
            style={{ background: 'linear-gradient(135deg, #00d4ff15, #a855f715)', border: '1px solid #00d4ff33' }}>
            <Zap size={28} color="#00d4ff" />
            <div className="absolute inset-0 rounded-2xl animate-pulse"
              style={{ boxShadow: '0 0 30px rgba(0,212,255,0.2)' }} />
          </div>
          <h1 className="text-2xl font-bold text-white tracking-tight">AetherGuard Sentinel</h1>
          <p className="text-sm mt-1" style={{ color: '#00d4ff' }}>Real-Time Threat Detection & SOC Intelligence</p>
        </div>

        {/* Login card */}
        <div className="glass-card p-8 cyber-border">
          <div className="flex items-center gap-2 mb-6">
            <Shield size={16} color="#00d4ff" />
            <span className="text-sm font-semibold text-gray-300">SOC Analyst Authentication</span>
          </div>

          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-gray-400 mb-1.5">Username</label>
              <input
                className="cyber-input w-full"
                placeholder="Enter username"
                value={username}
                onChange={e => setUsername(e.target.value)}
                autoComplete="username"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-400 mb-1.5">Password</label>
              <div className="relative">
                <input
                  className="cyber-input w-full pr-10"
                  type={showPassword ? 'text' : 'password'}
                  placeholder="Enter password"
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  autoComplete="current-password"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(p => !p)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
                >
                  {showPassword ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 rounded-lg font-semibold text-sm transition-all mt-2"
              style={{
                background: loading ? '#1f2937' : 'linear-gradient(135deg, #00d4ff22, #a855f722)',
                border: '1px solid #00d4ff44',
                color: loading ? '#6b7280' : '#00d4ff',
                boxShadow: loading ? 'none' : '0 0 20px rgba(0,212,255,0.15)',
              }}
            >
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <Activity size={14} className="animate-spin" /> Authenticating...
                </span>
              ) : 'Sign In to SOC Platform'}
            </button>
          </form>

          {/* Demo accounts */}
          <div className="mt-6 pt-4" style={{ borderTop: '1px solid #1f2937' }}>
            <p className="text-xs text-gray-500 mb-2">Quick access demo accounts:</p>
            <div className="flex gap-2">
              {[
                { label: 'Admin', u: 'admin', p: 'aetherguard2024', color: '#ff3366' },
                { label: 'Analyst', u: 'analyst', p: 'sentinel2024', color: '#00d4ff' },
                { label: 'Viewer', u: 'viewer', p: 'viewer2024', color: '#6b7280' },
              ].map(({ label, u, p, color }) => (
                <button
                  key={u}
                  onClick={() => fillDemo(u, p)}
                  className="flex-1 py-1.5 rounded text-xs font-medium transition-all hover:opacity-80"
                  style={{ background: `${color}15`, border: `1px solid ${color}44`, color }}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="text-center mt-6 space-y-1">
          <div className="flex items-center justify-center gap-4 text-xs text-gray-600">
            <span className="flex items-center gap-1"><AlertTriangle size={10} /> Authorized Access Only</span>
            <span>|</span>
            <span>All actions are audited</span>
          </div>
          <p className="text-xs text-gray-700">AetherGuard Sentinel v1.0 © 2026</p>
        </div>
      </div>
    </div>
  )
}
