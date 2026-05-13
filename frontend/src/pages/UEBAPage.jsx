import { useState, useEffect } from 'react'
import { uebaApi } from '../services/api'
import { Users, AlertTriangle, Activity, TrendingUp } from 'lucide-react'
import { getRiskColor } from '../utils/constants'
import { RadarChart, PolarGrid, PolarAngleAxis, Radar, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell } from 'recharts'

function RiskGauge({ score }) {
  const color = getRiskColor(score)
  const angle = (score / 100) * 180 - 90
  return (
    <div className="flex flex-col items-center">
      <div className="relative w-24 h-12 overflow-hidden">
        <div className="absolute inset-0 rounded-t-full border-4 border-gray-800" />
        <div
          className="absolute bottom-0 left-1/2 w-0.5 h-10 origin-bottom rounded"
          style={{ background: color, transform: `translateX(-50%) rotate(${angle}deg)`, transformOrigin: 'bottom center' }}
        />
      </div>
      <div className="text-xl font-bold mt-1" style={{ color }}>{score}</div>
      <div className="text-xs text-gray-500">Risk Score</div>
    </div>
  )
}

export default function UEBAPage() {
  const [users, setUsers] = useState([])
  const [selectedUser, setSelectedUser] = useState(null)
  const [loading, setLoading] = useState(false)

  const fetchUsers = async () => {
    setLoading(true)
    try {
      const res = await uebaApi.users()
      setUsers(res.data)
      if (res.data.length > 0 && !selectedUser) setSelectedUser(res.data[0])
    } catch (e) { console.error(e) }
    finally { setLoading(false) }
  }

  useEffect(() => {
    fetchUsers()
    const interval = setInterval(fetchUsers, 15000)
    return () => clearInterval(interval)
  }, [])

  const radarData = selectedUser ? [
    { subject: 'Login Freq', A: Math.min(100, selectedUser.current_hour_events * 5) },
    { subject: 'Risk Score', A: selectedUser.avg_risk_score },
    { subject: 'Peak Risk', A: selectedUser.peak_risk },
    { subject: 'Hourly Vol', A: Math.min(100, selectedUser.avg_hourly_events * 3) },
    { subject: 'Anomaly', A: selectedUser.anomaly_flag ? 80 : 20 },
  ] : []

  return (
    <div className="flex flex-col gap-4 h-full animate-fade-in">
      {/* Header stats */}
      <div className="grid grid-cols-3 gap-3 flex-shrink-0">
        <div className="glass-card p-4">
          <div className="text-xs text-gray-500 mb-1">Total Users Tracked</div>
          <div className="text-2xl font-bold" style={{ color: '#00d4ff' }}>{users.length}</div>
        </div>
        <div className="glass-card p-4">
          <div className="text-xs text-gray-500 mb-1">Anomalous Users</div>
          <div className="text-2xl font-bold" style={{ color: '#ff3366' }}>
            {users.filter(u => u.anomaly_flag).length}
          </div>
        </div>
        <div className="glass-card p-4">
          <div className="text-xs text-gray-500 mb-1">Avg Risk Score</div>
          <div className="text-2xl font-bold" style={{ color: '#ffaa00' }}>
            {users.length > 0 ? Math.round(users.reduce((s, u) => s + u.avg_risk_score, 0) / users.length) : 0}
          </div>
        </div>
      </div>

      <div className="flex-1 grid grid-cols-12 gap-4 min-h-0">
        {/* User list */}
        <div className="col-span-5 glass-card overflow-hidden flex flex-col">
          <div className="px-4 py-3 flex-shrink-0" style={{ borderBottom: '1px solid #1f2937' }}>
            <div className="flex items-center gap-2">
              <Users size={14} color="#00d4ff" />
              <span className="text-sm font-bold text-white">User Risk Rankings</span>
            </div>
          </div>
          <div className="flex-1 overflow-y-auto">
            {loading && users.length === 0 ? (
              <div className="p-6 text-center text-gray-500 text-sm">Loading user profiles...</div>
            ) : users.length === 0 ? (
              <div className="p-6 text-center text-gray-600 text-sm">No user data yet — logs streaming...</div>
            ) : (
              users.map((user, i) => (
                <div
                  key={user.username}
                  onClick={() => setSelectedUser(user)}
                  className="flex items-center gap-3 px-4 py-3 cursor-pointer transition-colors hover:bg-white/5"
                  style={{
                    borderBottom: '1px solid #1f2937',
                    background: selectedUser?.username === user.username ? 'rgba(0,212,255,0.05)' : undefined,
                  }}
                >
                  <span className="text-xs text-gray-600 w-5">{i + 1}</span>
                  <div
                    className="w-8 h-8 rounded-lg flex items-center justify-center text-xs font-bold flex-shrink-0"
                    style={{ background: '#1f2937', color: getRiskColor(user.avg_risk_score) }}
                  >
                    {user.username?.[0]?.toUpperCase()}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium text-gray-200">{user.username}</div>
                    <div className="text-xs text-gray-500">{user.total_events} events</div>
                  </div>
                  <div className="flex items-center gap-2">
                    {user.anomaly_flag && (
                      <AlertTriangle size={13} color="#ffaa00" />
                    )}
                    <div
                      className="w-10 h-10 rounded-full flex items-center justify-center text-xs font-bold border-2"
                      style={{
                        borderColor: getRiskColor(user.avg_risk_score),
                        color: getRiskColor(user.avg_risk_score),
                        background: `${getRiskColor(user.avg_risk_score)}11`,
                      }}
                    >
                      {Math.round(user.avg_risk_score)}
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* User detail */}
        <div className="col-span-7 flex flex-col gap-4">
          {selectedUser ? (
            <>
              <div className="glass-card p-4">
                <div className="flex items-center gap-4">
                  <div
                    className="w-14 h-14 rounded-xl flex items-center justify-center text-xl font-bold"
                    style={{ background: '#1f2937', color: getRiskColor(selectedUser.avg_risk_score) }}
                  >
                    {selectedUser.username?.[0]?.toUpperCase()}
                  </div>
                  <div className="flex-1">
                    <div className="text-lg font-bold text-white">{selectedUser.username}</div>
                    <div className="flex items-center gap-2 mt-1">
                      {selectedUser.anomaly_flag ? (
                        <span className="badge badge-high flex items-center gap-1"><AlertTriangle size={9} /> ANOMALOUS</span>
                      ) : (
                        <span className="badge badge-low">NORMAL</span>
                      )}
                    </div>
                  </div>
                  <RiskGauge score={Math.round(selectedUser.avg_risk_score)} />
                </div>

                <div className="grid grid-cols-3 gap-3 mt-4">
                  {[
                    { label: 'Total Events', value: selectedUser.total_events, color: '#00d4ff' },
                    { label: 'Hourly Avg', value: selectedUser.avg_hourly_events?.toFixed(1), color: '#ffaa00' },
                    { label: 'Peak Risk', value: selectedUser.peak_risk, color: '#ff3366' },
                  ].map(({ label, value, color }) => (
                    <div key={label} className="p-3 rounded-lg text-center" style={{ background: '#1f2937' }}>
                      <div className="text-xs text-gray-500">{label}</div>
                      <div className="text-lg font-bold mt-1" style={{ color }}>{value}</div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Radar chart */}
              <div className="glass-card p-4 flex-1">
                <div className="text-xs font-bold text-white mb-3">Behavioral Profile</div>
                <ResponsiveContainer width="100%" height={220}>
                  <RadarChart data={radarData}>
                    <PolarGrid stroke="#1f2937" />
                    <PolarAngleAxis dataKey="subject" tick={{ fill: '#6b7280', fontSize: 11 }} />
                    <Radar
                      name={selectedUser.username}
                      dataKey="A"
                      stroke={getRiskColor(selectedUser.avg_risk_score)}
                      fill={getRiskColor(selectedUser.avg_risk_score)}
                      fillOpacity={0.2}
                    />
                  </RadarChart>
                </ResponsiveContainer>
              </div>
            </>
          ) : (
            <div className="flex-1 glass-card flex items-center justify-center text-gray-600">
              Select a user to view profile
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
