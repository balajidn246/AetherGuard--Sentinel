import { useState, useEffect, useRef } from 'react'
import { dashboardApi } from '../services/api'
import useStore from '../store/useStore'
import { Globe, Zap, Activity } from 'lucide-react'
import { SEVERITY_COLORS } from '../utils/constants'

// Static country coordinates for the attack map
const COUNTRY_COORDS = {
  'Russia':         { x: 72, y: 22 },
  'China':          { x: 79, y: 35 },
  'United States':  { x: 20, y: 35 },
  'Germany':        { x: 52, y: 28 },
  'Netherlands':    { x: 51, y: 26 },
  'Brazil':         { x: 28, y: 60 },
  'Iran':           { x: 63, y: 36 },
  'North Korea':    { x: 82, y: 30 },
  'Romania':        { x: 55, y: 28 },
  'Ukraine':        { x: 57, y: 27 },
  'India':          { x: 71, y: 43 },
  'United Kingdom': { x: 49, y: 24 },
  'France':         { x: 50, y: 28 },
  'Canada':         { x: 18, y: 22 },
  'Australia':      { x: 83, y: 72 },
  'Unknown':        { x: 50, y: 50 },
}

// Target (UK/Europe) for destination
const TARGET = { x: 50, y: 28, label: 'HQ' }

function AttackLine({ src, dst, color, key }) {
  const [opacity, setOpacity] = useState(1)
  useEffect(() => {
    const t = setTimeout(() => setOpacity(0), 3000)
    return () => clearTimeout(t)
  }, [])
  const mx = (src.x + dst.x) / 2
  const my = Math.min(src.y, dst.y) - 15

  return (
    <g style={{ transition: 'opacity 1s', opacity }}>
      <path
        d={`M ${src.x}% ${src.y}% Q ${mx}% ${my}% ${dst.x}% ${dst.y}%`}
        fill="none"
        stroke={color}
        strokeWidth="1"
        strokeOpacity={0.6}
        strokeDasharray="4 2"
      />
      <circle cx={`${src.x}%`} cy={`${src.y}%`} r="3" fill={color} opacity={0.8}>
        <animate attributeName="r" values="3;6;3" dur="1s" repeatCount="1" />
        <animate attributeName="opacity" values="0.8;0.2;0" dur="3s" fill="freeze" />
      </circle>
    </g>
  )
}

export default function AttackMapPage() {
  const [attackLines, setAttackLines] = useState([])
  const [geoAttacks, setGeoAttacks] = useState([])
  const [stats, setStats] = useState({ total: 0, countries: 0 })
  const liveLogs = useStore(s => s.liveLogs)
  const lineRef = useRef(0)

  useEffect(() => {
    dashboardApi.geoAttacks().then(r => {
      setGeoAttacks(r.data)
      const countries = new Set(r.data.map(a => a.country)).size
      setStats({ total: r.data.length, countries })
    }).catch(() => {})
  }, [])

  // Add a new animated attack line for each geo-tagged log
  useEffect(() => {
    const geoLog = liveLogs[0]
    if (!geoLog?.country || !geoLog?.geo_lat) return

    const src = COUNTRY_COORDS[geoLog.country] || { x: Math.random() * 100, y: Math.random() * 100 }
    const color = SEVERITY_COLORS[geoLog.severity] || '#00d4ff'

    const id = ++lineRef.current
    setAttackLines(lines => [...lines.slice(-30), { id, src, dst: TARGET, color }])

    // Auto-remove after 4 seconds
    setTimeout(() => {
      setAttackLines(lines => lines.filter(l => l.id !== id))
    }, 4000)
  }, [liveLogs[0]?._id])

  return (
    <div className="flex flex-col gap-4 h-full animate-fade-in">
      {/* Stats bar */}
      <div className="grid grid-cols-4 gap-3 flex-shrink-0">
        {[
          { label: 'Live Attacks', value: attackLines.length, color: '#ff3366', icon: Zap },
          { label: 'Geo Events', value: stats.total, color: '#ffaa00', icon: Globe },
          { label: 'Countries', value: stats.countries, color: '#00d4ff', icon: Globe },
          { label: 'Active Paths', value: attackLines.length, color: '#a855f7', icon: Activity },
        ].map(({ label, value, color, icon: Icon }) => (
          <div key={label} className="glass-card p-4 flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0" style={{ background: `${color}18`, border: `1px solid ${color}33` }}>
              <Icon size={16} color={color} />
            </div>
            <div>
              <div className="text-xs text-gray-500">{label}</div>
              <div className="text-xl font-bold" style={{ color }}>{value}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Map */}
      <div className="flex-1 glass-card overflow-hidden relative">
        <div className="absolute inset-0 flex items-center justify-center">
          {/* World map background */}
          <div className="relative w-full h-full" style={{ background: 'linear-gradient(180deg, #030a18 0%, #050d20 100%)' }}>
            {/* Grid lines */}
            <svg className="absolute inset-0 w-full h-full opacity-10" xmlns="http://www.w3.org/2000/svg">
              {Array.from({ length: 18 }).map((_, i) => (
                <line key={`v${i}`} x1={`${(i + 1) * 5.5}%`} y1="0" x2={`${(i + 1) * 5.5}%`} y2="100%" stroke="#1f2937" strokeWidth="0.5" />
              ))}
              {Array.from({ length: 10 }).map((_, i) => (
                <line key={`h${i}`} x1="0" y1={`${(i + 1) * 10}%`} x2="100%" y2={`${(i + 1) * 10}%`} stroke="#1f2937" strokeWidth="0.5" />
              ))}
            </svg>

            {/* Attack lines SVG layer */}
            <svg className="absolute inset-0 w-full h-full" xmlns="http://www.w3.org/2000/svg">
              {attackLines.map(line => (
                <AttackLine key={line.id} src={line.src} dst={line.dst} color={line.color} />
              ))}
              {/* Target marker */}
              <circle cx={`${TARGET.x}%`} cy={`${TARGET.y}%`} r="5" fill="none" stroke="#00d4ff" strokeWidth="1.5">
                <animate attributeName="r" values="5;10;5" dur="2s" repeatCount="indefinite" />
                <animate attributeName="opacity" values="1;0.3;1" dur="2s" repeatCount="indefinite" />
              </circle>
              <circle cx={`${TARGET.x}%`} cy={`${TARGET.y}%`} r="3" fill="#00d4ff" />
            </svg>

            {/* Country dots for geo attacks */}
            <div className="absolute inset-0">
              {Object.entries(COUNTRY_COORDS).map(([country, pos]) => {
                const count = geoAttacks.filter(a => a.country === country).length
                if (count === 0) return null
                return (
                  <div
                    key={country}
                    className="absolute transform -translate-x-1/2 -translate-y-1/2"
                    style={{ left: `${pos.x}%`, top: `${pos.y}%` }}
                    title={`${country}: ${count} attacks`}
                  >
                    <div
                      className="rounded-full animate-pulse"
                      style={{
                        width: Math.min(4 + count * 2, 16),
                        height: Math.min(4 + count * 2, 16),
                        background: '#ff3366',
                        boxShadow: `0 0 ${Math.min(8 + count, 20)}px #ff336688`,
                        opacity: 0.8,
                      }}
                    />
                  </div>
                )
              })}
            </div>

            {/* Live event feed overlay */}
            <div className="absolute bottom-4 left-4 space-y-1" style={{ maxWidth: 400 }}>
              {attackLines.slice(-5).reverse().map(line => {
                const country = Object.entries(COUNTRY_COORDS).find(([, c]) => c.x === line.src.x && c.y === line.src.y)?.[0] || 'Unknown'
                return (
                  <div key={line.id} className="flex items-center gap-2 text-xs animate-fade-in" style={{ fontFamily: 'JetBrains Mono, monospace' }}>
                    <div className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: line.color }} />
                    <span style={{ color: line.color }}>ATTACK</span>
                    <span className="text-gray-400">{country} → Target</span>
                  </div>
                )
              })}
            </div>

            {/* Legend */}
            <div className="absolute top-4 right-4 glass-card p-3">
              <div className="text-xs font-bold text-gray-400 mb-2">SEVERITY</div>
              {[['critical','#ff3366'],['high','#ff6b35'],['medium','#ffaa00'],['low','#3b82f6']].map(([s, c]) => (
                <div key={s} className="flex items-center gap-2 mb-1">
                  <div className="w-2 h-2 rounded-full" style={{ background: c }} />
                  <span className="text-xs capitalize text-gray-400">{s}</span>
                </div>
              ))}
            </div>

            {/* Live indicator */}
            <div className="absolute top-4 left-4 flex items-center gap-2 px-3 py-1.5 rounded-lg" style={{ background: 'rgba(0,0,0,0.6)', border: '1px solid #1f2937' }}>
              <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
              <span className="text-xs font-bold" style={{ color: '#ff3366' }}>LIVE ATTACK MONITOR</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
