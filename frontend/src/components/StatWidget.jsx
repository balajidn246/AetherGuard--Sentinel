import { useEffect, useRef, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'

/**
 * Animated stat widget with counter animation and glow ring.
 */
export default function StatWidget({ label, value, icon: Icon, color = '#00d4ff', subtitle, trend }) {
  const [displayed, setDisplayed] = useState(0)
  const prev = useRef(0)

  useEffect(() => {
    const target = Number(value) || 0
    const start = prev.current
    prev.current = target
    if (start === target) return
    const duration = 600
    const startTime = performance.now()
    const raf = (now) => {
      const elapsed = now - startTime
      const progress = Math.min(elapsed / duration, 1)
      const eased = 1 - Math.pow(1 - progress, 3)
      setDisplayed(Math.round(start + (target - start) * eased))
      if (progress < 1) requestAnimationFrame(raf)
    }
    requestAnimationFrame(raf)
  }, [value])

  return (
    <div
      className="glass-card p-4 flex flex-col gap-3 relative overflow-hidden"
      style={{ '--glow-color': color }}
    >
      {/* Background glow */}
      <div
        className="absolute inset-0 pointer-events-none opacity-5"
        style={{ background: `radial-gradient(circle at top right, ${color}, transparent 60%)` }}
      />

      {/* Header */}
      <div className="flex items-center justify-between">
        <span className="text-xs text-gray-400 font-medium uppercase tracking-wider">{label}</span>
        <div
          className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
          style={{ background: `${color}18`, border: `1px solid ${color}33` }}
        >
          {Icon && <Icon size={15} color={color} />}
        </div>
      </div>

      {/* Value */}
      <div className="flex items-end gap-2">
        <motion.span
          className="text-3xl font-bold leading-none"
          style={{ color, fontVariantNumeric: 'tabular-nums' }}
          key={displayed}
        >
          {displayed.toLocaleString()}
        </motion.span>
        {trend !== undefined && (
          <span
            className="text-xs mb-1 font-medium"
            style={{ color: trend >= 0 ? '#00ff88' : '#ff3366' }}
          >
            {trend >= 0 ? '↑' : '↓'} {Math.abs(trend)}%
          </span>
        )}
      </div>

      {/* Subtitle */}
      {subtitle && <p className="text-xs text-gray-500">{subtitle}</p>}

      {/* Bottom glow bar */}
      <div
        className="absolute bottom-0 left-0 h-0.5 w-full"
        style={{ background: `linear-gradient(90deg, ${color}88, transparent)` }}
      />
    </div>
  )
}
