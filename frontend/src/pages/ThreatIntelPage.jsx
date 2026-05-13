import { useState, useEffect } from 'react'
import { threatIntelApi } from '../services/api'
import { Shield, Search, Plus, Trash2, RefreshCw, ExternalLink, AlertTriangle } from 'lucide-react'
import { formatDateTime } from '../utils/constants'
import { toast } from 'react-toastify'

export default function ThreatIntelPage() {
  const [iocs, setIocs] = useState([])
  const [feeds, setFeeds] = useState([])
  const [ipQuery, setIpQuery] = useState('')
  const [ipResult, setIpResult] = useState(null)
  const [ipLoading, setIpLoading] = useState(false)
  const [newIoc, setNewIoc] = useState({ ioc_type: 'ip', value: '', threat_type: 'malware', confidence: 75, notes: '' })
  const [loading, setLoading] = useState(false)

  const fetchData = async () => {
    setLoading(true)
    try {
      const [iocRes, feedsRes] = await Promise.all([threatIntelApi.iocs(), threatIntelApi.feeds()])
      setIocs(iocRes.data.iocs)
      setFeeds(feedsRes.data)
    } catch (e) { console.error(e) }
    finally { setLoading(false) }
  }

  useEffect(() => { fetchData() }, [])

  const checkIp = async () => {
    if (!ipQuery) return
    setIpLoading(true)
    setIpResult(null)
    try {
      const res = await threatIntelApi.ipReputation(ipQuery)
      setIpResult(res.data)
    } catch { toast.error('IP lookup failed') }
    finally { setIpLoading(false) }
  }

  const createIoc = async () => {
    if (!newIoc.value) { toast.error('IOC value required'); return }
    try {
      await threatIntelApi.createIoc(newIoc)
      toast.success('IOC added to database')
      setNewIoc({ ioc_type: 'ip', value: '', threat_type: 'malware', confidence: 75, notes: '' })
      fetchData()
    } catch { toast.error('Failed to create IOC') }
  }

  const deleteIoc = async (id) => {
    try {
      await threatIntelApi.deleteIoc(id)
      toast.success('IOC removed')
      fetchData()
    } catch { toast.error('Failed to delete') }
  }

  const getRiskColor = (score) => {
    if (score >= 75) return '#ff3366'
    if (score >= 50) return '#ffaa00'
    if (score >= 25) return '#3b82f6'
    return '#00ff88'
  }

  return (
    <div className="flex flex-col gap-4 h-full animate-fade-in">
      <div className="grid grid-cols-12 gap-4 flex-1 min-h-0">

        {/* Left Column */}
        <div className="col-span-8 flex flex-col gap-4">
          {/* IP Reputation Lookup */}
          <div className="glass-card p-4 flex-shrink-0">
            <div className="flex items-center gap-2 mb-3">
              <Search size={14} color="#00d4ff" />
              <span className="text-sm font-bold text-white">IP Reputation Lookup</span>
            </div>
            <div className="flex gap-2 mb-4">
              <input
                className="cyber-input flex-1"
                placeholder="Enter IP address (e.g. 185.220.101.47)"
                value={ipQuery}
                onChange={e => setIpQuery(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && checkIp()}
              />
              <button className="btn-cyber btn-cyber-primary" onClick={checkIp} disabled={ipLoading}>
                {ipLoading ? 'Checking...' : 'Check IP'}
              </button>
            </div>

            {ipResult && (
              <div
                className="rounded-lg p-4 animate-fade-in"
                style={{
                  background: ipResult.is_malicious ? 'rgba(255,51,102,0.1)' : 'rgba(0,255,136,0.1)',
                  border: `1px solid ${ipResult.is_malicious ? '#ff336644' : '#00ff8844'}`,
                }}
              >
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-lg text-white">{ipResult.ip}</span>
                    <span
                      className="badge"
                      style={{
                        background: ipResult.is_malicious ? '#ff336622' : '#00ff8822',
                        color: ipResult.is_malicious ? '#ff3366' : '#00ff88',
                        border: `1px solid ${ipResult.is_malicious ? '#ff336644' : '#00ff8844'}`,
                      }}
                    >
                      {ipResult.is_malicious ? '⚠ MALICIOUS' : '✓ CLEAN'}
                    </span>
                  </div>
                  <div className="text-right">
                    <div className="text-2xl font-bold" style={{ color: getRiskColor(ipResult.risk_score) }}>
                      {ipResult.risk_score}
                    </div>
                    <div className="text-xs text-gray-500">Risk Score</div>
                  </div>
                </div>
                <div className="grid grid-cols-3 gap-3 text-xs">
                  <div><span className="text-gray-500">Country:</span><span className="text-gray-200 ml-2">{ipResult.geo?.country}</span></div>
                  <div><span className="text-gray-500">City:</span><span className="text-gray-200 ml-2">{ipResult.geo?.city}</span></div>
                  <div><span className="text-gray-500">ASN:</span><span className="text-gray-200 ml-2">{ipResult.geo?.asn}</span></div>
                </div>
                {ipResult.tags?.length > 0 && (
                  <div className="flex gap-1.5 mt-3">
                    {ipResult.tags.map(t => (
                      <span key={t} className="text-xs px-2 py-0.5 rounded" style={{ background: '#1f2937', color: '#ffaa00' }}>{t}</span>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* IOC Table */}
          <div className="flex-1 glass-card overflow-hidden flex flex-col">
            <div className="flex items-center justify-between p-4 flex-shrink-0" style={{ borderBottom: '1px solid #1f2937' }}>
              <span className="text-sm font-bold text-white">IOC Database — {iocs.length} indicators</span>
              <button className="btn-cyber btn-cyber-primary" onClick={fetchData}><RefreshCw size={12} /></button>
            </div>
            <div className="overflow-auto flex-1">
              <table className="cyber-table">
                <thead className="sticky top-0">
                  <tr>
                    <th>Type</th>
                    <th>Value</th>
                    <th>Threat</th>
                    <th>Confidence</th>
                    <th>Source</th>
                    <th>Added</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {iocs.length === 0 ? (
                    <tr><td colSpan={7} className="text-center py-8 text-gray-600">No IOCs yet — add indicators above</td></tr>
                  ) : iocs.map((ioc, i) => (
                    <tr key={ioc._id || i}>
                      <td>
                        <span className="badge badge-medium">{ioc.ioc_type}</span>
                      </td>
                      <td className="font-mono text-xs" style={{ color: '#a855f7' }}>{ioc.value}</td>
                      <td className="text-xs text-gray-400">{ioc.threat_type}</td>
                      <td>
                        <div className="flex items-center gap-2">
                          <div className="w-16 h-1.5 rounded-full bg-gray-800">
                            <div className="h-full rounded-full" style={{ width: `${ioc.confidence}%`, background: getRiskColor(ioc.confidence) }} />
                          </div>
                          <span className="text-xs text-gray-400">{ioc.confidence}%</span>
                        </div>
                      </td>
                      <td className="text-xs text-gray-500">{ioc.source}</td>
                      <td className="text-xs text-gray-600">{formatDateTime(ioc.created_at)}</td>
                      <td>
                        <button onClick={() => deleteIoc(ioc._id)} className="text-gray-600 hover:text-red-400 transition-colors">
                          <Trash2 size={13} />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Right Column */}
        <div className="col-span-4 flex flex-col gap-4">
          {/* Add IOC */}
          <div className="glass-card p-4">
            <div className="flex items-center gap-2 mb-3">
              <Plus size={14} color="#00ff88" />
              <span className="text-sm font-bold text-white">Add IOC</span>
            </div>
            <div className="space-y-2">
              <select className="cyber-input w-full text-xs" value={newIoc.ioc_type}
                onChange={e => setNewIoc(f => ({ ...f, ioc_type: e.target.value }))}>
                {['ip', 'hash', 'domain', 'url'].map(t => <option key={t} value={t}>{t.toUpperCase()}</option>)}
              </select>
              <input className="cyber-input w-full text-xs" placeholder="IOC value" value={newIoc.value}
                onChange={e => setNewIoc(f => ({ ...f, value: e.target.value }))} />
              <select className="cyber-input w-full text-xs" value={newIoc.threat_type}
                onChange={e => setNewIoc(f => ({ ...f, threat_type: e.target.value }))}>
                {['malware', 'phishing', 'c2', 'scanner', 'ransomware', 'unknown'].map(t => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>
              <div>
                <label className="text-xs text-gray-500">Confidence: {newIoc.confidence}%</label>
                <input type="range" min={0} max={100} value={newIoc.confidence}
                  onChange={e => setNewIoc(f => ({ ...f, confidence: +e.target.value }))}
                  className="w-full mt-1 accent-cyan-400" />
              </div>
              <button className="btn-cyber btn-cyber-success w-full justify-center" onClick={createIoc}>
                <Plus size={12} /> Add to Database
              </button>
            </div>
          </div>

          {/* Threat Feeds */}
          <div className="glass-card p-4 flex-1">
            <div className="flex items-center gap-2 mb-3">
              <Shield size={14} color="#00d4ff" />
              <span className="text-sm font-bold text-white">Threat Feeds</span>
            </div>
            <div className="space-y-2">
              {feeds.map(feed => (
                <div key={feed.name} className="flex items-center justify-between p-2.5 rounded-lg" style={{ background: '#1f2937' }}>
                  <div>
                    <div className="text-xs font-medium text-gray-200">{feed.name}</div>
                    <div className="text-xs text-gray-500">{(feed.ioc_count || 0).toLocaleString()} IOCs</div>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <div className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
                    <span className="text-xs" style={{ color: '#00ff88' }}>LIVE</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
