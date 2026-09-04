import { useState, useEffect } from 'react'
import { rulesApi } from '../services/api'
import { ShieldCheck, Search, Filter, Play, ToggleLeft, ToggleRight, Tag, BookOpen, AlertCircle } from 'lucide-react'

export default function DetectionRulesPage() {
  const [rules, setRules] = useState([])
  const [loading, setLoading] = useState(true)
  const [ruleTypeFilter, setRuleTypeFilter] = useState('')
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedRule, setSelectedRule] = useState(null)
  const [testPayload, setTestPayload] = useState('{\n  "message": "Failed login attempt from 198.51.100.42",\n  "source_ip": "198.51.100.42",\n  "severity": "high"\n}')
  const [testResult, setTestResult] = useState(null)
  const [testing, setTesting] = useState(false)

  const fetchRules = async () => {
    setLoading(true)
    try {
      const params = {}
      if (ruleTypeFilter) params.rule_type = ruleTypeFilter
      const res = await rulesApi.list(params)
      setRules(res.data.rules || [])
      if (res.data.rules?.length > 0 && !selectedRule) {
        setSelectedRule(res.data.rules[0])
      }
    } catch (err) {
      console.error('Error fetching rules:', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchRules()
  }, [ruleTypeFilter])

  const handleToggle = async (ruleId, currentStatus) => {
    try {
      await rulesApi.toggle(ruleId, !currentStatus)
      fetchRules()
      if (selectedRule?.rule_id === ruleId) {
        setSelectedRule({ ...selectedRule, enabled: !currentStatus })
      }
    } catch (err) {
      console.error('Error toggling rule:', err)
    }
  }

  const handleTestRule = async () => {
    if (!selectedRule) return
    setTesting(true)
    setTestResult(null)
    try {
      const parsed = JSON.parse(testPayload)
      const res = await rulesApi.test(selectedRule.rule_id, parsed)
      setTestResult(res.data)
    } catch (err) {
      setTestResult({
        matched: false,
        reason: `Invalid JSON or execution error: ${err.message}`
      })
    } finally {
      setTesting(false)
    }
  }

  const filteredRules = rules.filter((r) => {
    if (!searchQuery) return true
    const q = searchQuery.toLowerCase()
    return (
      r.name.toLowerCase().includes(q) ||
      r.rule_id.toLowerCase().includes(q) ||
      r.description?.toLowerCase().includes(q)
    )
  })

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <ShieldCheck className="text-cyan-400" size={22} />
            Detection Rule Engineering
          </h1>
          <p className="text-xs text-gray-400 mt-0.5">
            Active threat detection rules across Python, Sigma, and YAML engines ({rules.length} total)
          </p>
        </div>
      </div>

      {/* Filter / Search Bar */}
      <div className="flex flex-wrap items-center gap-3 p-3 glass-card">
        <div className="relative flex-1 min-w-[200px]">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search rules by name, ID, or description..."
            className="cyber-input w-full pl-9 text-xs py-1.5"
          />
        </div>
        <select
          value={ruleTypeFilter}
          onChange={(e) => setRuleTypeFilter(e.target.value)}
          className="cyber-input text-xs py-1.5"
        >
          <option value="">All Engine Types</option>
          <option value="python">Python Stateful</option>
          <option value="sigma">Sigma Community</option>
          <option value="yaml">YAML Custom</option>
        </select>
      </div>

      {/* 2-Column Split: Rule List & Inspector/Tester */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Rules Table */}
        <div className="lg:col-span-2 glass-card overflow-hidden">
          <table className="cyber-table">
            <thead>
              <tr>
                <th>Rule Name / ID</th>
                <th>Type</th>
                <th>Severity</th>
                <th>MITRE ATT&CK</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={5} className="text-center py-8 text-gray-500">
                    Loading detection rules...
                  </td>
                </tr>
              ) : filteredRules.length === 0 ? (
                <tr>
                  <td colSpan={5} className="text-center py-8 text-gray-500">
                    No rules matched the current filter.
                  </td>
                </tr>
              ) : (
                filteredRules.map((r) => (
                  <tr
                    key={r.id || r.rule_id}
                    onClick={() => setSelectedRule(r)}
                    className={`cursor-pointer transition-colors ${selectedRule?.rule_id === r.rule_id ? 'bg-cyan-500/10' : ''}`}
                  >
                    <td>
                      <div className="font-semibold text-gray-200 text-sm">{r.name}</div>
                      <div className="text-xs text-gray-500 font-mono">{r.rule_id}</div>
                    </td>
                    <td>
                      <span className="text-xs uppercase font-mono px-2 py-0.5 rounded bg-gray-800 text-cyan-300 border border-gray-700">
                        {r.rule_type}
                      </span>
                    </td>
                    <td>
                      <span className={`badge badge-${r.severity}`}>
                        {r.severity}
                      </span>
                    </td>
                    <td>
                      <div className="flex flex-wrap gap-1">
                        {r.mitre_techniques?.slice(0, 2).map((m) => (
                          <span key={m} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-purple-900/40 text-purple-300 border border-purple-800/40">
                            {m}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td>
                      <button
                        onClick={(e) => {
                          e.stopPropagation()
                          handleToggle(r.rule_id, r.enabled)
                        }}
                        className={`text-xs flex items-center gap-1 font-semibold ${r.enabled ? 'text-green-400' : 'text-gray-500'}`}
                      >
                        {r.enabled ? <ToggleRight size={18} /> : <ToggleLeft size={18} />}
                        <span>{r.enabled ? 'Active' : 'Disabled'}</span>
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Rule Detail & Test Sandbox */}
        <div className="glass-card p-4 flex flex-col space-y-4">
          {selectedRule ? (
            <>
              <div className="border-b border-gray-800 pb-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs uppercase font-mono px-2 py-0.5 rounded bg-gray-800 text-cyan-300">
                    {selectedRule.rule_type}
                  </span>
                  <span className={`badge badge-${selectedRule.severity}`}>
                    {selectedRule.severity}
                  </span>
                </div>
                <h3 className="font-bold text-white text-base mt-2">{selectedRule.name}</h3>
                <div className="text-xs text-gray-500 font-mono">{selectedRule.rule_id}</div>
              </div>

              <div>
                <div className="text-xs text-gray-400 font-medium mb-1">Description</div>
                <p className="text-xs text-gray-300 bg-black/30 p-2.5 rounded border border-gray-800 leading-relaxed">
                  {selectedRule.description}
                </p>
              </div>

              {selectedRule.mitre_techniques?.length > 0 && (
                <div>
                  <div className="text-xs text-gray-400 font-medium mb-1">MITRE ATT&CK Mapping</div>
                  <div className="flex flex-wrap gap-1">
                    {selectedRule.mitre_techniques.map((m) => (
                      <span key={m} className="text-xs font-mono px-2 py-0.5 rounded bg-purple-900/30 text-purple-300 border border-purple-800/50">
                        {m}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {selectedRule.false_positive_notes && (
                <div>
                  <div className="text-xs text-gray-400 font-medium mb-1 flex items-center gap-1">
                    <AlertCircle size={13} className="text-amber-400" />
                    False Positive Guidance
                  </div>
                  <p className="text-xs text-amber-200/80 bg-amber-950/20 p-2 rounded border border-amber-900/30">
                    {selectedRule.false_positive_notes}
                  </p>
                </div>
              )}

              {/* Interactive Rule Testing Sandbox */}
              <div className="border-t border-gray-800 pt-3 flex-1 flex flex-col">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs text-gray-300 font-medium flex items-center gap-1">
                    <Play size={12} className="text-cyan-400" />
                    Test Sandbox (Mock Telemetry)
                  </span>
                  <button
                    onClick={handleTestRule}
                    disabled={testing}
                    className="btn-cyber btn-cyber-primary text-xs py-1 px-2.5"
                  >
                    {testing ? 'Evaluating...' : 'Run Test'}
                  </button>
                </div>
                <textarea
                  rows={5}
                  value={testPayload}
                  onChange={(e) => setTestPayload(e.target.value)}
                  className="cyber-input w-full font-mono text-[11px] p-2 bg-black/40 resize-none flex-1"
                />

                {testResult && (
                  <div className={`mt-2 p-2.5 rounded border text-xs ${testResult.matched ? 'bg-green-950/20 border-green-800/40 text-green-300' : 'bg-gray-900 border-gray-800 text-gray-400'}`}>
                    <div className="font-semibold flex items-center gap-1">
                      <span>Status:</span>
                      <span className={testResult.matched ? 'text-green-400' : 'text-gray-400'}>
                        {testResult.matched ? 'TRIGGERED (MATCH)' : 'NO MATCH'}
                      </span>
                    </div>
                    <div className="text-[11px] mt-0.5 opacity-80">{testResult.reason}</div>
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="text-center py-12 text-gray-500 text-xs">
              Select a rule to view details and execute test simulations.
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
