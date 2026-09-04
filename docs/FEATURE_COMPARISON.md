# AetherGuard--Sentinel — Feature Comparison

> Generated: 2026-09-04 | Phase 0 — Repository Discovery  
> Purpose: Map capabilities of mature open-source security platforms against AetherGuard--Sentinel to prioritise the product roadmap.  
> Reference platforms: Wazuh, Security Onion, OpenSearch Security Analytics, Elastic Security (OSS components), Sigma ecosystem, MITRE ATT&CK, MISP, OpenCTI

---

## Legend

| Status | Meaning |
|:---|:---|
| **DONE** | Implemented, tested, working in production |
| **PARTIAL** | Partially implemented; has gaps or stubs |
| **PLANNED** | Designed in this assessment; not yet implemented |
| **DEFERRED** | Out of scope for initial build |
| **N/A** | Not applicable to AetherGuard--Sentinel's target use case |

| Priority | Meaning |
|:---|:---|
| **P0** | Blocking — platform is not credible without this |
| **P1** | High — product differentiation or regulatory expectation |
| **P2** | Medium — strengthens platform significantly |
| **P3** | Low — nice to have; deferred until P0/P1/P2 complete |

---

## 1. Log Collection & Ingestion

| Capability | Wazuh | Security Onion | Elastic | AetherGuard Status | Priority | Open Source Implementation | Notes |
|:---|:---|:---|:---|:---|:---|:---|:---|
| Syslog TCP receiver | Yes | Yes | Yes | **DONE** | P0 | asyncio.start_server | Port 5514 active |
| Syslog UDP receiver | Yes | Yes | Yes | **PLANNED** | P1 | asyncio DatagramProtocol | UDP 514/5514 |
| Windows Event Log agent | Yes | Partial | Yes | **PLANNED** | P1 | Winlogbeat (free OSS) or NXLog-CE | Document agent config |
| Beats/agents | Yes | Yes | Yes | **PLANNED** | P1 | Filebeat + Logstash → /api/ingest | Compatibility layer |
| HTTP ingest API | Partial | No | Yes | **DONE** | P0 | FastAPI POST /api/ingest | Needs API key auth |
| REST API authentication for ingest | Partial | N/A | Yes | **PLANNED** | P0 | API key header middleware | Security gap |
| Multi-source normalization | Yes | Yes | Yes | **PARTIAL** | P0 | OCSF model + Pydantic | Needs more source parsers |
| OCSF normalization | No | No | Partial | **PARTIAL** | P1 | OCSF standard | Ahead of most OSS SIEMs |
| Sigma-compatible ingestion | Yes | Yes | Yes | **PARTIAL** | P1 | pySigma | Sigma engine is stub |
| Backpressure / queue overflow handling | Partial | Yes | Yes | **PLANNED** | P1 | Redis queue + async producer | Not yet implemented |
| TLS for log transport | Yes | Yes | Yes | **PLANNED** | P1 | Python ssl module | Not configured |
| Log compression | Partial | Yes | Yes | **PLANNED** | P2 | zlib/lz4 in ClickHouse | ClickHouse handles at rest |
| CEF format parsing | Yes | Partial | Yes | **PLANNED** | P2 | Custom parser | Common SIEM format |
| JSON log parsing | Yes | Yes | Yes | **DONE** | P0 | Pydantic model | API ingest uses JSON |
| Syslog format parsing | Partial | Yes | Yes | **PARTIAL** | P1 | rfcxxxx parsers | Basic raw line parsing only |

---

## 2. Storage & Data Management

| Capability | Wazuh | Security Onion | Elastic | AetherGuard Status | Priority | Open Source Implementation | Notes |
|:---|:---|:---|:---|:---|:---|:---|:---|
| High-volume event storage | OpenSearch | Elasticsearch | Elasticsearch | **DONE** | P0 | ClickHouse MergeTree | Superior compression + speed |
| Application metadata storage | SQLite/MySQL | PostgreSQL | PostgreSQL | **DONE** | P0 | PostgreSQL 16 + SQLAlchemy | Working with Alembic |
| Real-time cache/state | No | Redis | Redis | **DONE** | P0 | Redis 7.2 | Connected and healthy |
| Versioned migrations | Partial | Yes | N/A | **PARTIAL** | P0 | Alembic | 1 revision; needs expansion |
| Retention policies | Yes | Yes | Yes | **PLANNED** | P1 | ClickHouse TTL expressions | Not yet configured |
| Data archival | Partial | Yes | Yes | **DEFERRED** | P3 | MinIO (optional) | Not required initially |
| Index management | Yes | Yes | Yes | **PARTIAL** | P1 | ClickHouse ORDER BY + SKIPPING | Needs secondary indexes |
| Tenant data isolation | Yes | No | Partial | **PARTIAL** | P0 | tenant_id on all tables | Not enforced in all queries |
| Field-level search | Yes | Yes | Yes | **PARTIAL** | P1 | ClickHouse WHERE clauses | No structured field search UI |
| Full-text search | Yes | Yes | Yes | **PARTIAL** | P1 | ClickHouse LIKE / match() | Server-side only, no tokenization |
| Aggregation / analytics | Yes | Yes | Yes | **DONE** | P0 | ClickHouse GROUP BY | Dashboard queries working |

---

## 3. Normalization & Enrichment

| Capability | Wazuh | Security Onion | Elastic | AetherGuard Status | Priority | Open Source Implementation | Notes |
|:---|:---|:---|:---|:---|:---|:---|:---|
| Field normalization | Yes | Yes | Yes | **PARTIAL** | P0 | OCSFBaseEvent Pydantic model | Missing command_line, URL, domain fields |
| GeoIP enrichment | Yes | Yes | Yes | **PLANNED** | P2 | geoip2 (MaxMind GeoLite2 — free) | Needed for Attack Map real data |
| ASN enrichment | Partial | Yes | Yes | **PLANNED** | P2 | geoip2 ASN database | Useful for threat context |
| Hostname resolution | Partial | Yes | Yes | **PLANNED** | P2 | aiodns | Cache results in Redis |
| IOC enrichment at ingest | Partial | Yes | Yes | **PLANNED** | P1 | IOC lookup in PostgreSQL + Redis cache | Real-time tagging |
| MITRE ATT&CK tagging | Partial | Partial | Yes | **PARTIAL** | P1 | Sigma MITRE fields | Stored in signals; not enriched at ingest |
| User enrichment | Partial | No | Partial | **PLANNED** | P2 | Join with users table or LDAP | Entity context |
| Asset enrichment | No | Partial | Partial | **PLANNED** | P2 | Asset inventory table | Criticality/ownership context |
| Vendor-specific parsers | Yes | Yes | Yes | **PLANNED** | P2 | Parser registry pattern | Windows, Linux, network device parsers |

---

## 4. Detection Engineering

| Capability | Wazuh | Security Onion | Elastic | AetherGuard Status | Priority | Open Source Implementation | Notes |
|:---|:---|:---|:---|:---|:---|:---|:---|
| Sigma rule support | Yes | Yes | Yes | **PARTIAL** | P0 | pySigma library | Engine stub; parser not integrated |
| Custom rule language | Yes | Yes | Yes | **DONE** | P0 | Python rule classes + YAML | 8 Python + 1 YAML rule |
| Threshold rules | Partial | Yes | Yes | **PARTIAL** | P0 | BruteForceRule uses rolling window | Not generalized |
| Sequence detection | No | No | Yes | **PLANNED** | P1 | Custom correlation engine | Multi-step attack patterns |
| Temporal correlation | Partial | Partial | Partial | **PLANNED** | P0 | Redis time-window state | Not yet implemented |
| MITRE ATT&CK mapping in rules | Partial | Partial | Yes | **PARTIAL** | P1 | YAML rule MITRE field | Python rules lack MITRE metadata |
| Rule versioning | No | Partial | Yes | **PLANNED** | P1 | Git + version field in rule schema | Not implemented |
| Rule testing (unit) | No | No | Partial | **PLANNED** | P1 | pytest-based rule test framework | Not implemented |
| Rule replay against historical data | No | Partial | Partial | **PLANNED** | P2 | ClickHouse time-range replay | Not implemented |
| Rule enable/disable | Partial | Yes | Yes | **PLANNED** | P1 | Rule status field in PostgreSQL | Not implemented |
| Exception handling | Partial | Partial | Yes | **PLANNED** | P1 | Suppression list in rule YAML | Not implemented |
| False positive tracking | No | No | Partial | **PLANNED** | P2 | FP rate metric per rule | Not implemented |
| Rule management UI | No | Partial | Yes | **PLANNED** | P1 | React rule editor | Not implemented |
| Detection coverage dashboard | No | No | Yes | **PLANNED** | P1 | MITRE heatmap + rule coverage | Not implemented |

---

## 5. Detection Library (Rules Coverage)

| Category | Wazuh | Sigma Community | Elastic | AetherGuard Status | Priority | Notes |
|:---|:---|:---|:---|:---|:---|:---|
| Authentication brute force | Yes | Yes | Yes | **DONE** | P0 | BruteForceRule |
| Password spraying | Partial | Yes | Partial | **PLANNED** | P1 | |
| Repeated failure → success | Partial | Yes | Partial | **PLANNED** | P0 | Common credential compromise pattern |
| Unusual privileged auth | Partial | Yes | Yes | **PLANNED** | P1 | |
| New auth source | Yes | Yes | Yes | **PLANNED** | P1 | |
| Suspicious PowerShell | Partial | Yes | Yes | **DONE** | P0 | SuspiciousPowerShellRule |
| Suspicious process chains | Partial | Yes | Yes | **PLANNED** | P1 | |
| Privilege escalation | Partial | Yes | Yes | **DONE** | P0 | PrivilegeEscalationRule |
| Port scanning | No | Yes | Yes | **DONE** | P0 | PortScanRule |
| Data exfiltration indicators | No | Partial | Partial | **DONE** | P0 | DataExfiltrationRule |
| Malware indicators (hash/domain) | Yes | Yes | Yes | **DONE** | P0 | MalwareIndicatorsRule |
| Beaconing / C2 | Partial | Yes | Yes | **DONE** | P0 | BeaconingRule |
| Impossible travel | No | No | Yes | **DONE** | P1 | ImpossibleTravelRule (basic) |
| DNS tunneling | No | Partial | Partial | **PLANNED** | P1 | |
| Lateral movement (SMB/RDP) | Partial | Yes | Yes | **PLANNED** | P1 | |
| Web attack patterns | Partial | Yes | Yes | **PLANNED** | P1 | SQLi, path traversal, command injection |
| Linux privilege escalation | Yes | Yes | Partial | **PLANNED** | P1 | sudo abuse, SUID |
| Persistence mechanisms | Partial | Yes | Yes | **PLANNED** | P1 | Registry run keys, cron, services |
| Defense evasion | No | Yes | Partial | **PLANNED** | P2 | Log clearing, AV disabling |
| Cloud attacks | No | Partial | Yes | **DEFERRED** | P3 | Out of initial scope |

---

## 6. Correlation & Analytics

| Capability | Wazuh | Security Onion | Elastic | AetherGuard Status | Priority | Open Source Implementation | Notes |
|:---|:---|:---|:---|:---|:---|:---|:---|
| Per-entity correlation (user, host, IP) | Partial | Yes | Yes | **PLANNED** | P0 | Redis sliding-window state machine | Critical gap |
| Cross-event temporal correlation | No | Yes | Yes | **PLANNED** | P0 | Redis TTL state + sequence matcher | Critical gap |
| Multi-source correlation | No | Yes | Yes | **PLANNED** | P1 | Event pipeline fusion | |
| Baseline deviation | Partial | Partial | Partial | **PARTIAL** | P1 | UEBA + IsolationForest | In-memory only |
| Alert clustering / deduplication | Partial | Yes | Yes | **PARTIAL** | P1 | funnel.py for events | Not for signals |
| Risk scoring | Yes | Partial | Yes | **PARTIAL** | P1 | risk_scorer.py | Not persisted |
| Security Signal aggregation | No | No | Partial | **PLANNED** | P0 | Signal compression service | High priority |
| Case correlation | No | Partial | Partial | **PLANNED** | P1 | Case → signals → incidents | |

---

## 7. UEBA

| Capability | Wazuh | Security Onion | Elastic | AetherGuard Status | Priority | Open Source Implementation | Notes |
|:---|:---|:---|:---|:---|:---|:---|:---|
| User event baseline | Partial | No | Yes | **PARTIAL** | P0 | UEBAEngine (in-memory) | No persistence |
| Behavioral scoring | No | No | Yes | **PARTIAL** | P1 | risk_scorer.py | Not persisted |
| Statistical anomaly detection | No | No | Yes | **PARTIAL** | P1 | IsolationForest | Trained on synthetic data |
| Peer group analysis | No | No | Partial | **DEFERRED** | P3 | Complex ML requirement |
| Timeline of user activity | Partial | Partial | Yes | **PLANNED** | P1 | ClickHouse user_name query | |
| Entity profile view | No | No | Partial | **PLANNED** | P1 | React entity profile page | |
| UEBA → Signal integration | No | No | Partial | **PLANNED** | P0 | High-risk UEBA score triggers signal | Critical gap |
| Historical UEBA persistence | No | No | Yes | **PLANNED** | P0 | PostgreSQL UEBA snapshots | In-memory lost on restart |

---

## 8. Threat Intelligence

| Capability | Wazuh | Security Onion | Elastic | AetherGuard Status | Priority | Open Source Implementation | Notes |
|:---|:---|:---|:---|:---|:---|:---|:---|
| Internal IOC database | Partial | Yes | Yes | **DONE** | P0 | PostgreSQL iocs table | Working |
| MITRE ATT&CK integration | Yes | Yes | Yes | **PLANNED** | P0 | MITRE ATT&CK STIX (free) | Not yet fetched/displayed |
| CISA KEV feed | No | No | No | **PLANNED** | P1 | CISA KEV JSON API (free) | |
| abuse.ch (URLhaus, MalwareBazaar) | No | Partial | No | **PLANNED** | P1 | abuse.ch API (free) | |
| MISP integration | Yes | Yes | Partial | **DEFERRED** | P3 | MISP API | Needs MISP instance |
| OpenCTI integration | No | No | No | **DEFERRED** | P3 | OpenCTI API | |
| IOC enrichment at ingest | No | Partial | Yes | **PLANNED** | P1 | Redis-cached IOC lookup | |
| IOC hit rate tracking | Partial | Partial | Yes | **PLANNED** | P2 | hit_count field in iocs table | Field exists, not incremented |
| Feed auto-refresh | Partial | Yes | Yes | **PLANNED** | P1 | Background async scheduler | APScheduler or asyncio.create_task |
| IOC expiry | No | Yes | Yes | **PLANNED** | P2 | expires_at field + cleanup job | |
| Threat feed deduplication | Partial | Yes | Yes | **PLANNED** | P1 | Redis bloom filter or SQL UPSERT | |

---

## 9. AI / ML Capabilities

| Capability | Wazuh | Security Onion | Elastic | AetherGuard Status | Priority | Open Source Implementation | Notes |
|:---|:---|:---|:---|:---|:---|:---|:---|
| Local LLM integration | No | No | No | **DONE** | P0 | Ollama + llama3.2:1b | **Unique differentiator** |
| Context compression | No | No | No | **DONE** | P0 | ai_service.compress_context() | Working |
| Deterministic AI fallback | No | No | No | **DONE** | P0 | Severity-based fallback | Working |
| AI investigation on-demand | No | No | No | **DONE** | P0 | signals.py background task | Working |
| AI auto-enrichment on alert | No | No | No | **PLANNED** | P0 | Trigger on high/critical signal | Not yet automatic |
| AI output schema validation | No | No | No | **PLANNED** | P0 | Pydantic strict validation | Not implemented |
| Prompt injection protection | No | No | No | **PLANNED** | P0 | AI Security Gateway | Not implemented |
| Secret filtering in AI context | No | No | No | **PLANNED** | P0 | PII/secret scrubber | Not implemented |
| AI audit logging | No | No | No | **PLANNED** | P0 | Audit log for all AI requests | Not implemented |
| MITRE ATT&CK RAG | No | No | No | **PLANNED** | P1 | Indexed STIX retrieval | |
| Model router / provider abstraction | No | No | No | **PARTIAL** | P1 | ai_service.py (single provider) | No router; tightly coupled |
| Multiple model support | No | No | No | **PLANNED** | P2 | ModelRouter class | Allow different models |
| AI evaluation / gold dataset | No | No | No | **PLANNED** | P2 | 10-category test set | Required for quality assurance |

---

## 10. Investigation & Hunting

| Capability | Wazuh | Security Onion | Elastic | AetherGuard Status | Priority | Open Source Implementation | Notes |
|:---|:---|:---|:---|:---|:---|:---|:---|
| Log explorer (server-side pagination) | Partial | Yes | Yes | **DONE** | P0 | ClickHouse + React table | Working |
| Time-range filtering | Partial | Yes | Yes | **DONE** | P0 | ClickHouse WHERE time BETWEEN | Working |
| Full-text search in logs | Partial | Yes | Yes | **PARTIAL** | P0 | LIKE query; no tokenization | Slow at scale |
| Structured field filters | Partial | Yes | Yes | **PLANNED** | P1 | Filter builder UI | Not implemented |
| Saved queries | No | Yes | Partial | **PLANNED** | P1 | PostgreSQL saved_queries table | |
| Query history | No | Partial | Yes | **PLANNED** | P2 | Redux/Zustand local + server | |
| Investigation workspace | No | Partial | Yes | **PLANNED** | P0 | Dedicated investigation page | Not implemented |
| Timeline view | No | Yes | Yes | **PLANNED** | P0 | Chronological signal + event timeline | Not implemented |
| Entity pivot (user → events) | No | Partial | Yes | **PLANNED** | P0 | ClickHouse query by entity field | Not implemented |
| Entity profiles | No | Partial | Yes | **PLANNED** | P1 | Dedicated entity page | Not implemented |
| Threat hunting workspace | No | Yes | Yes | **PLANNED** | P1 | Query builder + hunt history | Not implemented |
| MITRE technique hunting | No | Partial | Yes | **PLANNED** | P1 | Filter by MITRE technique ID | Not implemented |
| Graph investigation | No | Partial | Partial | **PLANNED** | P2 | D3.js or Sigma.js (not graph DB) | Simple node graph from relations |
| Raw event view | Yes | Yes | Yes | **PARTIAL** | P1 | Log detail modal | Exists but limited |

---

## 11. Incident & Case Management

| Capability | Wazuh | Security Onion | Elastic | AetherGuard Status | Priority | Open Source Implementation | Notes |
|:---|:---|:---|:---|:---|:---|:---|:---|
| Incident CRUD | Yes | Partial | Yes | **DONE** | P0 | PostgreSQL incidents table | Working |
| Incident lifecycle states | Partial | Partial | Yes | **PARTIAL** | P0 | 5 states exist but limited transitions | Needs workflow enforcement |
| Case management distinct from incidents | No | No | Yes | **PLANNED** | P1 | cases table in PostgreSQL | Not yet separate |
| Evidence attachment to case | No | Partial | Yes | **PLANNED** | P1 | evidence_refs JSON in signals/incidents | Needs evidence browser |
| Analyst notes | Partial | Yes | Yes | **PARTIAL** | P1 | notes JSON field | Not displayed in UI |
| AI findings in case | No | No | Partial | **PLANNED** | P1 | Link ai_verdict to case | Not shown |
| Incident → signal correlation | No | No | Yes | **PARTIAL** | P1 | source_signal_ids field | Not bidirectional |
| SLA tracking | No | No | Partial | **PLANNED** | P3 | created_at + SLA config | |
| Email/notification on escalation | No | Partial | Yes | **PLANNED** | P3 | SMTP / webhook | |

---

## 12. SOAR

| Capability | Wazuh | Security Onion | Elastic | AetherGuard Status | Priority | Open Source Implementation | Notes |
|:---|:---|:---|:---|:---|:---|:---|:---|
| Playbook engine | Partial | No | Yes | **PLANNED** | P1 | Python playbook runner | Not implemented |
| Trigger on signal | Yes | No | Yes | **PLANNED** | P1 | Auto-trigger on signal severity | Not implemented |
| Approval workflow | No | No | Partial | **PLANNED** | P1 | PostgreSQL approvals table | Not implemented |
| Read-only actions (lookup, enrich) | Partial | No | Yes | **PLANNED** | P1 | Tool separation | Not implemented |
| Write actions (block IP, isolate) | Partial | No | Yes | **PLANNED** | P2 | Require approval by default | Not implemented |
| Action audit log | No | No | Yes | **PLANNED** | P0 | Every action recorded | Not implemented |
| Playbook versioning | No | No | Partial | **PLANNED** | P2 | Git-backed YAML playbooks | Not implemented |

---

## 13. User Interface

| Capability | Wazuh | Security Onion | Elastic | AetherGuard Status | Priority | Notes |
|:---|:---|:---|:---|:---|:---|:---|
| Professional SOC dashboard | Partial | Partial | Yes | **PARTIAL** | P0 | Needs full redesign |
| Real-time event stream | No | Partial | Yes | **DONE** | P0 | LiveLogFeed via WebSocket |
| Dark/Light theme | Dark only | Dark only | Yes | **PLANNED** | P1 | CSS custom properties |
| Responsive layout | Partial | Partial | Yes | **PLANNED** | P2 | |
| Keyboard navigation | No | No | Partial | **PLANNED** | P2 | |
| Accessibility (WCAG) | No | No | Partial | **PLANNED** | P3 | |
| Severity color system | Partial | Yes | Yes | **PLANNED** | P1 | Consistent tokens |
| Loading / empty / error states | No | Partial | Yes | **PLANNED** | P0 | Every page |
| Professional data tables | Partial | Yes | Yes | **PLANNED** | P0 | |
| Time range picker | No | Yes | Yes | **PLANNED** | P0 | |
| Filter builder | No | Yes | Yes | **PLANNED** | P1 | |
| Chart library | Recharts | Kibana-style | Kibana | **PARTIAL** | P1 | Recharts adequate |

---

## 14. Platform & Operations

| Capability | Wazuh | Security Onion | Elastic | AetherGuard Status | Priority | Notes |
|:---|:---|:---|:---|:---|:---|:---|
| Docker Compose deployment | Yes | Yes | Yes | **DONE** | P0 | Working with 6 services |
| Health checks | Partial | Yes | Yes | **DONE** | P0 | /api/health, /api/ready |
| Prometheus metrics | No | Yes | Yes | **PARTIAL** | P1 | Prometheus running; not instrumented |
| Grafana dashboards | No | Yes | Yes | **PARTIAL** | P1 | Grafana running; no dashboards |
| Structured logging | Partial | Yes | Yes | **DONE** | P0 | structlog |
| Audit logging | Yes | Yes | Yes | **PLANNED** | P0 | Not implemented |
| RBAC | Yes | Partial | Yes | **PARTIAL** | P0 | Not consistently enforced |
| Multi-tenancy | No | No | Partial | **PARTIAL** | P0 | tenant_id exists; not enforced |
| TLS / HTTPS | Yes | Yes | Yes | **PLANNED** | P1 | |
| Rate limiting | Partial | Yes | Yes | **PLANNED** | P1 | |
| Performance benchmarks | No | Partial | Yes | **PLANNED** | P1 | |
| Load testing | No | Partial | Yes | **PLANNED** | P2 | locust |
| Unit test suite | Yes | Partial | Yes | **PARTIAL** | P0 | E2E test exists; limited unit tests |
| Integration tests | Partial | Partial | Yes | **PLANNED** | P1 | |

---

## 15. Decided Capabilities for AetherGuard--Sentinel

### Include in v1.0 (P0/P1)
All P0 items above, plus selected P1 items:
- OCSF normalization with extended fields (command_line, url, domain, file_path)
- pySigma integration for Sigma rule parsing
- Correlation engine (Redis time-window, per-entity)
- MITRE ATT&CK fetch + integration
- CISA KEV and abuse.ch threat feeds
- IOC enrichment at ingest
- UEBA persistence to PostgreSQL
- AI Security Gateway (prompt injection, secret filter, schema validation)
- Auto-AI enrichment on critical signals
- Full frontend redesign with dark/light theme
- Entity profiles, timeline, investigation workspace
- Case management (distinct from incidents)
- Detection rule management UI
- MITRE ATT&CK coverage dashboard
- Audit logging
- Prometheus instrumentation
- Grafana dashboards

### Deferred to v2.0+ (P2/P3)
- MinIO object storage for archives
- MISP/OpenCTI integration
- Cloud attack detection rules
- Graph database
- Peer group UEBA analysis
- Email notifications
- Kubernetes deployment
- SLA tracking
- LDAP/AD integration
