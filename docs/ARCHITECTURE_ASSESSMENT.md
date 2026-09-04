# AetherGuard--Sentinel — Architecture Assessment

> Generated: 2026-09-04 | Phase 0 — Repository Discovery  
> Status: Baseline document. Do not modify code until this assessment is reviewed and the implementation plan is approved.

---

## 1. Current Architecture Overview

AetherGuard--Sentinel is a **Python/FastAPI + React/Vite** security operations platform. The current build is a partially-migrated system: the infrastructure layer (Docker, ClickHouse, PostgreSQL, Redis, Ollama) was correctly set up in a previous implementation phase, and core backend routes were rewritten from a fake-data prototype into real database queries. However, the **frontend remains largely a first-generation UI** and several backend subsystems are stubs or incomplete.

### 1.1 Infrastructure Layer (Docker Compose)

| Service | Image | Port(s) | Status | Role |
|:---|:---|:---|:---|:---|
| PostgreSQL 16 | `postgres:16-alpine` | 5432 | **Healthy** | Application metadata, users, signals, incidents, IOCs |
| ClickHouse | `clickhouse/clickhouse-server:latest-alpine` | 8123, 9000 | **Healthy** | High-volume security telemetry (OCSF events) |
| Redis 7.2 | `redis:7.2-alpine` | 6379 | **Healthy** | Cache, deduplication, session state |
| Ollama | `ollama/ollama:latest` | 11434 | **Healthy** | Local LLM inference (llama3.2:1b configured) |
| Prometheus | `prom/prometheus:latest` | 9090 | **Running** | Metrics collection (not yet instrumented) |
| Grafana OSS | `grafana/grafana-oss:latest` | 3000 | **Running** | Observability dashboards (not yet configured) |

### 1.2 Backend Architecture

**Framework:** FastAPI 0.115 + Uvicorn (async)  
**Language:** Python 3.13  
**Structure:** Monolithic single-process with async task concurrency

```
backend/
├── main.py                    # App entrypoint, lifespan, router registration
├── api/routes/                # 10 route modules
│   ├── auth.py               # Login, JWT, /me, user CRUD
│   ├── dashboard.py          # Stats, EPS, top attackers, MITRE coverage
│   ├── logs.py               # Log search (ClickHouse backed)
│   ├── alerts.py             # Security signals read/write
│   ├── incidents.py          # Incident lifecycle
│   ├── threat_intel.py       # IOC lookup
│   ├── users.py              # User management
│   ├── reports.py            # Report generation (stub)
│   ├── ingest.py             # Event ingestion endpoint
│   └── signals.py            # AI investigation trigger
├── api/middleware/auth.py     # JWT Bearer dependency
├── core/                      # Config, logging, exceptions, middleware, security, permissions
├── db/
│   ├── clickhouse.py         # ClickHouse client singleton
│   ├── postgres.py           # SQLAlchemy async engine + session
│   ├── redis.py              # Async Redis pool
│   ├── init_clickhouse.py    # Table creation script
│   ├── database.py           # Legacy SQLite helper (partially active)
│   └── sqlite_db.py          # Legacy SQLite (mostly replaced, still referenced)
├── models/
│   ├── events.py             # OCSFBaseEvent (Pydantic v2)
│   ├── signal.py             # SecuritySignal (SQLAlchemy ORM)
│   ├── incident.py           # Incident (SQLAlchemy ORM)
│   ├── ioc.py                # IOC (SQLAlchemy ORM)
│   └── user.py               # User (SQLAlchemy ORM)
├── detections/
│   ├── engine.py             # DetectionEngine — evaluates rules per event
│   ├── yaml_engine.py        # Dynamic YAML rule loader
│   ├── sigma_engine.py       # Sigma stub (non-functional)
│   └── rules/                # 8 Python rule classes + custom/ YAML dir
├── services/
│   ├── auth_service.py       # Argon2 authentication, JWT, user seeding
│   ├── ingest_service.py     # Event processing, ClickHouse insert
│   ├── syslog_receiver.py    # TCP port 5514 listener
│   └── ai_service.py         # Ollama HTTP client, context compression
├── pipeline/funnel.py         # Deduplication/rate-limiting pre-filter
├── ml/
│   ├── ueba.py               # In-memory UEBA (hourly counters + risk score)
│   ├── anomaly_detector.py   # IsolationForest baseline model
│   └── risk_scorer.py        # Combined risk scoring
├── simulator/                 # Log generator + attack simulator (DISABLED)
├── alembic/                   # DB migrations (1 revision applied)
└── tests/
    └── test_production_e2e.py # 7-step E2E acceptance test (all passing)
```

### 1.3 Frontend Architecture

**Framework:** React 19 + Vite 8 + Tailwind CSS 3 + React Router 7  
**State:** Zustand (single store)  
**Charts:** Recharts  
**HTTP:** Axios  
**Maps:** react-simple-maps (Attack Map)

```
frontend/src/
├── App.jsx                   # Router, ProtectedRoute, Layout
├── pages/                    # 10 page components
│   ├── DashboardPage.jsx     # Main dashboard (partially real data)
│   ├── LogExplorerPage.jsx   # Log search table (real ClickHouse)
│   ├── AlertsPage.jsx        # Security signals list
│   ├── IncidentsPage.jsx     # Incident management
│   ├── ThreatIntelPage.jsx   # IOC lookup UI
│   ├── AttackMapPage.jsx     # Geographic attack visualization
│   ├── UEBAPage.jsx          # User behavior analytics
│   ├── ReportsPage.jsx       # Reports (stub)
│   ├── SettingsPage.jsx      # Settings (stub)
│   └── LoginPage.jsx         # JWT login form
├── components/               # 5 shared components
│   ├── Sidebar.jsx           # Navigation sidebar
│   ├── TopNav.jsx            # Top bar with status indicators
│   ├── AlertCard.jsx         # Alert card with Investigate button
│   ├── LiveLogFeed.jsx       # Real-time WebSocket log stream
│   └── StatWidget.jsx        # KPI card widget
├── services/
│   ├── api.js                # Axios client with JWT interceptor
│   └── websocket.js          # WebSocket connection manager
├── store/useStore.js         # Zustand store (auth, logs, alerts, UI state)
└── hooks/useWebSocket.js     # WS hook connecting to /ws endpoint
```

---

## 2. Existing Features

### 2.1 Working / Operational
| Feature | Status | Notes |
|:---|:---|:---|
| JWT Authentication | **Working** | Argon2 passwords, PostgreSQL-backed users |
| Log Ingestion (`POST /api/ingest/`) | **Working** | OCSF normalization, ClickHouse storage, detection trigger |
| Syslog TCP receiver (port 5514) | **Working** | Raw line parsing, normalization, passes to ingest pipeline |
| ClickHouse telemetry storage | **Working** | OCSF-aligned schema, partition by month |
| Detection Engine (Python rules) | **Working** | 8 rules active: brute force, port scan, PowerShell, privilege escalation, impossible travel, data exfil, malware indicators, beaconing |
| YAML detection rules | **Working** | Dynamic loading from `rules/custom/` directory |
| SecuritySignal persistence | **Working** | PostgreSQL-backed, WebSocket broadcast on trigger |
| WebSocket real-time feed | **Working** | Logs and alerts pushed to connected clients |
| Dashboard stats | **Working** | Real ClickHouse + PostgreSQL aggregations |
| Log Explorer search | **Working** | Server-side pagination, time filter, keyword search |
| Incident CRUD | **Working** | PostgreSQL-backed lifecycle management |
| IOC lookup | **Working** | PostgreSQL-backed, returns UNKNOWN when not found |
| Health endpoints | **Working** | `/api/health`, `/api/ready` with real DB checks |
| AI investigation (background) | **Working** | Ollama integration with deterministic fallback |
| UEBA engine | **Working** | In-memory hourly counters, risk scoring |
| Anomaly detection | **Working** | IsolationForest baseline model |
| RBAC middleware | **Partial** | Three roles seeded; enforcement partially consistent |
| Prometheus/Grafana | **Running** | Not yet instrumented or configured |

### 2.2 Stub / Incomplete
| Feature | Status | Gap |
|:---|:---|:---|
| Sigma rule engine | **Stub** | File exists but has no real Sigma parsing |
| Reports page | **Stub** | Frontend only, no report generation backend |
| Settings page | **Stub** | Frontend only, no backend persistence |
| Attack Map | **Partial** | Visual only, data questionable |
| SOAR / Playbooks | **Missing** | Not implemented |
| Threat feeds (external) | **Missing** | No MITRE ATT&CK, CISA KEV, abuse.ch integration |
| Case management | **Missing** | No distinct Case object; Incidents serve both roles |
| Detection rule management UI | **Missing** | No UI for viewing/editing/testing rules |
| MITRE ATT&CK framework integration | **Missing** | MITRE technique IDs stored but not mapped/displayed |
| Entity profiles (User/Host/IP) | **Missing** | No entity-centric view |
| Timeline view | **Missing** | No chronological event timeline per entity/signal |
| Threat hunting workspace | **Missing** | No saved queries, query builder, hunt workspace |
| Asset management | **Missing** | No asset inventory |
| Audit log | **Missing** | No structured audit trail for admin actions |
| Multi-tenancy enforcement | **Partial** | `tenant_id` exists on all models but not enforced in all queries |
| Dark/Light theme | **Missing** | Dark-only, hardcoded `#030712` background |
| Correlation engine | **Missing** | Rules evaluate per-event; no cross-event correlation graph |
| Performance benchmarking | **Missing** | No benchmarks run |
| Documentation | **Missing** | README is minimal, no architecture/API docs |

---

## 3. Existing Data Flow

```
External Source (HTTP POST or TCP 5514)
        │
        ▼
   IngestService.process_events()
        │
        ├─► funnel.py (deduplication, rate-limit)
        │
        ├─► ClickHouse INSERT (OCSF events table)
        │
        ├─► DetectionEngine.evaluate()  ──► SecuritySignal (PostgreSQL)
        │           │                            │
        │           └─► YamlDetectionEngine      └─► WebSocket broadcast
        │
        └─► ws_manager.send_log()  ──► Frontend LiveLogFeed
```

### AI Investigation Flow (on-demand)
```
POST /api/signals/{id}/investigate
        │
        ▼
   signals.py route (background task)
        │
        ├─► PostgreSQL: fetch SecuritySignal
        │
        ├─► ClickHouse: fetch evidence events by source_ip / event_id
        │
        ├─► ai_service.compress_context() (rank, deduplicate, token-estimate)
        │
        ├─► Ollama POST /api/generate (llama3.2:1b)
        │       │
        │       └─► Deterministic fallback if offline
        │
        ├─► PostgreSQL: UPDATE SecuritySignal (ai_verdict, ai_analysis)
        │
        └─► WebSocket: broadcast AI_INVESTIGATION_COMPLETE
```

---

## 4. Database Architecture

### 4.1 PostgreSQL Schema (via Alembic)
| Table | Purpose | Key Fields |
|:---|:---|:---|
| `users` | Authentication and RBAC | id, username, hashed_password (Argon2), role, tenant_id |
| `security_signals` | Detection hits, AI verdicts | id, tenant_id, title, severity, status, rule_name, evidence_refs, ai_verdict |
| `incidents` | Incident response records | id, tenant_id, title, status, assignee, source_signal_ids |
| `iocs` | Threat intelligence indicators | id, tenant_id, ioc_type, value, threat_type, confidence |

### 4.2 ClickHouse Schema
| Table | Purpose |
|:---|:---|
| `events` | OCSF-normalized telemetry; partition by month, ordered by (tenant_id, time, category_name) |

**Missing indexes:** No secondary indexes on `src_ip`, `host_name`, `user_name` for hunting queries.

### 4.3 Legacy SQLite
- `aetherguard.db` exists in both root and `backend/` directories
- `db/sqlite_db.py` and `db/database.py` contain partial legacy code
- Most routes migrated to PostgreSQL but some import paths still reference old functions
- **Technical debt:** SQLite layer must be fully removed

---

## 5. Existing API Contracts

| Method | Path | Auth | Backend |
|:---|:---|:---|:---|
| POST | `/api/auth/login` | None | PostgreSQL |
| GET | `/api/auth/me` | JWT | JWT decode |
| GET | `/api/health` | None | Real DB checks |
| GET | `/api/ready` | None | Real DB checks |
| POST | `/api/ingest/` | None (should require key) | ClickHouse + Detection |
| GET | `/api/dashboard/stats` | JWT | ClickHouse + PostgreSQL |
| GET | `/api/dashboard/eps-history` | JWT | ClickHouse |
| GET | `/api/dashboard/top-attackers` | JWT | ClickHouse |
| GET | `/api/logs/search` | JWT | ClickHouse |
| GET | `/api/alerts/` | JWT | PostgreSQL |
| POST | `/api/alerts/{id}/acknowledge` | JWT | PostgreSQL |
| GET/POST | `/api/incidents/` | JWT | PostgreSQL |
| GET | `/api/threat-intel/lookup` | JWT | PostgreSQL |
| POST | `/api/signals/{id}/investigate` | JWT | Ollama + ClickHouse |
| GET | `/api/ueba/users` | None (needs auth) | In-memory |
| GET | `/api/ueba/user/{username}` | None (needs auth) | In-memory |

---

## 6. Existing Security Functionality

| Category | Mechanism | Quality |
|:---|:---|:---|
| Authentication | JWT HS256 + Argon2 password hashing | Good |
| Authorization | Role-based middleware (admin/analyst/viewer) | Partial — not consistently applied |
| Ingest auth | None — `/api/ingest/` is unauthenticated | **Security gap** |
| UEBA endpoints | Unauthenticated | **Security gap** |
| SQL injection | SQLAlchemy ORM parameterization | Good |
| ClickHouse injection | Parameterized queries in most routes | Good |
| Prompt injection | No protection in AI gateway | **Security gap** |
| Secret filtering | Not implemented in AI pipeline | **Security gap** |
| CORS | Configured for localhost:3000, 5173 | Acceptable for dev |
| TLS | Not configured | Expected for production |
| Audit trail | Not implemented | **Gap** |

---

## 7. Technical Debt

### Critical (blocking correctness)
1. **SQLite layer not fully removed** — `db/sqlite_db.py` and `db/database.py` exist and are still imported in some paths. The legacy `aetherguard.db` file sits in root and backend/. Must be completely eliminated.
2. **Ingest endpoint unauthenticated** — `POST /api/ingest/` accepts data from anyone. Needs API key or mTLS.
3. **UEBA endpoints unauthenticated** — `/api/ueba/users` and `/api/ueba/user/{username}` have no auth dependency.
4. **RBAC inconsistently enforced** — Some routes use `require_admin`, others use plain `get_current_user` with manual role checks, others have no protection.
5. **Import path inconsistency** — Mix of `from backend.X import` and `from X import` throughout codebase. Works only because of `sys.path.insert()` hack in `main.py`.

### High (degrading capability)
6. **Sigma engine is a stub** — `sigma_engine.py` exists but does not actually parse Sigma rules.
7. **UEBA is in-memory only** — State lost on restart; no PostgreSQL persistence.
8. **Correlation engine absent** — Detection is per-event only; no cross-event temporal correlation.
9. **Context compression not integrated into auto-detection flow** — AI is only triggered manually; there is no automatic AI enrichment pipeline.
10. **No connection pooling configuration** — ClickHouse client is a module-level singleton; PostgreSQL uses default asyncpg pool settings.
11. **No missing ClickHouse indexes** — `src_ip`, `user_name`, `host_name` are not indexed; hunting queries will be slow at scale.

### Medium (feature gaps)
12. **Threat intelligence is internal-only** — No external feeds (MITRE ATT&CK, CISA KEV, abuse.ch).
13. **Reports route is empty** — Returns stub response.
14. **Settings route is empty** — No backend persistence.
15. **No audit logging** — Admin actions are not recorded.
16. **Prometheus not instrumented** — Container runs but no application metrics are exported.
17. **Grafana not configured** — No dashboards provisioned.
18. **Detection rule library is small** — 8 Python rules + 1 YAML rule. Not enough for production coverage.
19. **No rule versioning or testing** — Rules have no version field, no test cases, no replay capability.

### Low (polish)
20. **Frontend is dark-only** — No theme switching.
21. **No responsive layout** — Fixed sidebar, not mobile-friendly.
22. **Sidebar navigation incomplete** — Doesn't reflect planned navigation structure.
23. **AttackMapPage** — Data source unclear; may render with no meaningful real data.
24. **Frontend error handling** — Inconsistent; some pages have no error state.

---

## 8. Performance Characteristics

| Dimension | Current State | Target |
|:---|:---|:---|
| Ingest throughput | Untested — single asyncio task per event batch | 100K events/sec (measured) |
| ClickHouse query latency | Untested | <100ms for aggregations on 1B rows |
| Detection latency | Untested — sequential Python rule evaluation | <50ms per event |
| AI investigation latency | 5–45s (depends on Ollama + CPU) | <30s (with GPU), deterministic fallback <1s |
| WebSocket fan-out | Untested | All connected clients, <100ms |
| Frontend initial load | Untested | <3s cold start |

---

## 9. Components Assessment

### PRESERVE (working, correctly implemented)
- FastAPI application structure and lifespan management
- Docker Compose infrastructure definition
- PostgreSQL + Alembic migration system
- ClickHouse OCSF events table schema
- Redis integration
- JWT + Argon2 authentication service
- Ingest service pipeline (OCSF → funnel → ClickHouse → detection)
- Detection engine (Python rule evaluation model)
- WebSocket manager
- Syslog TCP receiver (port 5514)
- AI service (Ollama client + context compression + fallback)
- Zustand frontend state management
- React Router with ProtectedRoute pattern
- E2E acceptance test suite

### REFACTOR (working but needs improvement)
- UEBA engine — add PostgreSQL persistence, integrate into signals
- Detection rules — add MITRE metadata, version fields, positive/negative tests
- RBAC middleware — consolidate, apply consistently across all routes
- Import path system — standardize to `backend.X` everywhere, remove sys.path hack
- ClickHouse schema — add secondary indexes for `src_ip`, `user_name`, `host_name`
- Frontend API integration — several pages still have incomplete real-data connections
- `ai_service.py` — integrate auto-enrichment into detection pipeline

### REPLACE (incorrect or blocking)
- `db/sqlite_db.py` — delete entirely after verifying no live dependencies
- `db/database.py` — delete or repurpose after verification
- `aetherguard.db` SQLite files — delete both instances
- Frontend UI design — full redesign required (current is functional prototype, not production SOC UI)

### ADD (missing, required for product completeness)
- Sigma parser integration (pySigma)
- Correlation engine (temporal, cross-entity)
- Threat intelligence feeds (MITRE ATT&CK STIX, CISA KEV, abuse.ch)
- Case management distinct from incidents
- SOAR playbook engine
- Detection rule management UI + testing + replay
- MITRE ATT&CK coverage dashboard
- Entity profile views (User, Host, IP, Domain)
- Timeline investigation view
- Threat hunting workspace with saved queries
- Asset inventory
- Audit log system
- Dark/Light theme system
- Prometheus instrumentation throughout backend
- Grafana dashboard provisioning
- API key/authentication for ingest endpoint
- Production TLS configuration
- Full documentation suite

---

## 10. Migration Strategy

The migration must be **incremental and non-destructive**. Working functionality is preserved at each phase.

### Phase 0 (Current): Assessment ✓
### Phase 1: Foundation hardening
- Remove SQLite layer completely
- Standardize all import paths
- Apply RBAC to all unprotected endpoints
- Add ingest API key authentication
- Add ClickHouse secondary indexes

### Phase 2: Backend expansion
- Persist UEBA state to PostgreSQL
- Implement Sigma parser (pySigma)
- Expand detection rule library (target: 40+ rules)
- Implement audit logging service
- Implement correlation engine (time-window state in Redis)
- Add external threat intelligence fetch (MITRE ATT&CK, CISA KEV, abuse.ch with caching)

### Phase 3: AI pipeline hardening
- Implement AI Security Gateway (prompt injection protection, secret filtering, output schema validation)
- Implement automatic AI enrichment trigger on high/critical signals
- Add RAG for MITRE ATT&CK and NIST knowledge

### Phase 4: Frontend transformation
- New professional design system (design tokens, consistent typography, density)
- Dark/Light theme toggle with persistence
- Implement full navigation structure
- Rebuild all pages with real data connections, loading/empty/error states
- Add: Detection Rules management, MITRE coverage, Entity profiles, Timeline, Case management, Threat Hunting, SOAR, Asset inventory, Audit log, Pipeline Health, System Health

### Phase 5: Observability and hardening
- Instrument all backend components with Prometheus metrics
- Provision Grafana dashboards
- Implement OpenTelemetry tracing
- Performance benchmark and optimize ingestion pipeline
- Security hardening: TLS, rate limiting, input size limits, tenant isolation tests

### Phase 6: Testing and documentation
- Expand test suite (unit, integration, security, load, replay)
- Write full documentation suite
- Create production deployment guide
