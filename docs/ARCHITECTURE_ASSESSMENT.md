# AetherGuard--Sentinel — Architecture Assessment

**Document type:** Phase 0 Repository Discovery  
**Status:** Baseline assessment before implementation  
**Date:** 2026-09-03  
**Scope:** Complete repository audit of the existing AetherGuard--Sentinel codebase

---

## Table of Contents

1. [Current Architecture](#1-current-architecture)
2. [Current Technology Stack](#2-current-technology-stack)
3. [Current Data Flow](#3-current-data-flow)
4. [Current APIs](#4-current-apis)
5. [Current Frontend](#5-current-frontend)
6. [Current Backend](#6-current-backend)
7. [Current Database](#7-current-database)
8. [Current Authentication / RBAC](#8-current-authentication--rbac)
9. [Existing Security Capabilities](#9-existing-security-capabilities)
10. [Existing UEBA](#10-existing-ueba)
11. [Existing Threat Intelligence](#11-existing-threat-intelligence)
12. [Existing Incident Management](#12-existing-incident-management)
13. [Existing Attack Simulation](#13-existing-attack-simulation)
14. [Existing Performance Bottlenecks](#14-existing-performance-bottlenecks)
15. [Existing Technical Debt](#15-existing-technical-debt)
16. [Missing Functionality](#16-missing-functionality)
17. [Security Weaknesses](#17-security-weaknesses)
18. [Proposed Target Architecture](#18-proposed-target-architecture)
19. [Technology Migration Plan](#19-technology-migration-plan)
20. [Implementation Phases](#20-implementation-phases)
21. [Dependency / License Assessment](#21-dependency--license-assessment)
22. [Local Zero-Mandatory-Cost Deployment Plan](#22-local-zero-mandatory-cost-deployment-plan)
23. [Production Deployment Plan](#23-production-deployment-plan)
24. [Testing Strategy](#24-testing-strategy)
25. [AI Architecture](#25-ai-architecture)
26. [Data-Compression Architecture](#26-data-compression-architecture)
27. [Risk Assessment](#27-risk-assessment)

---

## 1. Current Architecture

AetherGuard--Sentinel is a **single-process prototype** SOC dashboard application.

```
┌─────────────────────────────────────────────────────────┐
│                    BROWSER (React SPA)                   │
│  LoginPage │ DashboardPage │ LogExplorer │ AlertsPage   │
│  IncidentsPage │ ThreatIntelPage │ AttackMapPage        │
│  UEBAPage │ ReportsPage │ SettingsPage                  │
│                                                          │
│  Zustand store ← WebSocket (ws://localhost:8000/ws)     │
│  Axios REST  ← http://localhost:8000/api/*              │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────┐
│              FastAPI Backend (single process)             │
│                                                          │
│  main.py (lifespan startup)                              │
│    ├─ LogGenerator (async background task)               │
│    │    └─ Generates synthetic logs every 0.3-0.6s       │
│    ├─ AttackSimulator (async background task)            │
│    │    └─ Runs attack campaigns every 15-45s            │
│    ├─ DetectionEngine (8 hardcoded rules)                │
│    ├─ UEBAEngine (in-memory baselines)                   │
│    ├─ AnomalyDetector (IsolationForest on synthetic)     │
│    ├─ RiskScorer (composite: UEBA + anomaly)             │
│    └─ ConnectionManager (WebSocket broadcast)            │
│                                                          │
│  Data flow:                                              │
│  Generator → DB insert → UEBA record → Detection eval   │
│           → WebSocket broadcast                          │
│                                                          │
│  REST API: ~30 endpoints across 7 route files            │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────┐
│                     STORAGE                              │
│                                                          │
│  SQLite (aetherguard.db)        MongoDB / TinyDB         │
│  ├─ users                       ├─ logs (events)         │
│  └─ audit_logs                  ├─ alerts                │
│                                 ├─ incidents             │
│                                 └─ iocs                  │
│                                                          │
│  TinyDB fallback: data/aetherguard.json (~20MB)          │
└─────────────────────────────────────────────────────────┘
```

### Architecture classification

- **Pattern:** Monolithic single-process application
- **Data source:** 100% simulated (no real log ingestion)
- **State:** All runtime state in-memory (lost on restart)
- **Scale:** Single user, single tenant, single process
- **Deployment:** `python main.py` with `DEBUG=true`

### What works

- Real-time WebSocket streaming to the browser
- Dashboard with live EPS, severity charts, MITRE coverage
- 8 detection rules that trigger on simulated events
- Incident state machine with valid transitions
- Alert acknowledgment and escalation workflows
- IOC management (CRUD)
- User authentication (JWT)
- Basic role-based access (admin/analyst/viewer)
- CSV export for logs, alerts, incidents
- Attack simulation generating realistic-looking campaign data

### What is incomplete

- No real data ingestion (everything is simulated)
- No normalization schema (events are ad-hoc Python dicts)
- No analytical database (TinyDB is a JSON file)
- No multi-tenancy
- No AI/LLM integration
- No Sigma rule support
- No correlation engine
- No evidence preservation or chain of custody
- No deployment infrastructure (no Docker, no Compose)

---

## 2. Current Technology Stack

| Layer | Technology | Version | License | Status |
|-------|-----------|---------|---------|--------|
| **Backend framework** | FastAPI | 0.115.0 | MIT | ✅ Preserve |
| **ASGI server** | Uvicorn | 0.30.6 | BSD-3 | ✅ Preserve |
| **Data validation** | Pydantic | 2.9.2 | MIT | ✅ Preserve |
| **Settings** | pydantic-settings | 2.5.2 | MIT | ✅ Preserve |
| **JWT** | python-jose[cryptography] | 3.3.0 | MIT | ⚠️ Replace (unmaintained) |
| **Password hashing** | passlib[bcrypt] | 1.7.4 | BSD | ⚠️ Replace with argon2 |
| **Relational DB** | SQLite + aiosqlite | 0.20.0 | Public domain | ⚠️ Migrate to PostgreSQL |
| **ORM** | SQLAlchemy | 2.0.35 | MIT | ✅ Preserve |
| **Document DB** | MongoDB Motor | 3.6.0 | Apache-2.0 | ❌ Remove (replaced by ClickHouse) |
| **Document DB fallback** | TinyDB | 4.8.2 | MIT | ❌ Remove |
| **MongoDB driver** | pymongo | 4.9.2 | Apache-2.0 | ❌ Remove |
| **ML** | scikit-learn | 1.5.2 | BSD-3 | ✅ Preserve for UEBA |
| **ML core** | numpy | 2.1.1 | BSD-3 | ✅ Preserve |
| **PDF** | reportlab | 4.2.5 | BSD | ⚠️ Unused currently |
| **Frontend** | React | 18.x | MIT | ✅ Preserve |
| **Build** | Vite | 8.0.11 | MIT | ✅ Preserve |
| **State** | Zustand | 5.0.13 | MIT | ✅ Preserve |
| **HTTP client** | Axios | 1.16.0 | MIT | ✅ Preserve |
| **Charts** | Recharts | 3.8.1 | MIT | ⚠️ Consider ECharts |
| **Icons** | Lucide React | 1.14.0 | ISC | ✅ Preserve |
| **Routing** | React Router | 7.15.0 | MIT | ✅ Preserve |
| **Animations** | Framer Motion | 12.38.0 | MIT | ✅ Preserve |
| **Toasts** | React Toastify | 11.1.0 | MIT | ✅ Preserve |
| **CSS** | Tailwind CSS | 3.4.17 | MIT | ✅ Preserve |

### Dependencies installed but unused

- `date-fns` (frontend) — installed, never imported
- `react-simple-maps` (frontend) — installed, never imported
- `reportlab` (backend) — listed in requirements, import exists but PDF generation not implemented

### Missing from package.json

- `react` and `react-dom` are NOT declared in `package.json` dependencies (exist only in node_modules from prior install)

---

## 3. Current Data Flow

```
LogGenerator (Python async task)
    │
    │  Generates synthetic log every 0.3-0.6s
    │  Weighted: Windows 35%, Linux 25%, Firewall 20%, IDS 10%, Web 10%
    │
    ├──→ db_insert("logs", log)          → MongoDB/TinyDB
    ├──→ ueba_engine.record_event(log)   → In-memory dict
    ├──→ detection_engine.evaluate(log)   → 8 rules (in-memory windows)
    │        │
    │        └──→ If match: db_insert("alerts", alert) + ws_broadcast
    └──→ ws_manager.send_log(log)        → WebSocket to all clients

AttackSimulator (Python async task)
    │
    │  Runs one campaign every 15-45s
    │  10 campaign types (brute force, port scan, malware, etc.)
    │
    └──→ Injects batch of logs through same pipeline as above
```

### Critical finding: No real ingestion

There is **zero capability** to ingest real security telemetry. The entire data flow is:

1. `LogGenerator` creates fake data using hardcoded lists of hostnames, IPs, users
2. `AttackSimulator` creates fake attack campaign data
3. Both feed into the same in-process pipeline
4. Data is stored in MongoDB (or a 20MB TinyDB JSON file as fallback)
5. Data is broadcast to WebSocket clients

There is no syslog receiver, no API ingest endpoint, no file reader, no connector framework, no format detection, no normalization, no enrichment.

---

## 4. Current APIs

### Authentication (`api/routes/auth.py` — 112 lines)

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/api/auth/login` | Public | Login, returns JWT |
| GET | `/api/auth/me` | Bearer | Current user info |
| POST | `/api/auth/logout` | Bearer | Audit log only (stateless JWT) |
| GET | `/api/auth/users` | Admin | List all users |
| POST | `/api/auth/users` | Admin | Create user |

### Dashboard (`api/routes/dashboard.py` — 148 lines)

| Method | Path | Auth | Purpose | Data source |
|--------|------|------|---------|-------------|
| GET | `/api/dashboard/stats` | Bearer | KPI counts | DB aggregation |
| GET | `/api/dashboard/eps-history` | Bearer | 60-point EPS chart | **Random synthetic** |
| GET | `/api/dashboard/top-attackers` | Bearer | Top 10 source IPs | Last 5000 logs in-memory |
| GET | `/api/dashboard/top-targets` | Bearer | Top 10 hostnames | Last 5000 logs in-memory |
| GET | `/api/dashboard/mitre-coverage` | Bearer | Technique frequency | Last 1000 alerts |
| GET | `/api/dashboard/geo-attacks` | Bearer | Map coordinates | Last 200 logs with geo |
| GET | `/api/dashboard/recent-alerts` | Bearer | Latest 20 alerts | DB query |
| GET | `/api/dashboard/severity-timeline` | Bearer | 24h severity bars | **Random synthetic** |

### Logs (`api/routes/logs.py` — 92 lines)

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/api/logs/search` | Bearer | Search with filters (in-memory substring for TinyDB) |
| GET | `/api/logs/stats` | Bearer | Log distribution stats |
| GET | `/api/logs/live` | Bearer | Latest N logs |
| GET | `/api/logs/sources` | Bearer | Static source list |

### Alerts (`api/routes/alerts.py` — 113 lines)

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/api/alerts/` | Bearer | List with filters |
| GET | `/api/alerts/{id}` | Bearer | Single alert |
| POST | `/api/alerts/{id}/acknowledge` | Analyst | Acknowledge alert |
| POST | `/api/alerts/{id}/escalate` | Analyst | Escalate to incident |
| GET | `/api/alerts/stats/summary` | Bearer | Severity distribution |

### Incidents (`api/routes/incidents.py` — 193 lines)

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/api/incidents/` | Bearer | List with filters |
| GET | `/api/incidents/stats` | Bearer | Status counts |
| GET | `/api/incidents/{id}` | Bearer | Single incident |
| POST | `/api/incidents/` | Analyst | Create incident |
| PUT | `/api/incidents/{id}` | Analyst | Update incident |
| POST | `/api/incidents/{id}/transition` | Analyst | Status transition |
| POST | `/api/incidents/{id}/notes` | Bearer | Add note |

### Threat Intel (`api/routes/threat_intel.py` — 144 lines)

| Method | Path | Auth | Purpose | Data source |
|--------|------|------|---------|-------------|
| GET | `/api/threat-intel/iocs` | Bearer | List IOCs | DB |
| POST | `/api/threat-intel/iocs` | Bearer | Create IOC | DB |
| DELETE | `/api/threat-intel/iocs/{id}` | Bearer | Delete IOC | DB |
| GET | `/api/threat-intel/ip-reputation/{ip}` | Bearer | IP lookup | **Hardcoded + random** |
| GET | `/api/threat-intel/hash/{hash}` | Bearer | Hash lookup | **Hardcoded list** |
| GET | `/api/threat-intel/feeds` | Bearer | Feed status | **Hardcoded static** |
| GET | `/api/threat-intel/blocklist` | Bearer | Active IOCs | DB |

### Reports (`api/routes/reports.py` — 127 lines)

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/api/reports/logs/csv` | Bearer | CSV export |
| GET | `/api/reports/alerts/csv` | Bearer | CSV export |
| GET | `/api/reports/incidents/csv` | Bearer | CSV export |
| GET | `/api/reports/summary` | Bearer | JSON summary |

### Users (`api/routes/users.py` — 27 lines)

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/api/users/` | Admin | List users |
| GET | `/api/users/me` | Bearer | Current user |
| GET | `/api/users/{id}` | Admin | Single user |

### UEBA and Health (defined in `main.py`)

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/api/ueba/users` | Bearer | Top risky users |
| GET | `/api/ueba/user/{username}` | Bearer | User profile |
| GET | `/api/health` | Public | Health check |
| WS | `/ws` | None | Real-time streaming |

**Total: ~30 endpoints across 7 route files + main.py**

---

## 5. Current Frontend

### Architecture

- **Framework:** React 18 SPA with React Router v7
- **Language:** JavaScript/JSX (NOT TypeScript — despite tsconfig.json existing)
- **State:** Single Zustand store (auth, live logs buffer 500, alerts buffer 100, EPS, UI toggles)
- **Styling:** Tailwind CSS with custom `cyber` color palette (dark theme)
- **Charts:** Recharts (AreaChart, BarChart, PieChart, RadarChart)
- **Real-time:** Native WebSocket with auto-reconnect, heartbeat, client-side EPS calculation

### Pages (10 routes)

| Route | Component | Lines | Purpose |
|-------|-----------|-------|---------|
| `/login` | LoginPage | 162 | Auth with hardcoded demo credential buttons |
| `/dashboard` | DashboardPage | 263 | 6 KPIs + EPS chart + severity timeline + attackers + MITRE + alerts + log feed |
| `/logs` | LogExplorerPage | 203 | Search, filter, paginate, inspect raw JSON |
| `/alerts` | AlertsPage | 144 | Triage board, severity charts, acknowledge |
| `/incidents` | IncidentsPage | 333 | Full IR workflow: create, status transitions, timeline, notes |
| `/threat-intel` | ThreatIntelPage | 245 | IP reputation, IOC CRUD, feed status |
| `/attack-map` | AttackMapPage | 202 | SVG Bezier attack trajectories on world map |
| `/ueba` | UEBAPage | 200 | User risk rankings, radar profile, risk gauge |
| `/reports` | ReportsPage | 168 | Summary stats, CSV downloads |
| `/settings` | SettingsPage | 141 | Health, session, platform info, hardcoded rule lists |

### Reusable Components

| Component | Lines | Purpose |
|-----------|-------|---------|
| Sidebar | 144 | Navigation with collapse, unread badge, user profile |
| TopNav | 120 | Breadcrumb, EPS counter, WS status badge, notification drawer |
| AlertCard | 95 | Severity-colored alert card with inline acknowledge |
| StatWidget | 80 | Animated KPI card with cubic easing odometer |
| LiveLogFeed | 137 | Terminal-style real-time log viewer with filters |

### What works well

- The dark cyber theme is visually cohesive and professional
- Real-time WebSocket streaming creates an engaging live experience
- The dashboard provides a good SOC overview layout
- Incident management has a proper state machine
- The attack map visualization is creative and memorable

### What needs improvement

- No TypeScript (all code is .js/.jsx despite tsconfig existing)
- Hardcoded demo credentials in LoginPage
- No drill-down or pivot capability on any value
- No command palette or keyboard navigation
- Charts use Recharts (adequate but limited for security dashboards)
- Settings page has hardcoded rule and campaign lists
- `react` and `react-dom` missing from package.json dependencies
- Dead files: `main.ts`, `counter.ts`, `style.css` (Vite scaffolding artifacts)
- Unused deps: `date-fns`, `react-simple-maps`

---

## 6. Current Backend

### File inventory (backend/)

| Directory | Files | Total Lines | Purpose |
|-----------|-------|-------------|---------|
| `main.py` | 1 | 187 | App entrypoint, lifespan, WS endpoint |
| `api/routes/` | 7 | 856 | REST API endpoints |
| `api/middleware/` | 1 | 41 | Auth guards |
| `config/` | 1 | 20 | Pydantic Settings |
| `db/` | 2 | 357 | Database abstraction + SQLite ORM |
| `detections/` | 1 engine + 8 rules | 399 | Detection engine |
| `ml/` | 3 | 148 | Anomaly, UEBA, risk scoring |
| `services/` | 1 | 96 | Auth service |
| `simulator/` | 2 | 743 | Log generator + attack simulator |
| `websocket/` | 1 | 74 | WebSocket connection manager |
| `models/` | 0 | 0 | **EMPTY** |
| `data/` | 1 | 1 | TinyDB JSON file (~20MB) |

**Total backend: ~2,921 lines of Python** (excluding TinyDB data file)

### Code quality assessment

| Area | Rating | Notes |
|------|--------|-------|
| Project structure | ⚠️ Adequate | Clean directory layout, proper packages |
| Type safety | ❌ Poor | Core entities (logs, alerts, incidents) are untyped dicts |
| Error handling | ⚠️ Basic | Some try/except but inconsistent |
| Logging | ❌ Minimal | Uses print statements and basic logging |
| Testing | ❌ None | Zero test files exist |
| Documentation | ❌ Minimal | README only, no API docs, no architecture docs |
| Dependency injection | ⚠️ Ad-hoc | Via `app.state` attributes, not formal DI |
| Configuration | ⚠️ Fragile | Hardcoded secrets in settings.py fallback |

---

## 7. Current Database

### SQLite (`aetherguard.db`)

Used for: Authentication and audit only.

**`users` table:**

| Column | Type | Notes |
|--------|------|-------|
| id | String(36) PK | UUID |
| username | String(50) UNIQUE | |
| email | String(120) UNIQUE | |
| hashed_password | String(255) | bcrypt |
| role | String(20) | admin / analyst / viewer |
| is_active | Boolean | default True |
| full_name | String(100) | |
| department | String(100) | default "SOC" |
| created_at | DateTime | |
| last_login | DateTime | nullable |

**`audit_logs` table:**

| Column | Type | Notes |
|--------|------|-------|
| id | String(36) PK | UUID |
| user_id | String(36) | |
| username | String(50) | |
| action | String(100) | LOGIN, LOGOUT |
| resource | String(200) | URL path |
| details | Text | |
| ip_address | String(50) | |
| timestamp | DateTime | |

**Assessment:** SQLite is acceptable for development auth but must migrate to PostgreSQL for production multi-tenancy, concurrent access, and proper RBAC.

### MongoDB / TinyDB (document store)

Used for: All security data (logs, alerts, incidents, IOCs).

**Collections (untyped — no schema enforcement):**

- `logs` — Generated security events (ad-hoc dict structure)
- `alerts` — Detection matches (ad-hoc dict structure)
- `incidents` — IR cases (ad-hoc dict with timeline/notes arrays)
- `iocs` — Threat indicators (ad-hoc dict)

**TinyDB fallback:** When MongoDB is unavailable (which is the default development experience), all document data goes into `data/aetherguard.json`, a single-line JSON file that has grown to **20.4 MB**. TinyDB is synchronous and blocks the asyncio event loop during writes.

**Assessment:** This storage layer must be completely replaced. TinyDB cannot support production use. MongoDB is unnecessary when ClickHouse handles analytical queries and PostgreSQL handles transactional state. The document collections will migrate to:

- `logs` / `alerts` → ClickHouse (analytical, high-volume)
- `incidents` / `iocs` → PostgreSQL (transactional, relational)

---

## 8. Current Authentication / RBAC

### Authentication flow

1. User submits credentials to `POST /api/auth/login`
2. Server verifies bcrypt hash against SQLite `users` table
3. Server creates JWT with `sub`, `username`, `role`, `email` claims
4. JWT is signed with `HS256` using a **hardcoded secret key**
5. Frontend stores JWT in `localStorage` (`ag_token`)
6. Axios interceptor attaches `Authorization: Bearer <token>` to every request
7. Response interceptor catches 401 → clears localStorage → redirects to `/login`

### RBAC

Three roles exist with coarse enforcement:

| Role | Permissions |
|------|------------|
| `admin` | All endpoints + user management |
| `analyst` | Alert acknowledge, escalate, incident manage |
| `viewer` | Read-only on all data |

Enforcement is via two FastAPI dependencies:
- `require_admin(current_user)` — checks `role == "admin"`
- `require_analyst(current_user)` — checks `role in ("admin", "analyst")`

### Weaknesses

1. **Hardcoded JWT secret:** `"aetherguard-sentinel-ultra-secure-key-2024-production-soc"` in both `.env` and `config/settings.py`
2. **No token refresh:** Tokens expire in 60 min with no rotation
3. **No MFA support**
4. **No OIDC/SAML**
5. **Coarse RBAC:** Only 3 roles with only 2 guard functions (not fine-grained permissions)
6. **No tenant isolation:** All users see all data
7. **No API key support:** Only JWT Bearer
8. **WebSocket endpoint has no authentication at all** — anyone can connect to `/ws`
9. **Seeded credentials printed to console at startup**

---

## 9. Existing Security Capabilities

### Detection Engine (`detections/engine.py` — 74 lines)

Sequential rule evaluation: each log passes through all 8 rules. Matches create alert documents persisted to DB and broadcast via WebSocket.

### Detection Rules (8 total)

| Rule | Lines | Trigger | Severity | Stateful | MITRE |
|------|-------|---------|----------|----------|-------|
| BruteForce | 46 | ≥10 failed logins from same IP in 120s | high | Yes (window) | T1110.001, T1078 |
| PortScan | 48 | ≥20 unique dest ports denied from same IP in 60s | medium | Yes (window) | T1046 |
| PrivilegeEscalation | 37 | Event IDs 4728/4672/4720/4732/4756 or keywords | critical | No | T1078.002, T1098, T1134 |
| SuspiciousPowerShell | 40 | 21 suspicious patterns in powershell.exe/pwsh.exe | critical | No | T1059.001, T1027, T1140 |
| ImpossibleTravel | 20 | `event_type == "impossible_travel"` (pre-tagged by simulator) | high | No | T1078, T1534 |
| DataExfiltration | 32 | `bytes_out >= 10MB` or `event_type == "data_exfiltration"` | critical | No | T1041, T1048, T1030 |
| MalwareIndicators | 43 | 9 malware process names or 8 signature patterns | critical | No | T1059, T1055, T1036, T1071 |
| Beaconing | 48 | ≥8 connections from same host to same external IP in 300s | high | Yes (window) | T1071.001, T1102, T1008 |

### What works

- Rule engine pattern is clean (BaseRule → evaluate → match)
- Stateful windowed rules (brute force, port scan, beaconing) correctly expire old events
- MITRE ATT&CK technique mapping on every rule
- Tags for categorization

### What doesn't work

- ImpossibleTravel rule relies on simulator pre-tagging `event_type == "impossible_travel"` — it does not compute anything
- In-memory state (`_event_windows`) lost on restart
- No Sigma support
- No rule versioning, lifecycle, or testing
- No exceptions/allowlists/suppression
- No correlation between rules
- No risk-based aggregation
- No false-positive tracking

---

## 10. Existing UEBA

### Implementation (`ml/ueba.py` — 59 lines)

`UEBAEngine` maintains two in-memory data structures:

- `_user_hourly`: `{username: {hour_bucket: event_count}}`
- `_user_risk`: `{username: [last_1000_risk_scores]}`

### Computed metrics per user

- `avg_hourly_events`
- `current_hour_events`
- `avg_risk_score`
- `peak_risk`
- `total_events`
- `anomaly_flag`: True if `avg_risk > 60` OR `current_hour_events > 3× avg_hourly`

### Assessment

| Aspect | Status |
|--------|--------|
| Concept | ✅ Sound baseline approach |
| Implementation | ⚠️ Functional but fragile |
| Data persistence | ❌ In-memory only, lost on restart |
| Multi-process | ❌ Not safe across workers |
| Real baselines | ❌ Operates on simulated data |
| Peer grouping | ❌ Not implemented |
| Impossible travel | ❌ Faked by simulator, not computed |
| Entity types | ⚠️ Users only (no hosts, IPs, processes) |

**Verdict:** Preserve the concept and API surface. Refactor to use persistent storage (ClickHouse rollups or Redis) and extend to multiple entity types.

---

## 11. Existing Threat Intelligence

### Implementation (`api/routes/threat_intel.py` — 144 lines)

- **Hardcoded `THREAT_FEED` dict** with 10 IPs, 5 MD5 hashes, 5 domains
- **IOC CRUD** against the `iocs` collection (this works)
- **IP reputation lookup** matches against hardcoded list; unknown IPs get random scores, random countries, random ASNs
- **Hash lookup** matches against hardcoded MD5 list
- **Feed status** returns 5 hardcoded feed entries with static timestamps

### Assessment

| Aspect | Status |
|--------|--------|
| IOC storage/CRUD | ✅ Works |
| Real feeds (TAXII/MISP/STIX) | ❌ None |
| Real IP reputation | ❌ Hardcoded + random |
| Real hash lookup | ❌ Hardcoded list |
| IoC matching in pipeline | ❌ Not connected |
| Graph relationships | ❌ None |
| Confidence/TLP/expiry | ❌ None |

**Verdict:** IOC CRUD is usable. Everything else needs real data sources (abuse.ch, MITRE ATT&CK, CISA KEV, NVD) and actual lookup services with caching.

---

## 12. Existing Incident Management

### Implementation (`api/routes/incidents.py` — 193 lines)

**State machine:**
```
open → investigating → contained → resolved → closed
                    ↘              ↗
                     ←────────────
```

Valid transitions are properly enforced.

**Features:**
- Create incident with title, description, severity, assignee, tags, source_ip, hostname, MITRE techniques
- Update fields
- Status transitions with validation
- Timeline array (audit trail of status changes)
- Notes array (analyst comments with author + timestamp)
- Alert escalation creates incident and back-links
- Filtering by status, severity, assignee

### Assessment

| Aspect | Status |
|--------|--------|
| State machine | ✅ Correct, enforced server-side |
| Timeline | ✅ Functional event sourcing pattern |
| Notes/collaboration | ✅ Works |
| Alert escalation | ✅ Works |
| Evidence linking | ❌ No evidence chain |
| Observable extraction | ❌ None |
| Chain of custody | ❌ None |
| SLA timers | ❌ None |
| Case assignment | ⚠️ Basic (free text assignee) |
| Ticketing integration | ❌ None |

**Verdict:** Good foundation. Preserve the API contract and state machine. Migrate storage from MongoDB to PostgreSQL. Add evidence, observables, SLA, and AI investigation linking.

---

## 13. Existing Attack Simulation

### Implementation (`simulator/attack_simulator.py` — 388 lines)

10 campaign types with realistic synthetic data:

| Campaign | Events | Characteristics |
|----------|--------|-----------------|
| SSH Brute Force | 30-80 | Failed SSH from external IP against Linux hosts |
| RDP Brute Force | 20-60 | Failed EventID 4625 from China IP |
| Port Scan | 50-200 | Unique dest ports denied on FIREWALL-CORE |
| DDoS HTTP Flood | 40-100 | HTTP 503 from 5-20 attacker IPs |
| Malware Execution | varies | Process start of mimikatz, cobalt_beacon, etc. |
| Data Exfiltration | 1 | 50-500MB outbound transfer |
| Reverse Shell | varies | Outbound connection to port 4444 |
| Privilege Escalation | 1 | EventID 4728 adding to Domain Admins |
| Impossible Travel | 2 | Auth from China after USA login |
| PowerShell Attack | varies | Encoded commands, download cradles |

### Assessment

| Aspect | Status |
|--------|--------|
| Campaign variety | ✅ Good coverage of common attack types |
| Realism | ⚠️ Adequate for demo, not for detection testing |
| Integration | ✅ Feeds through detection engine |
| Replay capability | ❌ No replay from file/dataset |
| Public datasets | ❌ Not used |
| Test cases | ❌ No assertions on expected detections |

**Verdict:** Valuable for demos and development. Preserve. Extend to support replay of real datasets (CICIDS, UNSW-NB15) and add expected-detection assertions for testing.

---

## 14. Existing Performance Bottlenecks

### Critical bottlenecks

| # | Bottleneck | Impact | Severity |
|---|-----------|--------|----------|
| 1 | **TinyDB synchronous I/O** | Blocks asyncio event loop on every write; 20MB JSON file rewritten on updates | 🔴 Critical |
| 2 | **In-memory aggregation** | `top-attackers` loads 5,000 logs into Python memory; `log_stats` loads 10,000; `severity aggregation` loads 50,000 in TinyDB mode | 🔴 Critical |
| 3 | **No database indexing** | TinyDB has no indexes; MongoDB indexes not defined in code | 🟡 High |
| 4 | **Single-process state** | All detection windows, UEBA baselines, WebSocket connections in one process | 🟡 High |
| 5 | **No query pagination limits** | Some queries have no upper bound | 🟡 High |
| 6 | **WebSocket broadcast to all** | Every log event broadcasts to every connected client | 🟡 Medium |
| 7 | **Sequential rule evaluation** | 8 rules evaluated one-by-one per log (adequate now, won't scale with more rules) | 🟢 Low (currently) |

### Estimated current capacity

- **Events/sec:** ~2-3 EPS (limited by TinyDB sync writes)
- **Concurrent users:** ~5-10 (WebSocket broadcast + REST queries)
- **Data retention:** Days before TinyDB file becomes unwieldy

---

## 15. Existing Technical Debt

| # | Debt | Location | Risk |
|---|------|----------|------|
| 1 | **Empty models directory** — core entities are untyped dicts | `models/` | Schema drift, bugs, no validation |
| 2 | **Hardcoded JWT secret** committed to repo | `.env`, `config/settings.py` | Token forgery |
| 3 | **Hardcoded demo credentials** seeded on every startup | `services/auth_service.py` | Unauthorized access |
| 4 | **Unauthenticated WebSocket** — no token verification | `main.py` websocket_endpoint | Data exposure |
| 5 | **Circular ML logic** — AnomalyDetector uses `risk_score` and `anomaly_score` from the log to predict anomaly | `ml/anomaly_detector.py` | Meaningless results |
| 6 | **ImpossibleTravel rule** does nothing — relies on simulator pre-tagging | `detections/rules/impossible_travel.py` | False sense of capability |
| 7 | **Random data in APIs** — EPS history and severity timeline return `random.randint()` | `api/routes/dashboard.py` | Misleading dashboards |
| 8 | **SQLite URL ignored** — `init_sqlite()` hardcodes `sqlite+aiosqlite:///./aetherguard.db` ignoring `settings.SQLITE_URL` | `db/sqlite_db.py` | Config doesn't work |
| 9 | **Dead TypeScript files** — `main.ts`, `counter.ts`, `style.css` from Vite scaffold | `frontend/src/` | Confusing |
| 10 | **Frontend hardcoded backend URL** — `http://localhost:8000` in two places | `api.js`, `websocket.js` | Can't deploy elsewhere |
| 11 | **Inconsistent auth pattern for CSV export** — one uses fetch+blob, other uses `<a>` with `?token=` | `ReportsPage.jsx`, `LogExplorerPage.jsx` | Auth bypass risk |
| 12 | **Broken favicon** — `index.html` references `/shield.svg` which doesn't exist | `index.html` | 404 on load |

---

## 16. Missing Functionality

### Tier 1 — Required for production SOC

| # | Capability | Status |
|---|-----------|--------|
| 1 | Real telemetry ingestion (syslog, JSON, file, API) | ❌ Missing |
| 2 | Event normalization to a canonical schema | ❌ Missing |
| 3 | Analytical database (ClickHouse or equivalent) | ❌ Missing |
| 4 | Multi-tenancy | ❌ Missing |
| 5 | Fine-grained RBAC (permissions, not just roles) | ❌ Missing |
| 6 | Sigma rule support | ❌ Missing |
| 7 | Correlation engine | ❌ Missing |
| 8 | Security signals (the AI boundary abstraction) | ❌ Missing |
| 9 | Evidence packaging and retrieval | ❌ Missing |
| 10 | AI investigation (local LLM) | ❌ Missing |
| 11 | Docker/Docker Compose deployment | ❌ Missing |
| 12 | Test suite | ❌ Missing |
| 13 | Database migrations | ❌ Missing |
| 14 | Structured logging | ❌ Missing |
| 15 | Health checks (liveness/readiness) | ⚠️ Basic `/api/health` exists |

### Tier 2 — Required for competitive SOC

| # | Capability | Status |
|---|-----------|--------|
| 16 | Context compression / deterministic funnel | ❌ Missing |
| 17 | AI security gateway (injection defense) | ❌ Missing |
| 18 | SOAR with approval gates | ❌ Missing |
| 19 | Case management with evidence chain | ⚠️ Basic incidents exist |
| 20 | MITRE ATT&CK integration (beyond technique IDs) | ⚠️ IDs only |
| 21 | RAG (knowledge retrieval) | ❌ Missing |
| 22 | Report generation (PDF, HTML) | ⚠️ CSV only |
| 23 | Observability (metrics, tracing) | ❌ Missing |
| 24 | Replay/testing engine | ❌ Missing |
| 25 | Backup and disaster recovery | ❌ Missing |

---

## 17. Security Weaknesses

| # | Weakness | Risk | Remediation |
|---|----------|------|-------------|
| 1 | Hardcoded JWT secret in source code and .env | **Critical** — token forgery | Generate random secret at first run; never commit |
| 2 | Unauthenticated WebSocket endpoint | **High** — anyone can receive all logs/alerts | Require JWT token in WS connection handshake |
| 3 | No CSRF protection | **Medium** | Add CSRF tokens for state-changing operations |
| 4 | No rate limiting on any endpoint | **High** — brute force login | Add per-IP and per-user rate limiting |
| 5 | JWT stored in localStorage | **Medium** — XSS exfiltration | Consider httpOnly cookies or keep with strong CSP |
| 6 | No input validation on search queries | **Medium** — injection | Parameterize all DB queries |
| 7 | DEBUG=true in production config | **Medium** — stack trace exposure | Default to false |
| 8 | Demo credentials auto-seeded | **Medium** — known passwords | First-run wizard instead |
| 9 | No audit trail for data access | **High** — compliance | Log all data access with actor/timestamp |
| 10 | No tenant isolation | **Critical** for multi-tenant | Enforce at database level |

---

## 18. Proposed Target Architecture

```
                    SECURITY SOURCES
                         ↓
                    COLLECTORS / AGENTS
                         ↓
              ┌──── INGESTION API ────┐
              │  Syslog │ REST │ File │
              │  Tenant attribution    │
              │  Validation            │
              │  Raw preservation      │
              └──────────┬────────────┘
                         ↓
              ┌── TRANSPORT/BUFFER ───┐
              │  Redis Streams (dev)   │
              │  Redpanda (scale)      │
              └──────────┬────────────┘
                         ↓
              ┌── NORMALIZER ─────────┐
              │  Format detection      │
              │  Parser selection      │
              │  OCSF-aligned schema   │
              │  Enrichment (GeoIP,    │
              │    asset, identity)    │
              └──────────┬────────────┘
                         ↓
              ┌── DETERMINISTIC FUNNEL┐
              │  Filtering             │
              │  Deduplication         │
              │  Aggregation           │
              │  Thresholds            │
              │  Baselines             │
              └────┬─────────┬────────┘
                   ↓         ↓
              STORAGE     DETECTION
              (ClickHouse)  (Sigma + custom)
                   ↓         ↓
              └────┬─────────┘
                   ↓
              CORRELATION ENGINE
              (entity, sequence, multi-source)
                   ↓
              SECURITY SIGNAL
              (the AI boundary)
                   ↓
              EVIDENCE BUILDER
              (retrieve, rank, timeline)
                   ↓
              CONTEXT COMPRESSOR
              (deduplicate, aggregate, budget)
                   ↓
              AI SECURITY GATEWAY
              (injection defense, tenant validation,
               secret redaction, model routing, audit)
                   ↓
              LOCAL LLM (Ollama)
              (investigation, triage, explanation)
                   ↓
              STRUCTURED FINDING
              (verdict, evidence refs, MITRE, confidence)
                   ↓
              ┌── ANALYST CONSOLE ────┐
              │  Signals │ Timeline    │
              │  Investigation │ Cases │
              │  Detection │ Pipeline  │
              │  Threat Intel │ UEBA   │
              │  Reports │ Admin       │
              └──────────────────────┘
                   ↓
              CONTROLLED SOAR
              (approve → enrich → act → verify → audit)
```

### Key architectural principles

1. **The SIEM is the system of record; the AI is the reasoning layer**
2. **Deterministic funnel before AI** — compress billions of events to bounded signals
3. **Security signals are the central unit** — not raw events
4. **Evidence-linked everything** — every AI claim traces to source events
5. **AI fails gracefully** — SIEM continues if LLM is down
6. **AI is async** — never blocks ingestion or detection
7. **Zero mandatory cost** — all open-source, local AI, self-hostable

---

## 19. Technology Migration Plan

### Phase approach: PRESERVE → REFACTOR → EXTEND → INTEGRATE

| Current | Target | Migration strategy |
|---------|--------|-------------------|
| SQLite (auth) | PostgreSQL | Migrate schema via Alembic; keep SQLAlchemy ORM |
| MongoDB/TinyDB (events) | ClickHouse | New analytical store; events/alerts to ClickHouse |
| MongoDB/TinyDB (incidents/iocs) | PostgreSQL | Migrate to relational tables |
| No message queue | Redis Streams (dev) / Redpanda (scale) | Add transport layer between ingest and processing |
| No cache | Redis | Add for rate limiting, IoC cache, session state |
| No AI | Ollama (local LLM) | Add AI layer behind security gateway |
| No graph | PostgreSQL (indexed relationships first) | Graph queries via SQL; Neo4j only if needed |
| No object storage | MinIO | Add for raw log archive, evidence packages |
| No observability | Prometheus + Grafana | Add metrics and dashboards |
| bcrypt (passlib) | argon2 (argon2-cffi) | More resistant to GPU attacks |
| python-jose | PyJWT | python-jose is unmaintained |
| Recharts | ECharts | More capable for security visualizations |
| JavaScript | TypeScript | Gradual migration, file by file |

### What is preserved

- FastAPI backend framework
- SQLAlchemy ORM patterns
- Pydantic validation patterns
- React + Vite + Tailwind frontend
- Zustand state management
- WebSocket real-time streaming pattern
- Detection engine rule pattern (BaseRule → evaluate)
- Incident state machine
- Alert acknowledge/escalate workflow
- UEBA concept and API surface
- Attack simulation campaigns
- IOC CRUD
- Auth flow (JWT pattern, not the hardcoded secret)
- All 10 frontend pages (refactored, not deleted)

---

## 20. Implementation Phases

### Phase 0 — Repository Discovery ← **THIS DOCUMENT**

### Phase 1 — Foundation
- Docker Compose (ClickHouse, PostgreSQL, Redis, Ollama, Prometheus, Grafana)
- `.env.example` with all config externalized
- PostgreSQL schema + Alembic migrations
- ClickHouse normalized events schema
- Structured logging (structlog)
- Health endpoints (liveness/readiness per service)
- Fix security weaknesses (JWT secret, WS auth, rate limiting)

### Phase 2 — Ingestion
- REST ingest API with validation
- Syslog receiver (TCP/TLS)
- Format detection (JSON, syslog, CEF, Windows XML)
- Canonical event schema (OCSF-aligned)
- Raw event preservation (ClickHouse + MinIO archive)
- Tenant attribution at ingest
- Ingest metrics

### Phase 3 — Deterministic Funnel
- Filtering and allowlists
- Deduplication (content hash within time window)
- Aggregation (count windows, rate detection)
- Suppression (per-rule, per-entity)
- Threshold detection
- Baseline comparison (UEBA refactored to use ClickHouse)

### Phase 4 — Detection
- Sigma rule support (pySigma → ClickHouse SQL)
- Custom YAML rule format
- Rule versioning and lifecycle
- Exception/allowlist support
- 10 MVP detections with test cases
- Detection replay against stored events

### Phase 5 — Correlation
- Entity correlation (user, IP, host, session)
- Sequence detection (A → B → C in time window)
- Multi-source correlation
- State management with TTL (Redis)

### Phase 6 — Security Signals
- Signal schema definition
- Signal lifecycle (created → triaged → investigating → resolved)
- Evidence linking (signal → events)
- Signal-to-event compression ratio metric

### Phase 7 — Evidence
- Evidence retrieval service
- Relevance ranking
- Timeline construction
- Entity extraction
- IOC matching

### Phase 8 — AI Gateway
- Prompt injection defense (log content isolation)
- Secret/PII redaction before AI
- Tenant validation
- Context budget enforcement
- Model routing (small/medium/large)
- Audit logging for all AI requests

### Phase 9 — Local AI
- Ollama integration via provider abstraction
- Model configuration (name, context window, temperature)
- CPU and GPU support
- Fallback handling (AI down → SIEM continues)
- Async job queue for AI investigations

### Phase 10 — AI Investigation
- Investigation agent with read-only tools
- Structured output contract (verdict, evidence refs, MITRE, confidence)
- Confidence states (confirmed/high/likely/possible/unknown)
- Hallucination control (insufficient evidence → say so)
- Evidence attribution (every claim → source event)

### Phase 11 — Threat Intelligence / RAG
- MITRE ATT&CK data integration
- Public IOC feeds (abuse.ch, CISA KEV)
- IOC lookup caching (Redis)
- Knowledge retrieval for investigations

### Phase 12 — Console Enhancement
- TypeScript migration (incremental)
- Signal queue UI
- Investigation timeline
- Evidence viewer
- AI findings panel
- Detection management
- Pipeline health dashboard

### Phase 13 — SOAR
- Playbook schema (trigger → validate → enrich → decide → approve → act)
- Approval gates for high-impact actions
- Action execution and verification
- Audit trail

### Phase 14 — Hardening
- Tenant isolation tests
- Security testing
- Performance benchmarks
- Backup/restore procedures
- Failure recovery testing

### Phase 15 — Production Deployment
- Docker production profile
- Resource limits and health checks
- Deployment documentation
- Operations runbook

---

## 21. Dependency / License Assessment

### Backend dependencies (all open-source)

| Package | License | Status | Notes |
|---------|---------|--------|-------|
| fastapi | MIT | ✅ Keep | |
| uvicorn | BSD-3 | ✅ Keep | |
| pydantic | MIT | ✅ Keep | |
| pydantic-settings | MIT | ✅ Keep | |
| sqlalchemy | MIT | ✅ Keep | |
| aiosqlite | MIT | ⚠️ Keep for dev | Replace with asyncpg for production |
| python-jose | MIT | ⚠️ Replace | Unmaintained — use PyJWT |
| passlib | BSD | ⚠️ Replace | Use argon2-cffi directly |
| motor | Apache-2.0 | ❌ Remove | Replaced by ClickHouse + PostgreSQL |
| pymongo | Apache-2.0 | ❌ Remove | |
| tinydb | MIT | ❌ Remove | |
| scikit-learn | BSD-3 | ✅ Keep | For UEBA anomaly detection |
| numpy | BSD-3 | ✅ Keep | |
| reportlab | BSD | ⚠️ Unused | Keep if PDF generation needed, else remove |

### New dependencies (all open-source, zero mandatory cost)

| Package | License | Purpose |
|---------|---------|---------|
| asyncpg | Apache-2.0 | PostgreSQL async driver |
| alembic | MIT | Database migrations |
| clickhouse-connect | Apache-2.0 | ClickHouse client |
| redis (hiredis) | MIT | Cache, pub/sub, rate limiting |
| structlog | MIT/Apache-2.0 | Structured logging |
| argon2-cffi | MIT | Password hashing |
| PyJWT | MIT | JWT tokens |
| pySigma | LGPL-2.1 | Sigma rule compilation |
| httpx | BSD-3 | Async HTTP (Ollama, feeds) |
| prometheus-client | Apache-2.0 | Metrics |
| opentelemetry-api | Apache-2.0 | Tracing |

### Frontend dependencies (all open-source)

| Package | License | Status |
|---------|---------|--------|
| react / react-dom | MIT | ✅ Keep (add to package.json!) |
| vite | MIT | ✅ Keep |
| tailwindcss | MIT | ✅ Keep |
| zustand | MIT | ✅ Keep |
| axios | MIT | ✅ Keep |
| react-router-dom | MIT | ✅ Keep |
| recharts | MIT | ⚠️ Consider ECharts migration |
| lucide-react | ISC | ✅ Keep |
| framer-motion | MIT | ✅ Keep |
| react-toastify | MIT | ✅ Keep |
| date-fns | MIT | ⚠️ Remove (unused) |
| react-simple-maps | MIT | ⚠️ Remove (unused) |

### Infrastructure (all open-source, zero license cost)

| Component | License | Notes |
|-----------|---------|-------|
| ClickHouse | Apache-2.0 | Open-source analytical DB |
| PostgreSQL | PostgreSQL License (BSD-like) | Open-source relational DB |
| Redis | BSD-3 (Redis 7.x SSPL for 7.4+, BSD for 7.2) | Use Redis 7.2 (BSD) or Valkey (BSD) |
| Ollama | MIT | Local LLM runtime |
| MinIO | AGPL-3.0 | S3-compatible object storage |
| Prometheus | Apache-2.0 | Metrics |
| Grafana | AGPL-3.0 | Dashboards |
| Redpanda | BSL 1.1 (community) | Kafka-compatible (evaluate license) |

> **License note on Redis:** Redis 7.4+ uses SSPL. Use Redis 7.2 (BSD-3) or Valkey (BSD-3 fork) for fully open-source compliance.

> **License note on Redpanda:** Redpanda Community uses BSL 1.1 (converts to Apache-2.0 after 4 years). For development, Redis Streams may suffice; Redpanda/Kafka only needed at scale.

> **License note on MinIO:** AGPL-3.0 requires source disclosure if modified and served over network. For internal self-hosted use, this is typically acceptable.

---

## 22. Local Zero-Mandatory-Cost Deployment Plan

### Development profile

```bash
docker compose --profile dev up -d
```

Required services (all zero license cost):

| Service | Image | RAM | Disk | Port |
|---------|-------|-----|------|------|
| ClickHouse | clickhouse/clickhouse-server | 512MB-2GB | 1GB+ | 8123, 9000 |
| PostgreSQL | postgres:16-alpine | 256MB | 100MB | 5432 |
| Redis | redis:7.2-alpine (BSD) | 64MB | 10MB | 6379 |
| Ollama | ollama/ollama | 2-8GB | 4GB+ (model) | 11434 |
| Prometheus | prom/prometheus | 128MB | 100MB | 9090 |
| Grafana | grafana/grafana-oss | 128MB | 50MB | 3000 |
| Backend | Python FastAPI | 256MB | — | 8000 |
| Frontend | Node/Vite dev server | 128MB | — | 5173 |

**Minimum development machine:** 8GB RAM, 10GB free disk, any modern CPU

**Recommended:** 16GB RAM, SSD, for comfortable Ollama inference

### Optional services (add when needed)

| Service | When needed |
|---------|-------------|
| Redpanda | Event rate exceeds Redis Streams capacity (~100K+ EPS) |
| MinIO | Raw log archival required |
| Go processor | High-throughput parsing/correlation needed |

### Cost breakdown

| Item | Cost |
|------|------|
| Software licenses | $0 |
| AI API keys | $0 (Ollama is local) |
| Cloud services | $0 (self-hosted) |
| **Hardware** | **Existing dev machine** |

> **Honest note:** Zero license/API cost does NOT mean zero cost. CPU/GPU/RAM/storage/network hardware costs money. A machine with 16GB RAM and an SSD is the minimum practical requirement. GPU acceleration (for faster LLM inference) requires a compatible GPU ($200+).

---

## 23. Production Deployment Plan

### Docker Compose production profile

```bash
docker compose --profile prod up -d
```

### Minimum production architecture

```
Load Balancer (nginx/traefik)
     ↓
API (FastAPI × 2-4 workers)
     ↓
Processing Workers (Python)
     ↓
Redis (cache, state, streams)
     ↓
ClickHouse (1 node + 1 replica)
     ↓
PostgreSQL (primary + standby)
     ↓
Ollama / vLLM (AI inference)
     ↓
MinIO (archive)
     ↓
Prometheus + Grafana (observability)
```

### Resource estimates (small production)

| Service | CPU | RAM | Disk | Replicas |
|---------|-----|-----|------|----------|
| API | 2 cores | 2GB | 10GB | 2 |
| ClickHouse | 4 cores | 8GB | 100GB+ | 1+1 replica |
| PostgreSQL | 2 cores | 2GB | 20GB | 1+1 standby |
| Redis | 1 core | 1GB | 1GB | 1 |
| Ollama/vLLM | 4 cores / GPU | 8-16GB | 10GB | 1 |
| MinIO | 1 core | 1GB | storage | 1 |
| Prometheus | 1 core | 2GB | 50GB | 1 |
| Grafana | 0.5 core | 512MB | 1GB | 1 |

**Estimated total:** 16 cores, 32GB RAM, 200GB+ SSD

### Kubernetes

Kubernetes is justified only when:
- Multiple deployment environments require orchestration
- Auto-scaling is needed for variable load
- HA with automatic failover is required

For initial production, Docker Compose with proper health checks, resource limits, and volume persistence is sufficient.

---

## 24. Testing Strategy

### Test categories

| Level | Tool | Purpose | Priority |
|-------|------|---------|----------|
| Unit | pytest | Individual functions, validators, parsers | P0 |
| Integration | pytest + testcontainers | DB operations, API endpoints, auth flows | P0 |
| Detection | pytest | Rule fixtures (event in → expected alert out) | P0 |
| API contract | pytest + OpenAPI | Request/response schema validation | P0 |
| Tenant isolation | pytest | Assert tenant A cannot read tenant B's data | P0 (CI gate) |
| Security | pytest + bandit | Auth bypass, injection, secret leakage | P1 |
| AI evaluation | custom framework | Verdict accuracy, evidence attribution, hallucination | P1 |
| Performance | locust / k6 | EPS throughput, query latency, API response times | P1 |
| E2E | Playwright | Frontend workflows, login, search, investigate | P2 |
| Replay | custom | Historical dataset through full pipeline | P2 |

### CI gates (must pass before merge)

1. All unit and integration tests pass
2. Tenant isolation tests pass
3. Detection fixture tests pass
4. No new security warnings from bandit/semgrep
5. API schema validation passes

---

## 25. AI Architecture

### Core principle: AI is NOT the SIEM

```
1,000,000,000 raw events
        ↓ (deterministic funnel)
1,000 security signals
        ↓ (evidence packaging)
bounded AI context
        ↓ (local LLM investigation)
structured finding with evidence refs
```

### AI provider abstraction

```python
class AIProvider(ABC):
    async def investigate(self, context: InvestigationContext) -> Finding: ...
    async def triage(self, signal: SecuritySignal) -> TriageResult: ...
    async def classify(self, event: NormalizedEvent) -> Classification: ...

class OllamaProvider(AIProvider):
    """Local LLM via Ollama — zero API cost, self-hosted"""
    ...

class CompatibleExternalProvider(AIProvider):
    """Future: OpenAI-compatible API if organization chooses"""
    ...
```

### Model routing

| Task | Model size | Context | Example |
|------|-----------|---------|---------|
| Classification, extraction | Small (1-3B) | 2K tokens | Quick triage, severity classification |
| Standard investigation | Medium (7-13B) | 8K tokens | Timeline generation, correlation explanation |
| Complex reasoning | Large (30B+) | 16K+ tokens | Multi-source incident, ambiguous threats |

### AI security boundaries

- **AI can:** analyze, summarize, correlate, investigate, recommend, explain
- **AI cannot:** delete evidence, modify policy, execute commands, disable infrastructure
- **AI must:** cite evidence, express confidence, identify missing information, fail gracefully
- **AI must NOT:** fabricate users, IPs, CVEs, MITRE techniques, tool results

### Async processing

```
Security Signal
     ↓
AI Job Queue (Redis/Arq)
     ↓
AI Worker (separate process)
     ↓
AI Security Gateway (injection defense, tenant check, audit)
     ↓
Context Compression
     ↓
Model Router → Ollama
     ↓
Structured Finding
     ↓
Store + Notify Analyst
```

AI investigation is asynchronous. Ingestion and detection never wait for AI.

---

## 26. Data-Compression Architecture

### The deterministic funnel

```
Raw events:          1,000,000,000
     ↓ normalization
Normalized:          1,000,000,000
     ↓ filtering (noise, allowlists)
Filtered:              500,000,000
     ↓ deduplication (content hash + window)
Deduplicated:          100,000,000
     ↓ aggregation (count windows, rates)
Aggregated:             10,000,000
     ↓ threshold + baseline detection
Above threshold:         1,000,000
     ↓ correlation (entity, sequence)
Correlated:                100,000
     ↓ security signals
Signals:                     1,000
     ↓ evidence retrieval + ranking
Evidence per signal:           ~50 events
     ↓ context compression
AI context per signal:       ~2-8K tokens

COMPRESSION RATIO: 1,000,000 : 1
```

### Context budget per investigation

| Parameter | Default | Configurable |
|-----------|---------|-------------|
| MAX_EVENTS | 100 | Yes |
| MAX_TOKENS | 8,000 | Yes |
| MAX_ENTITIES | 50 | Yes |
| MAX_TIMELINE_ITEMS | 30 | Yes |
| MAX_IOCS | 20 | Yes |

### Evidence ranking criteria

1. Rare events (first-seen, unusual)
2. Successful state transitions (failed → success)
3. Privilege changes
4. IOC matches
5. Cross-source correlation
6. Temporal proximity to signal
7. Entity overlap with signal

### Compression metrics to track

```
raw_event_count
filtered_event_count
aggregated_event_count
signal_count
evidence_count
context_event_count
context_tokens
signal_to_event_ratio
events_per_signal
tokens_per_signal
```

---

## 27. Risk Assessment

| # | Risk | Impact | Likelihood | Mitigation |
|---|------|--------|-----------|------------|
| 1 | **Scope creep** — 101-section spec tempts building everything at once | Delivery failure | High | Phase-by-phase execution; each phase must be stable before proceeding |
| 2 | **TinyDB data loss** during migration | Lose demo data | Medium | Export before migration; demo data is regenerable anyway |
| 3 | **ClickHouse operational complexity** at small scale | Over-engineering | Medium | Start with single node; cluster only when justified |
| 4 | **Ollama model quality** for security investigation | Poor AI results | Medium | Evaluate multiple models; implement AI evaluation framework; model routing |
| 5 | **Python throughput ceiling** for high-EPS ingestion | Performance limit | Low (initially) | Python is adequate for 10K EPS; add Go only when measured bottleneck |
| 6 | **Breaking existing functionality** during refactor | User-facing regression | Medium | Preserve all existing API contracts; add tests before refactoring |
| 7 | **AGPL dependencies** (MinIO, Grafana) causing licensing concerns | Legal | Low | Self-hosted internal use is typically fine; document distinction |
| 8 | **Redis SSPL** if using Redis 7.4+ | License compliance | Low | Use Redis 7.2 (BSD) or Valkey (BSD fork) |
| 9 | **Single-developer bottleneck** | Slow delivery | High | Prioritize ruthlessly; build foundation first; defer non-essential features |
| 10 | **AI hallucination in security context** | False findings, missed threats | Medium | Structured output contract; confidence states; evidence attribution; human-in-loop |
| 11 | **Prompt injection via malicious logs** | AI control hijack | High | CaMeL-style separation; log content isolation; structured input; no raw log in system prompt |
| 12 | **Hardware cost for local LLM** | Developer experience | Medium | Support CPU-only; small models for triage; GPU optional |

---

## Summary: What to do next

### Immediate actions (Phase 1 — Foundation)

1. Create `docker-compose.yml` with ClickHouse, PostgreSQL, Redis, Ollama
2. Create `.env.example` — externalize ALL configuration
3. Fix critical security issues (JWT secret, WS auth, rate limiting)
4. Add PostgreSQL schema with Alembic migrations
5. Add ClickHouse normalized events table
6. Add structured logging
7. Add health endpoints
8. Add `react` and `react-dom` to frontend package.json
9. Remove dead files (`main.ts`, `counter.ts`, `style.css`, unused deps)
10. Add basic test infrastructure

### What NOT to do yet

- Do not add Redpanda/Kafka (Redis Streams for dev)
- Do not add Neo4j (indexed PostgreSQL relationships first)
- Do not add Kubernetes (Docker Compose first)
- Do not migrate frontend to TypeScript (incremental, later)
- Do not build SOAR (after signals and AI work)
- Do not delete the simulator (preserve for development/testing)
- Do not add Go services (Python first, measure, then optimize)

---

*This assessment was produced by inspecting every file in the AetherGuard--Sentinel repository. No code was modified during this assessment.*
