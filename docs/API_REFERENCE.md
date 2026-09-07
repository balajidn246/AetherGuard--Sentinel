# AetherGuard--Sentinel — API Reference

Base URL: `http://localhost:8000`  
WebSocket: `ws://localhost:8000/ws`  
Interactive OpenAPI UI: `http://localhost:8000/docs`

---

## Authentication

### User Login (`POST /api/auth/login`)
Authenticates an analyst or admin and returns a JWT access token.

**Request:**
```json
{
  "username": "analyst",
  "password": "sentinel2024"
}
```

**Response (`200 OK`):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "user": {
    "username": "analyst",
    "role": "analyst",
    "full_name": "SOC Analyst",
    "department": "Security Operations"
  }
}
```

### Ingestion Authentication
High-throughput ingestion endpoints authenticate via HTTP header:
```http
X-AetherGuard-Key: aetherguard_dev_ingest_key_2024
```

---

## Endpoints

### 1. Ingestion (`/api/ingest`)

#### `POST /api/ingest/events`
Ingest normalized OCSF event batches into ClickHouse & Detection Pipeline.
* **Headers:** `X-AetherGuard-Key: <key>`
* **Body:** Array of `OCSFBaseEvent` objects.

---

### 2. Cases (`/api/cases`)

* `GET /api/cases/` — List investigation cases (filters: `status`, `priority`, `owner_id`, `skip`, `limit`).
* `POST /api/cases/` — Create new investigation case.
* `GET /api/cases/{case_id}` — Retrieve case details with linked signals and evidence.
* `PATCH /api/cases/{case_id}` — Update case metadata (status, priority, owner, description).
* `POST /api/cases/{case_id}/notes` — Add analyst investigation note.
* `POST /api/cases/{case_id}/signals?signal_id={signal_id}` — Attach security signal to case.

---

### 3. Detection Rules (`/api/rules`)

* `GET /api/rules/` — List all registered detection rules.
* `GET /api/rules/{rule_id}` — Get rule details by UUID or rule ID.
* `PATCH /api/rules/{rule_id}/enable` — Toggle rule enabled/disabled state (`{"enabled": true/false}`).
* `POST /api/rules/{rule_id}/test` — Test a sample event payload against the rule sandbox.
* `POST /api/rules/` — Create a custom detection rule (Admin only).

---

### 4. Audit Trail (`/api/audit`)

* `GET /api/audit/` — Query immutable audit log records (Admin only).
  * Params: `action`, `actor_username`, `resource`, `skip`, `limit`.
* `GET /api/audit/actions` — Distinct list of recorded audit action names.

---

### 5. Threat Intelligence (`/api/threat-intel`)

* `GET /api/threat-intel/iocs` — List active IOC indicators.
* `POST /api/threat-intel/iocs` — Register new IOC indicator.
* `DELETE /api/threat-intel/iocs/{id}` — Deactivate IOC indicator.
* `GET /api/threat-intel/ip-reputation/{ip}` — Look up IP risk score and GeoIP metadata.
* `POST /api/threat-intel/sync` — Synchronize threat feeds (CISA Known Exploited Vulnerabilities).

---

### 6. User Entity Behavior Analytics (`/api/ueba`)

* `GET /api/ueba/users` — List user behavioral risk profiles with anomaly scores.
* `GET /api/ueba/user/{username}` — Get comprehensive behavioral baseline for a specific user.

---

### 7. Signals & AI Triage (`/api/signals`)

* `POST /api/signals/{signal_id}/investigate` — Trigger AI investigation through the AI Security Gateway.
* `GET /api/signals/ai-health` — Check status of local Ollama runtime and active model.

---

### 8. System & Health

* `GET /api/health` — Platform health check (PostgreSQL, ClickHouse, Redis, Ollama, WebSocket).
* `GET /metrics` — Prometheus OpenMetrics formatted stream.
