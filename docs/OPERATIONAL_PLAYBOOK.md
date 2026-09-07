# AetherGuard--Sentinel — Operational Playbook

This playbook provides operational procedures for deploying, maintaining, monitoring, and operating the **AetherGuard--Sentinel** platform in a SOC environment.

---

## 1. Quick Start & Service Orchestration

### Prerequisites
* **Docker Desktop** (Engine 24.0+, Compose v2)
* **Python 3.11+** (3.13 recommended)
* **Node.js 18+** & npm

### Starting Infrastructure Services
```bash
# Start all containerized dependencies (Postgres, ClickHouse, Redis, Ollama, Prometheus, Grafana)
docker compose up -d

# Verify container health
docker compose ps
```

Expected healthy services:
* `aetherguard-postgres`: port 5432 (PostgreSQL 16)
* `aetherguard-clickhouse`: port 8123 (HTTP) / 9000 (Native)
* `aetherguard-redis`: port 6379 (Redis 7.2)
* `aetherguard-ollama`: port 11434 (Ollama LLM runtime)
* `aetherguard-prometheus`: port 9090 (Prometheus scraper)
* `aetherguard-grafana`: port 3000 (Grafana Dashboard)

### Starting Backend API
```bash
# Windows PowerShell
$env:PYTHONPATH = "."
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload

# Linux / macOS
export PYTHONPATH="."
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

### Starting Frontend UI
```bash
cd frontend
npm install
npm run dev
```
Navigate to: `http://127.0.0.1:5173`

---

## 2. Default Credentials

| Role | Username | Password | Access Level |
| :--- | :--- | :--- | :--- |
| **Admin** | `admin` | `aetherguard2024` | Full Administrative & Rule Control |
| **Analyst** | `analyst` | `sentinel2024` | Triage, Cases, Investigations, Threat Intel |
| **Grafana** | `admin` | `admin` | Metrics and Observability Dashboards |

---

## 3. Telemetry Ingestion Operations

### HTTP OCSF Ingestion (`POST /api/ingest/events`)
Ingest OCSF-compliant event batches securely using the API key:
```bash
curl -X POST "http://127.0.0.1:8000/api/ingest/events" \
  -H "Content-Type: application/json" \
  -H "X-AetherGuard-Key: aetherguard_dev_ingest_key_2024" \
  -d '[
    {
      "class_uid": 4001,
      "class_name": "Authentication",
      "category_uid": 3,
      "category_name": "Identity & Access Management",
      "severity_id": 3,
      "severity": "medium",
      "message": "User failed login attempt",
      "src_ip": "198.51.100.42",
      "user_name": "alice",
      "source_log": "auth_service"
    }
  ]'
```

### Syslog Ingestion (RFC 3164 / 5424)
Send standard syslog messages to the local syslog receiver:
```bash
# Send via UDP/TCP to port 5514
echo "<134>1 2026-09-07T10:00:00Z firewall.corp - - - [security] DROP connection from 192.168.1.50 to port 22" | nc -u -w1 127.0.0.1 5514
```

---

## 4. SOC Analyst Workflow

```
[ Ingested Telemetry ]
          │
          ▼
 [ Pipeline Funnel ] (Deduplication)
          │
          ▼
 [ ClickHouse Cold Store ] ────► [ Detection Engine ]
                                        │ (Rule Match)
                                        ▼
                            [ SecuritySignal (Postgres) ]
                                        │
           ┌────────────────────────────┴────────────────────────────┐
           ▼                                                         ▼
[ Autonomous AI Triage ]                                 [ Real-Time UI Broadcast ]
(Ollama llama3.2:1b)                                             (WebSocket)
           │                                                         │
           ▼                                                         ▼
[ Verdict: MALICIOUS/SUSPICIOUS ] ──────────────► [ Analyst Alert Feed ]
                                                             │
                                                             ▼
                                                    [ Escalate to Case ]
                                                             │
                                                             ▼
                                                [ Case Investigation & Notes ]
                                                             │
                                                             ▼
                                                [ Escalation to Incident / Close ]
```

### 1. Alert Triage
1. Navigate to **Alert Center** (`/alerts`).
2. Filter by severity (`Critical`, `High`) and status (`Unacknowledged`).
3. Click **AI Triage** to trigger local Ollama evaluation.
4. Review the AI verdict badge (`MALICIOUS`, `SUSPICIOUS`, `BENIGN`), confidence, and analysis reasoning.

### 2. Case Escalation
1. Click **+ Case** directly on any high-confidence alert card.
2. The platform automatically creates a tracked Case in `/cases` with the alert signal and evidence linked.
3. Add timeline notes, assign priority, and attach additional signals.

### 3. Detection Rule Management
1. Navigate to **Detection Rules** (`/rules`).
2. Filter rules by MITRE ATT&CK technique or severity.
3. Toggle rule state on/off without restarting the backend.
4. Use the built-in **Rule Test Sandbox** to simulate log events against any rule before enabling it in production.

---

## 5. System Health & Observability

### Health Check Endpoint
```bash
curl http://127.0.0.1:8000/api/health
```
Response:
```json
{
  "status": "healthy",
  "database": {
    "postgres": "healthy",
    "clickhouse": "healthy"
  },
  "redis": "healthy",
  "ai": "healthy",
  "websocket_clients": 0
}
```

### Prometheus Metrics
Exposed at: `http://127.0.0.1:8000/metrics`
Key metrics:
* `aetherguard_events_ingested_total`: Count of ingested logs tagged by `tenant_id` and `source`.
* `aetherguard_signals_created_total`: Count of detections tagged by `tenant_id`, `severity`, and `rule`.
* `aetherguard_ai_investigations_total`: Total AI investigations tagged by `verdict`, `provider`, and `tenant_id`.
* `aetherguard_active_websocket_clients`: Current active analysts on WebSocket bus.
* `aetherguard_ingest_duration_seconds`: Histogram of event normalization & ingestion latency.

### Prometheus & Grafana
* Prometheus UI: `http://localhost:9090`
* Grafana: `http://localhost:3000` (User: `admin` / Password: `admin`)
  * Data source `Prometheus` is automatically provisioned.
