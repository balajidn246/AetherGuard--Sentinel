# AetherGuard Sentinel

![Status](https://img.shields.io/badge/status-production--ready-brightgreen)
![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python)
![React](https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react)
![TailwindCSS](https://img.shields.io/badge/TailwindCSS-06B6D4?style=for-the-badge&logo=tailwindcss)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-336791?style=for-the-badge&logo=postgresql)
![ClickHouse](https://img.shields.io/badge/ClickHouse-FFCC00?style=for-the-badge&logo=clickhouse&logoColor=black)
![Redis](https://img.shields.io/badge/Redis-DC382D?style=for-the-badge&logo=redis&logoColor=white)
![Prometheus](https://img.shields.io/badge/Prometheus-E6522C?style=for-the-badge&logo=prometheus)
![Ollama](https://img.shields.io/badge/Ollama-llama3.2:1b-white?style=for-the-badge)

A  integrated, production-oriented open-source Cybersecurity Operations Platform (SIEM / UEBA / SOAR) powered by local LLM reasoning.

---

## Architecture

```
                                   [ Telemetry Ingestion ]
                        (Syslog RFC 3164/5424 | HTTP OCSF Ingest)
                                            │
                                            ▼
                                [ Pipeline Funnel & Dedup ]
                                            │
                    ┌───────────────────────┴───────────────────────┐
                    ▼                                               ▼
         [ ClickHouse Cold Store ]                     [ Hybrid Detection Engine ]
      (Columnar Analytic Event Logs)                    (Stateful Python + YAML Rules)
                                                                    │
                                                                    ▼
                                                       [ PostgreSQL Relational Core ]
                                                      (Signals, Cases, Audits, UEBA)
                                                                    │
                                            ┌───────────────────────┴───────────────────────┐
                                            ▼                                               ▼
                              [ AI Security Gateway ]                           [ WebSocket Bus ]
                            (Secret Scrub / Ollama 1B)                                  │
                                            │                                           ▼
                                            └───────────────────────────────► [ React 19 Frontend ]
                                                                                (Live Threat Center)
```

---

## Core Capabilities

* **Real Telemetry Pipeline**: RFC 3164/5424 Syslog receiver (`:5514`) and high-throughput OCSF batch ingestion.
* **Dual Database Architecture**:
  * **ClickHouse**: Petabyte-scale columnar storage for raw security events with skipping indexes on `src_ip`, `user_name`, and `host_name`.
  * **PostgreSQL 16**: Relational storage for security signals, cases, detection rules, UEBA snapshots, and immutable audit trails.
* **Autonomous AI Triage**: Local LLM reasoning (`llama3.2:1b` via Ollama) with strict PII/secret scrubbing, prompt injection defense, and schema validation.
* **SOAR Playbooks**: Automated and analyst-gated containment actions (e.g. host isolation, credential revocation, IP blocking).
* **Incident & Case Management**: End-to-end investigation workspace with signal attachment, chronological notes, and status lifecycle.
* **Stateful UEBA Engine**: Hourly user profiling, statistical deviation detection, and PostgreSQL historical persistence.
* **Observability**: Native `/metrics` endpoint with Prometheus counters/histograms and pre-provisioned Grafana datasources.

---

## Quick Start

### 1. Prerequisites
* [Docker Desktop](https://www.docker.com/) (Engine 24+)
* Python 3.11+
* Node.js 18+
* [Ollama](https://ollama.ai/) with `llama3.2:1b` pulled (`ollama pull llama3.2:1b`)

### 2. Clone Repository
```bash
git clone https://github.com/balajidn246/AetherGuard--Sentinel.git
cd AetherGuard--Sentinel
```

### 3. Launch Infrastructure & Backend
```bash
# Start Docker infrastructure (Postgres, ClickHouse, Redis, Prometheus, Grafana)
docker compose up -d

# Start Backend API & Syslog Receiver
# (Windows PowerShell)
$env:PYTHONPATH = "."
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload

# (Linux / macOS)
export PYTHONPATH="."
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

Backend runs on: `http://localhost:8000` (Syslog listener on UDP/TCP port `5514`).

### 4. Launch Frontend UI
```bash
cd frontend
npm install
npm run dev
```

Frontend runs on: `http://localhost:5173`.

---

## Default Credentials

| Service | Username | Password | Role |
| :--- | :--- | :--- | :--- |
| **SOC Platform** | `admin` | `aetherguard2024` | System Administrator |
| **SOC Platform** | `analyst` | `sentinel2024` | Security Analyst |
| **Grafana** | `admin` | `admin` | Observability Admin |

---

## Verification & Testing

Run the automated test suites to verify end-to-end integrity:

```powershell
$env:PYTHONPATH = "."

# Phase 6 Unit Tests (12/12 passing)
python backend/tests/test_phase6_unit.py

# Phase 2 Backend Expansion Tests (5/5 passing)
python backend/tests/test_phase2_expansion.py

# Production End-to-End Test (7/7 passing with live Ollama AI)
python backend/tests/test_production_e2e.py

# Full SOC Syslog-to-Case Workflow Test (7/7 passing)
python backend/tests/test_full_soc_workflow.py
```

---

## Troubleshooting

### Port Already In Use
Kill conflicting processes:

#### Windows
```powershell
taskkill /F /IM python.exe
taskkill /F /IM node.exe
```

#### Linux / macOS
```bash
killall -9 python python3 node
```

---

## Documentation

* [Operational Playbook](docs/OPERATIONAL_PLAYBOOK.md) — Day-to-day SOC procedures, ingestion instructions, and health checks.
* [API Reference](docs/API_REFERENCE.md) — Comprehensive OpenAPI and WebSocket specifications.
* [Detection Engine Guide](docs/DETECTION_ENGINE_GUIDE.md) — Rule authoring, sliding window configuration, and MITRE mapping.
* [Architecture Assessment](docs/ARCHITECTURE_ASSESSMENT.md) — Full technical audit and architectural breakdown.
* [Feature Comparison](docs/FEATURE_COMPARISON.md) — Comparison against Wazuh and Elastic Security.

---

## License
[Apache 2.0](LICENSE)
