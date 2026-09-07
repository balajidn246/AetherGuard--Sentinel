# AetherGuard--Sentinel

![Status](https://img.shields.io/badge/status-production--ready-brightgreen)
![Python](https://img.shields.io/badge/python-3.13-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688)
![React](https://img.shields.io/badge/react-19.2-61dafb)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791)
![ClickHouse](https://img.shields.io/badge/ClickHouse-latest-ffcc00)
![Ollama](https://img.shields.io/badge/Ollama-llama3.2:1b-white)
![Prometheus](https://img.shields.io/badge/Prometheus-metrics-e6522c)

A serious, integrated, production-oriented open-source Cybersecurity Operations Platform (SIEM / UEBA / SOAR) powered by local LLM reasoning.

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

* **Real Telemetry Pipeline**: RFC 3164/5424 Syslog receiver and high-throughput OCSF batch ingestion.
* **Dual Database Architecture**:
  * **ClickHouse**: Petabyte-scale columnar storage for raw security events with skipping indexes on `src_ip`, `user_name`, and `host_name`.
  * **PostgreSQL 16**: Relational storage for security signals, cases, detection rules, UEBA snapshots, and immutable audit trails.
* **Autonomous AI Triage**: Local LLM reasoning (`llama3.2:1b` via Ollama) with strict PII/secret scrubbing, prompt injection defense, and schema validation.
* **Incident & Case Management**: End-to-end investigation workspace with signal attachment, chronological notes, and status lifecycle.
* **Stateful UEBA Engine**: Hourly user profiling, statistical deviation detection, and PostgreSQL historical persistence.
* **Observability**: Native `/metrics` endpoint with Prometheus counters/histograms and pre-provisioned Grafana datasources.

---

## Quick Start

### 1. Prerequisites
* [Docker Desktop](https://www.docker.com/) (Engine 24+)
* Python 3.11+
* Node.js 18+

### 2. Launch Services
```bash
# Start Docker infrastructure (Postgres, ClickHouse, Redis, Ollama, Prometheus, Grafana)
docker compose up -d

# Start Backend API
# (Windows PowerShell)
$env:PYTHONPATH = "."
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload

# (Linux / macOS)
export PYTHONPATH="."
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

### 3. Launch Frontend UI
```bash
cd frontend
npm install
npm run dev
```

Open `http://127.0.0.1:5173` in your browser.

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
Apache 2.0
