![React](https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react)
![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python)



# AetherGuard Sentinel

## Real-Time Threat Detection & SOC Intelligence Platform

### Features
- Real-time log streaming
- SIEM dashboard
- UEBA anomaly detection
- Incident management
- Threat intelligence
- Attack simulation
- Live attack map

### Tech Stack
- React.js
- FastAPI
- MongoDB
- WebSockets
- Scikit-learn

# System Architecture

                    ┌───────────────────────────┐
                    │      SOC Analysts         │
                    │  Security Administrators  │
                    └────────────┬──────────────┘
                                 │
                                 ▼
              ┌─────────────────────────────────┐
              │         React Frontend          │
              │---------------------------------│
              │ • Live Dashboard                │
              │ • Log Explorer                  │
              │ • Incident Management           │
              │ • UEBA Analytics                │
              │ • Reports & Visualizations      │
              └────────────┬────────────────────┘
                           │ REST API / WebSocket
                           ▼
              ┌─────────────────────────────────┐
              │         FastAPI Backend         │
              │---------------------------------│
              │ • JWT Authentication            │
              │ • API Endpoints                 │
              │ • WebSocket Server              │
              │ • RBAC Authorization            │
              │ • Incident Processing           │
              └────────────┬────────────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        ▼                  ▼                  ▼

┌────────────────┐ ┌────────────────┐ ┌─────────────────┐
│ Detection      │ │ UEBA / ML      │ │ Threat Intel    │
│ Engine          │ │ Analytics       │ │ Module          │
│----------------│ │----------------│ │----------------│
│ • Brute Force  │ │ • Isolation    │ │ • IOC Tracking │
│ • Port Scan    │ │   Forest       │ │ • IP Reputation│
│ • Malware      │ │ • Risk Scoring │ │ • Threat Feeds │
│ • PowerShell   │ │ • Anomalies    │ │ • Blacklists   │
└────────┬───────┘ └────────┬───────┘ └────────┬────────┘
         │                  │                  │
         └──────────────────┼──────────────────┘
                            ▼

              ┌─────────────────────────────────┐
              │         Data Layer              │
              │---------------------------------│
              │ • MongoDB / TinyDB              │
              │ • Security Logs                 │
              │ • Alerts & Incidents            │
              │ • User Data                     │
              │ • Threat Intelligence Data      │
              └─────────────────────────────────┘

                            ▲
                            │
              ┌─────────────────────────────────┐
              │       Attack Simulator          │
              │---------------------------------│
              │ • SSH Brute Force              │
              │ • DDoS Simulation              │
              │ • Malware Activity             │
              │ • Port Scanning                │
              │ • Unauthorized Access          │
              └─────────────────────────────────┘




### Installation
```bash
npm install
pip install -r requirements.txt




