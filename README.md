![React](https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react)
![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python)
![TailwindCSS](https://img.shields.io/badge/TailwindCSS-06B6D4?style=for-the-badge&logo=tailwindcss)
![MongoDB](https://img.shields.io/badge/MongoDB-4EA94B?style=for-the-badge&logo=mongodb)
![WebSockets](https://img.shields.io/badge/WebSockets-000000?style=for-the-badge)



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
# Installation Guide

## Prerequisites

Make sure the following are installed:

- Python 3.10+
- Node.js 18+
- npm
- Git

Optional:
- MongoDB (TinyDB fallback supported)

---

# Clone Repository

```bash
git clone https://github.com/balajidn246/AetherGuard--Sentinel.git
cd AetherGuard--Sentinel
```

---

# Backend Setup

```bash
cd backend
```

## Create Virtual Environment

### Windows
```bash
python -m venv venv
venv\Scripts\activate
```

### Linux/macOS
```bash
python3 -m venv venv
source venv/bin/activate
```

---

## Install Python Dependencies

```bash
pip install -r requirements.txt
```

---

## Start Backend Server

```bash
python main.py
```

Backend runs on:

```text
http://localhost:8000
```

---

# Frontend Setup

Open a NEW terminal:

```bash
cd frontend
```

---

## Install Frontend Dependencies

```bash
npm install
```

---

## Start Frontend

```bash
npm run dev
```

Frontend runs on:

```text
http://localhost:5173
```

---

# Default Login Credentials

## Admin
```text
Username: admin
Password: admin123
```

## Analyst
```text
Username: analyst
Password: analyst123
```

---

# Features Included

- Real-time WebSocket log streaming
- Threat detection engine
- UEBA anomaly analytics
- Incident response workflow
- Splunk-style log explorer
- Attack simulation engine
- JWT authentication
- SOC dashboard analytics

---

# Troubleshooting

## Port Already In Use

Kill running processes:

### Windows
```powershell
taskkill /F /IM python.exe
taskkill /F /IM node.exe
```

---

## Reinstall Frontend Packages

```bash
npm install
```

---

## Reinstall Backend Packages

```bash
pip install -r requirements.txt --force-reinstall
```

---

# Production Notes

This project is designed as an enterprise-style SOC/SIEM simulation platform for cybersecurity learning, research, and portfolio demonstration.


