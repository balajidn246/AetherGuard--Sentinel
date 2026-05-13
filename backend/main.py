"""
AetherGuard Sentinel — FastAPI Backend Entry Point
Real-Time Threat Detection & SOC Intelligence Platform
"""
import asyncio
import logging
import os
import sys
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

# ── Path fix so imports work when run from backend/ directory ────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("aetherguard")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup → yield → Shutdown."""
    logger.info("━" * 60)
    logger.info("  🛡️  AetherGuard Sentinel — Starting Up")
    logger.info("━" * 60)

    # 1. Database
    from db.database import init_mongodb, init_tinydb
    mongo_ok = await init_mongodb()
    if not mongo_ok:
        init_tinydb()

    from db.sqlite_db import init_sqlite
    await init_sqlite()

    # 2. Default users
    from services.auth_service import create_default_users
    await create_default_users()

    # 3. ML engines
    from ml.anomaly_detector import AnomalyDetector
    from ml.ueba import UEBAEngine
    from ml.risk_scorer import RiskScorer

    anomaly_detector = AnomalyDetector()
    ueba_engine = UEBAEngine()
    risk_scorer = RiskScorer(ueba_engine, anomaly_detector)

    # 4. WebSocket manager
    from websocket.manager import ConnectionManager
    ws_manager = ConnectionManager()

    # 5. Detection engine
    from detections.engine import DetectionEngine
    detection_engine = DetectionEngine(ws_manager)

    # 6. Log generator + attack simulator
    from simulator.log_generator import LogGenerator
    from simulator.attack_simulator import AttackSimulator

    log_generator = LogGenerator(ws_manager, detection_engine, risk_scorer)
    log_generator.set_ueba(ueba_engine)   # wire UEBA tracking
    attack_simulator = AttackSimulator(log_generator)

    # Attach to app state
    app.state.ws_manager = ws_manager
    app.state.log_generator = log_generator
    app.state.attack_simulator = attack_simulator
    app.state.detection_engine = detection_engine
    app.state.anomaly_detector = anomaly_detector
    app.state.ueba_engine = ueba_engine
    app.state.risk_scorer = risk_scorer

    # 7. Background tasks
    asyncio.create_task(log_generator.start_streaming())
    asyncio.create_task(attack_simulator.run_attack_campaigns())

    logger.info("━" * 60)
    logger.info("  ✅  AetherGuard Sentinel is ONLINE")
    logger.info("  📡  API:       http://localhost:8000")
    logger.info("  📡  WebSocket: ws://localhost:8000/ws")
    logger.info("  📡  API Docs:  http://localhost:8000/docs")
    logger.info("  🔑  admin / aetherguard2024")
    logger.info("  🔑  analyst / sentinel2024")
    logger.info("━" * 60)

    yield

    logger.info("🛑 AetherGuard Sentinel shutting down...")
    log_generator.stop()


# ── FastAPI App ──────────────────────────────────────────────────────────────
app = FastAPI(
    title="AetherGuard Sentinel API",
    description="Enterprise SOC/SIEM Platform — Real-Time Threat Detection",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ──────────────────────────────────────────────────────────────────
from api.routes import auth, dashboard, logs, alerts, incidents, threat_intel, users, reports

app.include_router(auth.router,         prefix="/api/auth",         tags=["Auth"])
app.include_router(dashboard.router,    prefix="/api/dashboard",    tags=["Dashboard"])
app.include_router(logs.router,         prefix="/api/logs",         tags=["Logs"])
app.include_router(alerts.router,       prefix="/api/alerts",       tags=["Alerts"])
app.include_router(incidents.router,    prefix="/api/incidents",    tags=["Incidents"])
app.include_router(threat_intel.router, prefix="/api/threat-intel", tags=["Threat Intel"])
app.include_router(users.router,        prefix="/api/users",        tags=["Users"])
app.include_router(reports.router,      prefix="/api/reports",      tags=["Reports"])


# ── Core Endpoints ───────────────────────────────────────────────────────────
@app.get("/", tags=["Root"])
async def root():
    return {
        "name": "AetherGuard Sentinel",
        "version": "1.0.0",
        "tagline": "Real-Time Threat Detection & SOC Intelligence Platform",
        "status": "operational",
        "docs": "/docs",
    }


@app.get("/api/health", tags=["Health"])
async def health():
    from db.database import USE_MONGO
    return {
        "status": "healthy",
        "database": "mongodb" if USE_MONGO else "tinydb",
        "websocket_clients": getattr(app.state, "ws_manager", None) and app.state.ws_manager.client_count,
    }


@app.get("/api/ueba/users", tags=["UEBA"])
async def ueba_users():
    return app.state.ueba_engine.get_top_risky_users()


@app.get("/api/ueba/user/{username}", tags=["UEBA"])
async def ueba_user(username: str):
    return app.state.ueba_engine.get_user_profile(username)


# ── WebSocket Endpoint ───────────────────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    ws_manager = app.state.ws_manager
    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            await ws_manager.handle_client_message(websocket, data)
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)


# ── Entry point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info",
    )
