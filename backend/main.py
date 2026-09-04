"""
AetherGuard Sentinel - FastAPI Backend Entry Point
Real-Time Threat Detection & SOC Intelligence Platform
"""
import asyncio
import logging
import os
import sys
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends
from fastapi.middleware.cors import CORSMiddleware


# -- Path fix so imports work when run from backend/ directory ----------------
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from backend.core.logging import setup_logging, get_logger
from backend.core.middleware import RequestContextMiddleware
from backend.core.exceptions import AetherGuardError, aetherguard_exception_handler

setup_logging()
logger = get_logger("aetherguard")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup ? yield ? Shutdown."""
    logger.info("=" * 60)
    logger.info("  [*] AetherGuard Sentinel - Starting Up")
    logger.info("=" * 60)

    # 1. Real Databases Startup Validation (Points 2 & 25)
    from backend.db.postgres import AsyncSessionLocal
    from backend.db.clickhouse import ClickHouseClient
    from backend.db.redis import check_redis_health
    from sqlalchemy import text

    try:
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
        logger.info("  [OK] PostgreSQL connected & verified")
    except Exception as exc:
        logger.error(f"  [FAIL] PostgreSQL connection failed: {exc}")

    try:
        ch = ClickHouseClient.get_client()
        if ch:
            ch.command("SELECT 1")
            logger.info("  [OK] ClickHouse connected & verified")
        else:
            logger.warning("  [WARN] ClickHouse client unavailable")
    except Exception as exc:
        logger.error(f"  [FAIL] ClickHouse connection failed: {exc}")

    if await check_redis_health():
        logger.info("  [OK] Redis connected & verified")
    else:
        logger.warning("  [WARN] Redis unavailable")

    # 2. Seed Default Users & Detection Rules in PostgreSQL
    from backend.services.auth_service import create_default_users
    from backend.services.rule_seeder import seed_default_rules
    await create_default_users()
    await seed_default_rules()

    # 3. ML engines
    from ml.anomaly_detector import AnomalyDetector
    from ml.ueba import UEBAEngine
    from ml.risk_scorer import RiskScorer

    anomaly_detector = AnomalyDetector()
    ueba_engine = UEBAEngine()
    await ueba_engine.load_baselines_from_db()
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
    # (Simulators disabled per user request - strict real-time database/API traffic only)
    # asyncio.create_task(log_generator.start_streaming())
    # asyncio.create_task(attack_simulator.run_attack_campaigns())
    
    from backend.services.syslog_receiver import SyslogReceiver
    syslog_receiver = SyslogReceiver(app_state=app.state, port=5514)
    app.state.syslog_receiver = syslog_receiver
    asyncio.create_task(syslog_receiver.start())

    logger.info("=" * 60)
    logger.info("  [ONLINE] AetherGuard Sentinel is READY")
    logger.info("  API:       http://localhost:8000")
    logger.info("  WebSocket: ws://localhost:8000/ws")
    logger.info("  API Docs:  http://localhost:8000/docs")
    logger.info("  admin / aetherguard2024")
    logger.info("  analyst / sentinel2024")
    logger.info("=" * 60)

    yield

    logger.info("[SHUTDOWN] AetherGuard Sentinel shutting down...")
    log_generator.stop()
    if hasattr(app.state, "syslog_receiver"):
        await app.state.syslog_receiver.stop()


# -- FastAPI App --------------------------------------------------------------
app = FastAPI(
    title="AetherGuard Sentinel API",
    description="Enterprise SOC/SIEM Platform - Real-Time Threat Detection",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_exception_handler(AetherGuardError, aetherguard_exception_handler)
app.add_middleware(RequestContextMiddleware)

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

from api.routes import auth, dashboard, logs, alerts, incidents, threat_intel, users, reports, ingest, signals, cases, rules, audit

app.include_router(auth.router,         prefix="/api/auth",         tags=["Auth"])
app.include_router(dashboard.router,    prefix="/api/dashboard",    tags=["Dashboard"])
app.include_router(logs.router,         prefix="/api/logs",         tags=["Logs"])
app.include_router(alerts.router,       prefix="/api/alerts",       tags=["Alerts"])
app.include_router(incidents.router,    prefix="/api/incidents",    tags=["Incidents"])
app.include_router(cases.router,        prefix="/api/cases",        tags=["Cases"])
app.include_router(rules.router,        prefix="/api/rules",        tags=["Detection Rules"])
app.include_router(audit.router,        prefix="/api/audit",        tags=["Audit"])
app.include_router(threat_intel.router, prefix="/api/threat-intel", tags=["Threat Intel"])
app.include_router(users.router,        prefix="/api/users",        tags=["Users"])
app.include_router(reports.router,      prefix="/api/reports",      tags=["Reports"])
app.include_router(ingest.router,       prefix="/api/ingest",       tags=["Ingestion"])
app.include_router(signals.router,      prefix="/api/signals",      tags=["Signals & AI"])



# -- Core Endpoints -----------------------------------------------------------
@app.get("/", tags=["Root"])
async def root():
    return {
        "name": "AetherGuard Sentinel",
        "version": "1.0.0",
        "tagline": "Real-Time Threat Detection & SOC Intelligence Platform",
        "status": "operational",
        "docs": "/docs",
    }


@app.get("/metrics", tags=["Observability"])
async def prometheus_metrics():
    """Exposes Prometheus application metrics for scraping."""
    from backend.core.metrics import get_metrics_response
    return get_metrics_response()



@app.get("/api/health", tags=["Health"])
async def health():
    """Real granular healthcheck distinguishing Application, Database, Queue, and AI health (Point 24)."""
    from backend.db.postgres import AsyncSessionLocal
    from backend.db.clickhouse import ClickHouseClient
    from backend.db.redis import check_redis_health
    from backend.services.ai_service import ai_service
    from sqlalchemy import text

    pg_status = "unavailable"
    try:
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
            pg_status = "healthy"
    except Exception:
        pg_status = "unavailable"

    ch_status = "unavailable"
    try:
        ch = ClickHouseClient.get_client()
        if ch and ch.command("SELECT 1") is not None:
            ch_status = "healthy"
    except Exception:
        ch_status = "unavailable"

    redis_ok = await check_redis_health()
    redis_status = "healthy" if redis_ok else "unavailable"

    ai_ok = await ai_service.check_health()
    ai_status = "healthy" if ai_ok else "unavailable"

    overall_status = "healthy" if (pg_status == "healthy" and ch_status == "healthy") else "degraded"
    if pg_status == "unavailable" and ch_status == "unavailable":
        overall_status = "unhealthy"

    return {
        "status": overall_status,
        "database": {
            "postgres": pg_status,
            "clickhouse": ch_status
        },
        "redis": redis_status,
        "ai": ai_status,
        "websocket_clients": getattr(app.state, "ws_manager", None) and app.state.ws_manager.client_count,
    }


@app.get("/api/ready", tags=["Health"])
async def ready():
    """Readiness probe. If critical databases are down, returns 503 DATABASE_UNAVAILABLE (Point 2)."""
    from backend.db.postgres import AsyncSessionLocal
    from backend.db.clickhouse import ClickHouseClient
    from sqlalchemy import text
    from fastapi.responses import JSONResponse

    pg_healthy = False
    ch_healthy = False
    try:
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
            pg_healthy = True
    except Exception:
        pass

    try:
        ch = ClickHouseClient.get_client()
        if ch and ch.command("SELECT 1") is not None:
            ch_healthy = True
    except Exception:
        pass

    if not pg_healthy or not ch_healthy:
        return JSONResponse(
            status_code=503,
            content={
                "status": "DATABASE_UNAVAILABLE",
                "postgres": "healthy" if pg_healthy else "unavailable",
                "clickhouse": "healthy" if ch_healthy else "unavailable"
            }
        )

    return {"status": "READY", "postgres": "healthy", "clickhouse": "healthy"}


from backend.api.middleware.auth import get_current_user

@app.get("/api/ueba/users", tags=["UEBA"])
async def ueba_users(current_user: dict = Depends(get_current_user)):
    return app.state.ueba_engine.get_top_risky_users()


@app.get("/api/ueba/user/{username}", tags=["UEBA"])
async def ueba_user(username: str, current_user: dict = Depends(get_current_user)):
    return app.state.ueba_engine.get_user_profile(username)



# -- WebSocket Endpoint -------------------------------------------------------
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


# -- Entry point --------------------------------------------------------------
if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info",
    )
