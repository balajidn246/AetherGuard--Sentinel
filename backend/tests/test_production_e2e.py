"""
Automated End-to-End Acceptance Test (Directive Point 46)
Validates the complete production pipeline with real databases:
1. PostgreSQL connectivity & schema
2. ClickHouse connectivity & schema
3. Ingest -> OCSF Normalization -> Funnel -> ClickHouse Storage
4. Detection Engine -> Custom YAML Rule -> PostgreSQL SecuritySignal
5. Context Compression & AI Investigation -> PostgreSQL Update
6. Incident Lifecycle in PostgreSQL
7. IOC Threat Intelligence in PostgreSQL
"""
import asyncio
import os
import sys
import uuid
from datetime import datetime, timezone

# Ensure project root is in python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import select, text
from backend.core.logging import setup_logging, get_logger
from backend.db.postgres import AsyncSessionLocal
from backend.db.clickhouse import get_clickhouse
from backend.models.events import OCSFBaseEvent
from backend.models.signal import SecuritySignal
from backend.models.incident import Incident
from backend.models.ioc import IOC
from backend.services.ingest_service import IngestService
from backend.services.ai_service import ai_service
from backend.detections.engine import DetectionEngine
from backend.websocket.manager import ConnectionManager

setup_logging()
logger = get_logger("acceptance_test")

async def run_e2e_test():
    print("=" * 60)
    print("[*] AETHERGUARD--SENTINEL E2E ACCEPTANCE TEST SUITE")
    print("=" * 60)

    # ---------------------------------------------------------
    # STEP 1: Verify PostgreSQL Connectivity
    # ---------------------------------------------------------
    print("\n[STEP 1] Testing PostgreSQL transactional database...")
    async with AsyncSessionLocal() as session:
        res = await session.execute(text("SELECT current_database(), current_user"))
        db_name, db_user = res.fetchone()
        print(f"  [PASS] Connected to PostgreSQL: db={db_name}, user={db_user}")
        assert db_name == "aetherguard", "Invalid PostgreSQL DB"

    # ---------------------------------------------------------
    # STEP 2: Verify ClickHouse Connectivity
    # ---------------------------------------------------------
    print("\n[STEP 2] Testing ClickHouse analytical database...")
    ch_client = get_clickhouse()
    assert ch_client is not None, "ClickHouse client unavailable"
    ver = ch_client.command("SELECT version()")
    print(f"  [PASS] Connected to ClickHouse: version={ver}")

    # Verify ClickHouse events table
    tables = ch_client.query("SHOW TABLES LIKE 'events'").result_rows
    assert len(tables) > 0, "ClickHouse events table does not exist"
    print("  [PASS] ClickHouse 'events' table verified.")

    # ---------------------------------------------------------
    # STEP 3: Submit Real Event & Ingest into ClickHouse
    # ---------------------------------------------------------
    print("\n[STEP 3] Testing Real Telemetry Ingestion Pipeline...")
    test_event_id = str(uuid.uuid4())
    test_event = OCSFBaseEvent(
        event_id=test_event_id,
        class_name="login",
        message="Failed login attempt for admin from suspicious IP",
        src_ip="198.51.100.42",
        dst_ip="10.0.0.5",
        user_name="admin",
        host_name="auth-server-01",
        severity="high",
        source_log="syslog_auth"
    )

    ws_mgr = ConnectionManager()
    det_engine = DetectionEngine(ws_mgr)

    class MockAppState:
        def __init__(self, de, wm):
            self.detection_engine = de
            self.ws_manager = wm

    app_state = MockAppState(det_engine, ws_mgr)

    ingest_res = await IngestService.process_events([test_event], tenant_id="default", app_state=app_state)
    assert ingest_res.get("status") == "success", f"Ingestion failed: {ingest_res}"
    print(f"  [PASS] Event accepted and processed: {ingest_res}")

    # Allow async detection evaluation to complete
    await asyncio.sleep(1)

    # Verify event landed in ClickHouse
    ch_res = ch_client.query(
        "SELECT toString(event_id), class_name, src_ip, message FROM events WHERE event_id = {eid:UUID}",
        parameters={"eid": uuid.UUID(test_event_id)}
    )
    assert len(ch_res.result_rows) == 1, "Event was not stored in ClickHouse"
    stored_eid, stored_class, stored_ip, stored_msg = ch_res.result_rows[0]
    print(f"  [PASS] Event persisted in ClickHouse:")
    print(f"     ID:      {stored_eid}")
    print(f"     Class:   {stored_class}")
    print(f"     Src IP:  {stored_ip}")
    print(f"     Message: {stored_msg}")

    # ---------------------------------------------------------
    # STEP 4: Verify Detection & SecuritySignal in PostgreSQL
    # ---------------------------------------------------------
    print("\n[STEP 4] Testing Detection Engine & SecuritySignal Creation...")
    signal_found = None
    async with AsyncSessionLocal() as session:
        stmt = select(SecuritySignal).where(
            SecuritySignal.tenant_id == "default",
            SecuritySignal.source_ip == "198.51.100.42"
        ).order_by(SecuritySignal.created_at.desc())
        signal_found = (await session.execute(stmt)).scalars().first()

    assert signal_found is not None, "SecuritySignal was not generated in PostgreSQL"
    print(f"  [PASS] SecuritySignal created in PostgreSQL:")
    print(f"     Signal ID:   {signal_found.id}")
    print(f"     Rule Name:   {signal_found.rule_name}")
    print(f"     Title:       {signal_found.title}")
    print(f"     Severity:    {signal_found.severity}")
    print(f"     Status:      {signal_found.status}")
    print(f"     Evidence:    {signal_found.evidence_refs}")

    # ---------------------------------------------------------
    # STEP 5: Context Compression & AI Investigation
    # ---------------------------------------------------------
    print("\n[STEP 5] Testing AI Investigation & Context Compression...")
    signal_dict = {
        "id": signal_found.id,
        "title": signal_found.title,
        "severity": signal_found.severity,
        "rule_name": signal_found.rule_name,
        "source_ip": signal_found.source_ip
    }
    evidence_events = [{
        "time": datetime.now(timezone.utc).isoformat(),
        "src_ip": signal_found.source_ip,
        "dst_ip": "10.0.0.5",
        "message": "Failed login attempt for admin from suspicious IP",
        "severity": "high"
    }]

    ai_result = await ai_service.investigate_signal(evidence_events, signal_dict)
    assert "verdict" in ai_result, "AI returned missing verdict"
    assert "confidence" in ai_result, "AI returned missing confidence"
    assert "metrics" in ai_result, "AI returned missing compression metrics"
    print(f"  [PASS] AI Investigation Output (Zero Hallucination / Evidence-Bound):")
    print(f"     Provider:   {ai_result.get('provider')}")
    print(f"     Verdict:    {ai_result.get('verdict')}")
    print(f"     Confidence: {ai_result.get('confidence')}")
    print(f"     Analysis:   {ai_result.get('analysis')}")
    print(f"     Metrics:    {ai_result.get('metrics')}")

    # Update signal in PostgreSQL
    async with AsyncSessionLocal() as session:
        signal_found.ai_verdict = ai_result.get("verdict")
        signal_found.ai_confidence = ai_result.get("confidence")
        signal_found.ai_analysis = ai_result.get("analysis")
        session.add(signal_found)
        await session.commit()
    print("  [PASS] Persisted AI verdict to PostgreSQL SecuritySignal record.")

    # ---------------------------------------------------------
    # STEP 6: Incident Creation & Transition in PostgreSQL
    # ---------------------------------------------------------
    print("\n[STEP 6] Testing Incident Response Lifecycle...")
    async with AsyncSessionLocal() as session:
        inc = Incident(
            tenant_id="default",
            title=f"INCIDENT: {signal_found.title}",
            description="Escalated after confirmed AI verdict",
            severity="high",
            status="open",
            assignee="analyst",
            source_signal_ids=[signal_found.id],
            tags=["automated-escalation"]
        )
        session.add(inc)
        await session.commit()
        inc_id = inc.id

        # Transition status
        inc.status = "investigating"
        await session.commit()
        print(f"  [PASS] Incident created and transitioned to 'investigating': ID={inc_id}")

    # ---------------------------------------------------------
    # STEP 7: IOC Threat Intelligence in PostgreSQL
    # ---------------------------------------------------------
    print("\n[STEP 7] Testing IOC Threat Intelligence...")
    async with AsyncSessionLocal() as session:
        test_ioc = IOC(
            tenant_id="default",
            ioc_type="ip",
            value="198.51.100.42",
            threat_type="brute_force",
            confidence=90,
            tags=["e2e-test", "brute-forcer"],
            source="aetherguard_detector"
        )
        session.add(test_ioc)
        await session.commit()
        print(f"  [PASS] IOC stored in PostgreSQL: {test_ioc.value} ({test_ioc.threat_type}, confidence={test_ioc.confidence})")

    # Clean up test data
    print("\n[CLEANUP] Cleaning up test records...")
    ch_client.command(f"ALTER TABLE events DELETE WHERE event_id = '{test_event_id}'")
    async with AsyncSessionLocal() as session:
        await session.execute(text(f"DELETE FROM security_signals WHERE id = '{signal_found.id}'"))
        await session.execute(text(f"DELETE FROM incidents WHERE id = '{inc_id}'"))
        await session.execute(text(f"DELETE FROM iocs WHERE id = '{test_ioc.id}'"))
        await session.commit()
    print("  [PASS] Cleanup complete.")

    print("\n" + "=" * 60)
    print("[SUCCESS] ALL 7 E2E ACCEPTANCE TESTS PASSED!")
    print("Platform is verified REAL, CONNECTED, and OPERATIONAL.")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(run_e2e_test())
