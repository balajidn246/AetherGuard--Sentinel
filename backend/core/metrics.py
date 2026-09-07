"""
Prometheus Observability Instrumentation for AetherGuard Sentinel.
Exposes standard metrics for event ingestion, detection throughput, AI investigations, and active connections.
"""
from prometheus_client import Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST
from fastapi import Response

# 1. Ingestion Metrics
EVENTS_INGESTED = Counter(
    "aetherguard_events_ingested_total",
    "Total security events ingested",
    ["tenant_id", "source"]
)

# 2. Detection Metrics
SIGNALS_CREATED = Counter(
    "aetherguard_signals_created_total",
    "Total security signals created by detection engines",
    ["tenant_id", "severity", "rule"]
)

# 3. AI Investigation Metrics
AI_INVESTIGATIONS = Counter(
    "aetherguard_ai_investigations_total",
    "Total AI investigations executed",
    ["verdict", "provider", "tenant_id"]
)

# 4. Infrastructure & Real-time Metrics
ACTIVE_WS_CLIENTS = Gauge(
    "aetherguard_active_websocket_clients",
    "Number of active WebSocket clients connected to the real-time event bus"
)

INGEST_LATENCY = Histogram(
    "aetherguard_ingest_duration_seconds",
    "Time spent processing and normalizing ingested events",
    ["tenant_id"],
    buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5]
)

def get_metrics_response() -> Response:
    """Renders all Prometheus metrics in open-metrics plain text format."""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
