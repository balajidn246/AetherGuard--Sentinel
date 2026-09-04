"""
Log search and query routes - REAL queries to ClickHouse OCSF events table.
Server-side pagination, full-text filtering, real data.
"""
from typing import Optional
from fastapi import APIRouter, Depends, Query
from api.middleware.auth import get_current_user
from backend.db.clickhouse import get_clickhouse

router = APIRouter()

@router.get("/search")
async def search_logs(
    q: Optional[str] = Query(None, description="Full-text keyword search"),
    severity: Optional[str] = Query(None),
    hostname: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
    destination_ip: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    log_source: Optional[str] = Query(None),
    limit: int = Query(50, le=500),
    skip: int = Query(0),
    current_user: dict = Depends(get_current_user),
):
    tenant_id = current_user.get("tenant_id", "default")
    logs_list = []
    total = 0

    ch_client = get_clickhouse()
    if not ch_client:
        return {"logs": [], "total": 0, "limit": limit, "skip": skip, "warning": "ClickHouse is currently offline"}

    conditions = ["tenant_id = {t:String}"]
    params = {"t": tenant_id}

    if severity:
        conditions.append("lower(severity) = {sev:String}")
        params["sev"] = severity.lower()
    if hostname:
        conditions.append("host_name = {host:String}")
        params["host"] = hostname
    if source_ip:
        conditions.append("src_ip = {sip:String}")
        params["sip"] = source_ip
    if destination_ip:
        conditions.append("dst_ip = {dip:String}")
        params["dip"] = destination_ip
    if event_type:
        conditions.append("lower(class_name) = {et:String}")
        params["et"] = event_type.lower()
    if log_source:
        conditions.append("source_log = {ls:String}")
        params["ls"] = log_source
    if q:
        conditions.append("(positionCaseInsensitive(message, {kw:String}) > 0 OR positionCaseInsensitive(raw_data, {kw:String}) > 0)")
        params["kw"] = q

    where_clause = " AND ".join(conditions)

    try:
        # Total count query (server-side)
        count_sql = f"SELECT count() FROM events WHERE {where_clause}"
        count_res = ch_client.query(count_sql, parameters=params)
        if count_res.result_rows:
            total = count_res.result_rows[0][0]

        # Paginated fetch query
        fetch_sql = f"""
        SELECT
            toString(event_id) AS id,
            formatDateTime(time, '%Y-%m-%dT%H:%M:%SZ') AS timestamp,
            class_name,
            category_name,
            severity,
            message,
            raw_data,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            user_name,
            host_name,
            process_name,
            file_hash,
            source_log
        FROM events
        WHERE {where_clause}
        ORDER BY time DESC
        LIMIT {limit} OFFSET {skip}
        """
        rows = ch_client.query(fetch_sql, parameters=params)

        for r in rows.result_rows:
            logs_list.append({
                "_id": r[0],
                "id": r[0],
                "timestamp": r[1],
                "created_at": r[1],
                "event_type": r[2],
                "category": r[3],
                "severity": r[4],
                "message": r[5],
                "raw_log": r[6],
                "source_ip": r[7],
                "dest_ip": r[8],
                "src_port": r[9],
                "dst_port": r[10],
                "username": r[11],
                "hostname": r[12],
                "process_name": r[13],
                "file_hash": r[14],
                "log_source": r[15]
            })
    except Exception as e:
        return {"logs": [], "total": 0, "limit": limit, "skip": skip, "error": str(e)}

    return {"logs": logs_list, "total": total, "limit": limit, "skip": skip}


@router.get("/stats")
async def log_stats(current_user: dict = Depends(get_current_user)):
    """Return real log aggregation metrics from ClickHouse."""
    tenant_id = current_user.get("tenant_id", "default")
    ch_client = get_clickhouse()
    
    total = 0
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    by_source = {}
    by_event_type = {}

    if ch_client:
        try:
            # Total count
            r_tot = ch_client.query("SELECT count() FROM events WHERE tenant_id = {t:String}", parameters={"t": tenant_id})
            if r_tot.result_rows:
                total = r_tot.result_rows[0][0]

            # Severity breakdown
            r_sev = ch_client.query("SELECT lower(severity), count() FROM events WHERE tenant_id = {t:String} GROUP BY lower(severity)", parameters={"t": tenant_id})
            for row in r_sev.result_rows:
                by_severity[str(row[0]).lower()] = row[1]

            # Source breakdown
            r_src = ch_client.query("SELECT source_log, count() FROM events WHERE tenant_id = {t:String} GROUP BY source_log", parameters={"t": tenant_id})
            for row in r_src.result_rows:
                by_source[str(row[0])] = row[1]

            # Event type breakdown
            r_et = ch_client.query("SELECT class_name, count() FROM events WHERE tenant_id = {t:String} GROUP BY class_name", parameters={"t": tenant_id})
            for row in r_et.result_rows:
                by_event_type[str(row[0])] = row[1]
        except Exception:
            pass

    return {
        "total": total,
        "by_severity": by_severity,
        "by_source": by_source,
        "by_event_type": by_event_type,
    }


@router.get("/live")
async def get_live_logs(
    limit: int = Query(50, le=200),
    current_user: dict = Depends(get_current_user),
):
    """Return latest real events from ClickHouse for live stream initial load."""
    tenant_id = current_user.get("tenant_id", "default")
    ch_client = get_clickhouse()
    logs_list = []

    if ch_client:
        try:
            query = f"""
            SELECT
                toString(event_id) AS id,
                formatDateTime(time, '%Y-%m-%dT%H:%M:%SZ') AS timestamp,
                class_name,
                severity,
                message,
                src_ip,
                dst_ip,
                host_name,
                source_log
            FROM events
            WHERE tenant_id = {{t:String}}
            ORDER BY time DESC
            LIMIT {limit}
            """
            rows = ch_client.query(query, parameters={"t": tenant_id})
            for r in rows.result_rows:
                logs_list.append({
                    "id": r[0],
                    "_id": r[0],
                    "timestamp": r[1],
                    "created_at": r[1],
                    "event_type": r[2],
                    "severity": r[3],
                    "message": r[4],
                    "source_ip": r[5],
                    "dest_ip": r[6],
                    "hostname": r[7],
                    "log_source": r[8]
                })
        except Exception:
            pass

    return logs_list


@router.get("/sources")
async def get_log_sources(current_user: dict = Depends(get_current_user)):
    """Return active distinct log sources observed in ClickHouse."""
    tenant_id = current_user.get("tenant_id", "default")
    ch_client = get_clickhouse()
    sources = []

    if ch_client:
        try:
            r = ch_client.query("SELECT DISTINCT source_log FROM events WHERE tenant_id = {t:String}", parameters={"t": tenant_id})
            sources = [row[0] for row in r.result_rows if row[0]]
        except Exception:
            pass

    if not sources:
        sources = ["syslog", "api", "api_raw"]

    return sources
