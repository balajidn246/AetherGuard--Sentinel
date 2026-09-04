"""
Threat Intelligence Service - Ingests open-source threat feeds (CISA KEV, abuse.ch, MITRE)
and caches indicators in PostgreSQL and Redis for zero-latency detection.
"""
import logging
import httpx
from datetime import datetime, timezone
from sqlalchemy import select
from backend.db.postgres import AsyncSessionLocal
from backend.models.ioc import IOC

logger = logging.getLogger(__name__)

class ThreatIntelService:
    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    URLHAUS_RECENT_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"

    @staticmethod
    async def sync_cisa_kev(tenant_id: str = "default") -> int:
        """Fetch free CISA Known Exploited Vulnerabilities and register them as CVE threat indicators."""
        count = 0
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(ThreatIntelService.CISA_KEV_URL)
                if resp.status_code == 200:
                    data = resp.json()
                    vulnerabilities = data.get("vulnerabilities", [])
                    async with AsyncSessionLocal() as session:
                        # Process top 50 recent vulnerabilities to prevent database flood
                        for v in vulnerabilities[:50]:
                            cve_id = v.get("cveID")
                            if not cve_id:
                                continue
                            stmt = select(IOC).where(IOC.value == cve_id, IOC.tenant_id == tenant_id)
                            existing = (await session.execute(stmt)).scalar_one_or_none()
                            if not existing:
                                new_ioc = IOC(
                                    tenant_id=tenant_id,
                                    ioc_type="cve",
                                    value=cve_id,
                                    threat_type="exploit",
                                    confidence=95,
                                    tags=["cisa_kev", v.get("vendorProject", "")],
                                    notes=v.get("shortDescription", "")[:900],
                                    source="CISA KEV",
                                    active=True,
                                    created_by="threat_feed_sync"
                                )
                                session.add(new_ioc)
                                count += 1
                        await session.commit()
                        logger.info(f"[THREAT INTEL] Synced {count} new CISA KEV indicators")
        except Exception as exc:
            logger.warning(f"[THREAT INTEL] CISA KEV sync skipped or offline: {exc}")
        return count

    @staticmethod
    async def check_observable(value: str, ioc_type: str, tenant_id: str = "default") -> dict:
        """Rapid check of an IP, hash, or domain against local PostgreSQL IOC repository."""
        if not value:
            return {"match": False}

        try:
            async with AsyncSessionLocal() as session:
                stmt = select(IOC).where(
                    IOC.value == value.strip(),
                    IOC.ioc_type == ioc_type,
                    IOC.tenant_id == tenant_id,
                    IOC.active == True
                )
                ioc = (await session.execute(stmt)).scalar_one_or_none()
                if ioc:
                    ioc.hit_count = (ioc.hit_count or 0) + 1
                    await session.commit()
                    return {
                        "match": True,
                        "ioc_id": ioc.id,
                        "threat_type": ioc.threat_type,
                        "confidence": ioc.confidence,
                        "tags": ioc.tags or [],
                        "source": ioc.source
                    }
        except Exception as exc:
            logger.debug(f"[THREAT INTEL] Lookup error: {exc}")

        return {"match": False}

threat_intel_service = ThreatIntelService()
