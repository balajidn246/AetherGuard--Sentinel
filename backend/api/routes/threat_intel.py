"""
Threat Intelligence routes — IOC management, IP reputation, blocklist.
"""
import random
from datetime import datetime
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from api.middleware.auth import get_current_user, require_analyst
from db.database import db_find, db_find_one, db_insert, db_update_one, db_count, db_delete

router = APIRouter()

# Known bad IPs/hashes (simulated threat feed)
THREAT_FEED = {
    "ips": [
        "185.220.101.47", "45.141.84.80", "194.165.16.11", "91.108.4.0",
        "185.220.100.255", "199.195.250.77", "192.42.116.16", "162.247.74.201",
        "104.244.74.55", "185.107.47.215",
    ],
    "hashes": [
        "d41d8cd98f00b204e9800998ecf8427e",
        "5d41402abc4b2a76b9719d911017c592",
        "098f6bcd4621d373cade4e832627b4f6",
        "aab3238922bcc25a6f606eb525ffdc56",
        "9a0364b9e99bb480dd25e1f0284c8555",
    ],
    "domains": [
        "malware-c2.ru", "phishing-site.cn", "exploit-kit.net",
        "botnet-cc.info", "ransomware-dropper.xyz",
    ],
}


class IOCCreate(BaseModel):
    ioc_type: str          # ip | hash | domain | url
    value: str
    threat_type: str = "unknown"   # malware | phishing | c2 | scanner
    confidence: int = 50   # 0-100
    tags: List[str] = []
    notes: str = ""
    source: str = "manual"


@router.get("/iocs")
async def list_iocs(
    ioc_type: Optional[str] = Query(None),
    limit: int = Query(50, le=500),
    skip: int = Query(0),
    current_user: dict = Depends(get_current_user),
):
    query = {}
    if ioc_type:
        query["ioc_type"] = ioc_type
    iocs = await db_find("iocs", query, limit=limit, skip=skip)
    total = await db_count("iocs", query)
    return {"iocs": iocs, "total": total}


@router.post("/iocs")
async def create_ioc(body: IOCCreate, current_user: dict = Depends(require_analyst)):
    ioc = {
        "ioc_type": body.ioc_type,
        "value": body.value,
        "threat_type": body.threat_type,
        "confidence": body.confidence,
        "tags": body.tags,
        "notes": body.notes,
        "source": body.source,
        "active": True,
        "created_by": current_user.get("username"),
        "hit_count": 0,
    }
    ioc_id = await db_insert("iocs", ioc)
    return {"message": "IOC created", "ioc_id": ioc_id}


@router.delete("/iocs/{ioc_id}")
async def delete_ioc(ioc_id: str, current_user: dict = Depends(require_analyst)):
    await db_delete("iocs", {"_id": ioc_id})
    return {"message": "IOC deleted"}


@router.get("/ip-reputation/{ip}")
async def ip_reputation(ip: str, current_user: dict = Depends(get_current_user)):
    """Check IP against threat feeds and IOC database."""
    is_known_bad = ip in THREAT_FEED["ips"]
    ioc_match = await db_find_one("iocs", {"value": ip, "ioc_type": "ip"})

    risk_score = 0
    tags = []
    if is_known_bad:
        risk_score = random.randint(75, 95)
        tags = ["threat_feed_match", "known_malicious"]
    elif ioc_match:
        risk_score = ioc_match.get("confidence", 50)
        tags = ioc_match.get("tags", []) + ["ioc_match"]
    else:
        risk_score = random.randint(5, 25)
        tags = ["clean"]

    return {
        "ip": ip,
        "risk_score": risk_score,
        "is_malicious": is_known_bad or (ioc_match is not None),
        "threat_feed_match": is_known_bad,
        "ioc_match": ioc_match is not None,
        "tags": tags,
        "geo": {
            "country": random.choice(["Russia", "China", "USA", "Germany", "Netherlands", "Unknown"]),
            "city": random.choice(["Moscow", "Beijing", "New York", "Frankfurt", "Amsterdam", "Unknown"]),
            "asn": f"AS{random.randint(1000, 99999)}",
        },
    }


@router.get("/hash/{hash_value}")
async def check_hash(hash_value: str, current_user: dict = Depends(get_current_user)):
    is_known_bad = hash_value in THREAT_FEED["hashes"]
    return {
        "hash": hash_value,
        "is_malicious": is_known_bad,
        "threat_type": "malware" if is_known_bad else "unknown",
        "risk_score": 95 if is_known_bad else 5,
    }


@router.get("/feeds")
async def get_threat_feeds(current_user: dict = Depends(get_current_user)):
    """Simulated threat feed status."""
    return [
        {"name": "AbuseIPDB", "status": "active", "last_updated": "2026-05-08T10:00:00", "ioc_count": 2847291},
        {"name": "AlienVault OTX", "status": "active", "last_updated": "2026-05-08T09:45:00", "ioc_count": 1234567},
        {"name": "VirusTotal", "status": "active", "last_updated": "2026-05-08T09:30:00", "ioc_count": 892341},
        {"name": "Emerging Threats", "status": "active", "last_updated": "2026-05-08T08:00:00", "ioc_count": 445123},
        {"name": "MISP Community", "status": "active", "last_updated": "2026-05-08T07:00:00", "ioc_count": 234567},
    ]


@router.get("/blocklist")
async def get_blocklist(current_user: dict = Depends(get_current_user)):
    iocs = await db_find("iocs", {"active": True}, limit=500)
    return {"blocklist": iocs, "total": len(iocs)}
