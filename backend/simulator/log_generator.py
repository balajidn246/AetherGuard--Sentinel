"""
Realistic Log Generator — produces authentic Windows, Linux, Firewall,
IDS/IPS, Auth, and Web server log events streamed via WebSocket.
"""
import asyncio
import random
import uuid
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Geo / Network Data
# ---------------------------------------------------------------------------
COUNTRIES = [
    ("Russia", 55.75, 37.61), ("China", 39.90, 116.39),
    ("United States", 37.09, -95.71), ("Germany", 51.16, 10.45),
    ("Netherlands", 52.13, 5.29), ("Brazil", -14.23, -51.93),
    ("Iran", 32.42, 53.68), ("North Korea", 40.33, 127.51),
    ("Romania", 45.94, 24.96), ("Ukraine", 48.37, 31.16),
    ("India", 20.59, 78.96), ("United Kingdom", 55.37, -3.43),
    ("France", 46.22, 2.21), ("Canada", 56.13, -106.34),
    ("Australia", -25.27, 133.77),
]

INTERNAL_IPS = [f"192.168.{random.randint(1,5)}.{random.randint(1,254)}" for _ in range(20)]
HOSTNAMES = [
    "DC01", "DC02", "WEB-SRV-01", "WEB-SRV-02", "DB-SRV-01", "DB-SRV-02",
    "FILE-SRV-01", "MAIL-SRV-01", "PROXY-01", "WORKSTATION-101",
    "WORKSTATION-102", "WORKSTATION-103", "ENDPOINT-HR-01", "ENDPOINT-FIN-01",
    "ENDPOINT-DEV-01", "JUMP-BOX-01", "VPN-GW-01", "FIREWALL-CORE",
    "IDS-SENSOR-01", "LINUX-APP-01",
]

USERNAMES = [
    "jsmith", "mjohnson", "awilliams", "rbrown", "administrator",
    "dbadmin", "svc_backup", "svc_monitor", "guest", "root",
    "ldapuser", "serviceaccount", "chadmin", "analyst01",
]

PROCESSES = [
    "lsass.exe", "svchost.exe", "powershell.exe", "cmd.exe", "wscript.exe",
    "cscript.exe", "mshta.exe", "regsvr32.exe", "certutil.exe", "wmic.exe",
    "net.exe", "whoami.exe", "mimikatz.exe", "rundll32.exe", "explorer.exe",
    "chrome.exe", "nginx", "apache2", "sshd", "systemd",
]

WINDOWS_EVENT_IDS = {
    4624: ("Successful Logon", "info"),
    4625: ("Failed Logon Attempt", "medium"),
    4648: ("Logon With Explicit Credentials", "medium"),
    4672: ("Special Privileges Assigned", "high"),
    4688: ("New Process Created", "low"),
    4698: ("Scheduled Task Created", "medium"),
    4720: ("User Account Created", "high"),
    4728: ("User Added to Privileged Group", "critical"),
    4768: ("Kerberos Authentication", "info"),
    4776: ("NTLM Authentication", "low"),
    7045: ("New Service Installed", "high"),
    1102: ("Audit Log Cleared", "critical"),
}

MITRE_MAPPING = {
    4625: ["T1110", "T1078"],
    4648: ["T1078"],
    4672: ["T1078.002", "T1134"],
    4688: ["T1059", "T1106"],
    4698: ["T1053.005"],
    4720: ["T1136"],
    4728: ["T1098"],
    7045: ["T1543.003"],
    1102: ["T1070.001"],
}


def _random_external_ip():
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def _random_geo():
    country, lat, lon = random.choice(COUNTRIES)
    # Jitter
    lat += random.uniform(-3, 3)
    lon += random.uniform(-3, 3)
    return country, round(lat, 4), round(lon, 4)


def _ts():
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Log builders
# ---------------------------------------------------------------------------

def build_windows_event_log() -> dict:
    event_id, (description, base_severity) = random.choice(list(WINDOWS_EVENT_IDS.items()))
    hostname = random.choice(HOSTNAMES)
    username = random.choice(USERNAMES)
    process = random.choice(PROCESSES)
    src_ip = random.choice(INTERNAL_IPS) if random.random() < 0.6 else _random_external_ip()
    country, lat, lon = _random_geo() if random.random() < 0.4 else (None, None, None)

    raw = (
        f"EventID={event_id} TimeCreated={_ts()} "
        f"Computer={hostname} SubjectUserName={username} "
        f"ProcessName={process} IpAddress={src_ip} "
        f"Workstation={hostname}"
    )

    return {
        "_id": str(uuid.uuid4()),
        "created_at": _ts(),
        "log_source": "windows_event",
        "event_id": event_id,
        "event_type": description.lower().replace(" ", "_"),
        "severity": base_severity,
        "hostname": hostname,
        "username": username,
        "source_ip": src_ip,
        "process": process,
        "message": f"[Windows] {description} | User: {username} | Host: {hostname} | PID: {random.randint(1000,65535)}",
        "raw_log": raw,
        "mitre_techniques": MITRE_MAPPING.get(event_id, []),
        "country": country,
        "geo_lat": lat,
        "geo_lon": lon,
        "anomaly_score": round(random.uniform(0.0, 0.3), 4),
        "risk_score": random.randint(10, 40),
    }


def build_linux_syslog() -> dict:
    hostname = random.choice(HOSTNAMES)
    username = random.choice(USERNAMES)
    src_ip = _random_external_ip() if random.random() < 0.5 else random.choice(INTERNAL_IPS)
    country, lat, lon = _random_geo() if random.random() < 0.5 else (None, None, None)
    severity_choices = ["info", "info", "info", "low", "medium"]
    severity = random.choice(severity_choices)
    facility = random.choice(["auth", "sshd", "kernel", "cron", "sudo", "systemd"])
    messages = [
        f"Accepted password for {username} from {src_ip} port {random.randint(1024,65535)} ssh2",
        f"Failed password for {username} from {src_ip} port {random.randint(1024,65535)} ssh2",
        f"sudo: {username} : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/passwd",
        f"Connection closed by {src_ip} port {random.randint(1024,65535)}",
        f"pam_unix(sshd:auth): authentication failure; user={username}",
        f"New session 42 of user {username}",
        f"session opened for user {username} by (uid=0)",
    ]
    msg = random.choice(messages)
    raw = f"May 8 {datetime.utcnow().strftime('%H:%M:%S')} {hostname} {facility}: {msg}"

    return {
        "_id": str(uuid.uuid4()),
        "created_at": _ts(),
        "log_source": "linux_syslog",
        "event_type": "syslog_event",
        "severity": severity,
        "hostname": hostname,
        "username": username,
        "source_ip": src_ip,
        "facility": facility,
        "message": f"[Linux] {facility}: {msg[:80]}",
        "raw_log": raw,
        "mitre_techniques": [],
        "country": country,
        "geo_lat": lat,
        "geo_lon": lon,
        "anomaly_score": round(random.uniform(0.0, 0.2), 4),
        "risk_score": random.randint(5, 30),
    }


def build_firewall_log() -> dict:
    hostname = "FIREWALL-CORE"
    src_ip = _random_external_ip()
    dst_ip = random.choice(INTERNAL_IPS)
    country, lat, lon = _random_geo()
    action = random.choices(["DENY", "ALLOW", "DENY", "DENY"], weights=[50, 30, 15, 5])[0]
    proto = random.choice(["TCP", "UDP", "ICMP"])
    dst_port = random.choice([22, 23, 25, 53, 80, 443, 445, 3389, 8080, 8443, 3306, 5432, 6379])
    severity = "low" if action == "ALLOW" else random.choice(["medium", "high"])

    raw = (
        f"date={datetime.utcnow().date()} time={datetime.utcnow().strftime('%H:%M:%S')} "
        f"action={action} proto={proto} src={src_ip} dst={dst_ip} "
        f"dport={dst_port} policy=default"
    )

    return {
        "_id": str(uuid.uuid4()),
        "created_at": _ts(),
        "log_source": "firewall",
        "event_type": f"firewall_{action.lower()}",
        "severity": severity,
        "hostname": hostname,
        "source_ip": src_ip,
        "dest_ip": dst_ip,
        "protocol": proto,
        "dest_port": dst_port,
        "action": action,
        "message": f"[Firewall] {action} {proto} {src_ip}→{dst_ip}:{dst_port}",
        "raw_log": raw,
        "mitre_techniques": ["T1071"] if action == "ALLOW" else [],
        "country": country,
        "geo_lat": lat,
        "geo_lon": lon,
        "anomaly_score": round(random.uniform(0.0, 0.4), 4),
        "risk_score": random.randint(10, 60) if action == "DENY" else random.randint(5, 20),
    }


def build_ids_alert() -> dict:
    hostname = "IDS-SENSOR-01"
    src_ip = _random_external_ip()
    dst_ip = random.choice(INTERNAL_IPS)
    country, lat, lon = _random_geo()
    signatures = [
        ("ET SCAN Nmap Scripting Engine", "medium", ["T1046"]),
        ("ET EXPLOIT MS17-010 EternalBlue", "critical", ["T1210"]),
        ("ET MALWARE Cobalt Strike Beacon", "critical", ["T1071.001", "T1055"]),
        ("ET POLICY Telnet Attempt", "low", ["T1021"]),
        ("ET SCAN Port Sweep", "medium", ["T1046"]),
        ("ET TROJAN Metasploit Meterpreter", "critical", ["T1059", "T1071"]),
        ("ET WEB_SERVER SQL Injection Attempt", "high", ["T1190", "T1505.003"]),
        ("ET MALWARE Ransomware Activity", "critical", ["T1486"]),
        ("ET CURRENT_EVENTS Phishing Kit", "high", ["T1566"]),
        ("ET DOS ICMP Flood", "high", ["T1498"]),
    ]
    sig, severity, mitre = random.choice(signatures)

    return {
        "_id": str(uuid.uuid4()),
        "created_at": _ts(),
        "log_source": "ids_ips",
        "event_type": "ids_alert",
        "severity": severity,
        "hostname": hostname,
        "source_ip": src_ip,
        "dest_ip": dst_ip,
        "signature": sig,
        "message": f"[IDS/IPS] {sig} | {src_ip} → {dst_ip}",
        "raw_log": f"[**] {sig} [**] {src_ip}:{random.randint(1024,65535)} -> {dst_ip}:{random.randint(1,1024)}",
        "mitre_techniques": mitre,
        "country": country,
        "geo_lat": lat,
        "geo_lon": lon,
        "anomaly_score": round(random.uniform(0.3, 0.9), 4),
        "risk_score": random.randint(40, 95),
    }


def build_web_server_log() -> dict:
    hostname = random.choice(["WEB-SRV-01", "WEB-SRV-02"])
    src_ip = _random_external_ip()
    country, lat, lon = _random_geo()
    methods = ["GET", "POST", "PUT", "DELETE"]
    paths = [
        "/", "/login", "/admin", "/api/users", "/.env",
        "/wp-admin/", "/../../../etc/passwd", "/api/data?id=1 OR 1=1",
        "/upload", "/api/admin/reset", "/actuator/env",
    ]
    codes = [200, 200, 200, 301, 302, 400, 401, 403, 404, 500]
    method = random.choice(methods)
    path = random.choice(paths)
    code = random.choice(codes)
    severity = "info" if code < 400 else ("medium" if code < 500 else "high")
    if path in ("/.env", "/../../../etc/passwd", "/api/admin/reset"):
        severity = "high"

    raw = f'{src_ip} - - [{datetime.utcnow().strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{method} {path} HTTP/1.1" {code} {random.randint(100,50000)}'

    return {
        "_id": str(uuid.uuid4()),
        "created_at": _ts(),
        "log_source": "web_server",
        "event_type": "http_request",
        "severity": severity,
        "hostname": hostname,
        "source_ip": src_ip,
        "http_method": method,
        "url_path": path,
        "status_code": code,
        "message": f"[Web] {method} {path} → HTTP {code} from {src_ip}",
        "raw_log": raw,
        "mitre_techniques": ["T1190"] if code in (200, 201) and path.startswith("/admin") else [],
        "country": country,
        "geo_lat": lat,
        "geo_lon": lon,
        "anomaly_score": round(random.uniform(0.0, 0.5), 4),
        "risk_score": random.randint(5, 50),
    }


# ---------------------------------------------------------------------------
# Log Generator main class
# ---------------------------------------------------------------------------

LOG_BUILDERS = [
    (build_windows_event_log, 35),
    (build_linux_syslog, 25),
    (build_firewall_log, 20),
    (build_ids_alert, 10),
    (build_web_server_log, 10),
]


class LogGenerator:
    def __init__(self, ws_manager, detection_engine=None, risk_scorer=None):
        self.ws_manager = ws_manager
        self.detection_engine = detection_engine
        self.risk_scorer = risk_scorer
        self._running = False
        self._interval = 0.4   # seconds between log events
        self._ueba = None      # set after startup

    def set_ueba(self, ueba_engine):
        self._ueba = ueba_engine

    def stop(self):
        self._running = False

    async def start_streaming(self):
        from db.database import db_insert
        self._running = True
        logger.info("📡 Log streaming started")

        builders, weights = zip(*LOG_BUILDERS)

        while self._running:
            try:
                builder = random.choices(builders, weights=weights, k=1)[0]
                log = builder()

                # Persist to DB
                await db_insert("logs", log)

                # UEBA — record user behaviour event
                if self._ueba and log.get("username"):
                    self._ueba.record_event(log)

                # Run through detection engine
                if self.detection_engine:
                    await self.detection_engine.evaluate(log)

                # Broadcast via WebSocket
                await self.ws_manager.send_log(log)

            except Exception as exc:
                logger.error(f"Log generator error: {exc}")

            await asyncio.sleep(self._interval + random.uniform(-0.1, 0.2))
