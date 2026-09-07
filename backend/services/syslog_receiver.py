"""
AetherGuard--Sentinel Syslog Receiver

Receives Syslog over TCP and UDP on port 5514, parses common RFC3164-style
headers plus security key/value pairs, preserves the original raw telemetry,
and converts the event into the canonical OCSFBaseEvent used by the
AetherGuard ingestion pipeline.
"""

import asyncio
import re
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

from backend.core.logging import get_logger
from backend.models.events import OCSFBaseEvent
from backend.services.ingest_service import IngestService

logger = get_logger(__name__)


# Example:
# <134>Sep 07 11:35:20 aetherguard-e2e AetherGuardTest[4242]: ...
SYSLOG_RE = re.compile(
    r"""
    ^
    (?:<(?P<pri>\d{1,3})>)?
    (?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)
    \s+
    (?P<day>\d{1,2})
    \s+
    (?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})
    \s+
    (?P<host>[^\s]+)
    \s+
    (?P<process>[^\s\[:]+)
    (?:\[(?P<pid>\d+)\])?
    :
    \s*
    (?P<body>.*)
    $
    """,
    re.VERBOSE,
)

# Accept common security telemetry forms:
# username=e2e-test
# src_ip=198.51.100.42
# event_type=authentication
# action=login
# result=failure
KV_RE = re.compile(
    r'(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)=(?P<value>"[^"]*"|\'[^\']*\'|\S+)'
)


MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


SEVERITY_BY_FACILITY_LEVEL = {
    0: "Emergency",
    1: "Alert",
    2: "Critical",
    3: "Error",
    4: "Warning",
    5: "Notice",
    6: "Informational",
    7: "Debug",
}


def _parse_priority(priority: Optional[str]) -> Tuple[int, int, str]:
    """
    Syslog PRI = facility * 8 + severity.
    Returns facility, severity_id, severity_name.
    """
    if priority is None:
        return 1, 6, "Informational"

    try:
        pri = int(priority)
    except (TypeError, ValueError):
        return 1, 6, "Informational"

    if pri < 0 or pri > 191:
        return 1, 6, "Informational"

    facility = pri // 8
    severity_id = pri % 8
    severity_name = SEVERITY_BY_FACILITY_LEVEL.get(
        severity_id,
        "Informational",
    )
    return facility, severity_id, severity_name


def _clean_value(value: str) -> str:
    """Remove surrounding single/double quotes from a parsed value."""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _parse_key_values(body: str) -> Dict[str, str]:
    """
    Parse security-oriented key/value pairs from the message body.

    Example:
        event_type=authentication username=e2e-test src_ip=10.0.0.5
    """
    result: Dict[str, str] = {}

    for match in KV_RE.finditer(body):
        key = match.group("key")
        value = _clean_value(match.group("value"))
        result[key] = value

    return result


def _first_nonempty(*values: Optional[str], default: str = "") -> str:
    for value in values:
        if value is not None and str(value).strip():
            return str(value).strip()
    return default


def _derive_class_name(event_type: str, body: str) -> str:
    """
    Convert common event-type values into a readable event class.
    """
    value = event_type.strip().lower()

    mapping = {
        "authentication": "Authentication",
        "auth": "Authentication",
        "login": "Authentication",
        "process": "Process Activity",
        "process_creation": "Process Activity",
        "network": "Network Activity",
        "network_connection": "Network Activity",
        "dns": "DNS Activity",
        "dns_query": "DNS Activity",
        "web": "Web Activity",
        "http": "Web Activity",
        "firewall": "Network Security",
        "ids": "Network Security",
        "ips": "Network Security",
        "file": "File Activity",
        "file_activity": "File Activity",
        "privilege_escalation": "Privilege Escalation",
        "powershell": "Command Execution",
        "command_execution": "Command Execution",
    }

    if value in mapping:
        return mapping[value]

    if value:
        return value.replace("_", " ").strip().title()

    body_lower = body.lower()

    if "failed password" in body_lower or "accepted password" in body_lower:
        return "Authentication"

    if "powershell" in body_lower:
        return "Command Execution"

    if "sudo" in body_lower or "privilege" in body_lower:
        return "Privilege Escalation"

    if "dns" in body_lower:
        return "DNS Activity"

    return "Unknown"


def _derive_category(class_name: str, event_type: str) -> str:
    value = f"{class_name} {event_type}".lower()

    if "auth" in value or "login" in value or "identity" in value:
        return "Identity & Access Management"

    if "process" in value or "command" in value or "powershell" in value:
        return "System Activity"

    if "dns" in value:
        return "Network Activity"

    if "network" in value or "firewall" in value or "ids" in value:
        return "Network Activity"

    if "web" in value or "http" in value:
        return "Application Activity"

    if "file" in value:
        return "File Activity"

    return "Uncategorized"


def _parse_original_timestamp(
    month: str,
    day: str,
    hour: str,
    minute: str,
    second: str,
) -> Optional[str]:
    """
    RFC3164 syslog doesn't carry a year or timezone.

    We use the current UTC year and attach UTC explicitly because the receiver
    must store a valid normalized timestamp. This is intentionally conservative
    and the raw timestamp remains available in original_time/raw_data.
    """
    try:
        now = datetime.now(timezone.utc)
        parsed = datetime(
            year=now.year,
            month=MONTHS[month],
            day=int(day),
            hour=int(hour),
            minute=int(minute),
            second=int(second),
            tzinfo=timezone.utc,
        )

        # Handle year rollover around New Year.
        if parsed > now and parsed.month == 12 and now.month == 1:
            parsed = parsed.replace(year=now.year - 1)

        return parsed.isoformat()
    except (KeyError, ValueError):
        return None


def parse_syslog(line: str, peer_ip: Optional[str]) -> dict:
    """
    Parse a Syslog message into normalized fields while preserving raw input.
    """
    raw = line

    match = SYSLOG_RE.match(line)

    if not match:
        # Even malformed/non-RFC3164 messages should not be discarded.
        kv = _parse_key_values(line)

        event_type = _first_nonempty(
            kv.get("event_type"),
            kv.get("type"),
            default="",
        )

        class_name = _derive_class_name(event_type, line)
        category_name = _derive_category(class_name, event_type)

        return {
            "class_name": class_name,
            "category_name": category_name,
            "severity_id": 6,
            "severity": "Informational",
            "original_time": "",
            "message": raw,
            "raw_data": raw,
            "src_ip": _first_nonempty(
                kv.get("src_ip"),
                kv.get("source_ip"),
                default=peer_ip or "",
            ),
            "dst_ip": _first_nonempty(
                kv.get("dst_ip"),
                kv.get("dest_ip"),
                kv.get("destination_ip"),
                default="",
            ),
            "src_port": _safe_int(
                _first_nonempty(kv.get("src_port"), default="0")
            ),
            "dst_port": _safe_int(
                _first_nonempty(kv.get("dst_port"), default="0")
            ),
            "user_name": _first_nonempty(
                kv.get("username"),
                kv.get("user"),
                kv.get("user_name"),
                default="",
            ),
            "host_name": _first_nonempty(
                kv.get("hostname"),
                kv.get("host"),
                kv.get("host_name"),
                default=peer_ip or "",
            ),
            "process_name": _first_nonempty(
                kv.get("process"),
                kv.get("process_name"),
                default="",
            ),
            "source_log": "syslog",
        }

    groups = match.groupdict()

    facility, severity_id, severity = _parse_priority(groups.get("pri"))

    body = groups.get("body") or ""
    kv = _parse_key_values(body)

    event_type = _first_nonempty(
        kv.get("event_type"),
        kv.get("eventType"),
        kv.get("type"),
        default="",
    )

    class_name = _derive_class_name(event_type, body)
    category_name = _derive_category(class_name, event_type)

    original_time = _parse_original_timestamp(
        groups["month"],
        groups["day"],
        groups["hour"],
        groups["minute"],
        groups["second"],
    )

    src_ip = _first_nonempty(
        kv.get("src_ip"),
        kv.get("source_ip"),
        kv.get("source.ip"),
        default=peer_ip or "",
    )

    dst_ip = _first_nonempty(
        kv.get("dst_ip"),
        kv.get("dest_ip"),
        kv.get("destination_ip"),
        kv.get("destination.ip"),
        default="",
    )

    user_name = _first_nonempty(
        kv.get("username"),
        kv.get("user_name"),
        kv.get("user"),
        kv.get("account"),
        kv.get("account_name"),
        default="",
    )

    host_name = _first_nonempty(
        kv.get("hostname"),
        kv.get("host_name"),
        kv.get("host"),
        default=groups.get("host"),
    )

    process_name = _first_nonempty(
        kv.get("process"),
        kv.get("process_name"),
        default=groups.get("process"),
    )

    src_port = _safe_int(
        _first_nonempty(
            kv.get("src_port"),
            kv.get("source_port"),
            default="0",
        )
    )

    dst_port = _safe_int(
        _first_nonempty(
            kv.get("dst_port"),
            kv.get("destination_port"),
            default="0",
        )
    )

    return {
        "class_name": class_name,
        "category_name": category_name,
        "severity_id": severity_id,
        "severity": severity,
        "original_time": original_time or "",
        "message": raw,
        "raw_data": raw,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "user_name": user_name,
        "host_name": host_name,
        "process_name": process_name,
        "source_log": "syslog",
    }


def _safe_int(value: str) -> int:
    try:
        number = int(value)
        return max(0, min(number, 65535))
    except (TypeError, ValueError):
        return 0


def build_event(line: str, peer_ip: Optional[str]) -> OCSFBaseEvent:
    parsed = parse_syslog(line, peer_ip)

    return OCSFBaseEvent(
        class_name=parsed["class_name"],
        category_name=parsed["category_name"],
        severity_id=parsed["severity_id"],
        severity=parsed["severity"],
        original_time=parsed["original_time"] or None,
        message=parsed["message"],
        raw_data=parsed["raw_data"],
        src_ip=parsed["src_ip"] or None,
        dst_ip=parsed["dst_ip"] or None,
        src_port=parsed["src_port"],
        dst_port=parsed["dst_port"],
        user_name=parsed["user_name"] or None,
        host_name=parsed["host_name"] or None,
        process_name=parsed["process_name"] or None,
        source_log=parsed["source_log"],
    )


class _UDPProtocol(asyncio.DatagramProtocol):
    """Asyncio UDP protocol that forwards datagrams into the same pipeline."""

    def __init__(self, receiver: "SyslogReceiver"):
        self.receiver = receiver
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        sockname = transport.get_extra_info("sockname")
        logger.info("Syslog UDP receiver started", address=sockname)

    def datagram_received(self, data: bytes, addr):
        asyncio.create_task(self.receiver.handle_udp_datagram(data, addr))

    def error_received(self, exc):
        logger.error("Syslog UDP receiver error", error=str(exc))

    def connection_lost(self, exc):
        logger.info(
            "Syslog UDP receiver stopped",
            error=str(exc) if exc else "",
        )


class SyslogReceiver:
    def __init__(
        self,
        app_state=None,
        host: str = "0.0.0.0",
        port: int = 5514,
    ):
        self.app_state = app_state
        self.host = host
        self.port = port
        self.server = None
        self.udp_transport = None

    async def _process_line(self, line: str, peer_ip: Optional[str]):
        if not line:
            return

        try:
            event = build_event(line, peer_ip)

            logger.info(
                "Syslog event normalized",
                source_ip=event.src_ip,
                user_name=event.user_name,
                host_name=event.host_name,
                class_name=event.class_name,
                source_log=event.source_log,
            )

            await IngestService.process_events(
                [event],
                tenant_id="default",
                app_state=self.app_state,
            )
        except Exception as exc:
            # Never let one malformed event kill the listener.
            logger.error(
                "Syslog event processing failed",
                error=str(exc),
                peer_ip=peer_ip,
            )

    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        peer = writer.get_extra_info("peername")
        peer_ip = peer[0] if peer else None

        logger.info(
            "Syslog TCP connection established",
            peer=peer,
        )

        try:
            while True:
                data = await reader.readline()

                if not data:
                    break

                line = data.decode("utf-8", errors="replace").strip()

                if not line:
                    continue

                await self._process_line(line, peer_ip)

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error(
                "Syslog TCP connection error",
                error=str(exc),
                peer=peer,
            )
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

            logger.info(
                "Syslog TCP connection closed",
                peer=peer,
            )

    async def handle_udp_datagram(self, data: bytes, addr):
        peer_ip = addr[0] if addr else None

        try:
            line = data.decode("utf-8", errors="replace").strip()

            if not line:
                return

            await self._process_line(line, peer_ip)

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error(
                "Syslog UDP datagram processing failed",
                error=str(exc),
                peer=addr,
            )

    async def start(self):
        """
        Start both TCP and UDP Syslog listeners on port 5514.
        """
        # TCP
        try:
            self.server = await asyncio.start_server(
                self.handle_client,
                self.host,
                self.port,
            )

            tcp_addrs = ", ".join(
                str(sock.getsockname())
                for sock in (self.server.sockets or [])
            )

            logger.info(
                "Syslog TCP receiver started",
                addresses=tcp_addrs,
            )

        except OSError as exc:
            logger.warning(
                "Syslog TCP receiver could not bind",
                host=self.host,
                port=self.port,
                error=str(exc),
            )

        # UDP
        try:
            loop = asyncio.get_running_loop()

            self.udp_transport, _ = await loop.create_datagram_endpoint(
                lambda: _UDPProtocol(self),
                local_addr=(self.host, self.port),
            )

            logger.info(
                "Syslog UDP receiver started",
                host=self.host,
                port=self.port,
            )

        except OSError as exc:
            logger.warning(
                "Syslog UDP receiver could not bind",
                host=self.host,
                port=self.port,
                error=str(exc),
            )

    async def stop(self):
        """Gracefully stop both TCP and UDP listeners."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.server = None

            logger.info("Syslog TCP receiver stopped")

        if self.udp_transport:
            self.udp_transport.close()
            self.udp_transport = None

            logger.info("Syslog UDP receiver stopped")