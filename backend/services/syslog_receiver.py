import asyncio
from backend.core.logging import get_logger
from backend.models.events import OCSFBaseEvent
from backend.services.ingest_service import IngestService

logger = get_logger(__name__)

class SyslogReceiver:
    def __init__(self, app_state=None, host: str = "0.0.0.0", port: int = 5514):
        self.app_state = app_state
        self.host = host
        self.port = port
        self.server = None

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info('peername')
        logger.info("Syslog connection established", peer=peer)
        try:
            while True:
                data = await reader.readline()
                if not data:
                    break
                
                line = data.decode('utf-8', errors='replace').strip()
                if not line:
                    continue
                
                # Basic Syslog to OCSF conversion
                event = OCSFBaseEvent(
                    message=line,
                    raw_data=line,
                    source_log="syslog",
                    src_ip=peer[0] if peer else None
                )
                
                # For local testing, we assume tenant is 'default' on port 5514
                # A production system would use TLS client certs or dedicated ports per tenant
                await IngestService.process_events([event], tenant_id="default", app_state=self.app_state)
        except Exception as e:
            logger.error("Syslog connection error", error=str(e), peer=peer)
        finally:
            writer.close()
            await writer.wait_closed()
            logger.info("Syslog connection closed", peer=peer)

    async def start(self):
        """Starts the async TCP server for Syslog."""
        try:
            self.server = await asyncio.start_server(self.handle_client, self.host, self.port)
            addrs = ', '.join(str(sock.getsockname()) for sock in self.server.sockets)
            logger.info(f"Syslog receiver started on {addrs}")
        except OSError as e:
            logger.warning(f"Syslog receiver could not bind to {self.host}:{self.port} ({e}). Telemetry can still be sent via /api/ingest.")

    async def stop(self):
        """Gracefully shuts down the Syslog server."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            logger.info("Syslog receiver stopped")
