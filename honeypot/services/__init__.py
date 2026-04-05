"""Base honeypot service with common session/logging helpers."""

import asyncio
import logging
import uuid
from abc import ABC, abstractmethod
from datetime import datetime

from ..models import Event, EventType, Session


class BaseHoneypotService(ABC):
    """Abstract base class for honeypot services."""

    service_name: str = "unknown"

    def __init__(self, config, database, alert_engine, geo_locator):
        self.config = config
        self.db = database
        self.alerts = alert_engine
        self.geo = geo_locator
        self.logger = logging.getLogger(f"honeypot.{self.service_name}")
        self._server = None
        self._active_tasks: set[asyncio.Task] = set()

    @abstractmethod
    async def start(self):
        """Start the service."""

    def _tracked_handler(self, handler):
        """Return a wrapper that tracks each client connection as a task."""
        async def wrapper(reader, writer):
            task = asyncio.current_task()
            self._active_tasks.add(task)
            try:
                await handler(reader, writer)
            except asyncio.CancelledError:
                pass
            finally:
                self._active_tasks.discard(task)
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
        return wrapper

    async def stop(self):
        """Stop the service and cancel active client connections."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        # Cancel all active client handler tasks
        for task in list(self._active_tasks):
            task.cancel()
        if self._active_tasks:
            await asyncio.gather(*self._active_tasks, return_exceptions=True)
            self.logger.info("%s service stopped (%d connections closed)",
                             self.service_name.upper(), len(self._active_tasks))
        else:
            self.logger.info("%s service stopped", self.service_name.upper())
        self._active_tasks.clear()

    async def _create_session(self, src_ip: str, src_port: int, dst_port: int, **metadata) -> Session:
        session = Session(
            id=str(uuid.uuid4()),
            service=self.service_name,
            src_ip=src_ip,
            src_port=src_port,
            dst_port=dst_port,
            metadata=metadata,
        )
        await self.db.save_session(session)
        self.logger.info("[%s] New session from %s:%d", session.id[:8], src_ip, src_port)

        # Log connection event
        await self._log(session, EventType.CONNECTION, {
            "message": f"New {self.service_name.upper()} connection"
        })

        # Background geo lookup
        asyncio.create_task(self.geo.lookup(src_ip))

        return session

    async def _end_session(self, session: Session):
        session.ended_at = datetime.utcnow().isoformat()
        await self.db.save_session(session)
        await self._log(session, EventType.DISCONNECT, {
            "message": f"{self.service_name.upper()} session ended"
        })

    async def _log(self, session: Session, event_type: EventType | str, data: dict) -> Event:
        if isinstance(event_type, EventType):
            event_type = event_type.value
        event = Event(
            session_id=session.id,
            event_type=event_type,
            service=self.service_name,
            src_ip=session.src_ip,
            data=data,
        )
        event = await self.db.save_event(event)
        # Process through alert engine
        await self.alerts.process_event(event)
        return event
