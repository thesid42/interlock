from contextlib import asynccontextmanager
import asyncio
import logging
from datetime import datetime, timezone
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.agent.runner import ReportRunner
from app.api.routes import create_router
from app.api.operations import create_operations_router
from app.config import Settings
from app.core.service import MemGuardService
from app.integrations.akash import AkashClient
from app.integrations.common import IntegrationError, IntegrationUnavailable
from app.integrations.guild import GuildClient
from app.integrations.slack import SlackMCPClient
from app.sandbox import IncidentSandbox
from app.security import SecurityOperations
from app.storage.clickhouse import ClickHouseAnalytics
from app.storage.outbox import OutboxExporter


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_environment()
    service = MemGuardService(settings.database_path)
    akash = AkashClient(settings)
    guild = GuildClient(settings)
    analytics = ClickHouseAnalytics(settings)
    exporter = OutboxExporter(settings.database_path, analytics)
    runner = ReportRunner(service, settings, akash)
    sandbox = IncidentSandbox(settings)
    slack = SlackMCPClient(settings)
    operations = SecurityOperations(service, settings, akash, guild, sandbox, exporter, slack=slack)
    worker_status = {"running": False, "last_tick_at": None, "last_error": None}

    async def work(stop):
        worker_status["running"] = True
        try:
            while not stop.is_set():
                try:
                    await asyncio.to_thread(operations.tick)
                    worker_status["last_tick_at"] = datetime.now(timezone.utc).isoformat()
                    worker_status["last_error"] = None
                except Exception as exc:
                    worker_status["last_error"] = type(exc).__name__
                    logging.getLogger(__name__).warning("Security worker failed: %s", type(exc).__name__)
                try:
                    await asyncio.wait_for(stop.wait(), timeout=max(1, getattr(settings, "security_tick_seconds", 5)))
                except asyncio.TimeoutError:
                    pass
        finally:
            worker_status["running"] = False

    @asynccontextmanager
    async def lifespan(application):
        stop = asyncio.Event()
        worker = asyncio.create_task(work(stop))
        try:
            yield
        finally:
            stop.set()
            await worker
            akash.close()
            sandbox.close()
            guild.close()
            analytics.close()

    application = FastAPI(title="Interlock", version="0.2.0", lifespan=lifespan,
                          description="Local agent-security operations, containment and isolated incident investigation.")
    application.state.service = service
    application.state.operations = operations
    application.state.worker_status = worker_status
    application.include_router(create_router(service, runner, settings, akash, guild, analytics, exporter,
                                            sandbox=sandbox, slack=slack, worker_status=worker_status))
    application.include_router(create_operations_router(operations, akash, settings, guild, sandbox, slack))

    @application.middleware("http")
    async def local_operator_boundary(request: Request, call_next):
        hosts = {"localhost", "127.0.0.1", "::1"}
        if request.url.hostname not in hosts:
            return JSONResponse(status_code=403, content={"detail": "This prototype accepts loopback hosts only"})
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            origin = request.headers.get("origin")
            if origin:
                parsed = urlsplit(origin)
                if parsed.scheme not in {"http", "https"} or parsed.hostname not in hosts:
                    return JSONResponse(status_code=403, content={"detail": "External websites cannot operate this local console"})
            if request.headers.get("sec-fetch-site") == "cross-site":
                return JSONResponse(status_code=403, content={"detail": "Cross-site mutations are not allowed"})
        return await call_next(request)

    @application.exception_handler(KeyError)
    async def not_found(request: Request, exc: KeyError):
        return JSONResponse(status_code=404, content={"detail": str(exc.args[0])})

    @application.exception_handler(ValueError)
    async def invalid_operation(request: Request, exc: ValueError):
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    @application.exception_handler(IntegrationUnavailable)
    async def unavailable(request: Request, exc: IntegrationUnavailable):
        return JSONResponse(status_code=503, content={"detail": str(exc)})

    @application.exception_handler(IntegrationError)
    async def provider_error(request: Request, exc: IntegrationError):
        return JSONResponse(status_code=502, content={"detail": str(exc)})

    return application


app = create_app()
