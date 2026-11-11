"""Point d'entree du backend : py -m uvicorn app.main:app --port 8000   (depuis le dossier backend/)"""
import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import auth, internal, keys, relay
from app.auth import AuthService
from app.config import Settings
from app.db import make_engine, make_session_factory
from app.errors import ApiError
from app.models import Base
from app.relay import ConnectionManager, RelayService
from app.soc_client import SocEmitter

log = logging.getLogger("securetalk.backend")


async def _heartbeat_loop(app, interval):
    """HEARTBEAT des sources auth et relay toutes les 60 s (regle R012 du SOC)."""
    while True:
        for source in ("auth", "relay"):
            app.state.emitter.emit(source, "HEARTBEAT", "info")
        try:
            await run_in_threadpool(app.state.emitter.flush_pending)
        except Exception:
            log.exception("flush des evenements en attente impossible")
        await asyncio.sleep(interval)


def create_app(settings=None):
    settings = settings or Settings.from_env()

    @asynccontextmanager
    async def lifespan(app):
        task = None
        if settings.heartbeat_seconds > 0:
            task = asyncio.create_task(_heartbeat_loop(app, settings.heartbeat_seconds))
        yield
        if task:
            task.cancel()
        app.state.emitter.shutdown()

    app = FastAPI(title="SecureTalk backend", version="1.0", lifespan=lifespan)
    engine = make_engine(settings.database_url)
    Base.metadata.create_all(engine)
    app.state.settings = settings
    app.state.engine = engine
    app.state.SessionLocal = make_session_factory(engine)
    app.state.emitter = SocEmitter(settings)
    app.state.manager = ConnectionManager()
    app.state.auth = AuthService(settings, app.state.emitter)
    app.state.relay = RelayService(settings, app.state.emitter, app.state.auth,
                                   app.state.SessionLocal, app.state.manager)

    @app.exception_handler(ApiError)
    async def api_error(request: Request, exc: ApiError):
        return JSONResponse(status_code=exc.status, content={"error": exc.code, "message": exc.message})

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        champs = sorted({".".join(str(x) for x in e["loc"] if x != "body") for e in exc.errors()})
        return JSONResponse(status_code=400, content={"error": "INVALID_FORMAT",
                                                      "message": "Champs invalides : " + ", ".join(champs)})

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        codes = {404: "NOT_FOUND", 405: "METHOD_NOT_ALLOWED"}
        return JSONResponse(status_code=exc.status_code,
                            content={"error": codes.get(exc.status_code, "HTTP_ERROR"), "message": str(exc.detail)})

    @app.exception_handler(Exception)
    async def unexpected(request: Request, exc: Exception):
        log.exception("erreur interne")                   # jamais de contenu de message dans les logs
        return JSONResponse(status_code=500, content={"error": "INTERNAL_ERROR", "message": "Erreur interne"})

    @app.get("/health")
    def health():
        return {"status": "ok", "service": "backend"}

    app.include_router(auth.router)
    app.include_router(relay.router)
    app.include_router(keys.router)
    app.include_router(internal.router)
    return app


app = create_app()
