"""FastAPI application factory and the uvicorn entry point.

The WebUI is bundled static files (no build step, no CDN) served from the same
origin as the API, so the browser never talks to anything but this process.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

from .. import __version__
from ..actions.executor import ActionError
from ..ai.providers import ProviderError
from ..config import Settings, load_settings
from .deps import STATE_KEY, AppState, get_state
from .routes_actions import router as actions_router
from .routes_ai import router as ai_router
from .routes_meta import router as meta_router
from .routes_scan import router as scan_router

logger = logging.getLogger("diskfree.api")
WEBUI_DIR = Path(__file__).resolve().parent.parent / "webui"

#: Paths that stay reachable without the UI token so the login form can load.
OPEN_PATHS = frozenset({"/", "/api/health", "/index.html", "/app.js", "/styles.css",
                        "/favicon.svg"})


class TokenAuthMiddleware(BaseHTTPMiddleware):
    """Optional bearer-token guard for the API.

    Off by default because DiskFree binds to loopback. When the operator binds to
    an interface other people can reach, ``DISKFREE_UI_TOKEN`` turns every ``/api``
    call into an authenticated one; the static UI stays reachable so it can prompt
    for the token.
    """

    def __init__(self, app, token: str | None) -> None:
        super().__init__(app)
        self.token = token

    async def dispatch(self, request: Request, call_next):
        if self.token and not _exempt(request.url.path):
            supplied = _bearer_of(request)
            if supplied != self.token:
                return JSONResponse(
                    status_code=401,
                    content={
                        "error": "A valid DiskFree token is required.",
                        "hint": "Send 'Authorization: Bearer <DISKFREE_UI_TOKEN>' or the "
                                "X-DiskFree-Token header.",
                    },
                    headers={"WWW-Authenticate": "Bearer"},
                )
        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Conservative headers for a local tool that shows file paths."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; font-src 'self'; "
            "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
        )
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        return response


def _exempt(path: str) -> bool:
    if path in OPEN_PATHS:
        return True
    if path.startswith("/ui/"):
        return True
    return path == "/" or not path.startswith("/api/")


def _bearer_of(request: Request) -> str | None:
    header = request.headers.get("x-diskfree-token")
    if header:
        return header.strip()
    authorization = request.headers.get("authorization", "")
    scheme, _, value = authorization.partition(" ")
    if scheme.lower() == "bearer" and value:
        return value.strip()
    return None


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the FastAPI application."""

    settings = settings or load_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        state = AppState.create(settings)
        setattr(app.state, STATE_KEY, state)
        logger.info(
            "DiskFree %s ready (data dir %s, writes %s, permanent delete %s)",
            __version__,
            settings.data_dir,
            "on" if settings.safety.allow_writes else "OFF",
            "on" if settings.safety.allow_permanent_delete else "off",
        )
        try:
            yield
        finally:
            state.jobs.clear()
            await state.aclose()

    app = FastAPI(
        title="DiskFree",
        version=__version__,
        description=(
            "AI powered disk manager and cleaner. Safe and efficient: read-only scans, "
            "rule-based risk floors, local-model advice, reversible removals."
        ),
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
    )

    app.add_middleware(SecurityHeadersMiddleware)
    if settings.ui_token:
        app.add_middleware(TokenAuthMiddleware, token=settings.ui_token)
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(settings.cors_origins),
            allow_credentials=False,
            allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type", "X-DiskFree-Token"],
        )

    for router in (meta_router, scan_router, ai_router, actions_router):
        app.include_router(router)

    @app.get("/api/health", include_in_schema=False)
    async def health() -> dict[str, object]:
        return {"status": "ok", "version": __version__}

    @app.exception_handler(ActionError)
    async def action_error_handler(_: Request, exc: ActionError) -> JSONResponse:
        return JSONResponse(status_code=409, content=exc.as_dict())

    @app.exception_handler(ProviderError)
    async def provider_error_handler(_: Request, exc: ProviderError) -> JSONResponse:
        return JSONResponse(status_code=502, content=exc.as_dict())

    @app.exception_handler(RequestValidationError)
    async def validation_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={"error": "The request body was not valid.", "detail": exc.errors()},
        )

    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        """Serve the bundled WebUI."""

        index_file = WEBUI_DIR / "index.html"
        if not index_file.is_file():  # pragma: no cover - packaging guard
            return JSONResponse(
                status_code=500,
                content={
                    "error": "The WebUI assets are missing from this installation.",
                    "hint": f"Expected {index_file}",
                },
            )
        return FileResponse(index_file, media_type="text/html")

    if WEBUI_DIR.is_dir():
        app.mount("/ui", StaticFiles(directory=WEBUI_DIR), name="ui")

    @app.get("/app.js", include_in_schema=False)
    async def app_js() -> FileResponse:
        return FileResponse(WEBUI_DIR / "app.js", media_type="application/javascript")

    @app.get("/styles.css", include_in_schema=False)
    async def styles_css() -> FileResponse:
        return FileResponse(WEBUI_DIR / "styles.css", media_type="text/css")

    @app.get("/favicon.svg", include_in_schema=False)
    async def favicon() -> FileResponse:
        return FileResponse(WEBUI_DIR / "favicon.svg", media_type="image/svg+xml")

    return app


#: ``uvicorn diskfree.api.app:app`` works out of the box.
app = create_app()


def run(host: str | None = None, port: int | None = None, **kwargs: object) -> None:
    """Start uvicorn programmatically (used by the CLI and ``run.py``)."""

    import uvicorn

    settings = load_settings()
    uvicorn.run(
        "diskfree.api.app:app",
        host=host or settings.host,
        port=port or settings.port,
        log_level=settings.log_level,
        **kwargs,  # type: ignore[arg-type]
    )


__all__ = ["WEBUI_DIR", "AppState", "app", "create_app", "get_state", "run"]
