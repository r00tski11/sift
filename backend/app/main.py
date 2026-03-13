"""FastAPI application entry point."""

from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from app.api import auth, dashboard, findings, imports, projects, scans
from app.config import settings

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):  # noqa: ANN001, ARG001
    """Application startup/shutdown lifecycle."""
    # Startup: ensure upload directory exists
    Path(settings.UPLOAD_DIR).mkdir(parents=True, exist_ok=True)
    logger.info("Upload directory ready: %s", settings.UPLOAD_DIR)
    yield
    # Shutdown: nothing to clean up


app = FastAPI(
    title="iOS Security Audit Platform",
    description="API for scanning and auditing iOS application security",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API routers under /api/v1
API_PREFIX = "/api/v1"
app.include_router(auth.router, prefix=API_PREFIX)
app.include_router(projects.router, prefix=API_PREFIX)
app.include_router(scans.router, prefix=API_PREFIX)
app.include_router(findings.router, prefix=API_PREFIX)
app.include_router(dashboard.router, prefix=API_PREFIX)
app.include_router(imports.router, prefix=API_PREFIX)


@app.get("/health")
def health_check() -> dict:
    """Basic health check endpoint."""
    return {"status": "healthy", "service": "ios-security-api"}


@app.websocket("/api/v1/ws/scans/{scan_id}")
async def scan_progress_ws(websocket: WebSocket, scan_id: int) -> None:
    """WebSocket endpoint for real-time scan progress updates.

    Subscribes to a Redis pub/sub channel for the given scan ID and
    forwards messages to the connected WebSocket client.
    """
    await websocket.accept()

    try:
        import redis.asyncio as aioredis

        r = aioredis.from_url(settings.REDIS_URL)
        pubsub = r.pubsub()
        await pubsub.subscribe(f"scan:{scan_id}")

        try:
            while True:
                message = await asyncio.wait_for(
                    pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0),
                    timeout=5.0,
                )
                if message and message["type"] == "message":
                    data = message["data"]
                    if isinstance(data, bytes):
                        data = data.decode("utf-8")
                    await websocket.send_text(data)

                    # Close after completion or failure
                    parsed = json.loads(data)
                    if parsed.get("type") in ("completed", "failed"):
                        break
        finally:
            await pubsub.unsubscribe(f"scan:{scan_id}")
            await pubsub.close()
            await r.close()

    except WebSocketDisconnect:
        logger.debug("WebSocket client disconnected for scan %d", scan_id)
    except ImportError:
        # redis.asyncio not available — send error and close
        await websocket.send_text(
            json.dumps({"type": "error", "message": "Redis async client not available"})
        )
    except Exception as exc:
        logger.warning("WebSocket error for scan %d: %s", scan_id, exc)
        try:
            await websocket.send_text(
                json.dumps({"type": "error", "message": str(exc)})
            )
        except Exception:
            pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass
