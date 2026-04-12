import logging
import os
import time
from collections import defaultdict, deque

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from backend.routes.scan import router as scan_router
from backend.services.storage import init_db

REQUEST_WINDOW_SECONDS = int(os.getenv("CYBERSCAN_RATE_LIMIT_WINDOW", "60"))
REQUEST_LIMIT = int(os.getenv("CYBERSCAN_RATE_LIMIT_MAX", "60"))

logging.basicConfig(
    level=os.getenv("CYBERSCAN_LOG_LEVEL", "INFO"),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("cyberscan.api")
request_log: dict[str, deque[float]] = defaultdict(deque)

app = FastAPI(
    title="CyberScan API",
    version="1.2.0",
    description="API para analizar archivos, URLs, hashes, dominios e IPs con VirusTotal.",
)
app.include_router(scan_router)


@app.on_event("startup")
def startup_event():
    init_db()
    logger.info("CyberScan API started")


@app.middleware("http")
async def rate_limit_requests(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    bucket = request_log[client_ip]

    while bucket and now - bucket[0] > REQUEST_WINDOW_SECONDS:
        bucket.popleft()

    if len(bucket) >= REQUEST_LIMIT:
        return JSONResponse(
            status_code=429,
            content={
                "detail": {
                    "message": "Demasiadas solicitudes. Intenta nuevamente en unos segundos.",
                    "window_seconds": REQUEST_WINDOW_SECONDS,
                    "limit": REQUEST_LIMIT,
                }
            },
        )

    bucket.append(now)
    response = await call_next(request)
    logger.info("%s %s -> %s", request.method, request.url.path, response.status_code)
    return response


@app.get("/")
def root():
    return {
        "message": "CyberScan API running",
        "docs": "/docs",
        "health": "ok",
        "rate_limit": {
            "limit": REQUEST_LIMIT,
            "window_seconds": REQUEST_WINDOW_SECONDS,
        },
    }
