from fastapi import FastAPI

from backend.routes.scan import router as scan_router

app = FastAPI(
    title="CyberScan API",
    version="1.1.0",
    description="API para analizar archivos, URLs, hashes, dominios e IPs con VirusTotal.",
)
app.include_router(scan_router)


@app.get("/")
def root():
    return {
        "message": "CyberScan API running",
        "docs": "/docs",
        "health": "ok",
    }
