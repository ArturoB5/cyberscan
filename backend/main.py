from fastapi import FastAPI, UploadFile, File
from backend.routes.scan import router as scan_router
import hashlib

app = FastAPI()
app.include_router(scan_router)

@app.get("/")
def root():
    return {"message": "CyberScan API running"}

async def scan_file(file: UploadFile = File(...)):
    content = await file.read()
    
    sha256_hash = hashlib.sha256(content).hexdigest()

    return {
        "filename": file.filename,
        "sha256": sha256_hash
    }