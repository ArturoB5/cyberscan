from fastapi import APIRouter, UploadFile, File
from pydantic import BaseModel
import hashlib
from backend.services.virustotal import check_file_hash, upload_file, scan_url, get_analysis
from backend.services.analyzer import analyze_result

class URLRequest(BaseModel):
    url: str

router = APIRouter()

@router.post("/scan/file")
async def scan_file(file: UploadFile = File(...)):
    content = await file.read()
    
    sha256_hash = hashlib.sha256(content).hexdigest()

    vt_result = check_file_hash(sha256_hash)

   
    # 🔥 SI NO EXISTE → subir archivo
    if "error" in vt_result:
        upload_response = upload_file(content, file.filename)

        return {
            "filename": file.filename,
            "sha256": sha256_hash,
            "status": "UPLOADED_FOR_ANALYSIS",
            "message": "File not found in VirusTotal. Uploaded for scanning.",
            "vt_response": upload_response
        }

    # 🔥 SI EXISTE → analizar normal
    risk = analyze_result(vt_result)

    return {
        "filename": file.filename,
        "sha256": sha256_hash,
        "risk": risk
    }

@router.get("/scan/result/{analysis_id}")
def get_scan_result(analysis_id: str):
    result = get_analysis(analysis_id)

    try:
        status = result["data"]["attributes"]["status"]

        # 🔄 Aún analizando
        if status != "completed":
            return {
                "status": status,
                "message": "Analysis in progress"
            }

        # ✅ Ya terminado
        stats = result["data"]["attributes"]["stats"]

        malicious = stats["malicious"]

        if malicious > 5:
            risk = "HIGH RISK"
        elif malicious > 0:
            risk = "MEDIUM RISK"
        else:
            risk = "LOW RISK"

        return {
            "status": "completed",
            "risk": risk,
            "stats": stats
        }

    except:
        return {
            "error": "Could not process analysis result",
            "raw": result
        }

@router.post("/scan/url")
def scan_url_endpoint(request: URLRequest):
    result = scan_url(request.url)

    try:
        analysis_id = result["data"]["id"]

        return {
            "url": request.url,
            "status": "SUBMITTED",
            "analysis_id": analysis_id
        }

    except:
        return {
            "error": "Could not analyze URL",
            "details": result
        }