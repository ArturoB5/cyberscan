import ipaddress
import re
from urllib.parse import urlparse

from fastapi import APIRouter, File, HTTPException, UploadFile
from pydantic import BaseModel

from backend.services.analyzer import analyze_result, extract_stats
from backend.services.virustotal import (
    VirusTotalError,
    calculate_sha256,
    get_analysis,
    get_domain_report,
    get_file_report,
    get_ip_report,
    submit_url,
    upload_file,
)

MAX_FILE_SIZE = 32 * 1024 * 1024
HASH_PATTERN = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")
DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


class URLRequest(BaseModel):
    url: str


class HashRequest(BaseModel):
    hash: str


class DomainRequest(BaseModel):
    domain: str


class IPRequest(BaseModel):
    ip: str


router = APIRouter(prefix="/scan", tags=["scan"])


def _handle_vt_error(exc: VirusTotalError) -> None:
    raise HTTPException(
        status_code=exc.status_code,
        detail={"message": exc.message, "details": exc.details},
    ) from exc


def _validate_public_url(value: str) -> str:
    parsed = urlparse(value.strip())
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise HTTPException(status_code=400, detail="La URL debe comenzar con http:// o https://")

    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(status_code=400, detail="La URL no contiene un host valido.")

    if hostname.lower() == "localhost":
        raise HTTPException(status_code=400, detail="No se permite analizar localhost.")

    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        if "." not in hostname:
            raise HTTPException(status_code=400, detail="La URL debe apuntar a un dominio publico valido.")
        return value.strip()

    if not ip.is_global:
        raise HTTPException(status_code=400, detail="Solo se permiten URLs con IPs publicas.")
    return value.strip()


def _validate_hash(value: str) -> str:
    normalized = value.strip()
    if not HASH_PATTERN.fullmatch(normalized):
        raise HTTPException(status_code=400, detail="El hash debe ser MD5, SHA1 o SHA256 valido.")
    return normalized.lower()


def _validate_domain(value: str) -> str:
    normalized = value.strip().lower()
    if normalized == "localhost" or not DOMAIN_PATTERN.fullmatch(normalized):
        raise HTTPException(status_code=400, detail="Debes ingresar un dominio valido.")
    return normalized


def _validate_public_ip(value: str) -> str:
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Debes ingresar una direccion IP valida.") from exc

    if not ip.is_global:
        raise HTTPException(status_code=400, detail="Solo se permite escanear IPs publicas.")
    return str(ip)


def _resource_response(resource_type: str, indicator: str, vt_result: dict) -> dict:
    attributes = vt_result.get("data", {}).get("attributes", {})
    stats = extract_stats(vt_result)

    return {
        "resource_type": resource_type,
        "indicator": indicator,
        "status": "completed",
        "risk": analyze_result(vt_result),
        "stats": stats,
        "last_analysis_date": attributes.get("last_analysis_date"),
        "reputation": attributes.get("reputation"),
        "categories": attributes.get("categories", {}),
        "raw": vt_result,
    }


@router.post("/file")
async def scan_file(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="El archivo debe tener nombre.")

    content = await file.read()
    size = len(content)

    if size == 0:
        raise HTTPException(status_code=400, detail="No se permiten archivos vacios.")
    if size > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail=f"El archivo supera el limite de {MAX_FILE_SIZE // (1024 * 1024)} MB.")

    sha256_hash = calculate_sha256(content)

    try:
        vt_result = get_file_report(sha256_hash)
        response = _resource_response("file", sha256_hash, vt_result)
        response.update(
            {
                "filename": file.filename,
                "sha256": sha256_hash,
                "source": "existing_report",
            }
        )
        return response
    except VirusTotalError as exc:
        if exc.status_code != 404:
            _handle_vt_error(exc)

    try:
        upload_response = upload_file(content, file.filename)
    except VirusTotalError as exc:
        _handle_vt_error(exc)

    analysis_id = upload_response.get("data", {}).get("id")
    return {
        "resource_type": "file",
        "filename": file.filename,
        "sha256": sha256_hash,
        "status": "submitted",
        "message": "Archivo enviado a VirusTotal para analisis.",
        "analysis_id": analysis_id,
    }


@router.post("/url")
def scan_url_endpoint(request: URLRequest):
    safe_url = _validate_public_url(request.url)
    try:
        result = submit_url(safe_url)
    except VirusTotalError as exc:
        _handle_vt_error(exc)

    analysis_id = result.get("data", {}).get("id")
    if not analysis_id:
        raise HTTPException(status_code=502, detail="VirusTotal no devolvio un analysis_id para la URL.")

    return {
        "resource_type": "url",
        "indicator": safe_url,
        "status": "submitted",
        "analysis_id": analysis_id,
    }


@router.post("/hash")
def scan_hash_endpoint(request: HashRequest):
    normalized_hash = _validate_hash(request.hash)
    try:
        result = get_file_report(normalized_hash)
    except VirusTotalError as exc:
        _handle_vt_error(exc)

    response = _resource_response("hash", normalized_hash, result)
    response["sha256"] = result.get("data", {}).get("id", normalized_hash)
    return response


@router.post("/domain")
def scan_domain_endpoint(request: DomainRequest):
    domain = _validate_domain(request.domain)
    try:
        result = get_domain_report(domain)
    except VirusTotalError as exc:
        _handle_vt_error(exc)
    return _resource_response("domain", domain, result)


@router.post("/ip")
def scan_ip_endpoint(request: IPRequest):
    public_ip = _validate_public_ip(request.ip)
    try:
        result = get_ip_report(public_ip)
    except VirusTotalError as exc:
        _handle_vt_error(exc)
    return _resource_response("ip", public_ip, result)


@router.get("/result/{analysis_id}")
def get_scan_result(analysis_id: str):
    try:
        result = get_analysis(analysis_id)
    except VirusTotalError as exc:
        _handle_vt_error(exc)

    attributes = result.get("data", {}).get("attributes", {})
    status = attributes.get("status", "unknown")
    stats = attributes.get("stats", {})

    if status != "completed":
        return {
            "status": status,
            "message": "Analysis in progress",
        }

    return {
        "status": "completed",
        "risk": analyze_result({"data": {"attributes": {"stats": stats}}}),
        "stats": stats,
        "raw": result,
    }
