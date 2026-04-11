import hashlib
import os
import time
from typing import Any

import requests
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
VT_BASE = "https://www.virustotal.com/api/v3"
TIMEOUT = 30
MAX_RETRIES = 3

session = requests.Session()


class VirusTotalError(Exception):
    def __init__(self, message: str, status_code: int = 500, details: Any | None = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details


def _ensure_api_key() -> None:
    if not VT_API_KEY:
        raise VirusTotalError(
            "VT_API_KEY no esta configurada en el entorno.",
            status_code=500,
        )


def calculate_sha256(file_bytes: bytes) -> str:
    return hashlib.sha256(file_bytes).hexdigest()


def _headers() -> dict[str, str]:
    _ensure_api_key()
    return {"x-apikey": VT_API_KEY}


def _request_json(method: str, url: str, use_base: bool = True, **kwargs: Any) -> dict[str, Any]:
    full_url = f"{VT_BASE}{url}" if use_base else url
    retries = kwargs.pop("retries", MAX_RETRIES)
    headers = kwargs.pop("headers", {})
    merged_headers = {**_headers(), **headers}

    last_error: VirusTotalError | None = None
    for attempt in range(retries):
        response = None
        try:
            response = session.request(
                method,
                full_url,
                headers=merged_headers,
                timeout=TIMEOUT,
                **kwargs,
            )

            if response.status_code in (429, 503) and attempt < retries - 1:
                time.sleep(2**attempt)
                continue

            if response.status_code == 404:
                raise VirusTotalError(
                    "No se encontraron resultados en VirusTotal.",
                    status_code=404,
                    details=response.json(),
                )

            if response.status_code >= 400:
                try:
                    details = response.json()
                except ValueError:
                    details = {"message": response.text}
                raise VirusTotalError(
                    "VirusTotal devolvio un error.",
                    status_code=response.status_code,
                    details=details,
                )

            return response.json()
        except requests.RequestException as exc:
            message = "No se pudo conectar con VirusTotal."
            if response is not None:
                message = f"{message} Codigo: {response.status_code}"
            last_error = VirusTotalError(message, status_code=502, details=str(exc))

    raise last_error or VirusTotalError("Error inesperado al consultar VirusTotal.")


def get_large_file_upload_url() -> str:
    return _request_json("GET", "/files/upload_url")["data"]


def get_file_report(file_hash: str) -> dict[str, Any]:
    return _request_json("GET", f"/files/{file_hash}")


def upload_file(file_bytes: bytes, filename: str) -> dict[str, Any]:
    if len(file_bytes) > 32 * 1024 * 1024:
        upload_url = get_large_file_upload_url()
        return _request_json(
            "POST",
            upload_url,
            use_base=False,
            files={"file": (filename, file_bytes)},
        )

    return _request_json(
        "POST",
        "/files",
        files={"file": (filename, file_bytes)},
    )


def submit_url(url_to_scan: str) -> dict[str, Any]:
    return _request_json("POST", "/urls", data={"url": url_to_scan})


def get_analysis(analysis_id: str) -> dict[str, Any]:
    return _request_json("GET", f"/analyses/{analysis_id}")


def get_domain_report(domain: str) -> dict[str, Any]:
    return _request_json("GET", f"/domains/{domain}")


def get_ip_report(ip_address: str) -> dict[str, Any]:
    return _request_json("GET", f"/ip_addresses/{ip_address}")
