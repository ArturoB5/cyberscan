import requests
import time
import hashlib
import os
import json
import base64
from dotenv import load_dotenv

load_dotenv() 
VT_API_KEY = os.getenv("VT_API_KEY")
VT_BASE = "https://www.virustotal.com/api/v3"
TIMEOUT = 30
MAX_RETRIES = 3
session = requests.Session()
session.headers.update({"x-apikey": VT_API_KEY})

def calculate_sha256(file_bytes: bytes) -> str:
    """Calcula el hash SHA-256 de un archivo"""
    return hashlib.sha256(file_bytes).hexdigest()

def _request_with_retries(method, url, **kwargs):
    """Realiza una solicitud con reintentos en caso de error 429 o 503"""
    retries = 3
    for attempt in range(retries):
        try:
            response = session.request(method, url, **kwargs, timeout=TIMEOUT)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            if response.status_code in [429, 503] and attempt < retries - 1:
                time.sleep(2 ** attempt)  # Backoff exponencial
                continue
            raise e 

def get_large_file_upload_url():
    """Obtiene la URL para subir archivos grandes"""
    return _request_with_retries("GET", f"{VT_BASE}/files/upload_url")["data"]

def get_file_report(file_hash: str):
    """Obtiene el informe de VirusTotal para un archivo usando su hash"""
    return _request_with_retries("GET", f"{VT_BASE}/files/{file_hash}")

def upload_file(file_bytes, filename):
    """Sube un archivo a VirusTotal"""
    file_hash = calculate_sha256(file_bytes)
    existing_report = get_file_report(file_hash)
    if existing_report:
        return existing_report  # Si el archivo ya fue analizado, devolvemos el informe

    if len(file_bytes) > 32 * 1024 * 1024:  # Si es mayor a 32 MB, subimos el archivo en partes
        upload_url = get_large_file_upload_url()
        return _request_with_retries("POST", upload_url, files={"file": (filename, file_bytes)})

    return _request_with_retries("POST", f"{VT_BASE}/files", files={"file": (filename, file_bytes)})

def normalize_report_data(data):
    """Normaliza los datos del informe de VirusTotal"""
    if "error" in data:
        return {"status": "error", "message": data.get("error")}

    result = {
        "status": data.get("status", "unknown"),
        "risk": classify_risk(data.get("stats", {})),
        "analysis_id": data.get("analysis_id", ""),
        "permalink": data.get("permalink", ""),
        "sha256": data.get("sha256", ""),
        "file_name": data.get("file_name", ""),
        "detection_stats": data.get("stats", {}),
        "engines": data.get("scan_engines", {}),
    }
    return result

def classify_risk(stats):
    """Clasifica el nivel de riesgo basándose en las estadísticas de VirusTotal"""
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    if malicious >= 5:
        return "HIGH RISK"
    if malicious >= 1 or suspicious >= 3:
        return "MEDIUM RISK"
    if suspicious >= 1:
        return "LOW RISK"
    return "SAFE"

def check_file_hash(hash_value):
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    
    headers = {
        "x-apikey": API_KEY
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        return {"error": "No data found"}


def upload_file(file_bytes, filename):
    url = "https://www.virustotal.com/api/v3/files"
    
    headers = {
        "x-apikey": API_KEY
    }

    files = {
        "file": (filename, file_bytes)
    }

    response = requests.post(url, headers=headers, files=files)

    return response.json()

def scan_url(url_to_scan):
    url = "https://www.virustotal.com/api/v3/urls"
    
    headers = {
        "x-apikey": API_KEY
    }

    data = {
        "url": url_to_scan
    }

    response = requests.post(url, headers=headers, data=data)

    return response.json()

def get_analysis(analysis_id):
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    
    headers = {
        "x-apikey": API_KEY
    }

    response = requests.get(url, headers=headers)

    return response.json()

def download_report(report_data):
    json_data = json.dumps(report_data)
    encoded_data = base64.b64encode(json_data.encode()).decode()

    st.download_button(
        label="Descargar Reporte",
        data=encoded_data,
        file_name="reporte.json",
        mime="application/json"
    )