# CyberScan Dashboard

CyberScan es una plataforma ligera para consultar indicadores de amenaza en VirusTotal desde una API con FastAPI y una interfaz en Streamlit.

Actualmente permite analizar:

- Archivos
- URLs publicas
- Hashes MD5, SHA1 y SHA256
- Dominios
- Direcciones IP publicas

## Que hace hoy

- Clasifica el riesgo en `SAFE`, `LOW RISK`, `MEDIUM RISK` o `HIGH RISK`
- Muestra conteos de motores (`malicious`, `suspicious`, `undetected`, etc.)
- Reutiliza reportes existentes cuando VirusTotal ya conoce el indicador
- Envia archivos y URLs a analisis cuando todavia no existe un reporte
- Bloquea entradas obvias no seguras para el flujo, como `localhost` o IPs no publicas
- Guarda historial local en SQLite
- Usa cache local por indicador para acelerar consultas repetidas
- Expone un resumen operativo de tipos de IOC y niveles de riesgo
- Permite descargar reportes en JSON desde la interfaz

## Arquitectura

- `backend/`: API en FastAPI
- `frontend/`: dashboard en Streamlit
- `backend/services/virustotal.py`: integracion con VirusTotal
- `backend/services/analyzer.py`: normalizacion basica del riesgo

## Requisitos

- Python 3.10 o superior
- Una API key de VirusTotal

## Instalacion

```bash
git clone https://github.com/ArturoB5/cyberscan.git
cd cyberscan
python -m venv .venv
```

Activar el entorno virtual:

```bash
# Windows
.venv\Scripts\activate

# Linux / macOS
source .venv/bin/activate
```

Instalar dependencias:

```bash
pip install -r requerimientos.txt
```

## Configuracion

Crea un archivo `.env` en la raiz del proyecto con:

```env
VT_API_KEY=tu_api_key_aqui
CYBERSCAN_API_URL=http://127.0.0.1:8000
CYBERSCAN_DB_PATH=cyberscan.db
CYBERSCAN_CACHE_TTL_HOURS=12
CYBERSCAN_RATE_LIMIT_WINDOW=60
CYBERSCAN_RATE_LIMIT_MAX=60
```

No se recomienda hardcodear la clave en el codigo.

## Ejecucion

Backend:

```bash
uvicorn backend.main:app --reload
```

Frontend:

```bash
streamlit run frontend/app.py
```

Servicios por defecto:

- API: `http://127.0.0.1:8000`
- UI: `http://localhost:8501`

## Endpoints principales

- `POST /scan/file`
- `POST /scan/url`
- `POST /scan/hash`
- `POST /scan/domain`
- `POST /scan/ip`
- `GET /scan/result/{analysis_id}`
- `GET /scan/history`
- `GET /scan/summary`

## Ejemplo de respuesta

```json
{
  "resource_type": "hash",
  "indicator": "44d88612fea8a8f36de82e1278abb02f",
  "status": "completed",
  "risk": "HIGH RISK",
  "stats": {
    "malicious": 61,
    "suspicious": 2,
    "undetected": 5
  }
}
```

## Seguridad y limites

- Los archivos vacios se rechazan
- Los archivos se limitan a 32 MB para evitar abuso de memoria en este flujo
- Solo se aceptan URLs con `http` o `https`
- Se rechazan `localhost` e IPs no publicas en escaneo de URL e IP
- El backend aplica rate limiting basico por IP
- Se registran historial y cache en SQLite para evitar trabajo repetido
- El analisis depende de la disponibilidad y cuota de VirusTotal

## Tests basicos

Puedes ejecutar la suite incluida con:

```bash
python -m unittest discover -s tests
```

## Roadmap sugerido

- Historial local de consultas
- Cache de respuestas por indicador
- Autenticacion de usuarios
- Exportacion de reportes
- Analisis enriquecido con reputacion y recomendaciones

## Autor

Arturo Badillo  
Avalon Labs

## Invitame un cafe

Si quieres apoyar el proyecto:

<a href="https://www.paypal.com/paypalme/arararcadabra?locale.x=es_XC&country.x=EC" target="_blank">
  <img src="https://img.shields.io/badge/Invitame%20un%20cafe-PayPal-00457C?style=for-the-badge&logo=paypal&logoColor=white" alt="Invitame un cafe">
</a>

## Disclaimer

Este proyecto es educativo y de apoyo operativo. No sustituye un sandbox, un EDR ni una plataforma profesional de threat intel.
