import json
import os
import time

import requests
import streamlit as st
try:
    from dotenv import load_dotenv
except ModuleNotFoundError:  # pragma: no cover - fallback para entornos minimos
    def load_dotenv() -> bool:
        return False

st.set_page_config(page_title="CyberScan", page_icon="🛡️", layout="wide")

load_dotenv()

BASE_URL = os.getenv("CYBERSCAN_API_URL", "http://127.0.0.1:8000")
REQUEST_TIMEOUT = int(os.getenv("CYBERSCAN_REQUEST_TIMEOUT", "30"))
POLL_INTERVAL = int(os.getenv("CYBERSCAN_POLL_INTERVAL", "2"))
MAX_POLLS = int(os.getenv("CYBERSCAN_MAX_POLLS", "15"))
THEMES = {
    "Claro": {
        "bg": "#f4f7fb",
        "panel": "#ffffff",
        "panel_alt": "#ecf2ff",
        "text": "#14213d",
        "muted": "#53627c",
        "accent": "#2563eb",
        "accent_soft": "#dbeafe",
        "border": "#d7e2f0",
        "good": "#0f766e",
        "warn": "#b45309",
        "danger": "#b91c1c",
        "shadow": "0 20px 60px rgba(20, 33, 61, 0.12)",
    },
    "Oscuro": {
        "bg": "#0b1220",
        "panel": "#111a2e",
        "panel_alt": "#17233d",
        "text": "#ebf3ff",
        "muted": "#9fb2d1",
        "accent": "#60a5fa",
        "accent_soft": "#1d4ed8",
        "border": "#24324e",
        "good": "#34d399",
        "warn": "#fbbf24",
        "danger": "#f87171",
        "shadow": "0 24px 80px rgba(0, 0, 0, 0.45)",
    },
}


def apply_theme(theme_name: str):
    theme = THEMES[theme_name]
    st.markdown(
        f"""
        <style>
            :root {{
                --bg: {theme["bg"]};
                --panel: {theme["panel"]};
                --panel-alt: {theme["panel_alt"]};
                --text: {theme["text"]};
                --muted: {theme["muted"]};
                --accent: {theme["accent"]};
                --accent-soft: {theme["accent_soft"]};
                --border: {theme["border"]};
                --good: {theme["good"]};
                --warn: {theme["warn"]};
                --danger: {theme["danger"]};
                --shadow: {theme["shadow"]};
            }}

            html, body, [class*="css"] {{
                font-family: Aptos, "Segoe UI", "Trebuchet MS", sans-serif;
            }}

            .stApp {{
                background:
                    radial-gradient(circle at top right, rgba(37, 99, 235, 0.16), transparent 28%),
                    radial-gradient(circle at top left, rgba(15, 118, 110, 0.10), transparent 24%),
                    linear-gradient(180deg, var(--bg), color-mix(in srgb, var(--bg) 88%, white 12%));
                color: var(--text);
            }}

            .block-container {{
                max-width: 1180px;
                padding-top: 2rem;
                padding-bottom: 2rem;
            }}

            [data-testid="stSidebar"] {{
                background: linear-gradient(180deg, var(--panel), var(--panel-alt));
                border-right: 1px solid var(--border);
            }}

            [data-testid="stSidebar"] * {{
                color: var(--text);
            }}

            div[data-testid="stVerticalBlock"] div:has(> div.cyberscan-card) {{
                width: 100%;
            }}

            .cyberscan-hero {{
                background: linear-gradient(135deg, var(--panel) 0%, var(--panel-alt) 100%);
                border: 1px solid var(--border);
                border-radius: 28px;
                padding: 28px 30px;
                box-shadow: var(--shadow);
                margin-bottom: 1.2rem;
                position: relative;
                overflow: hidden;
            }}

            .cyberscan-hero::after {{
                content: "";
                position: absolute;
                inset: auto -50px -60px auto;
                width: 180px;
                height: 180px;
                background: radial-gradient(circle, color-mix(in srgb, var(--accent) 35%, transparent), transparent 65%);
                filter: blur(8px);
            }}

            .cyberscan-eyebrow {{
                display: inline-block;
                padding: 6px 12px;
                border-radius: 999px;
                background: var(--accent-soft);
                color: var(--text);
                font-size: 0.82rem;
                font-weight: 700;
                letter-spacing: 0.03em;
                margin-bottom: 10px;
            }}

            .cyberscan-title {{
                font-size: 2.2rem;
                line-height: 1.05;
                font-weight: 800;
                margin: 0 0 10px 0;
                color: var(--text);
            }}

            .cyberscan-subtitle {{
                color: var(--muted);
                font-size: 1rem;
                max-width: 760px;
                margin-bottom: 0;
            }}

            .cyberscan-card {{
                background: linear-gradient(180deg, var(--panel), color-mix(in srgb, var(--panel) 80%, var(--panel-alt) 20%));
                border: 1px solid var(--border);
                border-radius: 24px;
                padding: 22px;
                box-shadow: var(--shadow);
                margin-bottom: 1rem;
            }}

            .cyberscan-card h3,
            .cyberscan-card p,
            .cyberscan-card li {{
                color: var(--text);
            }}

            .cyberscan-muted {{
                color: var(--muted);
            }}

            .cyberscan-badge-row {{
                display: flex;
                flex-wrap: wrap;
                gap: 10px;
                margin-top: 14px;
            }}

            .cyberscan-badge {{
                border-radius: 999px;
                padding: 8px 12px;
                border: 1px solid var(--border);
                background: color-mix(in srgb, var(--panel-alt) 65%, transparent);
                color: var(--text);
                font-size: 0.84rem;
                font-weight: 600;
            }}

            .cyberscan-risk {{
                border-radius: 18px;
                padding: 16px 18px;
                margin-bottom: 1rem;
                border: 1px solid var(--border);
                background: var(--panel-alt);
            }}

            .cyberscan-risk.safe {{
                border-color: color-mix(in srgb, var(--good) 45%, var(--border));
                background: color-mix(in srgb, var(--good) 12%, var(--panel));
            }}

            .cyberscan-risk.low {{
                border-color: color-mix(in srgb, var(--accent) 45%, var(--border));
                background: color-mix(in srgb, var(--accent) 12%, var(--panel));
            }}

            .cyberscan-risk.medium {{
                border-color: color-mix(in srgb, var(--warn) 45%, var(--border));
                background: color-mix(in srgb, var(--warn) 12%, var(--panel));
            }}

            .cyberscan-risk.high {{
                border-color: color-mix(in srgb, var(--danger) 45%, var(--border));
                background: color-mix(in srgb, var(--danger) 12%, var(--panel));
            }}

            .cyberscan-risk-title {{
                font-size: 1.05rem;
                font-weight: 800;
                margin-bottom: 0.35rem;
                color: var(--text);
            }}

            .cyberscan-risk-text {{
                color: var(--muted);
                margin: 0;
            }}

            div[data-testid="stMetric"] {{
                background: linear-gradient(180deg, var(--panel), var(--panel-alt));
                border: 1px solid var(--border);
                border-radius: 22px;
                padding: 16px 18px;
                box-shadow: var(--shadow);
            }}

            div[data-testid="stMetric"] label,
            div[data-testid="stMetric"] [data-testid="stMetricValue"] {{
                color: var(--text);
            }}

            .stTextInput input,
            .stFileUploader section,
            .stSelectbox div[data-baseweb="select"],
            .stRadio div[role="radiogroup"] {{
                border-radius: 18px;
            }}

            .stTextInput input,
            .stFileUploader section,
            div[data-baseweb="base-input"],
            div[data-baseweb="select"] > div {{
                background: var(--panel) !important;
                color: var(--text) !important;
                border: 1px solid var(--border) !important;
            }}

            .stButton > button,
            .stForm button[kind="primary"] {{
                background: linear-gradient(135deg, var(--accent), color-mix(in srgb, var(--accent) 70%, white 30%));
                color: white;
                border: none;
                border-radius: 16px;
                font-weight: 800;
                padding: 0.7rem 1rem;
                box-shadow: var(--shadow);
            }}

            .stButton > button:hover,
            .stForm button[kind="primary"]:hover {{
                filter: brightness(1.06);
            }}

            .stAlert {{
                border-radius: 18px;
                border: 1px solid var(--border);
            }}

            .streamlit-expanderHeader {{
                color: var(--text);
            }}

            .stCaption, .stMarkdown p {{
                color: var(--muted);
            }}
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_hero():
    st.markdown(
        """
        <section class="cyberscan-hero">
            <div class="cyberscan-eyebrow">THREAT INTEL DASHBOARD</div>
            <h1 class="cyberscan-title">CyberScan</h1>
            <p class="cyberscan-subtitle">
                Una interfaz ligera para inspeccionar indicadores con VirusTotal, priorizando claridad visual,
                contexto tecnico y decisiones rapidas.
            </p>
            <div class="cyberscan-badge-row">
                <span class="cyberscan-badge">Archivo</span>
                <span class="cyberscan-badge">URL</span>
                <span class="cyberscan-badge">Hash</span>
                <span class="cyberscan-badge">Dominio</span>
                <span class="cyberscan-badge">IP publica</span>
            </div>
        </section>
        """,
        unsafe_allow_html=True,
    )


def open_card(title: str, body: str | None = None):
    st.markdown('<section class="cyberscan-card">', unsafe_allow_html=True)
    st.markdown(f"### {title}")
    if body:
        st.markdown(f'<p class="cyberscan-muted">{body}</p>', unsafe_allow_html=True)


def close_card():
    st.markdown("</section>", unsafe_allow_html=True)


def load_dashboard_snapshot():
    try:
        summary = api_request("GET", "/scan/summary")
        history = api_request("GET", "/scan/history", params={"limit": 8})
        return summary, history.get("items", [])
    except Exception:
        return None, []


def api_request(method: str, path: str, **kwargs):
    response = requests.request(
        method,
        f"{BASE_URL}{path}",
        timeout=REQUEST_TIMEOUT,
        **kwargs,
    )
    try:
        data = response.json()
    except ValueError:
        response.raise_for_status()
        raise ValueError("La respuesta del backend no es JSON valido.")

    if response.status_code >= 400:
        detail = data.get("detail", data)
        if isinstance(detail, dict):
            message = detail.get("message", detail)
        else:
            message = detail
        raise RuntimeError(str(message))

    return data


def poll_result(analysis_id: str):
    for _ in range(MAX_POLLS):
        result_data = api_request("GET", f"/scan/result/{analysis_id}")
        status = str(result_data.get("status", "")).lower()

        if status == "completed":
            return result_data
        if status in {"failed", "error"}:
            raise RuntimeError(result_data.get("message", "El analisis fallo."))

        time.sleep(POLL_INTERVAL)

    raise TimeoutError("El analisis tardo demasiado. Intenta nuevamente en unos segundos.")


def show_friendly_result(risk: str):
    normalized = str(risk).upper()
    messages = {
        "HIGH RISK": ("high", "Riesgo alto detectado", "No abras ni ejecutes este indicador hasta verificarlo."),
        "MEDIUM RISK": ("medium", "Riesgo medio", "Hay senales sospechosas y conviene revisar el detalle tecnico."),
        "LOW RISK": ("low", "Riesgo bajo", "No parece critico, pero vale la pena validar el contexto."),
        "SAFE": ("safe", "Sin detecciones conocidas", "No se observaron amenazas conocidas en el reporte devuelto."),
    }
    level, title, message = messages.get(
        normalized,
        ("low", "Resultado no concluyente", "No hubo suficientes datos para clasificar el indicador."),
    )
    st.markdown(
        f"""
        <div class="cyberscan-risk {level}">
            <div class="cyberscan-risk-title">{title}</div>
            <p class="cyberscan-risk-text">{message}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_ioc_summary(result_data: dict):
    resource_type = result_data.get("resource_type", "resultado")
    indicator = result_data.get("indicator") or result_data.get("sha256") or "N/D"
    reputation = result_data.get("reputation", "N/D")
    source = result_data.get("source", "live")

    st.markdown(
        f"""
        <div class="cyberscan-card">
            <h3>IOC summary</h3>
            <p class="cyberscan-muted"><strong>Tipo:</strong> {resource_type}</p>
            <p class="cyberscan-muted"><strong>Indicador:</strong> {indicator}</p>
            <p class="cyberscan-muted"><strong>Reputacion:</strong> {reputation}</p>
            <p class="cyberscan-muted"><strong>Fuente:</strong> {source}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_result(result_data: dict):
    risk = result_data.get("risk", "UNKNOWN")
    stats = result_data.get("stats", {})
    show_friendly_result(risk)
    render_ioc_summary(result_data)

    top_left, top_mid, top_right = st.columns(3)
    top_left.metric("Riesgo", risk)
    top_mid.metric("Malicious", stats.get("malicious", 0))
    top_right.metric("Suspicious", stats.get("suspicious", 0))

    bottom_left, bottom_mid, bottom_right = st.columns(3)
    bottom_left.metric("Undetected", stats.get("undetected", 0))
    bottom_mid.metric("Harmless", stats.get("harmless", 0))
    bottom_right.metric("Timeout", stats.get("timeout", 0))

    if result_data.get("reputation") is not None:
        st.caption(f"Reputacion reportada por VirusTotal: {result_data['reputation']}")

    categories = result_data.get("categories") or {}
    if categories:
        st.write("Categorias detectadas:")
        st.json(categories)

    st.download_button(
        label="Descargar reporte JSON",
        data=json.dumps(result_data, indent=2, ensure_ascii=False),
        file_name=f"cyberscan-report-{result_data.get('resource_type', 'scan')}.json",
        mime="application/json",
    )

    with st.expander("Detalles tecnicos"):
        st.json(result_data)


def handle_submitted_scan(payload: dict):
    analysis_id = payload.get("analysis_id")
    if not analysis_id:
        st.error("No se pudo obtener el ID del analisis.")
        st.json(payload)
        return

    st.info(f"Analisis enviado. ID: {analysis_id}")
    final_result = poll_result(analysis_id)
    render_result(final_result)


st.sidebar.title("CyberScan")
theme_name = st.sidebar.radio("Modo visual", list(THEMES.keys()), horizontal=True)
apply_theme(theme_name)
st.sidebar.info(
    """
Tipos de analisis disponibles:
- Archivo
- URL
- Hash
- Dominio
- IP publica
"""
)
st.sidebar.caption("Recuerda no subir datos sensibles ni internos.")
st.sidebar.markdown("---")
st.sidebar.markdown(
    """
    **Sugerencia de uso**

    Empieza por hash o dominio cuando ya tengas un IOC.
    Usa archivo o URL cuando necesites detonacion remota en VirusTotal.
    """
)

render_hero()
summary, recent_history = load_dashboard_snapshot()

summary_col_1, summary_col_2, summary_col_3 = st.columns(3)
summary_col_1.markdown(
    f"""
    <div class="cyberscan-card">
        <h3>Escaneos recientes</h3>
        <p class="cyberscan-muted">{(summary or {}).get('total_scans', 0)} consultas registradas</p>
    </div>
    """,
    unsafe_allow_html=True,
)
summary_col_2.markdown(
    f"""
    <div class="cyberscan-card">
        <h3>TTL de cache</h3>
        <p class="cyberscan-muted">{(summary or {}).get('cache_ttl_hours', 'N/D')} horas</p>
    </div>
    """,
    unsafe_allow_html=True,
)
summary_col_3.markdown(
    f"""
    <div class="cyberscan-card">
        <h3>Endpoint activo</h3>
        <p class="cyberscan-muted">{BASE_URL}</p>
    </div>
    """,
    unsafe_allow_html=True,
)

if summary:
    trend_left, trend_right = st.columns([1.4, 1])
    with trend_left:
        st.markdown("### Resumen operativo")
        st.json(
            {
                "by_risk": summary.get("by_risk", {}),
                "by_type": summary.get("by_type", {}),
            }
        )
    with trend_right:
        st.markdown("### Historial reciente")
        if recent_history:
            st.dataframe(recent_history, use_container_width=True, hide_index=True)
        else:
            st.info("Aun no hay historial guardado.")

privacy_accepted = st.checkbox(
    "Acepto que cualquier indicador enviado sera consultado externamente y no incluire informacion confidencial."
)
if not privacy_accepted:
    st.warning("Debes aceptar el aviso antes de analizar.")
    st.stop()

option = st.radio(
    "Selecciona el tipo de analisis",
    ["Archivo", "URL", "Hash", "Dominio", "IP publica"],
    horizontal=True,
)

left, right = st.columns([1, 1])

with left:
    if option == "Archivo":
        open_card("Escaneo de archivo", "Sube un archivo para consultar si ya existe un reporte o enviarlo a analisis.")
        with st.form("file_scan_form"):
            uploaded_file = st.file_uploader("Selecciona un archivo", key="file_upload")
            analyze_file = st.form_submit_button("Analizar archivo")
        close_card()

        if analyze_file:
            if not uploaded_file:
                st.warning("Debes seleccionar un archivo.")
            else:
                try:
                    with st.spinner("Consultando VirusTotal..."):
                        payload = api_request(
                            "POST",
                            "/scan/file",
                            files={"file": (uploaded_file.name, uploaded_file.getvalue())},
                        )
                    with right:
                        st.subheader("Resultado")
                        if payload.get("status") == "submitted":
                            handle_submitted_scan(payload)
                        else:
                            render_result(payload)
                except Exception as exc:
                    with right:
                        st.subheader("Resultado")
                        st.error(str(exc))

    elif option == "URL":
        open_card("Escaneo de URL", "Acepta solo URLs publicas con http o https.")
        with st.form("url_scan_form"):
            url = st.text_input("Ingresa una URL publica")
            analyze_url = st.form_submit_button("Analizar URL")
        close_card()

        if analyze_url:
            if not url.strip():
                st.warning("Debes ingresar una URL.")
            else:
                try:
                    with st.spinner("Enviando URL a VirusTotal..."):
                        payload = api_request("POST", "/scan/url", json={"url": url})
                    with right:
                        st.subheader("Resultado")
                        handle_submitted_scan(payload)
                except Exception as exc:
                    with right:
                        st.subheader("Resultado")
                        st.error(str(exc))

    elif option == "Hash":
        open_card("Busqueda por hash", "Consulta reportes existentes por MD5, SHA1 o SHA256.")
        with st.form("hash_scan_form"):
            hash_value = st.text_input("Ingresa un hash MD5, SHA1 o SHA256")
            analyze_hash = st.form_submit_button("Buscar hash")
        close_card()

        if analyze_hash:
            if not hash_value.strip():
                st.warning("Debes ingresar un hash.")
            else:
                try:
                    with st.spinner("Consultando hash..."):
                        payload = api_request("POST", "/scan/hash", json={"hash": hash_value})
                    with right:
                        st.subheader("Resultado")
                        render_result(payload)
                except Exception as exc:
                    with right:
                        st.subheader("Resultado")
                        st.error(str(exc))

    elif option == "Dominio":
        open_card("Busqueda por dominio", "Ideal para reputacion web y clasificacion de infraestructura.")
        with st.form("domain_scan_form"):
            domain = st.text_input("Ingresa un dominio")
            analyze_domain = st.form_submit_button("Analizar dominio")
        close_card()

        if analyze_domain:
            if not domain.strip():
                st.warning("Debes ingresar un dominio.")
            else:
                try:
                    with st.spinner("Consultando dominio..."):
                        payload = api_request("POST", "/scan/domain", json={"domain": domain})
                    with right:
                        st.subheader("Resultado")
                        render_result(payload)
                except Exception as exc:
                    with right:
                        st.subheader("Resultado")
                        st.error(str(exc))

    else:
        open_card("Busqueda por IP publica", "Acepta solo direcciones publicas para evitar consultas internas por error.")
        with st.form("ip_scan_form"):
            ip_address = st.text_input("Ingresa una direccion IP publica")
            analyze_ip = st.form_submit_button("Analizar IP")
        close_card()

        if analyze_ip:
            if not ip_address.strip():
                st.warning("Debes ingresar una IP.")
            else:
                try:
                    with st.spinner("Consultando IP..."):
                        payload = api_request("POST", "/scan/ip", json={"ip": ip_address})
                    with right:
                        st.subheader("Resultado")
                        render_result(payload)
                except Exception as exc:
                    with right:
                        st.subheader("Resultado")
                        st.error(str(exc))

st.markdown("---")
feature_col_1, feature_col_2, feature_col_3 = st.columns(3)
feature_col_1.markdown(
    """
    <div class="cyberscan-card">
        <h3>Ligera</h3>
        <p class="cyberscan-muted">Sin base de datos obligatoria ni dependencias pesadas para correr localmente.</p>
    </div>
    """,
    unsafe_allow_html=True,
)
feature_col_2.markdown(
    """
    <div class="cyberscan-card">
        <h3>Enfocada</h3>
        <p class="cyberscan-muted">Valida entradas publicas y presenta lo importante sin ruido visual innecesario.</p>
    </div>
    """,
    unsafe_allow_html=True,
)
feature_col_3.markdown(
    """
    <div class="cyberscan-card">
        <h3>Escalable</h3>
        <p class="cyberscan-muted">Lista para crecer con cache, historial, autenticacion y exportacion de reportes.</p>
    </div>
    """,
    unsafe_allow_html=True,
)
st.caption("CyberScan prioriza entradas publicas y evita el envio accidental de indicadores internos.")
