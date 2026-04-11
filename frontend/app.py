import streamlit as st
import requests
import time
from stqdm import stqdm 

st.set_page_config(page_title="CyberScan", page_icon="🛡️", layout="centered")

BASE_URL = "http://127.0.0.1:8000"
REQUEST_TIMEOUT = 30
POLL_INTERVAL = 2
MAX_POLLS = 15

# Aviso de privacidad
privacy_accepted = st.checkbox("Acepto que este archivo será analizado externamente. No debo subir contenido confidencial.")
if not privacy_accepted:
    st.warning("Debes aceptar los términos para proceder.")
    st.stop()

# Subir archivo
uploaded_file = st.file_uploader("Selecciona un archivo")
if uploaded_file:
    st.subheader(f"Subiendo archivo: {uploaded_file.name}")
    # Aquí va el código para subir el archivo con SHA-256, y la lógica de analización
    # Recuerda usar la función de reintentos y manejo de errores
    with st.spinner("Analizando..."):
        result_data = scan_file(uploaded_file)  # Función de análisis
        render_result(result_data)

def show_progress_bar():
    with stqdm(total=100, desc="Analizando...") as progress_bar:
        for i in range(100):
            time.sleep(0.1)  # Simula trabajo
            progress_bar.update(1)

show_progress_bar()

def show_friendly_result(risk):
    risk = str(risk).upper()
    if risk == "HIGH RISK":
        st.error("🚨 Alto riesgo detectado")
        st.write("Este contenido podría ser peligroso. Se recomienda no abrirlo ni ejecutarlo.")
    elif risk == "MEDIUM RISK":
        st.warning("⚠️ Riesgo medio")
        st.write("Se detectaron elementos sospechosos. Procede con precaución.")
    elif risk == "LOW RISK":
        st.info("🔎 Riesgo bajo")
        st.write("Se detectó un riesgo bajo. Revisa los detalles antes de continuar.")
    else:
        st.success("✅ Seguro")
        st.write("No se detectaron amenazas conocidas.")

def render_result(result_data):
    risk = result_data.get("risk", "UNKNOWN")
    stats = result_data.get("stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)
    show_friendly_result(risk)
    st.metric("Nivel de riesgo", risk)
    st.metric("Detecciones", malicious)
    c1, c2, c3 = st.columns(3)
    c1.metric("Malicious", malicious)
    c2.metric("Suspicious", suspicious)
    c3.metric("Undetected", undetected)
    with st.expander("🔍 Detalles técnicos"):
        st.json(result_data)

def poll_result(analysis_id):
    """
    Consulta repetidamente el resultado hasta que esté completado
    o hasta agotar los intentos.
    """
    for _ in range(MAX_POLLS):
        try:
            response = requests.get(
                f"{BASE_URL}/scan/result/{analysis_id}",
                timeout=REQUEST_TIMEOUT
            )
            response.raise_for_status()
            result_data = response.json()

            status = str(result_data.get("status", "")).lower()

            if status == "completed":
                return result_data

            if status in ["failed", "error"]:
                return {
                    "status": "error",
                    "message": result_data.get("message", "El análisis falló.")
                }

            time.sleep(POLL_INTERVAL)

        except requests.exceptions.RequestException as e:
            return {
                "status": "error",
                "message": f"Error consultando resultado: {e}"
            }

    return {
        "status": "timeout",
        "message": "El análisis tardó demasiado. Intenta nuevamente en unos segundos."
    }

def scan_file(uploaded_file):
    try:
        st.info(f"Enviando archivo: {uploaded_file.name}")
        response = requests.post(
            f"{BASE_URL}/scan/file",
            files={"file": (uploaded_file.name, uploaded_file.getvalue())},
            timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        data = response.json()

        # Si la API devuelve el riesgo directamente, usa esa información para mostrar los resultados
        risk = data.get("risk", "UNKNOWN")
        show_friendly_result(risk)
        
        # Muestra el resto de la información recibida
        if "stats" in data:
            stats = data["stats"]
            st.metric("Nivel de riesgo", risk)
            st.metric("Detecciones", stats.get("malicious", 0))
            
            c1, c2, c3 = st.columns(3)
            c1.metric("Malicious", stats.get("malicious", 0))
            c2.metric("Suspicious", stats.get("suspicious", 0))
            c3.metric("Undetected", stats.get("undetected", 0))
            
            with st.expander("🔍 Detalles técnicos"):
                st.json(data)

        else:
            st.error("No se encontraron estadísticas detalladas.")

    except requests.exceptions.RequestException as e:
        st.error(f"Error al enviar el archivo al backend: {e}")
    except ValueError:
        st.error("La respuesta del backend no es JSON válido.")

def scan_url(url):
    try:
        response = requests.post(
            f"{BASE_URL}/scan/url",
            json={"url": url},
            timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        data = response.json()

        analysis_id = data.get("analysis_id")

        if not analysis_id:
            st.error("No se pudo obtener el ID del análisis de la URL.")
            st.json(data)
            return

        result_data = poll_result(analysis_id)

        if result_data.get("status") == "completed":
            render_result(result_data)
        elif result_data.get("status") == "timeout":
            st.warning(result_data.get("message", "Tiempo de espera agotado."))
        else:
            st.error(result_data.get("message", "No se pudo completar el análisis."))

    except requests.exceptions.RequestException as e:
        st.error(f"Error al enviar la URL al backend: {e}")
    except ValueError:
        st.error("La respuesta del backend no es JSON válido.")

# HEADER
st.markdown("# 🛡️ CyberScan Dashboard")
st.caption("🚀 Avalon Labs | Arturo Badillo")

# SIDEBAR
st.sidebar.title("🛡️ CyberScan")
st.sidebar.markdown("### Panel")
st.sidebar.info(
    """
✔️ Escaneo de archivos  
✔️ Escaneo de URLs  
✔️ Clasificación automática  
"""
)
st.sidebar.markdown("---")
st.sidebar.caption("Avalon Labs 🚀")

# SELECTOR
option = st.radio("Selecciona tipo de análisis:", ["Archivo", "URL"])
col1, col2 = st.columns([1, 1])

# 📂 ARCHIVO
if option == "Archivo":
    with col1:
        st.subheader("📂 Subir archivo")
        uploaded_file = st.file_uploader("Selecciona un archivo")
        analyze_file = st.button("Analizar archivo", key="analyze_file")
    if analyze_file:
        with col2:
            st.subheader("📊 Resultado")

            if not uploaded_file:
                st.warning("Debes seleccionar un archivo antes de analizar.")
            else:
                with st.spinner("Analizando archivo..."):
                    scan_file(uploaded_file)

# 🌐 URL
if option == "URL":
    with col1:
        st.subheader("🌐 Analizar URL")
        url = st.text_input("Ingresa una URL")
        analyze_url = st.button("Analizar URL", key="analyze_url")
    if analyze_url:
        with col2:
            st.subheader("📊 Resultado")
            if not url:
                st.warning("Debes ingresar una URL.")
            elif not url.startswith(("http://", "https://")):
                st.warning("Ingresa una URL válida (http:// o https://)")
            else:
                with st.spinner("Analizando URL..."):
                    scan_url(url)

# FOOTER
st.markdown("---")
st.markdown(
    """
    <div style='text-align: center; opacity: 0.7;'>
        🛡️ CyberScan Dashboard <br>
        ⚡ Built by: Arturo Badillo | Avalon Labs
    </div>
    """,
    unsafe_allow_html=True
)