# 🛡️ CyberScan Dashboard

> 🚀 Plataforma inteligente de análisis de amenazas para archivos y URLs
> ⚡ Powered by Avalon Labs
> 👤 Author: Arturo Badillo

---

## 🌐 Overview

**CyberScan** es una aplicación web que permite analizar archivos y URLs en busca de posibles amenazas utilizando la API de **VirusTotal**.

El sistema está diseñado con una arquitectura moderna:

- 🔙 Backend: API con FastAPI
- 🎨 Frontend: Dashboard interactivo con Streamlit
- 🧠 Análisis: Clasificación automática de riesgo basada en múltiples motores antivirus

---

## ✨ Features

✔️ Escaneo de archivos en tiempo real
✔️ Análisis de URLs sospechosas
✔️ Clasificación de riesgo (LOW / MEDIUM / HIGH)
✔️ Visualización amigable para usuarios no técnicos
✔️ Dashboard moderno estilo SaaS
✔️ Modo claro / oscuro
✔️ Detalles técnicos expandibles
✔️ Integración con VirusTotal API

---

## 🧠 ¿Cómo funciona?

1. El usuario sube un archivo o ingresa una URL
2. Se envía a la API backend
3. Se consulta o sube a VirusTotal
4. Se obtiene el resultado del análisis
5. Se clasifica el riesgo automáticamente
6. Se presenta en un dashboard visual

---

## 🖼️ Preview

_(Aquí puedes agregar screenshots del dashboard más adelante)_

---

## 🛠️ Tech Stack

- 🐍 Python
- ⚡ FastAPI
- 🎨 Streamlit
- 🔍 VirusTotal API
- 📦 Requests

---

## ⚙️ Instalación

### 1. Clonar repositorio

```bash
git clone https://github.com/tu-usuario/cyberscan.git
cd cyberscan
```

---

### 2. Crear entorno virtual

```bash
python -m venv .venv
source .venv/bin/activate  # Linux / Mac
.venv\Scripts\activate     # Windows
```

---

### 3. Instalar dependencias

```bash
pip install -r requirements.txt
```

---

### 4. Configurar API Key

En:

```bash
backend/services/virustotal.py
```

Agrega tu API Key:

```python
API_KEY = "TU_API_KEY"
```

---

## ▶️ Ejecución

### 🔹 Backend

```bash
uvicorn backend.main:app --reload
```

👉 Disponible en:
http://127.0.0.1:8000

---

### 🔹 Frontend

```bash
streamlit run frontend/app.py
```

👉 Disponible en:
http://localhost:8501

---

## 📊 Ejemplo de resultado

```json
{
  "status": "completed",
  "risk": "LOW RISK",
  "stats": {
    "malicious": 0,
    "suspicious": 0,
    "undetected": 62
  }
}
```

---

## 🚀 Roadmap

- [ ] 🌍 Deploy público
- [ ] 🧾 Historial de análisis
- [ ] 🔐 Autenticación de usuarios
- [ ] 📊 Gráficos de resultados
- [ ] 🤖 Explicación con IA

---

## 🧑‍💻 Autor

**Arturo Badillo**
🚀 Avalon Labs

---

## ⚠️ Disclaimer

Este proyecto es educativo y depende de la API de VirusTotal.
No reemplaza soluciones profesionales de ciberseguridad.

---

## ⭐ Support

Si te gusta este proyecto:

👉 Dale una estrella ⭐ en GitHub
👉 Compártelo
👉 Úsalo como base para tus propios proyectos
👉 Dona

---

## ☕ Buy Me a Coffee

Si quieres apoyar el proyecto:

## [![Buy Me a Coffee](https://img.shields.io/badge/Support-Buy%20Me%20a%20Coffee-orange?style=for-the-badge&logo=paypal)](https://paypal.me/arararcadabra?locale.x=es_XC&country.x=EC)

---

## 🛡️ Avalon Labs

> “Building the future of software”
