from pathlib import Path
import os

try:
    from dotenv import load_dotenv
except ModuleNotFoundError:  # pragma: no cover - fallback para entornos minimos
    load_dotenv = None


PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENV_PATH = PROJECT_ROOT / ".env"


def _load_env_file_manually(env_path: Path) -> bool:
    loaded = False
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if not key or key in os.environ:
            continue

        os.environ[key] = value
        loaded = True

    return loaded


def load_project_env() -> bool:
    if not ENV_PATH.exists():
        return False
    if load_dotenv is not None:
        return load_dotenv(dotenv_path=ENV_PATH, override=False)
    return _load_env_file_manually(ENV_PATH)
