import os
import tempfile
from pathlib import Path
from typing import Set

class Settings:
    PROJECT_NAME: str = "AppSec Sentinel - Production Readiness & Vulnerability Auditor"
    VERSION: str = "3.0.0"
    API_PREFIX: str = "/api"

    MAX_FILE_SIZE_BYTES: int = int(os.getenv("MAX_FILE_SIZE_BYTES", 100 * 1024 * 1024))
    ALLOWED_EXTENSIONS: Set[str] = {".apk", ".exe"}

    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent
    STORAGE_DIR: Path = Path(os.getenv("STORAGE_DIR", os.path.join(tempfile.gettempdir(), "appsec_sentinel", "uploads")))
    REPORT_DIR: Path = Path(os.getenv("REPORT_DIR", os.path.join(tempfile.gettempdir(), "appsec_sentinel", "reports")))

    RATE_LIMIT_REQUESTS_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_RPM", "60"))
    CORS_ORIGINS: list[str] = ["*"]

    LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "none")
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    OLLAMA_URL: str = os.getenv("OLLAMA_URL", "http://localhost:11434")

    ZIP_BOMB_MAX_RATIO: float = 10.0
    ZIP_BOMB_MAX_UNCOMPRESSED_BYTES: int = 300 * 1024 * 1024

settings = Settings()
settings.STORAGE_DIR.mkdir(parents=True, exist_ok=True)
settings.REPORT_DIR.mkdir(parents=True, exist_ok=True)
