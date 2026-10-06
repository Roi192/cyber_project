"""Configuration - every value comes from environment variables (.env)."""
import os

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _int(name, default):
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


HOST = os.getenv("HOST", "0.0.0.0")
PORT = _int("PORT", 5002)
SECRET_KEY = os.getenv("SECRET_KEY", "dev-only-change-me")
API_KEY = os.getenv("API_KEY", "").strip()

DATABASE_PATH = os.path.join(BASE_DIR, os.getenv("DATABASE_PATH", "data/monitoring.db"))
RETENTION_DAYS = _int("RETENTION_DAYS", 30)
REPUTATION_CACHE_HOURS = _int("REPUTATION_CACHE_HOURS", 24)
VT_API_KEY = os.getenv("VT_API_KEY", "").strip()
