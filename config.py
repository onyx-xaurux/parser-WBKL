import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# Пути к файлам
SOURCES_FILE = BASE_DIR / "sources.txt"
TG_FILE = BASE_DIR / "tg.txt"
WHITELIST_FILE = BASE_DIR / "ru.sni.yaml.txt"
WORKING_FILE = BASE_DIR / "working_proxies.txt"
DEAD_CACHE_FILE = BASE_DIR / "dead_cache.json"

# Настройки Telegram
TG_API_ID = os.getenv("TG_API_ID", "").strip()
TG_API_HASH = os.getenv("TG_API_HASH", "").strip()
TG_SESSION_STRING = os.getenv("TG_SESSION_STRING", "").strip()
TG_MESSAGES_LIMIT = 50

# Настройки сети
CHECK_TIMEOUT = 10
MAX_DOWNLOAD_SIZE = 5 * 1024 * 1024
REQUEST_TIMEOUT = 25
MAX_CONCURRENT_CHECKS = 10

# Кеширование (в часах)
CACHE_TTL_HOURS = 2
