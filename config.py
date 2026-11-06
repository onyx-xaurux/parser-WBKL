import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# Файлы источников
SOURCES_FILE = BASE_DIR / "sources.txt"
TG_FILE = BASE_DIR / "tg.txt"

# Белые списки (создаются скриптом fetch_whitelist.py)
WHITELIST_IPS = BASE_DIR / "whitelist_ips.txt"
WHITELIST_SNI = BASE_DIR / "whitelist_sni.txt"

# Результаты
WORKING_FILE = BASE_DIR / "working_proxies.txt"
DEAD_CACHE_FILE = BASE_DIR / "dead_cache.json"

# Telegram
TG_API_ID = os.getenv("TG_API_ID", "").strip()
TG_API_HASH = os.getenv("TG_API_HASH", "").strip()
TG_SESSION_STRING = os.getenv("TG_SESSION_STRING", "").strip()

# Настройки проверки
CHECK_TIMEOUT = 10
MAX_CONCURRENT_CHECKS = 10
CACHE_TTL_HOURS = 2  # Проверять мертвые раз в 2 часа
