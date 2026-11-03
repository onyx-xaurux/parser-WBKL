import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# Источники
SOURCES_FILE = BASE_DIR / "sources.txt"
TG_FILE = BASE_DIR / "tg.txt"

# Единый whitelist
WHITELIST_FILE = BASE_DIR / "whitelist.txt"

# Результаты
WORKING_FILE = BASE_DIR / "working_proxies.txt"
DEAD_CACHE_FILE = BASE_DIR / "dead_cache.json"

# Telegram Secrets
TG_API_ID = os.getenv("TG_API_ID", "")
TG_API_HASH = os.getenv("TG_API_HASH", "")
TG_SESSION_STRING = os.getenv("TG_SESSION_STRING", "")

# Базовый прокси
BASE_PROXY = os.getenv("BASE_PROXY", "").strip()

# sing-box
SING_BOX_PATH = os.getenv("SING_BOX_PATH", "sing-box")

# Проверка
CHECK_URL = "https://cp.cloudflare.com/generate_204"
CHECK_TIMEOUT = 15
MAX_CONCURRENT_CHECKS = 4

# Dead cache
DEAD_CACHE_HOURS = 2

# Загрузка источников
REQUEST_TIMEOUT = 20
MAX_DOWNLOAD_SIZE = 5 * 1024 * 1024

# Telegram
TG_MESSAGES_LIMIT = 50

SUPPORTED_PROTOCOLS = (
    "vless://",
    "vmess://",
    "trojan://",
)

ENCODING = "utf-8"
