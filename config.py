import os
from pathlib import Path

# Корневая директория проекта
BASE_DIR = Path(__file__).resolve().parent

# Файлы проекта
SOURCES_FILE = BASE_DIR / "sources.txt"
TG_FILE = BASE_DIR / "tg.txt"

WHITELIST_IPS_FILE = BASE_DIR / "whitelist_ips.txt"
WHITELIST_SNI_FILE = BASE_DIR / "whitelist_sni.txt"

WORKING_FILE = BASE_DIR / "working_proxies.txt"
DEAD_CACHE_FILE = BASE_DIR / "dead_cache.json"

# Telegram
TG_API_ID = os.getenv("TG_API_ID", "")
TG_API_HASH = os.getenv("TG_API_HASH", "")
TG_SESSION_STRING = os.getenv("TG_SESSION_STRING", "")

# Базовый SOCKS/HTTP-прокси
BASE_PROXY = os.getenv("BASE_PROXY", "").strip()

# Настройки проверки
CHECK_URL = "https://cp.cloudflare.com/generate_204"

CHECK_TIMEOUT = 15
MAX_CONCURRENT_CHECKS = 20

# Кеш нерабочих серверов
DEAD_CACHE_HOURS = 2

# Ограничения загрузки
REQUEST_TIMEOUT = 20
MAX_DOWNLOAD_SIZE = 5 * 1024 * 1024

# Поддерживаемые протоколы
SUPPORTED_PROTOCOLS = (
    "vless://",
    "vmess://",
    "trojan://",
)

# Кодировка
ENCODING = "utf-8"
