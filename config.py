import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
SOURCES_FILE = BASE_DIR / "sources.txt"
TG_FILE = BASE_DIR / "tg.txt"
WHITELIST_FILE = BASE_DIR / "ru.sni.yaml.txt"
WORKING_FILE = BASE_DIR / "working_proxies.txt"
DEAD_CACHE_FILE = BASE_DIR / "dead_cache.json"

TG_API_ID = os.getenv("TG_API_ID", "").strip()
TG_API_HASH = os.getenv("TG_API_HASH", "").strip()
TG_SESSION_STRING = os.getenv("TG_SESSION_STRING", "").strip()
BASE_PROXY = os.getenv("BASE_PROXY", "").strip()

SING_BOX_PATH = os.getenv("SING_BOX_PATH", "sing-box")
SING_BOX_VERSION = "1.11.15"

CHECK_URLS = {
    "cloudflare": "https://cp.cloudflare.com/generate_204",
    "apple": "https://captive.apple.com",
    "telegram": "https://api.telegram.org",
}
CHECK_TIMEOUT = 15
MAX_CONCURRENT_CHECKS = 3
RECHECK_AFTER_HOURS = 2
REQUEST_TIMEOUT = 25
MAX_DOWNLOAD_SIZE = 5 * 1024 * 1024
TG_MESSAGES_LIMIT = 50

SUPPORTED_PROTOCOLS = ("vless://", "vmess://", "trojan://", "ss://")
