import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

SOURCES_FILE = BASE_DIR / "sources.txt"
TG_FILE = BASE_DIR / "tg.txt"

WHITELIST_FILE = BASE_DIR / "whitelist.txt"

WORKING_FILE = BASE_DIR / "working_proxies.txt"
DEAD_CACHE_FILE = BASE_DIR / "dead_cache.json"

TG_API_ID = os.getenv("TG_API_ID", "")
TG_API_HASH = os.getenv("TG_API_HASH", "")
TG_SESSION_STRING = os.getenv("TG_SESSION_STRING", "")

BASE_PROXY = os.getenv("BASE_PROXY", "").strip()

SING_BOX_PATH = os.getenv("SING_BOX_PATH", "sing-box")

CHECK_URL = "https://cp.cloudflare.com/generate_204"

CHECK_TIMEOUT = 15
MAX_CONCURRENT_CHECKS = 4

DEAD_CACHE_HOURS = 2

REQUEST_TIMEOUT = 20
MAX_DOWNLOAD_SIZE = 5 * 1024 * 1024

SUPPORTED_PROTOCOLS = (
    "vless://",
    "vmess://",
    "trojan://",
)

ENCODING = "utf-8"
