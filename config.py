from pathlib import Path

# Пути к файлам
PARSED_RESULTS = Path("parsed_results.json")
WORKING_PROXIES = Path("working_proxies.txt")
DEAD_CACHE = Path("dead_cache.json")

# Белые списки
WHITELIST_IPS = Path("whitelist_ips.txt")
WHITELIST_SNI = Path("whitelist_sni.txt")

# Настройки проверки
CHECK_TIMEOUT = 5  # секунд на проверку одного сервера
MAX_CONCURRENT_CHECKS = 50  # одновременных проверок
CACHE_TTL_HOURS = 24  # сколько часов помнить мертвый сервер
