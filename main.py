import asyncio
import logging
import sys
from pathlib import Path

from config import WHITELIST_IPS, WHITELIST_SNI, WORKING_PROXIES, CHECK_TIMEOUT
from parser import parse_text
from checker import Checker

logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(message)s')
logger = logging.getLogger("scanner")

async def main():
    # 1. Загружаем белые списки
    if not WHITELIST_IPS.exists() or not WHITELIST_SNI.exists():
        logger.error("Whitelists not found! Run fetch_whitelist.py first.")
        sys.exit(1)

    allowed_ips = set(WHITELIST_IPS.read_text(encoding="utf-8").splitlines())
    allowed_snis = set(WHITELIST_SNI.read_text(encoding="utf-8").splitlines())
    logger.info(f"Loaded {len(allowed_ips)} allowed IPs and {len(allowed_snis)} SNIs")

    # 2. Читаем локальные источники (если есть)
    sources = Path("sources.txt")
    text = ""
    if sources.exists():
        text = sources.read_text(encoding="utf-8")
    else:
        logger.warning("sources.txt not found, using empty text")

    # 3. Парсим
    found_ips, found_hosts = parse_text(text)
    logger.info(f"Found {len(found_ips)} IPs and {len(found_hosts)} Hosts in sources")

    # 4. Фильтруем по белому списку
    # Берем только те домены, что есть в белом списке
    valid_snis = [h for h in found_hosts if h in allowed_snis]
    logger.info(f"Filtered to {len(valid_snis)} valid SNIs")

    if not valid_snis:
        logger.warning("No valid SNIs found. Nothing to check.")
        return

    checker = Checker()
    alive = []

    # 5. Проверяем
    # Для каждой связки IP:PORT из источников + валидный SNI
    tasks = []
    for ip_port in found_ips:
        ip = ip_port.split(":")[0]
        if ip not in allowed_ips:
            continue # Пропускаем IP, которых нет в белом списке
        
        for sni in valid_snis:
            tasks.append(checker.check(ip, sni))

    if not tasks:
        logger.warning("No valid pairs to check.")
        return

    logger.info(f"Starting check for {len(tasks)} pairs...")
    results = await asyncio.gather(*tasks)

    for task_idx, (ip_port, sni) in enumerate([(ip, sni) for ip in found_ips for sni in valid_snis]):
        pass # тут нужно сопоставить результаты

    # Так как gather не возвращает индексы, сделаем проще:
    checked_results = []
    for ip_port in found_ips:
        ip = ip_port.split(":")[0]
        if ip not in allowed_ips: continue
        for sni in valid_snis:
            checked_results.append((ip_port, sni))

    # Пакетная проверка
    sem = asyncio.Semaphore(50)
    
    async def check_pair(ip_port, sni):
        async with sem:
            ip = ip_port.split(":")[0]
            is_alive = await checker.check(ip, sni)
            if is_alive:
                logger.info(f"[ALIVE] {ip_port}#{sni}")
                return f"{ip_port}#{sni}"
            return None

    final_tasks = [check_pair(ip, sni) for ip, sni in checked_results]
    final_results = await asyncio.gather(*final_tasks)

    alive = [r for r in final_results if r]
    
    # 6. Сохраняем результаты
    WORKING_PROXIES.write_text("\n".join(alive), encoding="utf-8")
    checker.save_cache()
    
    logger.info(f"Done! Alive: {len(alive)}. Saved to {WORKING_PROXIES}")

if __name__ == "__main__":
    asyncio.run(main())
