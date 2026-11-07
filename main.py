import asyncio
import logging
import sys
from parser import collect_all
from checker import Checker
from proxy_fetcher import get_working_proxy
from config import WORKING_FILE, MAX_CONCURRENT_CHECKS

logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | %(message)s', stream=sys.stdout)
logger = logging.getLogger("scanner")

async def main():
    logger.info("=== ЗАПУСК СКАНИРОВАНИЯ ===")
    
    # 1. Ищем валидный базовый прокси (РФ)
    base_proxy = await get_working_proxy()
    
    # 2. Собираем конфиги
    configs = await collect_all()
    logger.info(f"К проверке готово конфигов: {len(configs)}")
    
    if not configs:
        return

    # 3. Проверяем
    checker = Checker(base_proxy=base_proxy)
    sem = asyncio.Semaphore(MAX_CONCURRENT_CHECKS)
    
    async def check_pair(cfg):
        async with sem:
            ip = cfg.get('server')
            sni = cfg.get('sni')
            raw = cfg.get('raw')
            proto = cfg.get('protocol', 'vless')
            
            if await checker.check(ip, sni, raw, proto):
                logger.info(f"[ALIVE] {raw[:60]}...")
                return raw
            return None

    logger.info("Начинаем проверку...")
    tasks = [check_pair(cfg) for cfg in configs]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    for res in results:
        if isinstance(res, Exception):
            logger.error(f"[GATHER ERROR] {type(res).__name__}: {res}")

    alive = [r for r in results if r and not isinstance(r, Exception)]
    WORKING_FILE.write_text("\n".join(alive), encoding="utf-8")
    checker.save()
    
    logger.info(f"=== ГОТОВО. РАБОЧИХ ПРОКСИ: {len(alive)} ===")
    await asyncio.sleep(1)

if __name__ == "__main__":
    asyncio.run(main())
