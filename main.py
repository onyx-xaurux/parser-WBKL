import asyncio
import logging
import sys
import os
import re

from parser import collect_all
from checker import Checker
from config import WORKING_FILE, MAX_CONCURRENT_CHECKS

logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s | %(levelname)s | %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger("scanner")

async def main():
    logger.info("=========================================")
    logger.info("ЗАПУСК СКАНИРОВАНИЯ")
    logger.info("=========================================")

    # 1. Собираем конфиги (парсер сам скачает белые списки и отфильтрует)
    configs = await collect_all()
    logger.info(f"Найдено и отфильтровано конфигов: {len(configs)}")

    if not configs:
        logger.warning("Нет конфигов для проверки. Выход.")
        return

    # 2. Проверяем
    checker = Checker()
    sem = asyncio.Semaphore(MAX_CONCURRENT_CHECKS)
    
    async def check_pair(cfg):
        async with sem:
            raw = cfg.get("raw", "")
            ip = cfg.get("server", "")
            sni = cfg.get("sni", "")
            
            if not ip or not sni:
                return None
                
            is_alive = await checker.check(ip, sni, raw)
            if is_alive:
                logger.info(f"[ЖИВОЙ] {raw[:50]}...")
                return raw
            return None

    logger.info(f"Начинаем проверку {len(configs)} конфигов...")
    tasks = [check_pair(cfg) for cfg in configs]
    results = await asyncio.gather(*tasks)

    alive = [r for r in results if r]
    
    # 3. Сохраняем
    WORKING_FILE.write_text("\n".join(alive), encoding="utf-8")
    checker.save_cache()
    
    logger.info("=========================================")
    logger.info(f"ГОТОВО! РАБОЧИХ ПРОКСИ: {len(alive)}")
    logger.info("=========================================")

if __name__ == "__main__":
    asyncio.run(main())
