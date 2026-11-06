import asyncio
import logging
import sys
from parser import collect_all
from checker import Checker
from config import WORKING_FILE, MAX_CONCURRENT_CHECKS

logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | %(message)s', stream=sys.stdout)
logger = logging.getLogger("scanner")

async def main():
    logger.info("=== ЗАПУСК СКАНИРОВАНИЯ ===")
    
    # 1. Сбор данных
    configs = await collect_all()
    logger.info(f"К проверке готово конфигов: {len(configs)}")
    if not configs:
        return

    # 2. Проверка
    checker = Checker()
    sem = asyncio.Semaphore(MAX_CONCURRENT_CHECKS)
    
    async def check_pair(cfg):
        async with sem:
            # Безопасно достаем данные, поддерживаем и dict, и объекты класса
            if isinstance(cfg, dict):
                ip = cfg.get('server') or cfg.get('ip') or ""
                sni = cfg.get('sni') or cfg.get('host') or ""
                raw = cfg.get('raw') or cfg.get('link') or ""
            else:
                ip = getattr(cfg, 'server', getattr(cfg, 'ip', ""))
                sni = getattr(cfg, 'sni', getattr(cfg, 'host', ""))
                raw = getattr(cfg, 'raw', getattr(cfg, 'original_link', ""))
            
            if not ip or not sni:
                return None

            if await checker.check(ip, sni, raw):
                logger.info(f"[ALIVE] {raw[:60]}...")
                return raw
            return None

    logger.info("Начинаем проверку...")
    tasks = [check_pair(cfg) for cfg in configs]
    results = await asyncio.gather(*tasks)
    
    # 3. Сохранение
    alive = [r for r in results if r]
    WORKING_FILE.write_text("\n".join(alive), encoding="utf-8")
    checker.save()
    
    logger.info(f"=== ГОТОВО. РАБОЧИХ ПРОКСИ: {len(alive)} ===")

if __name__ == "__main__":
    asyncio.run(main())
