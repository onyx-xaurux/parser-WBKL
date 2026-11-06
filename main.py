import asyncio
import logging
import sys
import traceback
from parser import collect_all
from checker import Checker
from config import WORKING_FILE, MAX_CONCURRENT_CHECKS

logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | %(message)s', stream=sys.stdout)
logger = logging.getLogger("scanner")

async def main():
    logger.info("=== ЗАПУСК СКАНИРОВАНИЯ ===")
    
    configs = await collect_all()
    logger.info(f"К проверке готово конфигов: {len(configs)}")
    
    if not configs:
        return

    # Выводим ключи для отладки
    for c in configs[:3]:
        logger.info(f"DEBUG: {c.get('protocol')} | {c.get('raw', '')[:60]}...")
        logger.info(f"DEBUG KEYS: {list(c.keys())}")
        logger.info(f"DEBUG IP/SNI: {c.get('server')} / {c.get('sni')}")

    checker = Checker()
    sem = asyncio.Semaphore(MAX_CONCURRENT_CHECKS)
    
    async def check_pair(cfg):
        async with sem:
            try:
                ip = cfg.get('server')
                sni = cfg.get('sni')
                raw = cfg.get('raw')
                proto = cfg.get('protocol', 'vless')
                
                if not ip or not sni:
                    logger.error(f"[SKIP] Пустой IP или SNI: {cfg}")
                    return None
                
                if await checker.check(ip, sni, raw, proto):
                    logger.info(f"[ALIVE] {raw[:60]}...")
                    return raw
                return None
            except Exception as e:
                logger.error(f"[CRITICAL] Ошибка при проверке {str(cfg.get('raw', ''))[:30]}: {e}")
                traceback.print_exc()
                return None

    logger.info("Начинаем проверку...")
    tasks = [check_pair(cfg) for cfg in configs]
    results = await asyncio.gather(*tasks)
    
    alive = [r for r in results if r]
    WORKING_FILE.write_text("\n".join(alive), encoding="utf-8")
    checker.save()
    
    logger.info(f"=== ГОТОВО. РАБОЧИХ ПРОКСИ: {len(alive)} ===")
    await asyncio.sleep(1)

if __name__ == "__main__":
    asyncio.run(main())
