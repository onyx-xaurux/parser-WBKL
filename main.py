import asyncio
import logging

from config import WORKING_FILE
from parser import collect_all
from checker import check_all

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(asctime)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

async def main():
    log.info("========== PROXY PARSER START ==========")
    configs = await collect_all()
    log.info("После сбора и whitelist: %d", len(configs))
    alive = await check_all(configs)
    log.info("Новых успешных проверок: %d", len(alive))
    log.info("Всего строк в архиве: %d", len(WORKING_FILE.read_text(encoding="utf-8").splitlines()) if WORKING_FILE.exists() else 0)
    log.info("========== PARSER FINISHED ==========")

if __name__ == "__main__":
    asyncio.run(main())
