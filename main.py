import asyncio
import logging

from config import WORKING_FILE
from parser import collect_all
from checker import check_all

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(asctime)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

logger = logging.getLogger(__name__)


async def main():
    logger.info("========== PROXY PARSER START ==========")

    try:
        configs = await collect_all()
        logger.info("После фильтрации: %d", len(configs))

        alive = await check_all(configs)

        unique = {
            config["raw"]: config
            for config in alive
        }

        output = "\n".join(unique.keys())

        WORKING_FILE.write_text(
            output + ("\n" if output else ""),
            encoding="utf-8"
        )

        logger.info(
            "Рабочих конфигов сохранено: %d",
            len(unique)
        )

        logger.info("========== PARSER FINISHED ==========")

    except Exception:
        logger.exception("Критическая ошибка программы")
        raise


if __name__ == "__main__":
    asyncio.run(main())
    
