
import os
import json
import logging

from pathlib import Path
from dataclasses import dataclass
from dotenv import load_dotenv


# Загружаем переменные из .env, если файл существует
load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
CACHE_DIR = BASE_DIR / "cache"

DATA_DIR.mkdir(exist_ok=True)
CACHE_DIR.mkdir(exist_ok=True)


@dataclass
class Settings:
    # Telegram
    tg_api_id: str = os.getenv("TG_API_ID", "")
    tg_api_hash: str = os.getenv("TG_API_HASH", "")
    tg_session_string: str = os.getenv("TG_SESSION_STRING", "")

    # Файлы
    sources_file: Path = DATA_DIR / "sources.txt"
    telegram_sources_file: Path = DATA_DIR / "telegram_sources.txt"

    dead_cache_file: Path = BASE_DIR / "dead_cache.json"
    working_proxies_file: Path = BASE_DIR / "working_proxies.txt"

    # Кеш
    dead_cache_ttl: int = int(
        os.getenv("DEAD_CACHE_TTL", "86400")
    )

    # HTTP
    request_timeout: int = int(
        os.getenv("REQUEST_TIMEOUT", "15")
    )

    # Логирование
    log_level: str = os.getenv("LOG_LEVEL", "INFO")

    # Общие настройки
    max_concurrency: int = int(
        os.getenv("MAX_CONCURRENCY", "5")
    )

    @property
    def telegram_enabled(self) -> bool:
        return bool(
            self.tg_api_id
            and self.tg_api_hash
            and self.tg_session_string
        )


settings = Settings()


def setup_logging():
    logging.basicConfig(
        level=getattr(
            logging,
            settings.log_level.upper(),
            logging.INFO
        ),
        format=(
            "%(asctime)s | "
            "%(levelname)s | "
            "%(name)s | "
            "%(message)s"
        ),
        handlers=[
            logging.StreamHandler()
        ],
        force=True
    )


def load_json(path: Path, default=None):
    if default is None:
        default = {}

    try:
        if not path.exists():
            return default

        with path.open("r", encoding="utf-8") as file:
            return json.load(file)

    except (OSError, json.JSONDecodeError) as error:
        logging.error(
            "Не удалось загрузить %s: %s",
            path,
            error
        )
        return default


def save_json(path: Path, data):
    try:
        path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        temp_path = path.with_suffix(
            path.suffix + ".tmp"
        )

        with temp_path.open("w", encoding="utf-8") as file:
            json.dump(
                data,
                file,
                ensure_ascii=False,
                indent=4
            )

        temp_path.replace(path)

    except OSError as error:
        logging.error(
            "Не удалось сохранить %s: %s",
            path,
            error
        )
        raise


if __name__ == "__main__":
    setup_logging()

    print("Project configuration loaded")
    print(f"Base directory: {BASE_DIR}")
    print(f"Telegram enabled: {settings.telegram_enabled}")
    print(f"Dead cache TTL: {settings.dead_cache_ttl}")
