
import asyncio
import json
import logging
import os
import tempfile
import time

from pathlib import Path
from dataclasses import dataclass
from typing import Optional


from config import settings, load_json, save_json


logger = logging.getLogger(__name__)


@dataclass
class CacheEntry:
    address: str
    timestamp: float
    reason: str


class DeadCache:
    """
    Хранилище записей о ранее недоступных узлах.

    TTL задаётся в секундах.
    """

    def __init__(
        self,
        path: Path = settings.dead_cache_file,
        ttl: int = settings.dead_cache_ttl
    ):
        self.path = Path(path)
        self.ttl = ttl
        self.entries = self._load()

    def _load(self) -> dict:
        data = load_json(self.path, default={})

        if not isinstance(data, dict):
            logger.warning("Invalid cache format")
            return {}

        return data

    def _is_expired(self, timestamp: float) -> bool:
        return time.time() - timestamp > self.ttl

    def cleanup(self):
        """Удаляет записи с истёкшим TTL."""

        original_count = len(self.entries)

        self.entries = {
            address: entry
            for address, entry in self.entries.items()
            if isinstance(entry, dict)
            and isinstance(entry.get("timestamp"), (int, float))
            and not self._is_expired(entry["timestamp"])
        }

        removed = original_count - len(self.entries)

        if removed:
            logger.info(
                "Cache cleanup: removed %d expired entries",
                removed
            )

        self.save()

    def contains(self, address: str) -> bool:
        entry = self.entries.get(address)

        if not isinstance(entry, dict):
            return False

        timestamp = entry.get("timestamp")

        if not isinstance(timestamp, (int, float)):
            return False

        if self._is_expired(timestamp):
            self.entries.pop(address, None)
            return False

        return True

    def add(
        self,
        address: str,
        reason: str = "unavailable"
    ):
        self.entries[address] = {
            "timestamp": time.time(),
            "reason": reason
        }

        logger.info("Added to dead cache: %s", address)

    def remove(self, address: str):
        self.entries.pop(address, None)

    def save(self):
        save_json(self.path, self.entries)

    def count(self) -> int:
        return len(self.entries)


class TemporaryConfig:
    """
    Безопасное создание временного JSON-файла.
    """

    def __init__(self, config: dict):
        self.config = config
        self.path: Optional[Path] = None

    def __enter__(self):
        fd, filename = tempfile.mkstemp(
            suffix=".json",
            prefix="xray_"
        )

        self.path = Path(filename)

        try:
            with os.fdopen(fd, "w", encoding="utf-8") as file:
                json.dump(
                    self.config,
                    file,
                    ensure_ascii=False,
                    indent=2
                )
        except Exception:
            self.path.unlink(missing_ok=True)
            self.path = None
            raise

        return self.path

    def __exit__(self, exc_type, exc_value, traceback):
        if self.path:
            self.path.unlink(missing_ok=True)


class XrayProcess:
    """
    Управление жизненным циклом локального Xray subprocess.

    Этот класс не формирует конфигурации подключения
    и не сканирует внешние узлы.
    """

    def __init__(
        self,
        binary_path: Path,
        config_path: Path
    ):
        self.binary_path = Path(binary_path)
        self.config_path = Path(config_path)
        self.process: Optional[asyncio.subprocess.Process] = None

    async def start(self):
        if not self.binary_path.is_file():
            raise FileNotFoundError(
                f"Xray binary not found: {self.binary_path}"
            )

        if not self.config_path.is_file():
            raise FileNotFoundError(
                f"Config not found: {self.config_path}"
            )

        self.process = await asyncio.create_subprocess_exec(
            str(self.binary_path),
            "run",
            "-c",
            str(self.config_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT
        )

        logger.info(
            "Xray process started, PID=%s",
            self.process.pid
        )

    async def stop(self):
        if self.process is None:
            return

        if self.process.returncode is None:
            self.process.terminate()

            try:
                await asyncio.wait_for(
                    self.process.wait(),
                    timeout=5
                )
            except asyncio.TimeoutError:
                self.process.kill()
                await self.process.wait()

        logger.info("Xray process stopped")

        self.process = None

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.stop()


class Checker:
    """
    Общий менеджер состояния проверки.
    """

    def __init__(self):
        self.cache = DeadCache()

    def initialize(self):
        self.cache.cleanup()

        logger.info(
            "Checker initialized. Dead cache entries: %d",
            self.cache.count()
        )

    def is_cached(self, address: str) -> bool:
        return self.cache.contains(address)

    def mark_dead(
        self,
        address: str,
        reason: str = "unavailable"
    ):
        self.cache.add(address, reason)
        self.cache.save()

    def clear_dead(self, address: str):
        self.cache.remove(address)
        self.cache.save()


async def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s"
    )

    checker = Checker()
    checker.initialize()

    logger.info("Checker module is ready")


if __name__ == "__main__":
    asyncio.run(main())
