import asyncio
import logging
import json
import sys

from pathlib import Path
from datetime import datetime, timezone

from config import settings, setup_logging
from parser import parse_text
from checker import Checker


logger = logging.getLogger("proxy_scanner")


class Scanner:

    def __init__(self):
        self.checker = Checker()

        self.addresses = set()
        self.hosts = set()

        self.stats = {
            "sources_processed": 0,
            "sources_failed": 0,
            "addresses_found": 0,
            "hosts_found": 0,
            "checked": 0,
            "alive": 0,
            "dead": 0,
            "skipped_from_cache": 0,
        }

        self.semaphore = asyncio.Semaphore(10)

    async def initialize(self):
        logger.info("Initializing scanner")

        self.checker.initialize()

        logger.info("Scanner initialized")

    async def load_local_sources(self):
        """
        Загружает текстовые источники
        из локальных файлов.
        """

        source_files = [
            settings.sources_file,
            settings.telegram_sources_file,
        ]

        for source_file in source_files:

            if not source_file.exists():
                logger.warning(
                    "Source file not found: %s",
                    source_file
                )
                continue

            try:
                text = source_file.read_text(
                    encoding="utf-8"
                )

                if not text.strip():
                    continue

                await self.process_text(
                    text,
                    source_file.name
                )

            except Exception:
                self.stats["sources_failed"] += 1

                logger.exception(
                    "Failed to read source: %s",
                    source_file
                )

    async def process_text(
        self,
        text: str,
        source_name: str
    ):
        """
        Обрабатывает текстовый источник.
        """

        try:
            result = parse_text(text)

            for address in result.addresses:
                self.addresses.add(
                    f"{address.ip}:{address.port}"
                )

            for host in result.hosts:
                self.hosts.add(host.value)

            self.stats["sources_processed"] += 1

            logger.info(
                "[%s] Found %d addresses and %d hosts",
                source_name,
                len(result.addresses),
                len(result.hosts)
            )

        except Exception:
            self.stats["sources_failed"] += 1

            logger.exception(
                "Parser failed for source: %s",
                source_name
            )

    def export_results(self):
        """
        Сохраняет результаты парсинга.
        Формат parsed_results.json не изменяется.
        """

        output = {
            "generated_at": datetime.now(
                timezone.utc
            ).isoformat(),

            "statistics": {
                "sources_processed": self.stats["sources_processed"],
                "sources_failed": self.stats["sources_failed"],
                "addresses_found": len(self.addresses),
                "hosts_found": len(self.hosts),
            },

            "addresses": sorted(self.addresses),

            "hosts": sorted(self.hosts),
        }

        output_path = Path("parsed_results.json")

        temp_path = output_path.with_suffix(
            ".json.tmp"
        )

        try:
            temp_path.write_text(
                json.dumps(
                    output,
                    ensure_ascii=False,
                    indent=4
                ),
                encoding="utf-8"
            )

            temp_path.replace(output_path)

            logger.info(
                "Results saved: %s",
                output_path
            )

        except OSError:
            logger.exception(
                "Failed to save parsed results"
            )
            raise

    async def check_pairs(self):
        """
        Проверка комбинаций address + host.

        Максимум 10 одновременных проверок.
        """

        working = set()

        pairs = [
            (address, host)
            for address in sorted(self.addresses)
            for host in sorted(self.hosts)
        ]

        logger.info(
            "Total pairs to check: %d",
            len(pairs)
        )

        async def check_one(address, host):

            async with self.semaphore:

                # Проверяем кеш
                if self.checker.is_cached(address):

                    self.stats["skipped_from_cache"] += 1

                    logger.info(
                        "[SKIPPED] %s#%s cached",
                        address,
                        host
                    )

                    return

                self.stats["checked"] += 1

                try:
                    result = await self.checker.check(
                        address,
                        host
                    )

                    if result:
                        working.add(
                            f"{address}#{host}"
                        )

                        self.stats["alive"] += 1

                    else:
                        self.stats["dead"] += 1

                except Exception:

                    self.stats["dead"] += 1

                    logger.exception(
                        "Unexpected check error: %s#%s",
                        address,
                        host
                    )

        await asyncio.gather(
            *[
                check_one(address, host)
                for address, host in pairs
            ]
        )

        # Записываем рабочие пары
        output_path = settings.working_proxies_file

        output_path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        output_path.write_text(
            "".join(
                f"{item}\n"
                for item in sorted(working)
            ),
            encoding="utf-8"
        )

        logger.info(
            "Working pairs saved: %d",
            len(working)
        )

    def print_statistics(self):

        logger.info("=" * 45)
        logger.info("SCAN STATISTICS")
        logger.info("=" * 45)

        logger.info(
            "Sources processed: %d",
            self.stats["sources_processed"]
        )

        logger.info(
            "Sources failed: %d",
            self.stats["sources_failed"]
        )

        logger.info(
            "Addresses found: %d",
            self.stats["addresses_found"]
        )

        logger.info(
            "Hosts found: %d",
            self.stats["hosts_found"]
        )

        logger.info(
            "Checked: %d",
            self.stats["checked"]
        )

        logger.info(
            "Alive: %d",
            self.stats["alive"]
        )

        logger.info(
            "Dead: %d",
            self.stats["dead"]
        )

        logger.info(
            "Skipped from cache: %d",
            self.stats["skipped_from_cache"]
        )

        logger.info(
            "Cached dead entries: %d",
            self.checker.cache.count()
        )

        logger.info("=" * 45)

    async def run(self):

        await self.initialize()

        logger.info("Starting scanner")

        try:
            # Этап 1: получение локальных источников
            await self.load_local_sources()

            self.stats["addresses_found"] = len(
                self.addresses
            )

            self.stats["hosts_found"] = len(
                self.hosts
            )

            # Этап 2: сохранение результатов парсинга
            self.export_results()

            # Этап 3: проверка комбинаций
            if self.addresses and self.hosts:

                await self.check_pairs()

            else:
                logger.warning(
                    "No addresses or hosts found. "
                    "Skipping checks."
                )

                # Не затираем предыдущий список рабочих пар
                logger.info(
                    "Existing working_proxies.txt preserved"
                )

        finally:
            # Сохраняем кеш в любом случае
            self.checker.cache.save()

            self.print_statistics()

            logger.info("Scanner finished")


async def async_main():

    setup_logging()

    scanner = Scanner()

    try:
        await scanner.run()

    except KeyboardInterrupt:
        logger.warning("Scanner interrupted")

    except Exception:
        logger.exception(
            "Fatal scanner error"
        )

        sys.exit(1)


def main():

    try:
        asyncio.run(async_main())

    except KeyboardInterrupt:
        logger.warning(
            "Application stopped by user"
        )


if __name__ == "__main__":
    main()
