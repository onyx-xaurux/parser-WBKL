
import asyncio
import logging
import json
import sys

from pathlib import Path
from datetime import datetime, timezone

from config import settings, setup_logging
from parser import parse_text, parsed_to_dict
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
        }

    async def initialize(self):
        logger.info("Initializing scanner")

        self.checker.initialize()

        logger.info("Scanner initialized")

    async def load_local_sources(self):
        """
        Загружает текстовые источники из локальных файлов.
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

    async def process_text(self, text: str, source_name: str):
        """
        Обрабатывает один текстовый источник.
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
        Сохраняет найденные данные в JSON.
        """

        output = {
            "generated_at": datetime.now(
                timezone.utc
            ).isoformat(),

            "statistics": self.stats,

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
            logger.exception("Failed to save results")
            raise

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
            len(self.addresses)
        )

        logger.info(
            "Hosts found: %d",
            len(self.hosts)
        )

        logger.info(
            "Cached dead entries: %d",
            self.checker.cache.count()
        )

        logger.info("=" * 45)

    async def run(self):
        await self.initialize()

        logger.info("Starting scanner")

        await self.load_local_sources()

        self.stats["addresses_found"] = len(
            self.addresses
        )

        self.stats["hosts_found"] = len(
            self.hosts
        )

        self.export_results()

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
        logger.exception("Fatal scanner error")
        sys.exit(1)


def main():
    try:
        asyncio.run(async_main())

    except KeyboardInterrupt:
        logger.warning("Application stopped by user")


if __name__ == "__main__":
    main()
