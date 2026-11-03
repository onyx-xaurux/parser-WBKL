import asyncio
import aiohttp
import base64
import json
import logging
import re
import socket
import ipaddress

from io import BytesIO
from urllib.parse import urlsplit, parse_qs
from bs4 import BeautifulSoup

from telethon import TelegramClient
from telethon.sessions import StringSession

from config import (
    SOURCES_FILE,
    TG_FILE,
    WHITELIST_FILE,
    TG_API_ID,
    TG_API_HASH,
    TG_SESSION_STRING,
    REQUEST_TIMEOUT,
    MAX_DOWNLOAD_SIZE,
    TG_MESSAGES_LIMIT,
    SUPPORTED_PROTOCOLS,
)

logger = logging.getLogger(__name__)

CONFIG_PATTERN = re.compile(
    r'(?:vless|vmess|trojan)://[^\s<>"\']+',
    re.IGNORECASE
)


def read_lines(path):
    if not path.exists():
        logger.warning("Файл отсутствует: %s", path.name)
        return []

    try:
        return [
            line.strip()
            for line in path.read_text(
                encoding="utf-8-sig"
            ).splitlines()
            if line.strip()
            and not line.strip().startswith("#")
        ]

    except OSError:
        logger.exception("Ошибка чтения %s", path.name)
        return []


def load_whitelist():
    """Формат строки: IP|SNI."""

    pairs = set()

    for line in read_lines(WHITELIST_FILE):
        try:
            ip, sni = line.split("|", 1)

            ip = str(
                ipaddress.ip_address(ip.strip())
            )

            sni = sni.strip().lower().rstrip(".")

            if not sni:
                continue

            pairs.add((ip, sni))

        except ValueError:
            logger.warning(
                "Некорректная строка whitelist: %s",
                line
            )

    logger.info(
        "Whitelist загружен: %d пар IP/SNI",
        len(pairs)
    )

    return pairs


def decode_base64_text(content):
    content = content.strip()

    if not content:
        return content

    compact = "".join(content.split())

    try:
        padded = compact + "=" * (-len(compact) % 4)

        decoded = base64.b64decode(
            padded,
            altchars=b"-_",
            validate=True
        ).decode("utf-8-sig")

        if any(
            protocol in decoded.lower()
            for protocol in SUPPORTED_PROTOCOLS
        ):
            return decoded

    except Exception:
        pass

    return content


def parse_config(uri):
    try:
        protocol = uri.split("://", 1)[0].lower()

        if protocol not in ("vless", "vmess", "trojan"):
            return None

        if protocol == "vmess":
            encoded = uri.split("://", 1)[1]
            encoded += "=" * (-len(encoded) % 4)

            decoded = base64.urlsafe_b64decode(
                encoded
            ).decode("utf-8")

            data = json.loads(decoded)

            server = data.get("add", "")
            sni = (
                data.get("sni")
                or data.get("host")
                or ""
            )

        else:
            parsed = urlsplit(uri)
            params = parse_qs(parsed.query)

            server = parsed.hostname or ""

            sni = (
                params.get("sni", [""])[0]
                or params.get("serverName", [""])[0]
            )

        if not server or not sni:
            return None

        return {
            "raw": uri,
            "protocol": protocol,
            "server": server,
            "sni": sni.lower().rstrip("."),
        }

    except Exception as error:
        logger.debug("Ошибка разбора конфига: %s", error)
        return None


def extract_json_configs(obj):
    results = []

    if isinstance(obj, dict):
        protocol = str(
            obj.get("type", obj.get("protocol", ""))
        ).lower()

        server = (
            obj.get("server")
            or obj.get("address")
            or obj.get("host")
            or ""
        )

        tls = obj.get("tls", {})
        if not isinstance(tls, dict):
            tls = {}

        sni = (
            obj.get("sni")
            or obj.get("server_name")
            or obj.get("servername")
            or tls.get("server_name", "")
        )

        if (
            protocol in ("vless", "vmess", "trojan")
            and server
            and sni
        ):
            results.append({
                "raw": json.dumps(
                    obj,
                    ensure_ascii=False
                ),
                "protocol": protocol,
                "server": str(server),
                "sni": str(sni).lower().rstrip("."),
            })

        for value in obj.values():
            results.extend(
                extract_json_configs(value)
            )

    elif isinstance(obj, list):
        for item in obj:
            results.extend(
                extract_json_configs(item)
            )

    elif isinstance(obj, str):
        results.extend(extract_configs(obj))

    return results


def extract_configs(text):
    results = []

    for match in CONFIG_PATTERN.findall(text):
        config = parse_config(match.rstrip(".,;"))

        if config:
            results.append(config)

    decoder = json.JSONDecoder()

    for match in re.finditer(r"[\[{]", text):
        try:
            obj, _ = decoder.raw_decode(
                text[match.start():]
            )

            results.extend(
                extract_json_configs(obj)
            )

        except (json.JSONDecodeError, ValueError):
            continue

    unique = {}

    for config in results:
        unique[config["raw"]] = config

    return list(unique.values())


async def resolve_server(server):
    try:
        return str(ipaddress.ip_address(server))

    except ValueError:
        pass

    try:
        loop = asyncio.get_running_loop()

        records = await asyncio.wait_for(
            loop.getaddrinfo(
                server,
                None,
                type=socket.SOCK_STREAM
            ),
            timeout=5
        )

        for record in records:
            try:
                return str(
                    ipaddress.ip_address(record[4][0])
                )

            except ValueError:
                continue

    except Exception:
        logger.warning(
            "Не удалось определить IP: %s",
            server
        )

    return None


async def apply_whitelist(configs, allowed_pairs):
    accepted = []
    unique = set()

    for config in configs:
        server_ip = await resolve_server(
            config["server"]
        )

        sni = config["sni"].lower().rstrip(".")

        if not server_ip or (server_ip, sni) not in allowed_pairs:
            logger.warning(
                "[WARN] Найден конфиг, но он не в белом списке: %s | %s",
                config["server"],
                sni
            )
            continue

        config["ip"] = server_ip

        key = (
            server_ip,
            sni,
            config["raw"]
        )

        if key not in unique:
            unique.add(key)
            accepted.append(config)

    return accepted


async def fetch_source(session, url):
    try:
        logger.info("Загрузка источника: %s", url)

        async with session.get(
            url,
            allow_redirects=True
        ) as response:

            response.raise_for_status()

            content = await response.content.read(
                MAX_DOWNLOAD_SIZE + 1
            )

            if len(content) > MAX_DOWNLOAD_SIZE:
                logger.warning(
                    "Источник превышает лимит размера: %s",
                    url
                )
                return ""

            text = content.decode(
                "utf-8-sig",
                errors="replace"
            )

            content_type = response.headers.get(
                "Content-Type", ""
            ).lower()

            if (
                "text/html" in content_type
                or "<html" in text[:1000].lower()
            ):
                soup = BeautifulSoup(
                    text,
                    "html.parser"
                )

                text = soup.get_text(separator="\n")

            return decode_base64_text(text)

    except Exception:
        logger.exception("Ошибка источника: %s", url)
        return ""


async def collect_web_sources():
    sources = read_lines(SOURCES_FILE)
    collected = []

    timeout = aiohttp.ClientTimeout(
        total=REQUEST_TIMEOUT
    )

    async with aiohttp.ClientSession(
        timeout=timeout,
        headers={"User-Agent": "Mozilla/5.0"}
    ) as session:

        for url in sources:
            text = await fetch_source(session, url)

            if text:
                collected.extend(
                    extract_configs(text)
                )

    logger.info(
        "Веб-источники: найдено %d конфигов",
        len(collected)
    )

    return collected


async def collect_telegram_sources():
    if not all((
        TG_API_ID,
        TG_API_HASH,
        TG_SESSION_STRING
    )):
        logger.warning(
            "Telegram пропущен: отсутствуют секреты"
        )
        return []

    channels = read_lines(TG_FILE)

    if not channels:
        return []

    collected = []

    client = TelegramClient(
        StringSession(TG_SESSION_STRING),
        int(TG_API_ID),
        TG_API_HASH
    )

    try:
        await client.connect()

        if not await client.is_user_authorized():
            logger.error(
                "Telegram-сессия не авторизована"
            )
            return []

        for channel in channels:
            channel = channel.lstrip("@")

            logger.info(
                "[INFO] Начинаем парсинг канала @%s",
                channel
            )

            try:
                entity = await client.get_entity(channel)

                async for message in client.iter_messages(
                    entity,
                    limit=TG_MESSAGES_LIMIT
                ):
                    text = message.message or ""

                    if text:
                        collected.extend(
                            extract_configs(
                                decode_base64_text(text)
                            )
                        )

                    if (
                        message.file
                        and message.file.name
                        and message.file.name.lower().endswith(
                            (".txt", ".json")
                        )
                    ):
                        buffer = BytesIO()

                        try:
                            await client.download_media(
                                message,
                                file=buffer
                            )

                            file_text = buffer.getvalue().decode(
                                "utf-8-sig",
                                errors="replace"
                            )

                            collected.extend(
                                extract_configs(
                                    decode_base64_text(file_text)
                                )
                            )

                        except Exception:
                            logger.exception(
                                "Ошибка загрузки Telegram-вложения"
                            )

                        finally:
                            buffer.close()

            except Exception:
                logger.exception(
                    "Ошибка канала @%s",
                    channel
                )

    finally:
        if client.is_connected():
            await client.disconnect()

    logger.info(
        "Telegram: найдено %d конфигов",
        len(collected)
    )

    return collected


async def collect_all():
    logger.info("Начинаем сбор источников")

    results = await asyncio.gather(
        collect_web_sources(),
        collect_telegram_sources(),
        return_exceptions=True
    )

    configs = []

    for result in results:
        if isinstance(result, Exception):
            logger.error(
                "Ошибка сборщика: %s",
                result
            )
        else:
            configs.extend(result)

    unique = {
        config["raw"]: config
        for config in configs
    }

    configs = list(unique.values())

    logger.info(
        "Всего уникальных конфигов: %d",
        len(configs)
    )

    allowed_pairs = load_whitelist()

    filtered = await apply_whitelist(
        configs,
        allowed_pairs
    )

    logger.info(
        "После whitelist осталось: %d",
        len(filtered)
    )

    return filtered
