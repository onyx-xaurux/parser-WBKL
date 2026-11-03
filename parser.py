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
    WHITELIST_IPS_FILE,
    WHITELIST_SNI_FILE,
    TG_API_ID,
    TG_API_HASH,
    TG_SESSION_STRING,
    REQUEST_TIMEOUT,
    MAX_DOWNLOAD_SIZE,
    SUPPORTED_PROTOCOLS,
)

logger = logging.getLogger(__name__)

CONFIG_PATTERN = re.compile(
    r'(?:vless|vmess|trojan)://[^\s<>"\']+',
    re.IGNORECASE
)


def read_lines(path):
    """Читает непустые строки из файла."""
    if not path.exists():
        logger.warning("Файл отсутствует: %s", path.name)
        return []

    try:
        return [
            line.strip()
            for line in path.read_text(
                encoding="utf-8-sig"
            ).splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
    except OSError:
        logger.exception("Ошибка чтения %s", path.name)
        return []


def load_whitelist():
    """Загружает белые списки IP и SNI."""

    ips = set()
    snis = set()

    for value in read_lines(WHITELIST_IPS_FILE):
        try:
            ips.add(str(ipaddress.ip_address(value)))
        except ValueError:
            logger.warning("Некорректный IP в whitelist: %s", value)

    for value in read_lines(WHITELIST_SNI_FILE):
        snis.add(value.lower().rstrip("."))

    logger.info(
        "Whitelist загружен: IP=%d, SNI=%d",
        len(ips),
        len(snis)
    )

    return ips, snis


def decode_base64_text(content):
    """Пробует декодировать Base64-подписку."""

    content = content.strip()

    if not content:
        return content

    candidates = [
        content,
        content.replace("-", "+").replace("_", "/")
    ]

    for candidate in candidates:
        try:
            candidate += "=" * (-len(candidate) % 4)

            decoded = base64.b64decode(
                candidate,
                validate=True
            ).decode("utf-8-sig")

            if any(
                protocol in decoded.lower()
                for protocol in SUPPORTED_PROTOCOLS
            ):
                return decoded

        except Exception:
            continue

    return content


def extract_json_objects(text):
    """Извлекает JSON-объекты из произвольного текста."""

    decoder = json.JSONDecoder()
    objects = []

    for match in re.finditer(r"[\[{]", text):
        try:
            obj, _ = decoder.raw_decode(text[match.start():])
            objects.append(obj)
        except (json.JSONDecodeError, ValueError):
            continue

    return objects


def extract_json_configs(obj):
    """Ищет параметры серверов в JSON."""

    found = []

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

        sni = (
            obj.get("sni")
            or obj.get("server_name")
            or obj.get("servername")
            or obj.get("tls", {}).get("server_name", "")
            if isinstance(obj.get("tls", {}), dict)
            else obj.get("sni", "")
        )

        if server and sni and protocol in (
            "vless", "vmess", "trojan"
        ):
            found.append({
                "raw": json.dumps(obj, ensure_ascii=False),
                "protocol": protocol,
                "server": str(server),
                "sni": str(sni).lower().rstrip("."),
            })

        for value in obj.values():
            found.extend(extract_json_configs(value))

    elif isinstance(obj, list):
        for item in obj:
            found.extend(extract_json_configs(item))

    elif isinstance(obj, str):
        found.extend(extract_configs(obj))

    return found


def parse_config(uri):
    """Разбирает URI VLESS, VMess или Trojan."""

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

            server = parsed.hostname or ""

            params = parse_qs(parsed.query)

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
        logger.debug(
            "Не удалось разобрать конфиг: %s",
            error
        )
        return None


def extract_configs(text):
    """Извлекает URI и JSON-конфигурации."""

    results = []

    # URI
    for match in CONFIG_PATTERN.findall(text):
        config = parse_config(match.rstrip(".,;"))
        if config:
            results.append(config)

    # JSON
    for obj in extract_json_objects(text):
        results.extend(extract_json_configs(obj))

    # Удаление повторов
    unique = {}

    for item in results:
        unique[item["raw"]] = item

    return list(unique.values())


async def resolve_server(server):
    """Получает IP-адрес сервера."""

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
            ip = record[4][0]

            try:
                return str(ipaddress.ip_address(ip))
            except ValueError:
                continue

    except Exception:
        logger.warning(
            "Не удалось определить IP: %s",
            server
        )

    return None


async def apply_whitelist(configs, allowed_ips, allowed_snis):
    """Оставляет только конфиги с разрешёнными IP и SNI."""

    accepted = []
    unique = set()

    for config in configs:
        server_ip = await resolve_server(config["server"])
        sni = config["sni"].lower()

        if (
            server_ip
            and server_ip in allowed_ips
            and sni in allowed_snis
        ):
            config["ip"] = server_ip

            key = (server_ip, sni, config["protocol"])

            if key not in unique:
                unique.add(key)
                accepted.append(config)

        else:
            logger.warning(
                "[WARN] Найден конфиг, но он не в белом списке: %s / %s",
                config["server"],
                sni
            )

    return accepted


async def fetch_source(session, url):
    """Загружает подписку или HTML-страницу."""

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
                    "Источник слишком большой: %s",
                    url
                )
                return ""

            text = content.decode(
                "utf-8-sig",
                errors="replace"
            )

            # HTML
            if (
                "text/html" in response.headers.get(
                    "Content-Type", ""
                ).lower()
                or "<html" in text[:1000].lower()
            ):
                soup = BeautifulSoup(text, "html.parser")
                text = soup.get_text(separator="\n")

            return decode_base64_text(text)

    except Exception:
        logger.exception("Ошибка источника: %s", url)
        return ""


async def collect_web_sources():
    """Собирает данные из sources.txt."""

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
                collected.extend(extract_configs(text))

    logger.info(
        "Из веб-источников найдено конфигов: %d",
        len(collected)
    )

    return collected


async def collect_telegram_sources():
    """Читает последние сообщения Telegram-каналов."""

    if not all((
        TG_API_ID,
        TG_API_HASH,
        TG_SESSION_STRING
    )):
        logger.warning(
            "Telegram пропущен: не заданы TG_API_ID, "
            "TG_API_HASH или TG_SESSION_STRING"
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
            logger.error("Telegram-сессия не авторизована")
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
                    limit=50
                ):
                    text = message.message or ""

                    if text:
                        collected.extend(
                            extract_configs(
                                decode_base64_text(text)
                            )
                        )

                    # Вложения TXT и JSON
                    if message.file and message.file.name:
                        filename = message.file.name.lower()

                        if filename.endswith((".txt", ".json")):
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
                                    "Ошибка вложения: %s",
                                    filename
                                )

                            finally:
                                buffer.close()

            except Exception:
                logger.exception(
                    "Ошибка обработки канала @%s",
                    channel
                )

    finally:
        if client.is_connected():
            await client.disconnect()

    logger.info(
        "Из Telegram найдено конфигов: %d",
        len(collected)
    )

    return collected


async def collect_all():
    """Общий сбор и фильтрация конфигураций."""

    logger.info("Начинаем сбор источников")

    web_task = collect_web_sources()
    tg_task = collect_telegram_sources()

    results = await asyncio.gather(
        web_task,
        tg_task,
        return_exceptions=True
    )

    configs = []

    for result in results:
        if isinstance(result, Exception):
            logger.error("Ошибка сборщика: %s", result)
        else:
            configs.extend(result)

    # Удаляем дубликаты
    unique = {
        item["raw"]: item
        for item in configs
    }

    configs = list(unique.values())

    logger.info(
        "Всего найдено уникальных конфигов: %d",
        len(configs)
    )

    allowed_ips, allowed_snis = load_whitelist()

    filtered = await apply_whitelist(
        configs,
        allowed_ips,
        allowed_snis
    )

    logger.info(
        "После whitelist осталось: %d",
        len(filtered)
    )

    return filtered
