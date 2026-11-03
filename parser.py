import asyncio
import base64
import ipaddress
import json
import logging
import re
from io import BytesIO
from pathlib import Path
from urllib.parse import urlsplit, parse_qs, unquote

import aiohttp
import yaml
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

log = logging.getLogger(__name__)

URI_RE = re.compile(
    r"""(?:vless|vmess|trojan|ss)://[^\s<>"']+""",
    re.IGNORECASE,
)

SUPPORTED = ("vless", "vmess", "trojan", "ss")


# --------------------------------------------------
# ЧТЕНИЕ ФАЙЛОВ
# --------------------------------------------------

def read_lines(path):
    path = Path(path)

    if not path.exists():
        log.warning("Файл не найден: %s", path.name)
        return []

    try:
        return [
            line.strip()
            for line in path.read_text(encoding="utf-8-sig").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
    except Exception:
        log.exception("Ошибка чтения файла %s", path.name)
        return []


# --------------------------------------------------
# BASE64
# --------------------------------------------------

def decode_base64_text(value):
    if not value:
        return None

    value = "".join(value.strip().split())
    value += "=" * (-len(value) % 4)

    try:
        decoded = base64.urlsafe_b64decode(value)
        return decoded.decode("utf-8")
    except Exception:
        return None


# --------------------------------------------------
# РАЗБОР КОНФИГУРАЦИЙ
# --------------------------------------------------

def parse_config(raw):
    raw = raw.strip()

    if not raw:
        return None

    try:
        parsed = urlsplit(raw)
        protocol = parsed.scheme.lower()

        if protocol not in SUPPORTED:
            return None

        # VMess: JSON внутри Base64
        if protocol == "vmess":
            payload = decode_base64_text(parsed.netloc + parsed.path)

            if not payload:
                return None

            data = json.loads(payload)

            server = data.get("add") or data.get("server")
            port = int(data.get("port", 0))
            sni = (
                data.get("sni")
                or data.get("host")
                or server
            )

            if not server or not 1 <= port <= 65535:
                return None

            return {
                "raw": raw,
                "protocol": "vmess",
                "server": server,
                "port": port,
                "sni": str(sni).lower().rstrip("."),
                "json": data,
            }

        # Остальные URI
        server = parsed.hostname
        port = parsed.port

        if not server or not port:
            return None

        query = parse_qs(parsed.query, keep_blank_values=True)

        def get_param(name, default=""):
            values = query.get(name)
            return unquote(values[0]) if values else default

        sni = (
            get_param("sni")
            or get_param("serverName")
            or get_param("host")
            or server
        )

        result = {
            "raw": raw,
            "protocol": protocol,
            "server": server,
            "port": port,
            "sni": sni.lower().rstrip("."),
        }

        if protocol == "vless":
            result["uuid"] = unquote(parsed.username or "")
            result["query"] = query

        elif protocol == "trojan":
            result["password"] = unquote(parsed.username or "")
            result["query"] = query

        elif protocol == "ss":
            result["query"] = query
            result["userinfo"] = parsed.netloc.rsplit("@", 1)[0]

        return result

    except Exception as error:
        log.debug("Не удалось разобрать конфигурацию: %s", error)
        return None


# --------------------------------------------------
# ИЗВЛЕЧЕНИЕ КОНФИГУРАЦИЙ ИЗ ТЕКСТА
# --------------------------------------------------

def extract_configs(text):
    if not text:
        return []

    found = []

    for match in URI_RE.findall(text):
        config = parse_config(match.rstrip(".,;"))

        if config:
            found.append(config)

    # JSON с конфигурацией
    try:
        data = json.loads(text)

        objects = data if isinstance(data, list) else [data]

        for item in objects:
            if not isinstance(item, dict):
                continue

            protocol = str(
                item.get("type") or item.get("protocol") or ""
            ).lower()

            if protocol not in SUPPORTED:
                continue

            server = item.get("server") or item.get("add")
            port = item.get("server_port") or item.get("port")

            if not server or not port:
                continue

            try:
                port = int(port)
                if not 1 <= port <= 65535:
                    continue
            except (TypeError, ValueError):
                continue

            sni = (
                item.get("server_name")
                or item.get("sni")
                or item.get("host")
                or server
            )

            found.append({
                "raw": json.dumps(item, ensure_ascii=False),
                "protocol": protocol,
                "server": str(server),
                "port": port,
                "sni": str(sni).lower().rstrip("."),
                "json": item,
            })

    except (ValueError, TypeError):
        pass

    # Base64-подписка
    if not found:
        decoded = decode_base64_text(text)

        if decoded and decoded != text:
            found.extend(extract_configs(decoded))

    return found


# --------------------------------------------------
# YAML WHITELIST
# --------------------------------------------------

def load_whitelist():
    pairs = set()

    if not Path(WHITELIST_FILE).exists():
        log.error("Whitelist не найден: %s", WHITELIST_FILE)
        return pairs

    try:
        with open(WHITELIST_FILE, "r", encoding="utf-8-sig") as file:
            data = yaml.safe_load(file)

        if not isinstance(data, dict):
            log.error("Неверная структура YAML whitelist")
            return pairs

        names = data.get("names", [])

        if not isinstance(names, list):
            log.error("В YAML отсутствует корректный список names")
            return pairs

        for entry in names:
            if not isinstance(entry, dict):
                continue

            sni = str(entry.get("name", "")).strip().lower().rstrip(".")

            if not sni:
                continue

            ips = entry.get("ips", [])

            if not isinstance(ips, list):
                continue

            for ip_text in ips:
                try:
                    ip = str(ipaddress.ip_address(str(ip_text).strip()))
                    pairs.add((ip, sni))
                except ValueError:
                    continue

        log.info(
            "Whitelist: загружено %d уникальных пар IP/SNI",
            len(pairs),
        )

    except Exception:
        log.exception("Ошибка чтения YAML whitelist")

    return pairs


# --------------------------------------------------
# DNS
# --------------------------------------------------

async def resolve_server(server):
    try:
        ipaddress.ip_address(server)
        return server
    except ValueError:
        pass

    try:
        loop = asyncio.get_running_loop()

        results = await loop.getaddrinfo(
            server,
            None,
            family=0,
            type=0,
        )

        for result in results:
            ip = result[4][0]

            try:
                return str(ipaddress.ip_address(ip))
            except ValueError:
                continue

    except Exception as error:
        log.debug("DNS ошибка для %s: %s", server, error)

    return None


# --------------------------------------------------
# WHITELIST FILTER
# --------------------------------------------------

async def apply_whitelist(configs, allowed_pairs):
    if not allowed_pairs:
        log.error(
            "Whitelist пуст. Конфигурации не допускаются к проверке."
        )
        return []

    result = []
    checked_dns = {}

    for config in configs:
        server = config.get("server")
        sni = str(config.get("sni") or server or "").lower().rstrip(".")

        if not server or not sni:
            continue

        if server not in checked_dns:
            checked_dns[server] = await resolve_server(server)

        server_ip = checked_dns[server]

        if not server_ip:
            continue

        if (server_ip, sni) in allowed_pairs:
            config["resolved_ip"] = server_ip
            result.append(config)

    log.info(
        "Whitelist: прошло %d из %d конфигураций",
        len(result),
        len(configs),
    )

    return result


# --------------------------------------------------
# ЗАГРУЗКА WEB-ИСТОЧНИКОВ
# --------------------------------------------------

async def fetch_source(session, source):
    source = source.strip()

    # Не отправляем VLESS/VMess/Trojan/SS в HTTP-клиент.
    if not source.lower().startswith(("http://", "https://")):
        config = parse_config(source)

        if config:
            log.info("Источник является готовой конфигурацией: %s",
                     config["protocol"])
            return [config]

        log.warning("Пропущен неподдерживаемый источник: %s", source[:100])
        return []

    try:
        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)

        async with session.get(
            source,
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0"},
            allow_redirects=True,
        ) as response:

            response.raise_for_status()

            content = await response.content.read(MAX_DOWNLOAD_SIZE + 1)

            if len(content) > MAX_DOWNLOAD_SIZE:
                log.warning("Источник превышает лимит размера: %s", source)
                return []

            text = content.decode("utf-8", errors="replace")

            soup = BeautifulSoup(text, "html.parser")
            text = soup.get_text("\n")

            configs = extract_configs(text)

            log.info(
                "Источник %s: найдено %d конфигураций",
                source[:100],
                len(configs),
            )

            return configs

    except Exception:
        log.exception("Ошибка источника: %s", source[:100])
        return []


async def collect_web_sources():
    sources = read_lines(SOURCES_FILE)

    if not sources:
        log.warning("sources.txt пуст")
        return []

    connector = aiohttp.TCPConnector(
        limit=20,
        ssl=False,
    )

    async with aiohttp.ClientSession(connector=connector) as session:
        results = await asyncio.gather(
            *[fetch_source(session, source) for source in sources],
            return_exceptions=True,
        )

    configs = []

    for result in results:
        if isinstance(result, list):
            configs.extend(result)
        elif isinstance(result, Exception):
            log.error("Ошибка сбора web-источника: %s", result)

    log.info("Веб-источники: найдено %d конфигураций", len(configs))
    return configs


# --------------------------------------------------
# TELEGRAM
# --------------------------------------------------

def normalize_channel(value):
    value = value.strip()

    if not value:
        return None

    if value.startswith("https://t.me/"):
        value = value.replace("https://t.me/", "", 1)
    elif value.startswith("http://t.me/"):
        value = value.replace("http://t.me/", "", 1)

    value = value.strip("/")

    # Приватные invite-ссылки не являются username.
    if value.startswith("+") or value.startswith("joinchat/"):
        return None

    if value.startswith("@"):
        value = value[1:]

    if not re.fullmatch(r"[A-Za-z0-9_]{5,}", value):
        return None

    return value


async def collect_telegram_sources():
    channels = read_lines(TG_FILE)

    if not channels:
        log.warning("tg.txt пуст")
        return []

    if not TG_API_ID or not TG_API_HASH or not TG_SESSION_STRING:
        log.warning("Telegram Secrets не настроены")
        return []

    try:
        api_id = int(TG_API_ID)
    except ValueError:
        log.error("TG_API_ID должен быть числом")
        return []

    client = TelegramClient(
        StringSession(TG_SESSION_STRING),
        api_id,
        TG_API_HASH,
    )

    configs = []

    try:
        await client.start()

        for channel_line in channels:
            channel = normalize_channel(channel_line)

            if not channel:
                log.warning(
                    "Пропущена некорректная или приватная ссылка: %s",
                    channel_line,
                )
                continue

            log.info("Начинаем парсинг канала @%s", channel)

            try:
                entity = await client.get_entity(channel)

                async for message in client.iter_messages(
                    entity,
                    limit=TG_MESSAGES_LIMIT,
                ):
                    if message.message:
                        configs.extend(
                            extract_configs(message.message)
                        )

                    if message.media:
                        try:
                            buffer = BytesIO()

                            await client.download_media(
                                message.media,
                                file=buffer,
                            )

                            content = buffer.getvalue()

                            if len(content) > MAX_DOWNLOAD_SIZE:
                                continue

                            text = content.decode(
                                "utf-8",
                                errors="replace",
                            )

                            configs.extend(extract_configs(text))

                        except Exception as error:
                            log.warning(
                                "Ошибка вложения в @%s: %s",
                                channel,
                                error,
                            )

            except Exception as error:
                log.warning(
                    "Ошибка Telegram-канала @%s: %s",
                    channel,
                    error,
                )
                continue

    except Exception:
        log.exception("Ошибка подключения Telegram")

    finally:
        if client.is_connected():
            await client.disconnect()

    log.info("Telegram: найдено %d конфигураций", len(configs))
    return configs


# --------------------------------------------------
# ОБЩИЙ СБОР
# --------------------------------------------------

async def collect_all():
    log.info("Начинаем сбор источников")

    web_configs, tg_configs = await asyncio.gather(
        collect_web_sources(),
        collect_telegram_sources(),
    )

    all_configs = web_configs + tg_configs

    unique = {}

    for config in all_configs:
        raw = config.get("raw")

        if raw:
            unique[raw] = config

    configs = list(unique.values())

    log.info(
        "Всего уникальных конфигураций: %d",
        len(configs),
    )

    allowed_pairs = load_whitelist()

    configs = await apply_whitelist(
        configs,
        allowed_pairs,
    )

    log.info(
        "После сбора и whitelist: %d",
        len(configs),
    )

    return configs
