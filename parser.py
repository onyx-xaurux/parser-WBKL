import asyncio
import base64
import ipaddress
import json
import logging
import re
from pathlib import Path
from urllib.parse import urlsplit, parse_qs, unquote

import aiohttp
from bs4 import BeautifulSoup
from telethon import TelegramClient
from telethon.sessions import StringSession

from config import (
    SOURCES_FILE, TG_FILE, WHITELIST_FILE,
    TG_API_ID, TG_API_HASH, TG_SESSION_STRING,
    REQUEST_TIMEOUT, MAX_DOWNLOAD_SIZE, TG_MESSAGES_LIMIT,
    SUPPORTED_PROTOCOLS,
)

log = logging.getLogger(__name__)
URI_RE = re.compile(r'(?:vless|vmess|trojan|ss)://[^\s<>"\\']+', re.I)

def read_text(path):
    try:
        return path.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        log.warning("Файл не найден: %s", path.name)
        return ""

def read_lines(path):
    return [x.strip() for x in read_text(path).splitlines()
            if x.strip() and not x.strip().startswith("#")]

def decode_subscription(text):
    text = text.strip()
    if not text:
        return ""
    candidates = [text, re.sub(r"\s+", "", text)]
    for candidate in candidates:
        try:
            padded = candidate + "=" * (-len(candidate) % 4)
            decoded = base64.b64decode(padded, validate=False).decode("utf-8", "ignore")
            if any(p in decoded.lower() for p in SUPPORTED_PROTOCOLS):
                return decoded
        except Exception:
            pass
    return text

def extract_configs(text):
    text = decode_subscription(text)
    found = URI_RE.findall(text)
    cleaned = []
    for item in found:
        item = item.rstrip("),;]}>'\"")
        if item.lower().startswith(SUPPORTED_PROTOCOLS):
            cleaned.append(item)
    # JSON-ссылки и JSON-массивы поддерживаются через URI-поля.
    try:
        obj = json.loads(text)
        def walk(value):
            if isinstance(value, str):
                if value.lower().startswith(SUPPORTED_PROTOCOLS):
                    cleaned.append(value.strip())
            elif isinstance(value, dict):
                for v in value.values():
                    walk(v)
            elif isinstance(value, list):
                for v in value:
                    walk(v)
        walk(obj)
    except Exception:
        pass
    return list(dict.fromkeys(cleaned))

def load_whitelist():
    """Формат строк: IP|SNI. Комментарии начинаются с #."""
    pairs = set()
    for line in read_lines(WHITELIST_FILE):
        line = line.strip().strip("-").strip()
        if "|" in line:
            ip, sni = line.split("|", 1)
        elif re.search(r"\bip\s*:", line, re.I):
            # YAML-подобные строки поддерживаются парсером ниже как отдельные ключи.
            continue
        else:
            continue
        try:
            ip = str(ipaddress.ip_address(ip.strip().strip('"\\'')))
            sni = sni.strip().strip('"\\'').lower().rstrip(".")
            if sni:
                pairs.add((ip, sni))
        except ValueError:
            log.warning("Некорректная строка whitelist: %s", line)
    return pairs

def get_server_sni(uri):
    try:
        if uri.startswith("vmess://"):
            raw = uri[8:]
            data = json.loads(base64.b64decode(raw + "=" * (-len(raw) % 4)))
            return data.get("add", ""), (data.get("sni") or data.get("host") or "").lower()
        parsed = urlsplit(uri)
        params = parse_qs(parsed.query)
        return parsed.hostname or "", (params.get("sni", [""])[0] or "").lower().rstrip(".")
    except Exception:
        return "", ""

async def resolve_ips(host):
    try:
        ipaddress.ip_address(host)
        return {str(ipaddress.ip_address(host))}
    except ValueError:
        pass
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None, type=0)
        return {x[4][0] for x in infos}
    except Exception:
        return set()

async def apply_whitelist(configs):
    allowed = load_whitelist()
    if not allowed:
        log.warning("Whitelist пуст или не распознан; фильтрация остановлена, конфиги не пропускаются.")
        return []
    result = []
    for uri in configs:
        host, sni = get_server_sni(uri)
        ips = await resolve_ips(host) if host else set()
        if any((ip, sni) in allowed for ip in ips):
            result.append(uri)
    log.info("Whitelist: %d из %d конфигов прошло", len(result), len(configs))
    return result

async def fetch_http(session, url):
    async with session.get(url, timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)) as resp:
        data = await resp.content.read(MAX_DOWNLOAD_SIZE + 1)
        if len(data) > MAX_DOWNLOAD_SIZE:
            raise ValueError("Источник превышает лимит загрузки")
        return data.decode("utf-8", "ignore")

async def collect_web():
    sources = read_lines(SOURCES_FILE)
    results = []
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        for source in sources:
            source = source.strip()
            if source.lower().startswith(SUPPORTED_PROTOCOLS):
                results.extend(extract_configs(source))
                continue
            if not source.startswith(("http://", "https://")):
                log.warning("Пропущен неизвестный источник: %s", source[:100])
                continue
            try:
                body = await fetch_http(session, source)
                soup = BeautifulSoup(body, "html.parser")
                text = soup.get_text("\n") if "<html" in body[:1000].lower() else body
                results.extend(extract_configs(text))
            except Exception:
                log.exception("Ошибка HTTP-источника: %s", source)
    log.info("Веб-источники: найдено %d конфигов", len(results))
    return results

async def collect_telegram():
    channels = read_lines(TG_FILE)
    if not channels:
        return []
    if not (TG_API_ID and TG_API_HASH and TG_SESSION_STRING):
        log.warning("Telegram пропущен: не заданы TG_API_ID/TG_API_HASH/TG_SESSION_STRING")
        return []
    client = TelegramClient(StringSession(TG_SESSION_STRING), int(TG_API_ID), TG_API_HASH)
    results = []
    try:
        await client.start()
        for channel in channels:
            try:
                entity = await client.get_entity(channel)
                async for msg in client.iter_messages(entity, limit=TG_MESSAGES_LIMIT):
                    if msg.message:
                        results.extend(extract_configs(msg.message))
                    if msg.media and getattr(msg, "file", None):
                        name = (msg.file.name or "").lower()
                        if name.endswith((".txt", ".json", ".yaml", ".yml")):
                            data = await client.download_media(msg, file=bytes)
                            if data:
                                results.extend(extract_configs(data.decode("utf-8", "ignore")))
            except Exception:
                log.exception("Ошибка Telegram-канала: %s", channel)
    finally:
        await client.disconnect()
    log.info("Telegram: найдено %d конфигов", len(results))
    return results

async def collect_all():
    log.info("Начинаем сбор источников")
    web, tg = await asyncio.gather(collect_web(), collect_telegram())
    all_configs = list(dict.fromkeys(web + tg))
    log.info("Всего уникальных конфигов: %d", len(all_configs))
    return await apply_whitelist(all_configs)
