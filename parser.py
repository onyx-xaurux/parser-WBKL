import asyncio
import base64
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
    SOURCES_FILE, TG_FILE, WHITELIST_FILE, TG_API_ID, TG_API_HASH, TG_SESSION_STRING,
    REQUEST_TIMEOUT, MAX_DOWNLOAD_SIZE, TG_MESSAGES_LIMIT
)

log = logging.getLogger(__name__)
# Добавили поддержку hy2 и hysteria2
URI_RE = re.compile(r"""(?:vless|vmess|trojan|ss|hy2|hysteria2)://[^\s<>"']+""", re.IGNORECASE)

class ConfigExtractor:
    @staticmethod
    def parse_uri(raw):
        try:
            parsed = urlsplit(raw)
            protocol = parsed.scheme.lower()
            if protocol not in ("vless", "vmess", "trojan", "ss", "hy2", "hysteria2"): 
                return None

            if protocol == "vmess":
                payload = "".join((parsed.netloc + parsed.path).strip().split())
                payload += "=" * (-len(payload) % 4)
                data = json.loads(base64.urlsafe_b64decode(payload).decode("utf-8"))
                server = data.get("add") or data.get("server")
                port = int(data.get("port", 0))
                sni = data.get("sni") or data.get("host") or server
                if not server or not 1 <= port <= 65535: return None
                return {"raw": raw, "protocol": "vmess", "server": server, "port": port, "sni": str(sni).lower()}

            server = parsed.hostname
            port = parsed.port
            if not server or not port: return None

            query = parse_qs(parsed.query, keep_blank_values=True)
            get_param = lambda n: unquote(query.get(n, [""])[0])
            
            sni = get_param("sni") or get_param("serverName") or get_param("host") or get_param("peer") or server
            return {"raw": raw, "protocol": protocol, "server": server, "port": port, "sni": sni.lower().rstrip(".")}
        except Exception:
            return None

    @classmethod
    def extract(cls, text):
        found = []
        for match in URI_RE.findall(text):
            cfg = cls.parse_uri(match.rstrip(".,;"))
            if cfg: found.append(cfg)
        return found

class SourceFetcher:
    @staticmethod
    def read_lines(path):
        if not Path(path).exists(): return []
        return [l.strip() for l in Path(path).read_text(encoding="utf-8-sig").splitlines() if l.strip() and not l.startswith("#")]

    @staticmethod
    async def fetch_web(session, url):
        if not url.lower().startswith(("http://", "https://")):
            return []
        try:
            async with session.get(url, timeout=REQUEST_TIMEOUT, headers={"User-Agent": "Mozilla/5.0"}) as resp:
                content = await resp.content.read(MAX_DOWNLOAD_SIZE)
                text = BeautifulSoup(content.decode("utf-8", errors="replace"), "html.parser").get_text("\n")
                return ConfigExtractor.extract(text)
        except Exception:
            return []

    @classmethod
    async def fetch_telegram(cls):
        channels = cls.read_lines(TG_FILE)
        if not channels or not TG_API_ID or not TG_SESSION_STRING: return []
        
        client = TelegramClient(StringSession(TG_SESSION_STRING), int(TG_API_ID), TG_API_HASH)
        configs = []
        try:
            await client.start()
            for ch in channels:
                ch_name = ch.replace("https://t.me/", "").replace("@", "").strip("/")
                try:
                    entity = await client.get_entity(ch_name)
                    async for msg in client.iter_messages(entity, limit=TG_MESSAGES_LIMIT):
                        if msg.message: configs.extend(ConfigExtractor.extract(msg.message))
                        if msg.media:
                            buffer = BytesIO()
                            await client.download_media(msg.media, file=buffer)
                            configs.extend(ConfigExtractor.extract(buffer.getvalue().decode("utf-8", errors="replace")))
                except Exception:
                    continue
        finally:
            if client.is_connected(): await client.disconnect()
        return configs

def load_whitelist():
    pairs = set()
    if not WHITELIST_FILE.exists(): return pairs
    try:
        data = yaml.safe_load(WHITELIST_FILE.read_text(encoding="utf-8-sig"))
        for item in data.get("names", []):
            sni = str(item.get("name", "")).strip().lower()
            for ip in item.get("ips", []):
                pairs.add((str(ip).strip(), sni))
    except Exception:
        pass
    return pairs

async def collect_all():
    log.info("Сбор данных...")
    web_urls = SourceFetcher.read_lines(SOURCES_FILE)
    
    async with aiohttp.ClientSession() as session:
        web_tasks = [SourceFetcher.fetch_web(session, url) for url in web_urls]
        web_results = await asyncio.gather(*web_tasks)
    
    web_configs = [item for sublist in web_results for item in sublist]
    tg_configs = await SourceFetcher.fetch_telegram()
    
    unique_configs = {cfg['raw']: cfg for cfg in (web_configs + tg_configs)}.values()
    
    allowed = load_whitelist()
    filtered = [cfg for cfg in unique_configs if (cfg['server'], cfg['sni']) in allowed]
    
    log.info(f"Собрано {len(unique_configs)}, прошло фильтр: {len(filtered)}")
    return filtered
