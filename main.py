import asyncio
import logging
import sys
import os
import aiohttp
from pathlib import Path
from bs4 import BeautifulSoup

from telethon import TelegramClient
from telethon.sessions import StringSession

from config import (
    WHITELIST_IPS, WHITELIST_SNI, WORKING_PROXIES,
    LOCAL_SOURCES, WEB_SOURCES, TG_SOURCES
)
from parser import parse_text
from checker import Checker

logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(message)s')
logger = logging.getLogger("scanner")

def load_local_text():
    if LOCAL_SOURCES.exists():
        return LOCAL_SOURCES.read_text(encoding="utf-8")
    return ""

async def fetch_url(session, url):
    try:
        async with session.get(url, timeout=15) as response:
            if response.status == 200:
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                return soup.get_text(separator='\n', strip=True)
    except Exception as e:
        logger.error(f"Failed to fetch {url}: {e}")
    return ""

async def load_web_sources():
    if not WEB_SOURCES.exists():
        return ""
    urls = [line.strip() for line in WEB_SOURCES.read_text().splitlines() if line.strip() and not line.startswith('#')]
    if not urls:
        return ""
    logger.info(f"Fetching {len(urls)} web sources...")
    text = ""
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_url(session, url) for url in urls]
        results = await asyncio.gather(*tasks)
        text = "\n".join(results)
    return text

async def load_telegram_sources():
    if not TG_SOURCES.exists():
        return ""
    api_id = os.getenv("TG_API_ID")
    api_hash = os.getenv("TG_API_HASH")
    session_str = os.getenv("TG_SESSION_STRING")

    if not api_id or not api_hash or not session_str:
        logger.warning("Telegram credentials not set. Skipping TG sources.")
        return ""

    targets = [line.strip() for line in TG_SOURCES.read_text().splitlines() if line.strip() and not line.startswith('#')]
    if not targets:
        return ""

    logger.info(f"Fetching {len(targets)} Telegram sources...")
    text = ""
    
    try:
        client = TelegramClient(StringSession(session_str), int(api_id), api_hash)
        await client.connect()
        
        if not await client.is_user_authorized():
            logger.error("Telegram session is not authorized.")
            await client.disconnect()
            return ""

        for target in targets:
            try:
                logger.info(f"Reading TG: {target}")
                messages = await client.get_messages(target, limit=100)
                for msg in messages:
                    if msg.text:
                        text += msg.text + "\n"
            except Exception as e:
                logger.error(f"Failed to read {target}: {e}")
                
        await client.disconnect()
    except Exception as e:
        logger.error(f"Telegram client error: {e}")
    return text

async def main():
    if not WHITELIST_IPS.exists() or not WHITELIST_SNI.exists():
        logger.error("Whitelists not found! Run fetch_whitelist.py first.")
        sys.exit(1)

    allowed_ips = set(WHITELIST_IPS.read_text(encoding="utf-8").splitlines())
    allowed_snis = set(WHITELIST_SNI.read_text(encoding="utf-8").splitlines())
    logger.info(f"Loaded {len(allowed_ips)} allowed IPs and {len(allowed_snis)} SNIs")

    all_text = []
    logger.info("Loading local sources...")
    all_text.append(load_local_text())
    
    logger.info("Loading web sources...")
    all_text.append(await load_web_sources())
    
    logger.info("Loading telegram sources...")
    all_text.append(await load_telegram_sources())

    full_text = "\n".join(all_text)
    logger.info(f"Total collected text size: {len(full_text)} characters")

    configs = parse_text(full_text)
    logger.info(f"Parsed {len(configs)} configs from all sources")

    if not configs:
        logger.warning("No valid configs found.")
        return

    valid_configs = []
    for cfg in configs:
        if cfg.ip in allowed_ips and cfg.sni in allowed_snis:
            valid_configs.append(cfg)
    
    logger.info(f"Filtered to {len(valid_configs)} configs matching whitelist")

    if not valid_configs:
        logger.warning("No configs matched the whitelist.")
        return

    checker = Checker()
    sem = asyncio.Semaphore(50)
    
    async def check_pair(cfg):
        async with sem:
            is_alive = await checker.check(cfg.ip, cfg.sni)
            if is_alive:
                logger.info(f"[ALIVE] {cfg.raw}")
                return cfg.raw
            return None

    logger.info(f"Starting check for {len(valid_configs)} configs...")
    tasks = [check_pair(cfg) for cfg in valid_configs]
    results = await asyncio.gather(*tasks)

    alive = [r for r in results if r]
    
    WORKING_PROXIES.write_text("\n".join(alive), encoding="utf-8")
    checker.save_cache()
    
    logger.info(f"Done! Alive: {len(alive)}. Saved to {WORKING_PROXIES}")

if __name__ == "__main__":
    asyncio.run(main())
