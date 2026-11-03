import asyncio
import logging
import sys
import os
import aiohttp
import base64
import re
from pathlib import Path
from bs4 import BeautifulSoup
from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.errors import FloodWaitError

from config import (
    WHITELIST_IPS, WHITELIST_SNI, WORKING_PROXIES,
    LOCAL_SOURCES, WEB_SOURCES, TG_SOURCES
)
from parser import parse_text
from checker import Checker

# НАСТРОЙКА ЛОГОВ (чтобы всё было видно)
logging.basicConfig(
    level=logging.DEBUG, 
    format='%(asctime)s | %(levelname)s | %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger("scanner")

def load_local_text():
    logger.info("=> [1/4] Читаем локальные файлы (sources.txt)...")
    if LOCAL_SOURCES.exists():
        content = LOCAL_SOURCES.read_text(encoding="utf-8")
        logger.info(f"   Прочитано {len(content)} символов.")
        return content
    logger.warning("   Файл sources.txt не найден, пропускаем.")
    return ""

async def fetch_url(session, url):
    logger.debug(f"   Скачиваем: {url}")
    try:
        async with session.get(url, timeout=15) as response:
            if response.status == 200:
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                return soup.get_text(separator='\n', strip=True)
            else:
                logger.warning(f"   Ошибка {response.status} при скачивании {url}")
    except Exception as e:
        logger.error(f"   Не удалось скачать {url}: {e}")
    return ""

async def load_web_sources():
    logger.info("=> [2/4] Читаем веб-источники (web_sources.txt)...")
    if not WEB_SOURCES.exists():
        logger.warning("   Файл web_sources.txt не найден, пропускаем.")
        return ""
    urls = [line.strip() for line in WEB_SOURCES.read_text().splitlines() if line.strip() and not line.startswith('#')]
    if not urls:
        logger.warning("   Файл web_sources.txt пуст.")
        return ""
    
    logger.info(f"   Найдено {len(urls)} ссылок. Начинаем скачивание...")
    text = ""
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_url(session, url) for url in urls]
        results = await asyncio.gather(*tasks)
        text = "\n".join(results)
    return text

async def load_telegram_sources():
    logger.info("=> [3/4] Читаем Telegram (tg_sources.txt)...")
    if not TG_SOURCES.exists():
        logger.warning("   Файл tg_sources.txt не найден.")
        return ""
        
    api_id = os.getenv("TG_API_ID")
    api_hash = os.getenv("TG_API_HASH")
    session_str = os.getenv("TG_SESSION_STRING")

    if not api_id or not api_hash or not session_str:
        logger.warning("   Секреты Telegram не заданы в GitHub. Пропускаем.")
        return ""

    targets = [line.strip() for line in TG_SOURCES.read_text().splitlines() if line.strip() and not line.startswith('#')]
    if not targets:
        logger.warning("   Список каналов пуст.")
        return ""

    logger.info(f"   Найдено {len(targets)} каналов/ботов. Подключаемся к Telegram...")
    text = ""
    checked_channels = set()
    
    try:
        client = TelegramClient(StringSession(session_str), int(api_id), api_hash)
        await client.connect()
        
        if not client.is_user_authorized():
            logger.error("   ОШИБКА: Сессия Telegram не авторизована (session string протух).")
            await client.disconnect()
            return ""

        queue = list(targets)
        
        while queue:
            target = queue.pop(0)
            if target in checked_channels:
                continue
            checked_channels.add(target)
            
            try:
                logger.info(f"   Читаем канал: {target}")
                messages = await client.get_messages(target, limit=50)
                logger.info(f"   Получено {len(messages)} сообщений из {target}")
                
                found_configs = 0
                
                for msg in messages:
                    if msg.text:
                        text += msg.text + "\n"
                        if "vless://" in msg.text or "trojan://" in msg.text or "vmess://" in msg.text:
                            found_configs += 1
                        
                        # Ищем ссылки на другие каналы
                        links = re.findall(r'https?://t\.me/([a-zA-Z0-9_]+)', msg.text)
                        for link in links:
                            channel = f"@{link}"
                            if channel not in checked_channels and not link.startswith("joinchat") and link != "proxy":
                                queue.append(channel)
                                
                    if msg.document:
                        try:
                            file_bytes = await client.download_media(msg, file=bytes)
                            if file_bytes:
                                file_text = file_bytes.decode('utf-8', errors='ignore')
                                text += file_text + "\n"
                                if "vless://" in file_text or "vmess://" in file_text:
                                    found_configs += 1
                        except Exception as e:
                            logger.error(f"   Ошибка чтения файла: {e}")
                            
                if found_configs > 0:
                    logger.info(f"   >>> Найдено {found_configs} конфигов/файлов в {target}!")
                    
            except FloodWaitError as e:
                logger.warning(f"   ЛИМИТ TELEGRAM! Ждем {e.seconds} секунд...")
                await asyncio.sleep(e.seconds)
                queue.append(target)
            except Exception as e:
                logger.error(f"   Ошибка чтения {target}: {e}")
                
        await client.disconnect()
        logger.info("   Отключились от Telegram.")
    except Exception as e:
        logger.error(f"   КРИТИЧЕСКАЯ ОШИБКА Telegram: {e}")
    return text

async def main():
    logger.info("=========================================")
    logger.info("ЗАПУСК СКАНИРОВАНИЯ")
    logger.info("=========================================")

    logger.info("=> [0/4] Загружаем белые списки...")
    if not WHITELIST_IPS.exists() or not WHITELIST_SNI.exists():
        logger.error("   ОШИБКА: Файлы белых списков не найдены! Запусти fetch_whitelist.py")
        sys.exit(1)

    allowed_ips = set(WHITELIST_IPS.read_text(encoding="utf-8").splitlines())
    allowed_snis = set(WHITELIST_SNI.read_text(encoding="utf-8").splitlines())
    logger.info(f"   Загружено {len(allowed_ips)} IP и {len(allowed_snis)} SNI.")

    all_text = []
    all_text.append(load_local_text())
    all_text.append(await load_web_sources())
    all_text.append(await load_telegram_sources())

    full_text = "\n".join(all_text)
    logger.info(f"=> [4/4] Собрано всего текста: {len(full_text)} символов.")

    logger.info("=> НАЧИНАЕМ ПАРСИНГ КОНФИГОВ (vless/vmess)...")
    configs = parse_text(full_text)
    logger.info(f"   Найдено конфигов: {len(configs)}")

    if not configs:
        logger.warning("   КОНФИГОВ НЕ НАЙДЕНО. Завершаем работу.")
        return

    logger.info("=> ФИЛЬТРУЕМ ПО БЕЛОМУ СПИСКУ...")
    valid_configs = []
    for cfg in configs:
        if cfg.ip in allowed_ips and cfg.sni in allowed_snis:
            valid_configs.append(cfg)
    
    logger.info(f"   После фильтрации осталось: {len(valid_configs)} конфигов.")

    if not valid_configs:
        logger.warning("   НИ ОДИН КОНФИГ НЕ ПОДОШЕЛ ПОД БЕЛЫЙ СПИСОК.")
        return

    logger.info("=> НАЧИНАЕМ ПРОВЕРКУ (TLS) ЧЕРЕЗ CHECKER...")
    checker = Checker()
    sem = asyncio.Semaphore(20) # Чуть уменьшили для стабильности
    
    async def check_pair(cfg):
        async with sem:
            is_alive = await checker.check(cfg.ip, cfg.sni)
            if is_alive:
                logger.info(f"   [ЖИВОЙ] {cfg.raw}")
                return cfg.original_link if cfg.original_link else cfg.raw
            return None

    logger.info(f"   Проверяем {len(valid_configs)} конфигов...")
    tasks = [check_pair(cfg) for cfg in valid_configs]
    results = await asyncio.gather(*tasks)

    alive = [r for r in results if r]
    
    WORKING_PROXIES.write_text("\n".join(alive), encoding="utf-8")
    checker.save_cache()
    
    logger.info("=========================================")
    logger.info(f"ГОТОВО! РАБОЧИХ ПРОКСИ: {len(alive)}")
    logger.info(f"Сохранено в файл: {WORKING_PROXIES}")
    logger.info("=========================================")

if __name__ == "__main__":
    asyncio.run(main())
