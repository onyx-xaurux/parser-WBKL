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

    logger.info(f"Fetching Telegram sources (text + files + deep links)...")
    text = ""
    checked_channels = set()
    
    try:
        client = TelegramClient(StringSession(session_str), int(api_id), api_hash)
        await client.connect()
        
        if not client.is_user_authorized():
            logger.error("Telegram session is not authorized.")
            await client.disconnect()
            return ""

        queue = list(targets)
        
        while queue:
            target = queue.pop(0)
            if target in checked_channels:
                continue
            checked_channels.add(target)
            
            try:
                logger.info(f"Reading TG: {target}")
                messages = await client.get_messages(target, limit=100)
                
                found_configs = 0
                
                for msg in messages:
                    # 1. Читаем текст
                    if msg.text:
                        msg_text = msg.text
                        text += msg_text + "\n"
                        
                        if "vless://" in msg_text or "trojan://" in msg_text or "vmess://" in msg_text:
                            found_configs += 1
                        
                        links = re.findall(r'https?://t\.me/([a-zA-Z0-9_]+)', msg_text)
                        for link in links:
                            channel = f"@{link}"
                            if channel not in checked_channels and not link.startswith("joinchat") and link != "proxy":
                                queue.append(channel)
                    
                    # 2. Читаем прикрепленные файлы (.txt, .json)
                    if msg.document:
                        try:
                            file_bytes = await client.download_media(msg, file=bytes)
                            if file_bytes:
                                file_text = file_bytes.decode('utf-8', errors='ignore')
                                text += file_text + "\n"
                                if "vless://" in file_text or "vmess://" in file_text:
                                    found_configs += 1
                        except Exception as e:
                            logger.error(f"Failed to read file from {target}: {e}")
                            
                if found_configs > 0:
                    logger.info(f"  -> Найдено {found_configs} конфигов/файлов в канале {target}!")
                    
            except FloodWaitError as e:
                logger.warning(f"FloodWait на {target}. Ждем {e.seconds} секунд...")
                await asyncio.sleep(e.seconds)
                queue.append(target)
            except Exception as e:
                logger.error(f"Failed to read {target}: {e}")
                
        await client.disconnect()
    except Exception as e:
        logger.error(f"Telegram client error: {e}")
    return text
