# 5. Проверяем через TLS
    checker = Checker()
    sem = asyncio.Semaphore(50)
    
    async def check_pair(cfg):
        async with sem:
            is_alive = await checker.check(cfg.ip, cfg.sni)
            if is_alive:
                logger.info(f"[ALIVE] {cfg.raw}")
                # Возвращаем ОРИГИНАЛЬНУЮ ССЫЛКУ
                return cfg.original_link if cfg.original_link else cfg.raw
            return None

    logger.info(f"Starting check for {len(valid_configs)} configs...")
    tasks = [check_pair(cfg) for cfg in valid_configs]
    results = await asyncio.gather(*tasks)

    alive = [r for r in results if r]
    
    # Сохраняем ссылки vless://...
    WORKING_PROXIES.write_text("\n".join(alive), encoding="utf-8")
