    valid_configs = []
    for cfg in configs:
        if cfg.ip in allowed_ips and cfg.sni in allowed_snis:
            valid_configs.append(cfg)
    
    logger.info(f"   После фильтрации осталось: {len(valid_configs)} конфигов.")

    # ... (дальше идет проверка)

    async def check_pair(cfg):
        async with sem:
            # Передаем cfg.original_link, чтобы Xray взял оттуда реальный UUID
            is_alive = await checker.check(cfg.ip, cfg.sni, cfg.original_link)
            if is_alive:
                logger.info(f"   [ЖИВОЙ] {cfg.raw}")
                return cfg.original_link if cfg.original_link else cfg.raw
            return None
