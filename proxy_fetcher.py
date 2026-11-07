import asyncio
import aiohttp
import random
from aiohttp_socks import ProxyConnector

PROXY_SOURCES = [
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt"
]

async def fetch_proxy_list():
    proxies = set()
    async with aiohttp.ClientSession() as session:
        for url in PROXY_SOURCES:
            try:
                async with session.get(url, timeout=10) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        for line in text.splitlines():
                            line = line.strip()
                            if line and ":" in line:
                                proxies.add(f"socks5://{line}")
            except Exception:
                continue
    return list(proxies)

async def check_proxy(proxy_url, timeout=5):
    """Строгая проверка: работает ли прокси и отдает ли он IP РФ"""
    try:
        connector = ProxyConnector.from_url(proxy_url)
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get("http://ip-api.com/json/?fields=status,countryCode,query", timeout=timeout) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("status") == "success" and data.get("countryCode") == "RU":
                        return data.get("query") # Возвращаем IP, если он РФ
    except Exception:
        pass
    return None

async def get_working_proxy():
    print("[PROXY FETCH] Скачиваем список открытых SOCKS5...")
    proxies = await fetch_proxy_list()
    print(f"[PROXY FETCH] Найдено {len(proxies)} прокси. Ищем строго РФ...")
    
    random.shuffle(proxies)
    sem = asyncio.Semaphore(20)
    
    async def check_with_sem(p):
        async with sem:
            ip = await check_proxy(p)
            if ip:
                print(f"[BASE PROXY OK] Найден валидный РФ прокси: {p} (IP: {ip})")
                return p
            return None

    tasks = [check_with_sem(p) for p in proxies]
    results = await asyncio.gather(*tasks)
    
    for res in results:
        if res:
            return res
            
    print("[BASE PROXY FAIL] Не найдено рабочих РФ SOCKS5. Проверка без базового прокси.")
    return ""
