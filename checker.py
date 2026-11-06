import asyncio
import json
import time
import ssl
import socket
from config import DEAD_CACHE_FILE, CHECK_TIMEOUT, CACHE_TTL_HOURS

class DeadCache:
    def __init__(self, path, ttl_hours):
        self.path = path
        self.ttl = ttl_hours * 3600
        self.data = self._load()

    def _load(self):
        if self.path.exists():
            try:
                return json.loads(self.path.read_text())
            except Exception:
                return {}
        return {}

    def save(self):
        self.path.write_text(json.dumps(self.data, indent=2))

    def is_dead(self, ip, sni):
        key = f"{ip}#{sni}"
        if key in self.data:
            if time.time() - self.data[key] < self.ttl:
                return True
            else:
                del self.data[key]
        return False

    def mark_dead(self, ip, sni):
        self.data[f"{ip}#{sni}"] = time.time()

class Checker:
    def __init__(self):
        self.cache = DeadCache(DEAD_CACHE_FILE, CACHE_TTL_HOURS)

    async def check(self, ip, sni, link, protocol):
        if self.cache.is_dead(ip, sni):
            return False

        # Создаем SSL контекст (проверяем рукопожатие)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            # Пытаемся установить защищенное соединение (TLS Handshake)
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 443, ssl=ctx, server_hostname=sni),
                timeout=CHECK_TIMEOUT
            )
            
            # Если соединение установилось — сервер жив
            writer.close()
            await writer.wait_closed()
            print(f"[ALIVE] {ip} | {sni}")
            return True
            
        except Exception:
            self.cache.mark_dead(ip, sni)
            return False

    def save(self):
        self.cache.save()
