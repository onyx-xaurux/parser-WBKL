import asyncio
import json
import ssl
import time
from config import DEAD_CACHE, CHECK_TIMEOUT, CACHE_TTL_HOURS

class Checker:
    def __init__(self):
        self.cache_file = DEAD_CACHE
        self.cache = self._load_cache()
        self.ttl = CACHE_TTL_HOURS * 3600

    def _load_cache(self):
        if self.cache_file.exists():
            try:
                return json.loads(self.cache_file.read_text())
            except:
                return {}
        return {}

    def save_cache(self):
        self.cache_file.write_text(json.dumps(self.cache, indent=2))

    def is_dead(self, ip, sni):
        key = f"{ip}#{sni}"
        if key in self.cache:
            if time.time() - self.cache[key] < self.ttl:
                return True
            else:
                del self.cache[key]
        return False

    def mark_dead(self, ip, sni):
        self.cache[f"{ip}#{sni}"] = time.time()

    async def check(self, ip, sni):
        if self.is_dead(ip, sni):
            return False

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 443, ssl=ctx, server_hostname=sni),
                timeout=CHECK_TIMEOUT
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            self.mark_dead(ip, sni)
            return False
