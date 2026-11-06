import asyncio
import json
import time
import os
import socket
import tempfile
import subprocess
import re
from pathlib import Path
import aiohttp
from aiohttp_socks import ProxyConnector
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

class XrayRunner:
    def __init__(self, bin_path=Path("./xray")):
        self.bin = bin_path

    def _get_free_port(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1', 0))
            return s.getsockname()[1]

    def _build_config(self, link, ip, sni, local_port):
        uuid = "00000000-0000-0000-0000-000000000000"
        match = re.search(r'vless://([^@]+)@', link)
        if match:
            uuid = match.group(1)

        return {
            "log": {"loglevel": "none"},
            "inbounds": [{"port": local_port, "listen": "127.0.0.1", "protocol": "socks", "settings": {"udp": False}}],
            "outbounds": [{
                "protocol": "vless",
                "settings": {"vnext": [{"address": ip, "port": 443, "users": [{"id": uuid, "encryption": "none"}]}]},
                "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {"serverName": sni, "allowInsecure": True}}
            }]
        }

    async def test_proxy(self, ip, sni, link, timeout):
        if not self.bin.exists():
            print(f"[FAIL] Бинарник Xray не найден по пути {self.bin}")
            return False

        local_port = self._get_free_port()
        config = self._build_config(link, ip, sni, local_port)
        
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(config, f)
            config_path = f.name

        process = None
        try:
            process = await asyncio.create_subprocess_exec(
                str(self.bin), "run", "-c", config_path,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            await asyncio.sleep(1.5) # Ждем запуска Xray

            connector = ProxyConnector.from_url(f"socks5://127.0.0.1:{local_port}")
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get("https://www.youtube.com", timeout=timeout) as response:
                    if response.status in (200, 301, 302):
                        return True
                    else:
                        print(f"[FAIL] {ip} | HTTP код: {response.status}")
                        return False
        except Exception as e:
            print(f"[ERROR] {ip} | {type(e).__name__}: {e}")
            return False
        finally:
            if process:
                process.terminate()
                await process.wait()
            if os.path.exists(config_path):
                os.remove(config_path)

class Checker:
    def __init__(self):
        self.cache = DeadCache(DEAD_CACHE_FILE, CACHE_TTL_HOURS)
        self.runner = XrayRunner()

    async def check(self, ip, sni, link):
        if self.cache.is_dead(ip, sni):
            return False
            
        is_alive = await self.runner.test_proxy(ip, sni, link, CHECK_TIMEOUT)
        
        if not is_alive:
            self.cache.mark_dead(ip, sni)
            
        return is_alive

    def save(self):
        self.cache.save()
