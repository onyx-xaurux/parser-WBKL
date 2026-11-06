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
from config import DEAD_CACHE, CHECK_TIMEOUT, CACHE_TTL_HOURS

class Checker:
    def __init__(self):
        self.cache_file = DEAD_CACHE
        self.cache = self._load_cache()
        self.ttl = CACHE_TTL_HOURS * 3600
        self.xray_bin = Path("./xray")

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

    def _get_free_port(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1', 0))
            return s.getsockname()[1]

    def _build_config(self, link, ip, sni, local_port):
        uuid = "00000000-0000-0000-0000-000000000000"
        if link.startswith("vless://"):
            match = re.match(r'vless://([^@]+)@', link)
            if match:
                uuid = match.group(1)

        config = {
            "log": {"loglevel": "none"},
            "inbounds": [{
                "port": local_port,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"udp": False}
            }],
            "outbounds": [{
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": ip,
                        "port": 443,
                        "users": [{"id": uuid, "encryption": "none"}]
                    }]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {"serverName": sni, "allowInsecure": True}
                }
            }]
        }
        return config

    async def check(self, ip, sni, link=""):
        if self.is_dead(ip, sni):
            return False

        if not self.xray_bin.exists():
            print("Скачиваем Xray...")
            try:
                subprocess.run(["curl", "-L", "-o", "xray.zip", "https://github.com/XTLS/Xray-core/releases/download/v1.8.7/Xray-linux-64.zip"], check=True)
                subprocess.run(["unzip", "-o", "xray.zip", "-d", "."], check=True)
                self.xray_bin.chmod(0o755)
            except Exception as e:
                print(f"Ошибка скачивания Xray: {e}")
                return False

        local_port = self._get_free_port()
        config = self._build_config(link, ip, sni, local_port)
        
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(config, f)
            config_path = f.name

        process = None
        try:
            process = await asyncio.create_subprocess_exec(
                str(self.xray_bin), "run", "-c", config_path,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            await asyncio.sleep(1.5)

            connector = ProxyConnector.from_url(f"socks5://127.0.0.1:{local_port}")
            async with aiohttp.ClientSession(connector=connector) as session:
                # ЗАПРАШИВАЕМ ЗАБЛОКИРОВАННЫЙ САЙТ
                # Если он откроется — значит сервер реально обходит ТСПУ
                async with session.get("https://www.youtube.com", timeout=CHECK_TIMEOUT) as response:
                    if response.status in (200, 301, 302):
                        return True
        except Exception as e:
            pass
        finally:
            if process:
                process.terminate()
                await process.wait()
            if os.path.exists(config_path):
                os.remove(config_path)

        self.mark_dead(ip, sni)
        return False
