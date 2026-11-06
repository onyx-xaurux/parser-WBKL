import asyncio
import json
import time
import os
import socket
import tempfile
import subprocess
import re
from pathlib import Path
from urllib.parse import parse_qs, unquote
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
        # Разбираем ссылку вручную, чтобы вытащить все параметры
        parsed = re.match(r'vless://([^@]+)@([^:]+):(\d+)\?([^#\s]+)', link)
        if not parsed:
            return None
            
        uuid = parsed.group(1)
        query_str = parsed.group(4)
        query = parse_qs(query_str)

        def get_q(key, default=""):
            val = query.get(key, [default])[0]
            return unquote(val) if val else default

        network = get_q("type", "tcp")
        security = get_q("security", "none")
        
        stream_settings = {
            "network": network,
            "security": security
        }

        if security == "tls":
            stream_settings["tlsSettings"] = {
                "serverName": sni,
                "allowInsecure": True,
                "fingerprint": get_q("fp", "chrome")
            }
        elif security == "reality":
            stream_settings["realitySettings"] = {
                "serverName": sni,
                "fingerprint": get_q("fp", "chrome"),
                "publicKey": get_q("pbk"),
                "shortId": get_q("sid"),
                "spiderX": get_q("spx", "/")
            }

        if network == "ws":
            stream_settings["wsSettings"] = {
                "path": get_q("path", "/"),
                "headers": {"Host": get_q("host", sni)}
            }
        elif network == "grpc":
            stream_settings["grpcSettings"] = {
                "serviceName": get_q("serviceName", "")
            }
        elif network == "xhttp":
            stream_settings["xhttpSettings"] = {
                "path": get_q("path", "/"),
                "host": get_q("host", sni),
                "mode": get_q("mode", "auto")
            }

        # Формируем итоговый JSON для Xray
        config = {
            "log": {"loglevel": "none"},
            "inbounds": [{"port": local_port, "listen": "127.0.0.1", "protocol": "socks", "settings": {"udp": False}}],
            "outbounds": [{
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": ip,
                        "port": 443,
                        "users": [{
                            "id": uuid,
                            "encryption": "none",
                            "flow": get_q("flow") # Важно для xtls-rprx-vision
                        }]
                    }]
                },
                "streamSettings": stream_settings
            }]
        }
        return config

    async def test_proxy(self, ip, sni, link, timeout):
        if not self.bin.exists():
            print(f"[FAIL] Бинарник Xray не найден по пути {self.bin}")
            return False

        local_port = self._get_free_port()
        config = self._build_config(link, ip, sni, local_port)
        
        if not config:
            print(f"[FAIL] {ip} | Не удалось разобрать ссылку (возможно, не vless)")
            return False

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(config, f)
            config_path = f.name

        process = None
        try:
            process = await asyncio.create_subprocess_exec(
                str(self.bin), "run", "-c", config_path,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            await asyncio.sleep(1.5) # Ждем запуска Xray

            # Проверяем, не упал ли Xray
            if process.returncode is not None:
                stderr = (await process.stderr.read()).decode()
                print(f"[FAIL] {ip} | Xray упал. Ошибка: {stderr.strip()[:100]}")
                return False

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
