import asyncio
import json
import time
import os
import socket
import tempfile
import subprocess
import re
import traceback
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
    def __init__(self):
        # Берем абсолютный путь
        self.bin = Path("xray").resolve()

    def _get_free_port(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1', 0))
            return s.getsockname()[1]

    def _build_config(self, link, ip, sni, local_port):
        parsed = re.match(r'vless://([^@]+)@([^:]+):(\d+)\?([^#\s]+)', link)
        if not parsed:
            return None
            
        uuid = parsed.group(1)
        query = parse_qs(parsed.group(4))

        def get_q(key, default=""):
            val = query.get(key, [default])[0]
            return unquote(val) if val else default

        network = get_q("type", "tcp")
        security = get_q("security", "none")
        
        stream_settings = {"network": network, "security": security}

        if security == "tls":
            stream_settings["tlsSettings"] = {"serverName": sni, "allowInsecure": True, "fingerprint": get_q("fp", "chrome")}
        elif security == "reality":
            stream_settings["realitySettings"] = {"serverName": sni, "fingerprint": get_q("fp", "chrome"), "publicKey": get_q("pbk"), "shortId": get_q("sid"), "spiderX": get_q("spx", "/")}

        if network == "ws":
            stream_settings["wsSettings"] = {"path": get_q("path", "/"), "headers": {"Host": get_q("host", sni)}}
        elif network == "grpc":
            stream_settings["grpcSettings"] = {"serviceName": get_q("serviceName", "")}
        elif network == "xhttp":
            stream_settings["xhttpSettings"] = {"path": get_q("path", "/"), "host": get_q("host", sni), "mode": get_q("mode", "auto")}

        return {
            "log": {"loglevel": "none"},
            "inbounds": [{"port": local_port, "listen": "127.0.0.1", "protocol": "socks", "settings": {"udp": False}}],
            "outbounds": [{
                "protocol": "vless",
                "settings": {"vnext": [{"address": ip, "port": 443, "users": [{"id": uuid, "encryption": "none", "flow": get_q("flow")}]}]},
                "streamSettings": stream_settings
            }]
        }

    async def test_vless(self, ip, sni, link, timeout):
        print(f"[TEST] {ip} | {sni}")
        if not self.bin.exists():
            print(f"[FAIL] Бинарник Xray не найден: {self.bin}")
            return False

        local_port = self._get_free_port()
        config = self._build_config(link, ip, sni, local_port)
        
        if not config:
            print(f"[FAIL] {ip} | Ошибка парсинга ссылки")
            return False

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(config, f)
            config_path = f.name

        process = None
        try:
            process = await asyncio.create_subprocess_exec(
                str(self.bin), "run", "-c", config_path,
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
            )
            await asyncio.sleep(1.5)

            # Если Xray упал с ошибкой
            if process.returncode is not None:
                stderr = (await process.stderr.read()).decode()
                print(f"[FAIL] {ip} | Xray упал: {stderr.strip()[:100]}")
                return False

            connector = ProxyConnector.from_url(f"socks5://127.0.0.1:{local_port}")
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get("https://www.youtube.com", timeout=timeout) as response:
                    if response.status in (200, 301, 302):
                        print(f"[SUCCESS] {ip}")
                        return True
                    else:
                        print(f"[FAIL] {ip} | HTTP {response.status}")
                        return False

        except asyncio.TimeoutError:
            print(f"[TIMEOUT] {ip} | Не ответил за {timeout} сек")
            return False
        except Exception as e:
            print(f"[ERROR] {ip} | {type(e).__name__}: {e}")
            return False
        finally:
            if process and process.returncode is None:
                try:
                    process.terminate()
                    await process.wait()
                except ProcessLookupError:
                    pass
            if os.path.exists(config_path):
                os.remove(config_path)

    async def test_hysteria(self, ip, port, sni, link, timeout):
        return False

class Checker:
    def __init__(self):
        self.cache = DeadCache(DEAD_CACHE_FILE, CACHE_TTL_HOURS)
        self.runner = XrayRunner()

    async def check(self, ip, sni, link, protocol):
        if self.cache.is_dead(ip, sni):
            return False
            
        if protocol in ("hy2", "hysteria2"):
            is_alive = await self.runner.test_hysteria(ip, 443, sni, link, CHECK_TIMEOUT)
        else:
            is_alive = await self.runner.test_vless(ip, sni, link, CHECK_TIMEOUT)
        
        if not is_alive:
            self.cache.mark_dead(ip, sni)
            
        return is_alive

    def save(self):
        self.cache.save()
