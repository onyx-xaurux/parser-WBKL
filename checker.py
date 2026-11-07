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

# МАССИВ ДЛЯ РАСШИРЕНИЯ ПРОВЕРОК
CHECK_URLS = [
    "https://api.telegram.org",
    # "https://cp.cloudflare.com/generate_204", 
    # "https://www.youtube.com"
]

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
    def __init__(self, base_proxy=""):
        self.bin = Path("xray").resolve()
        self.base_proxy = base_proxy

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

        outbound = {
            "protocol": "vless",
            "settings": {"vnext": [{"address": ip, "port": 443, "users": [{"id": uuid, "encryption": "none", "flow": get_q("flow")}]}]},
            "streamSettings": stream_settings
        }

        outbounds = [outbound]

        # Если есть базовый прокси (РФ), добавляем каскад
        if self.base_proxy:
            outbound["proxySettings"] = {"tag": "base-proxy"}
            
            if self.base_proxy.startswith("socks5://"):
                proxy_str = self.base_proxy[9:]
            else:
                proxy_str = self.base_proxy

            if "@" in proxy_str:
                auth, addr = proxy_str.split("@")
                user, pwd = auth.split(":")
                host, port = addr.split(":")
            else:
                user, pwd = "", ""
                host, port = proxy_str.split(":")
            
            proxy_outbound = {
                "tag": "base-proxy",
                "protocol": "socks",
                "settings": {
                    "servers": [{
                        "address": host,
                        "port": int(port),
                        "users": [{"user": user, "pass": pwd}] if user else []
                    }]
                }
            }
            outbounds.append(proxy_outbound)

        return {
            "log": {"loglevel": "warning"},
            "inbounds": [{"port": local_port, "listen": "127.0.0.1", "protocol": "socks", "settings": {"udp": False}}],
            "outbounds": outbounds
        }

    async def test_via_xray(self, ip, sni, link, timeout):
        print(f"[XRAY START] {ip} | {sni} | Base Proxy: {'Yes' if self.base_proxy else 'No'}")
        if not self.bin.exists():
            print(f"[FAIL] {ip} | Xray не найден по пути {self.bin}")
            return False

        local_port = self._get_free_port()
        config = self._build_config(link, ip, sni, local_port)
        
        if not config:
            print(f"[FAIL] {ip} | Не удалось распарсить ссылку")
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

            if process.returncode is not None:
                stderr = (await process.stderr.read()).decode()
                print(f"[FAIL] {ip} | Xray упал: {stderr.strip()[:200]}")
                return False

            connector = ProxyConnector.from_url(f"socks5://127.0.0.1:{local_port}")
            async with aiohttp.ClientSession(connector=connector) as session:
                # ИТЕРИРУЕМСЯ ПО ВСЕМ САЙТАМ ИЗ CHECK_URLS
                for url in CHECK_URLS:
                    try:
                        async with session.get(url, timeout=timeout) as resp:
                            if resp.status not in (200, 204, 301, 302):
                                print(f"[FAIL] {ip} | {url} -> {resp.status}")
                                return False
                            print(f"[SITE OK] {ip} | {url} -> {resp.status}")
                    except Exception as e:
                        print(f"[FAIL] {ip} | {url} упал: {type(e).__name__}")
                        return False
                
                return True # Все сайты из списка открылись

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

class Checker:
    def __init__(self, base_proxy=""):
        self.cache = DeadCache(DEAD_CACHE_FILE, CACHE_TTL_HOURS)
        self.runner = XrayRunner(base_proxy=base_proxy)

    def _get_transport_type(self, link):
        match = re.search(r'[?&]type=([^&]+)', link)
        if match:
            return match.group(1).lower()
        return "tcp"

    async def check(self, ip, sni, link, protocol):
        if self.cache.is_dead(ip, sni):
            return False

        transport = self._get_transport_type(link)
        
        # UDP пропускаем без проверки
        if transport in ("udp", "hy2", "hysteria2", "hysteria", "wireguard") or protocol in ("hy2", "hysteria2"):
            print(f"[ALIVE] {ip} | {sni} | (UDP, пропущен)")
            return True

        is_alive = await self.runner.test_via_xray(ip, sni, link, CHECK_TIMEOUT)
        
        if not is_alive:
            self.cache.mark_dead(ip, sni)
            
        return is_alive

    def save(self):
        self.cache.save()
