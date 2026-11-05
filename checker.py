import asyncio
import base64
import json
import logging
import os
import socket
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit, parse_qs, unquote

import aiohttp
from aiohttp_socks import ProxyConnector

from config import (
    SING_BOX_PATH, CHECK_URLS, CHECK_TIMEOUT, MAX_CONCURRENT_CHECKS,
    DEAD_CACHE_FILE, WORKING_FILE, RECHECK_AFTER_HOURS, BASE_PROXY,
)

log = logging.getLogger(__name__)

def load_json(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default

def save_json_atomic(path, data):
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)

def decode_vmess(uri):
    raw = uri[8:].split("#", 1)[0]
    return json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))

def make_outbound(uri):
    if uri.startswith("vless://"):
        p = urlsplit(uri)
        q = parse_qs(p.query)
        tls_on = q.get("security", [""])[0] in ("tls", "reality")
        tls = {"enabled": tls_on}
        sni = q.get("sni", [""])[0]
        if sni:
            tls["server_name"] = sni
        fp = q.get("fp", [""])[0]
        if fp:
            tls["utls"] = {"enabled": True, "fingerprint": fp}
        if q.get("security", [""])[0] == "reality":
            tls["reality"] = {
                "enabled": True,
                "public_key": q.get("pbk", [""])[0],
                "short_id": q.get("sid", [""])[0],
            }
        out = {
            "type": "vless", "tag": "node", "server": p.hostname,
            "server_port": p.port, "uuid": unquote(p.username or ""),
            "tls": tls,
        }
        flow = q.get("flow", [""])[0]
        if flow:
            out["flow"] = flow
        return out
    if uri.startswith("vmess://"):
        d = decode_vmess(uri)
        tls_on = str(d.get("tls", "")).lower() in ("tls", "true", "1")
        out = {
            "type": "vmess", "tag": "node", "server": d["add"],
            "server_port": int(d["port"]), "uuid": d["id"],
            "security": d.get("scy") or "auto",
            "alter_id": int(d.get("aid") or 0),
        }
        if tls_on:
            out["tls"] = {"enabled": True, "server_name": d.get("sni") or d.get("host") or d["add"]}
        net = d.get("net", "tcp")
        if net == "ws":
            out["transport"] = {"type": "ws", "path": d.get("path") or "/"}
            if d.get("host"):
                out["transport"]["headers"] = {"Host": d["host"]}
        elif net == "grpc":
            out["transport"] = {"type": "grpc", "service_name": d.get("path", "")}
        return out
    if uri.startswith("trojan://"):
        p = urlsplit(uri)
        q = parse_qs(p.query)
        tls = {"enabled": True}
        if q.get("sni", [""])[0]:
            tls["server_name"] = q["sni"][0]
        out = {
            "type": "trojan", "tag": "node", "server": p.hostname,
            "server_port": p.port, "password": unquote(p.username or ""),
            "tls": tls,
        }
        return out
    if uri.startswith("ss://"):
        raw = uri[5:].split("#", 1)[0].split("?", 1)[0]
        if "@" not in raw:
            decoded = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)).decode()
            raw = decoded
        userinfo, address = raw.rsplit("@", 1)
        if ":" not in userinfo:
            userinfo = base64.urlsafe_b64decode(userinfo + "=" * (-len(userinfo) % 4)).decode()
        method, password = userinfo.split(":", 1)
        hostport = urlsplit("//" + address)
        return {
            "type": "shadowsocks", "tag": "node", "server": hostport.hostname,
            "server_port": hostport.port, "method": method, "password": unquote(password),
        }
    raise ValueError("Неподдерживаемый протокол")

def build_singbox_config(uri, socks_port):
    outbound = make_outbound(uri)
    config = {
        "log": {"level": "error"},
        "inbounds": [{
            "type": "socks", "tag": "local-socks",
            "listen": "127.0.0.1", "listen_port": socks_port,
        }],
        "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
        "route": {"final": "node"},
    }
    return config

async def free_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port

async def wait_socks(port, process):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.returncode is not None:
            raise RuntimeError("sing-box завершился до запуска локального SOCKS")
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.close()
            await writer.wait_closed()
            return
        except OSError:
            await asyncio.sleep(0.2)
    raise TimeoutError("Локальный SOCKS sing-box не запустился")

async def http_get_via_proxy(port, url):
    connector = ProxyConnector.from_url(f"socks5://127.0.0.1:{port}")
    timeout = aiohttp.ClientTimeout(total=CHECK_TIMEOUT)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        async with session.get(url, allow_redirects=True) as response:
            await response.read()
            return 200 <= response.status < 400

async def check_one(uri, cache, lock):
    now = int(time.time())
    old = cache.get(uri)
    interval = RECHECK_AFTER_HOURS * 3600
    if old and now - int(old.get("last_checked", 0)) < interval:
        log.info("Пропуск по dead cache (повтор через 2 часа): %s", uri[:70])
        return False

    port = await free_port()
    config = build_singbox_config(uri, port)
    process = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(config, f, ensure_ascii=False)
            config_path = f.name
        process = await asyncio.create_subprocess_exec(
            SING_BOX_PATH, "run", "-c", config_path,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await wait_socks(port, process)
        checks = {}
        for name, url in CHECK_URLS.items():
            try:
                checks[name] = await http_get_via_proxy(port, url)
            except Exception:
                checks[name] = False
        success = any(checks.values())
        if success:
            log.info("Рабочий конфиг: %s", uri[:90])
            async with lock:
                cache.pop(uri, None)
            return True
        log.info("Не прошёл HTTP GET: %s", uri[:90])
        async with lock:
            cache[uri] = {
                "last_checked": now,
                "checks": checks,
                "first_failed": old.get("first_failed", now) if old else now,
            }
        return False
    except Exception as exc:
        log.warning("Ошибка проверки %s: %s", uri[:70], exc)
        async with lock:
            cache[uri] = {
                "last_checked": now,
                "checks": {},
                "error": str(exc)[:300],
                "first_failed": old.get("first_failed", now) if old else now,
            }
        return False
    finally:
        if process and process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=3)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
        if "config_path" in locals():
            try:
                os.unlink(config_path)
            except OSError:
                pass

async def check_all(configs):
    # parser.py передаёт словари с метаданными; checker работает с исходными URI.
    normalized = []
    for item in configs:
        if isinstance(item, dict):
            raw = item.get("raw")
            if isinstance(raw, str) and raw.strip():
                normalized.append(raw.strip())
            else:
                log.warning("Пропущена конфигурация без исходной ссылки: %r", item)
        elif isinstance(item, str) and item.strip():
            normalized.append(item.strip())
        else:
            log.warning("Пропущен объект неизвестного формата: %r", item)

    # Убираем дубликаты, сохраняя порядок.
    normalized = list(dict.fromkeys(normalized))

    cache = load_json(DEAD_CACHE_FILE, {})
    if not isinstance(cache, dict):
        log.warning("Dead cache повреждён или имеет неверный формат; начинаем с пустого словаря")
        cache = {}

    lock = asyncio.Lock()
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_CHECKS)

    async def limited(uri):
        async with semaphore:
            return await check_one(uri, cache, lock)

    results = await asyncio.gather(
        *(limited(uri) for uri in normalized),
        return_exceptions=True,
    )

    for uri, result in zip(normalized, results):
        if isinstance(result, Exception):
            log.error(
                "Необработанная ошибка проверки %s: %s",
                str(uri)[:70],
                result,
            )

    # Рабочий файл — накопительный архив успешных конфигураций.
    existing = set()
    if WORKING_FILE.exists():
        existing.update(
            line.strip()
            for line in WORKING_FILE.read_text(encoding="utf-8").splitlines()
            if line.strip()
        )

    for uri, result in zip(normalized, results):
        if result is True:
            existing.add(uri)

    WORKING_FILE.write_text(
        "\n".join(sorted(existing)) + ("\n" if existing else ""),
        encoding="utf-8",
    )

    # Неуспешные записи сохраняются в dead_cache.json.
    # last_checked используется только для интервала повторной проверки.
    save_json_atomic(DEAD_CACHE_FILE, cache)

    return [
        uri
        for uri, result in zip(normalized, results)
        if result is True
    ]
