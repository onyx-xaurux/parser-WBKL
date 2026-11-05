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

def make_transport(network, path="", host="", service_name=""):
    network = (network or "tcp").strip().lower()
    path = path or ""
    host = host or ""
    service_name = service_name or ""

    if network in ("", "tcp", "raw"):
        return None
    if network == "ws":
        transport = {"type": "ws"}
        if path:
            transport["path"] = path
        if host:
            transport["headers"] = {"Host": host}
        return transport
    if network == "grpc":
        return {"type": "grpc", "service_name": service_name}
    if network in ("http", "h2"):
        transport = {"type": "http"}
        if path:
            transport["path"] = path
        if host:
            transport["host"] = [item.strip() for item in host.split(",") if item.strip()]
        return transport
    if network == "httpupgrade":
        transport = {"type": "httpupgrade"}
        if path:
            transport["path"] = path
        if host:
            transport["host"] = host
        return transport
    if network == "quic":
        return {"type": "quic"}
    if network == "xhttp":
        raise ValueError(
            "Транспорт XHTTP не поддерживается стандартной сборкой sing-box 1.11.15"
        )
    raise ValueError(f"Неподдерживаемый транспорт: {network}")


def safe_target(uri):
    try:
        parsed = urlsplit(uri)
        return f"{parsed.scheme}://{parsed.hostname or '?'}:{parsed.port or '?'}"
    except Exception:
        return "не удалось определить адрес узла"


def make_outbound(uri):
    if uri.startswith("vless://"):
        p = urlsplit(uri)
        q = parse_qs(p.query, keep_blank_values=True)
        security = q.get("security", [""])[0].lower()
        tls_on = security in ("tls", "reality")
        tls = {"enabled": tls_on}
        sni = q.get("sni", [""])[0]
        if sni:
            tls["server_name"] = sni
        fp = q.get("fp", [""])[0]
        if fp and tls_on:
            tls["utls"] = {"enabled": True, "fingerprint": fp}
        if security == "reality":
            tls["reality"] = {
                "enabled": True,
                "public_key": q.get("pbk", [""])[0],
                "short_id": q.get("sid", [""])[0],
            }
        alpn = q.get("alpn", [""])[0]
        if alpn and tls_on:
            tls["alpn"] = [item for item in alpn.split(",") if item]
        out = {
            "type": "vless", "tag": "node", "server": p.hostname,
            "server_port": p.port, "uuid": unquote(p.username or ""),
            "tls": tls,
        }
        flow = q.get("flow", [""])[0]
        if flow:
            if flow != "xtls-rprx-vision":
                raise ValueError(f"Неподдерживаемый VLESS flow: {flow}")
            out["flow"] = flow

        service_name = (
            q.get("serviceName", [""])[0]
            or q.get("service_name", [""])[0]
            or q.get("path", [""])[0]
        )
        transport = make_transport(
            q.get("type", ["tcp"])[0],
            path=q.get("path", [""])[0],
            host=q.get("host", [""])[0] or q.get("sni", [""])[0],
            service_name=service_name,
        )
        if transport:
            out["transport"] = transport
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
        transport = make_transport(
            net,
            path=d.get("path") or "",
            host=d.get("host") or "",
            service_name=d.get("serviceName") or d.get("path") or "",
        )
        if transport:
            out["transport"] = transport
        return out
    if uri.startswith("trojan://"):
        p = urlsplit(uri)
        q = parse_qs(p.query, keep_blank_values=True)
        tls = {"enabled": True}
        if q.get("sni", [""])[0]:
            tls["server_name"] = q["sni"][0]
        alpn = q.get("alpn", [""])[0]
        if alpn:
            tls["alpn"] = [item for item in alpn.split(",") if item]
        out = {
            "type": "trojan", "tag": "node", "server": p.hostname,
            "server_port": p.port, "password": unquote(p.username or ""),
            "tls": tls,
        }
        service_name = (
            q.get("serviceName", [""])[0]
            or q.get("service_name", [""])[0]
            or q.get("path", [""])[0]
        )
        transport = make_transport(
            q.get("type", ["tcp"])[0],
            path=q.get("path", [""])[0],
            host=q.get("host", [""])[0] or q.get("sni", [""])[0],
            service_name=service_name,
        )
        if transport:
            out["transport"] = transport
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
            output = ""
            if process.stdout:
                try:
                    output = (await process.stdout.read()).decode("utf-8", errors="replace")
                except Exception:
                    pass
            raise RuntimeError(
                f"sing-box завершился до запуска локального SOCKS "
                f"(код {process.returncode}): {output[-2500:] or 'нет вывода'}"
            )
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
            return response.status

async def check_one(uri, cache, lock):
    now = int(time.time())
    old = cache.get(uri)
    interval = RECHECK_AFTER_HOURS * 3600
    old_checks = old.get("checks") if isinstance(old, dict) else None
    has_real_http_result = isinstance(old_checks, dict) and bool(old_checks)
    # Старые записи с checks={} означают ошибку до HTTP GET, а не мёртвый прокси.
    if has_real_http_result and now - int(old.get("last_checked", 0)) < interval:
        log.info("Пропуск по dead cache (HTTP GET уже проверялся): %s", safe_target(uri))
        return False

    process = None
    config_path = None
    target = safe_target(uri)
    try:
        port = await free_port()
        config = build_singbox_config(uri, port)
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(config, f, ensure_ascii=False)
            config_path = f.name
        process = await asyncio.create_subprocess_exec(
            SING_BOX_PATH, "run", "-c", config_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        await wait_socks(port, process)
        checks = {}
        for name, url in CHECK_URLS.items():
            try:
                status = await http_get_via_proxy(port, url)
                checks[name] = 200 <= status < 400
                if checks[name]:
                    log.info("HTTP %s: успешно, статус %d (%s)", name, status, target)
                else:
                    log.warning("HTTP %s: получен статус %d (%s)", name, status, target)
            except Exception as exc:
                checks[name] = False
                log.warning(
                    "HTTP %s: %s: %s (%s)",
                    name,
                    type(exc).__name__,
                    str(exc)[:240] or "без дополнительного описания",
                    target,
                )
        success = any(checks.values())
        if success:
            log.info("Рабочий конфиг: %s", target)
            async with lock:
                cache.pop(uri, None)
            return True
        log.info("Не прошёл ни один HTTP GET: %s", target)
        async with lock:
            cache[uri] = {
                "last_checked": now,
                "checks": checks,
                "first_failed": old.get("first_failed", now) if old else now,
            }
        return False
    except Exception as exc:
        # Ошибка запуска sing-box не доказывает, что удалённый прокси нерабочий.
        # Не добавляем такую запись в dead cache: следующий запуск попробует снова.
        log.error("Проверка не дошла до HTTP GET для %s: %s", target, exc)
        return False
    finally:
        if process and process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=3)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
        if config_path:
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
