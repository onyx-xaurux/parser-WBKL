
import asyncio
import aiohttp
import json
import logging
import os
import socket
import tempfile

from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import urlsplit, parse_qs

from aiohttp_socks import ProxyConnector

from config import (
    BASE_PROXY,
    SING_BOX_PATH,
    CHECK_URL,
    CHECK_TIMEOUT,
    MAX_CONCURRENT_CHECKS,
    DEAD_CACHE_HOURS,
    DEAD_CACHE_FILE,
)

logger = logging.getLogger(__name__)


def load_cache():
    if not DEAD_CACHE_FILE.exists():
        return {}

    try:
        data = json.loads(
            DEAD_CACHE_FILE.read_text(
                encoding="utf-8"
            )
        )

        return data if isinstance(data, dict) else {}

    except (OSError, json.JSONDecodeError):
        logger.exception("Ошибка чтения dead_cache.json")
        return {}


def save_cache(cache):
    DEAD_CACHE_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    fd, temp_path = tempfile.mkstemp(
        dir=DEAD_CACHE_FILE.parent,
        suffix=".tmp"
    )

    try:
        with os.fdopen(
            fd,
            "w",
            encoding="utf-8"
        ) as file:
            json.dump(
                cache,
                file,
                ensure_ascii=False,
                indent=2
            )

        os.replace(
            temp_path,
            DEAD_CACHE_FILE
        )

    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def cache_is_fresh(entry):
    try:
        timestamp = datetime.fromisoformat(
            entry["timestamp"]
        )

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(
                tzinfo=timezone.utc
            )

        age = (
            datetime.now(timezone.utc)
            - timestamp
        )

        return age < timedelta(
            hours=DEAD_CACHE_HOURS
        )

    except (KeyError, ValueError, TypeError):
        return False


def parse_base_proxy():
    if not BASE_PROXY:
        return None

    parsed = urlsplit(BASE_PROXY)

    scheme = parsed.scheme.lower()

    if scheme in ("socks5", "socks5h"):
        proxy_type = "socks"
        version = "5"

    elif scheme == "socks4":
        proxy_type = "socks"
        version = "4"

    elif scheme == "http":
        proxy_type = "http"
        version = None

    else:
        raise ValueError(
            "BASE_PROXY: поддерживаются socks4, socks5 и http"
        )

    if not parsed.hostname or not parsed.port:
        raise ValueError("Некорректный BASE_PROXY")

    outbound = {
        "type": proxy_type,
        "tag": "base",
        "server": parsed.hostname,
        "server_port": parsed.port,
    }

    if version:
        outbound["version"] = version

    if parsed.username:
        outbound["username"] = parsed.username

    if parsed.password:
        outbound["password"] = parsed.password

    return outbound


def build_node(config):
    """Создаёт outbound sing-box из URI или JSON."""

    raw = config["raw"]
    protocol = config["protocol"]

    if raw.lstrip().startswith("{"):
        outbound = json.loads(raw)

        if not isinstance(outbound, dict):
            raise ValueError("JSON outbound должен быть объектом")

        if outbound.get("type") not in (
            "vless", "vmess", "trojan"
        ):
            raise ValueError("Неподдерживаемый JSON protocol")

        outbound["tag"] = "node"

        if BASE_PROXY:
            outbound["detour"] = "base"

        return outbound

    if protocol == "vmess":
        import base64

        encoded = raw.split("://", 1)[1]
        encoded += "=" * (-len(encoded) % 4)

        data = json.loads(
            base64.urlsafe_b64decode(encoded)
        )

        outbound = {
            "type": "vmess",
            "tag": "node",
            "server": data["add"],
            "server_port": int(data["port"]),
            "uuid": data["id"],
            "security": data.get("scy", "auto"),
            "alter_id": int(data.get("aid", 0)),
        }

        network = data.get("net", "")
        host = data.get("host", "")
        path = data.get("path", "/")

        security = data.get("tls", "")

    else:
        parsed = urlsplit(raw)
        params = parse_qs(parsed.query)

        if not parsed.hostname or not parsed.port:
            raise ValueError("Некорректный адрес сервера")

        outbound = {
            "type": protocol,
            "tag": "node",
            "server": parsed.hostname,
            "server_port": parsed.port,
        }

        if protocol == "vless":
            if not parsed.username:
                raise ValueError("Отсутствует UUID VLESS")

            outbound["uuid"] = parsed.username

            flow = params.get("flow", [""])[0]

            if flow:
                outbound["flow"] = flow

        elif protocol == "trojan":
            if parsed.password is None:
                raise ValueError("Отсутствует пароль Trojan")

            outbound["password"] = parsed.password

        network = params.get("type", [""])[0]
        host = params.get("host", [""])[0]
        path = params.get("path", ["/"])[0]

        security = params.get(
            "security",
            ["tls" if protocol == "trojan" else ""]
        )[0]

    if BASE_PROXY:
        outbound["detour"] = "base"

    sni = config["sni"]

    if security in ("tls", "reality", "true"):
        tls = {
            "enabled": True,
            "server_name": sni,
        }

        fingerprint = (
            data.get("fp", "")
            if protocol == "vmess"
            else params.get("fp", [""])[0]
        )

        if fingerprint:
            tls["utls"] = {
                "enabled": True,
                "fingerprint": fingerprint,
            }

        if security == "reality":
            public_key = params.get("pbk", [""])[0]
            short_id = params.get("sid", [""])[0]

            if not public_key:
                raise ValueError("Reality: отсутствует pbk")

            tls["reality"] = {
                "enabled": True,
                "public_key": public_key,
                "short_id": short_id,
            }

        outbound["tls"] = tls

    if network == "ws":
        transport = {
            "type": "ws",
            "path": path,
        }

        if host:
            transport["headers"] = {
                "Host": host
            }

        outbound["transport"] = transport

    elif network == "grpc":
        service_name = (
            params.get("serviceName", [""])[0]
            if protocol != "vmess"
            else path.strip("/")
        )

        outbound["transport"] = {
            "type": "grpc",
            "service_name": service_name,
        }

    return outbound


def get_free_port():
    with socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    ) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


async def wait_for_socks(process, port):
    """Ожидает готовности локального SOCKS-входа."""

    deadline = asyncio.get_running_loop().time() + 8

    while asyncio.get_running_loop().time() < deadline:
        if process.returncode is not None:
            raise RuntimeError(
                "sing-box завершился при запуске"
            )

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    "127.0.0.1",
                    port
                ),
                timeout=0.5
            )

            writer.close()
            await writer.wait_closed()

            return

        except (OSError, asyncio.TimeoutError):
            await asyncio.sleep(0.2)

    raise TimeoutError("SOCKS-вход не запустился")


async def check_through_singbox(config):
    """Проверяет конфиг через локальный SOCKS-туннель."""

    process = None

    try:
        node = build_node(config)
        port = get_free_port()

        outbounds = []

        base = parse_base_proxy()

        if base:
            outbounds.append(base)

        outbounds.append(node)

        sing_config = {
            "log": {
                "level": "error"
            },

            "inbounds": [
                {
                    "type": "socks",
                    "tag": "local",
                    "listen": "127.0.0.1",
                    "listen_port": port
                }
            ],

            "outbounds": outbounds,

            "route": {
                "final": "node"
            }
        }

        with tempfile.TemporaryDirectory(
            prefix="proxy_check_"
        ) as temp_dir:

            config_path = Path(temp_dir) / "config.json"

            config_path.write_text(
                json.dumps(sing_config),
                encoding="utf-8"
            )

            process = await asyncio.create_subprocess_exec(
                SING_BOX_PATH,
                "run",
                "-c",
                str(config_path),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )

            await wait_for_socks(process, port)

            connector = ProxyConnector.from_url(
                f"socks5://127.0.0.1:{port}"
            )

            timeout = aiohttp.ClientTimeout(
                total=CHECK_TIMEOUT
            )

            async with aiohttp.ClientSession(
                connector=connector,
                timeout=timeout
            ) as session:

                async with session.get(
                    CHECK_URL,
                    allow_redirects=False
                ) as response:

                    return response.status in (200, 204)

    except Exception as error:
        logger.debug(
            "Ошибка проверки %s: %s",
            config.get("ip"),
            error
        )

        return False

    finally:
        if process and process.returncode is None:
            process.terminate()

            try:
                await asyncio.wait_for(
                    process.wait(),
                    timeout=3
                )

            except asyncio.TimeoutError:
                process.kill()
                await process.wait()


async def check_all(configs):
    """Проверяет список конфигов и обновляет dead cache."""

    cache = load_cache()
    alive = []

    semaphore = asyncio.Semaphore(
        MAX_CONCURRENT_CHECKS
    )

    async def check_one(config):
        key = (
            f'{config["ip"]}:{config["sni"]}'
        )

        if cache_is_fresh(cache.get(key, {})):
            logger.info(
                "[SKIP] Пропущен из кеша: %s",
                key
            )
            return None

        async with semaphore:
            result = await check_through_singbox(config)

        if result:
            logger.info(
                "[ALIVE] Успешно проверен %s",
                config["ip"]
            )

            cache.pop(key, None)

            return config

        logger.warning(
            "[DEAD] Сервер упал в кеш: %s",
            key
        )

        cache[key] = {
            "ip": config["ip"],
            "sni": config["sni"],
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat()
        }

        return False

    results = await asyncio.gather(
        *(check_one(config) for config in configs),
        return_exceptions=True
    )

    for result in results:
        if isinstance(result, dict):
            alive.append(result)

        elif isinstance(result, Exception):
            logger.error(
                "Ошибка задачи проверки: %s",
                result
            )

    cache = {
        key: value
        for key, value in cache.items()
        if cache_is_fresh(value)
    }

    save_cache(cache)

    logger.info(
        "Проверка завершена. Рабочих серверов: %d",
        len(alive)
    )

    return alive
