
import re
import ipaddress
import logging

from dataclasses import dataclass
from typing import Optional


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ServerAddress:
    ip: str
    port: int


@dataclass(frozen=True)
class HostMetadata:
    value: str
    source: str


@dataclass
class ParsedData:
    addresses: list[ServerAddress]
    hosts: list[HostMetadata]


IP_PORT_PATTERN = re.compile(
    r"(?<![\w.])"
    r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})"
    r":"
    r"(?P<port>\d{1,5})"
    r"(?!\d)"
)

HOST_PATTERN = re.compile(
    r"""(?ix)
    \b(?:sni|server_name|servername|host|hostname)
    \s*[:=]\s*
    ["']?
    (?P<host>
        (?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+
        [a-z]{2,63}
    )
    ["']?
    """
)


def validate_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def validate_port(value: str) -> bool:
    try:
        port = int(value)
        return 1 <= port <= 65535
    except (ValueError, TypeError):
        return False


def extract_addresses(text: str) -> list[ServerAddress]:
    if not isinstance(text, str) or not text:
        return []

    results = set()

    for match in IP_PORT_PATTERN.finditer(text):
        ip = match.group("ip")
        port = match.group("port")

        if not validate_ip(ip):
            continue

        if not validate_port(port):
            continue

        results.add(
            ServerAddress(
                ip=ip,
                port=int(port)
            )
        )

    return sorted(
        results,
        key=lambda item: (item.ip, item.port)
    )


def extract_hosts(text: str) -> list[HostMetadata]:
    if not isinstance(text, str) or not text:
        return []

    results = set()

    for match in HOST_PATTERN.finditer(text):
        host = match.group("host").lower()

        results.add(
            HostMetadata(
                value=host,
                source="text"
            )
        )

    return sorted(
        results,
        key=lambda item: item.value
    )


def parse_text(text: str) -> ParsedData:
    if not isinstance(text, str):
        raise TypeError("Input must be a string")

    addresses = extract_addresses(text)
    hosts = extract_hosts(text)

    logger.info(
        "Parsed text: %d addresses, %d hosts",
        len(addresses),
        len(hosts)
    )

    return ParsedData(
        addresses=addresses,
        hosts=hosts
    )


def parse_many(texts: list[str]) -> list[ParsedData]:
    results = []

    for index, text in enumerate(texts):
        try:
            results.append(parse_text(text))

        except Exception:
            logger.exception(
                "Parsing failed for item %d",
                index
            )

    return results


def parsed_to_dict(data: ParsedData) -> dict:
    return {
        "addresses": [
            {
                "ip": item.ip,
                "port": item.port
            }
            for item in data.addresses
        ],
        "hosts": [
            {
                "value": item.value,
                "source": item.source
            }
            for item in data.hosts
        ]
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    sample = """
    Server address: 192.0.2.10:443
    SNI: example.com
    Host: cdn.example.org
    """

    result = parse_text(sample)

    print(parsed_to_dict(result))
