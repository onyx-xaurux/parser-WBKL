import re
import json
import base64
from urllib.parse import parse_qs

class ProxyConfig:
    def __init__(self, ip, port, sni):
        self.ip = ip
        self.port = port
        self.sni = sni
        self.raw = f"{ip}:{port}#{sni}"

    def __repr__(self):
        return self.raw

def extract_vless(text):
    configs = []
    for match in re.finditer(r'vless://([^@]+)@([^:]+):(\d+)\?([^#]+)(?:#.*)?', text):
        ip = match.group(2)
        port = match.group(3)
        params = parse_qs(match.group(4))
        sni = params.get('sni', params.get('host', [''])[0])
        if ip and port and sni:
            configs.append(ProxyConfig(ip, port, sni))
    return configs

def extract_trojan(text):
    configs = []
    for match in re.finditer(r'trojan://([^@]+)@([^:]+):(\d+)\?([^#]+)(?:#.*)?', text):
        ip = match.group(2)
        port = match.group(3)
        params = parse_qs(match.group(4))
        sni = params.get('sni', params.get('host', [''])[0])
        if ip and port and sni:
            configs.append(ProxyConfig(ip, port, sni))
    return configs

def extract_vmess(text):
    configs = []
    for match in re.finditer(r'vmess://([A-Za-z0-9+/=]+)', text):
        try:
            b64 = match.group(1)
            b64 += "=" * ((4 - len(b64) % 4) % 4)
            decoded = base64.b64decode(b64).decode('utf-8')
            data = json.loads(decoded)
            ip = data.get('add')
            port = str(data.get('port', ''))
            sni = data.get('sni') or data.get('host', '')
            if ip and port and sni:
                configs.append(ProxyConfig(ip, port, sni))
        except Exception:
            pass
    return configs

def extract_json_configs(text):
    configs = []
    for match in re.finditer(r'\{[^{}]*"server"\s*:\s*"([^"]+)"[^{}]*"server_port"\s*:\s*(\d+)[^{}]*\}', text):
        ip = match.group(1)
        port = match.group(2)
        block = match.group(0)
        sni_match = re.search(r'"(?:sni|server_name|host)"\s*:\s*"([^"]+)"', block)
        sni = sni_match.group(1) if sni_match else ""
        if ip and port and sni:
            configs.append(ProxyConfig(ip, port, sni))
    return configs

def parse_text(text):
    all_configs = []
    all_configs.extend(extract_vless(text))
    all_configs.extend(extract_trojan(text))
    all_configs.extend(extract_vmess(text))
    all_configs.extend(extract_json_configs(text))

    unique = {}
    for c in all_configs:
        unique[c.raw] = c
    return list(unique.values())
