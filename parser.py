import re
import json
import base64
from urllib.parse import parse_qs

class ProxyConfig:
    def __init__(self, ip, port, sni, original_link=""):
        self.ip = str(ip)
        self.port = str(port)
        
        if isinstance(sni, list):
            sni = sni[0] if sni else ""
        
        self.sni = str(sni).strip().lower()
        self.raw = f"{self.ip}:{self.port}#{self.sni}"
        self.original_link = original_link

    def __repr__(self):
        return self.raw

def _get_param(params, key):
    val = params.get(key)
    if isinstance(val, list):
        return val[0] if val else ""
    return val or ""

def extract_vless(text):
    configs = []
    for match in re.finditer(r'(vless://[^\s]+)', text):
        full_link = match.group(1)
        parsed = re.match(r'vless://([^@]+)@([^:]+):(\d+)\?([^#\s]+)(?:#.*)?', full_link)
        if parsed:
            ip = parsed.group(2)
            port = parsed.group(3)
            params = parse_qs(parsed.group(4))
            sni = _get_param(params, 'sni') or _get_param(params, 'host')
            
            if ip and port and sni:
                configs.append(ProxyConfig(ip, port, sni, full_link))
    return configs

def extract_trojan(text):
    configs = []
    for match in re.finditer(r'(trojan://[^\s]+)', text):
        full_link = match.group(1)
        parsed = re.match(r'trojan://([^@]+)@([^:]+):(\d+)\?([^#\s]+)(?:#.*)?', full_link)
        if parsed:
            ip = parsed.group(2)
            port = parsed.group(3)
            params = parse_qs(parsed.group(4))
            sni = _get_param(params, 'sni') or _get_param(params, 'host')
            
            if ip and port and sni:
                configs.append(ProxyConfig(ip, port, sni, full_link))
    return configs

def extract_vmess(text):
    configs = []
    for match in re.finditer(r'(vmess://[^\s]+)', text):
        full_link = match.group(1)
        try:
            b64 = full_link.replace('vmess://', '')
            b64 += "=" * ((4 - len(b64) % 4) % 4)
            decoded = base64.b64decode(b64).decode('utf-8')
            data = json.loads(decoded)
            
            ip = data.get('add')
            port = str(data.get('port', ''))
            sni = data.get('sni') or data.get('host', '')
            
            if ip and port and sni:
                configs.append(ProxyConfig(ip, port, sni, full_link))
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

# ВОТ ТА САМАЯ ФУНКЦИЯ, КОТОРОЙ НЕ ХВАТАЛО
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
