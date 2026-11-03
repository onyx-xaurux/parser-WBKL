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
        self.original_link = original_link # <--- СОХРАНЯЕМ ССЫЛКУ

    def __repr__(self):
        return self.raw

def _get_param(params, key):
    val = params.get(key)
    if isinstance(val, list):
        return val[0] if val else ""
    return val or ""

def extract_vless(text):
    configs = []
    # Ищем ссылки, захватывая их целиком
    for match in re.finditer(r'(vless://[^\s]+)', text):
        full_link = match.group(1)
        # Разбираем ссылку для проверки
        parsed = re.match(r'vless://([^@]+)@([^:]+):(\d+)\?([^#]+)(?:#.*)?', full_link)
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
        parsed = re.match(r'trojan://([^@]+)@([^:]+):(\d+)\?([^#]+)(?:#.*)?', full_link)
        if parsed:
            ip = parsed.group(2)
            port = parsed.group(3)
            params = parse_qs(parsed.group(4))
            sni = _get_param(params, 'sni') or _get_param(params, 'host')
            
            if ip and port and sni:
                configs.append(ProxyConfig(ip, port, sni, full_link))
    return configs

# VMess и JSON оставляем как есть, они проверяются по IP и SNI
# (Для VMess ссылка тоже сохраняется)
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

# ... функции extract_json_configs и parse_text оставляем без изменений ...
