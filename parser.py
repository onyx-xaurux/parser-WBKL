import re

# Ищем IP:PORT
IP_PORT_REGEX = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{2,5}\b')
# Ищем домены
DOMAIN_REGEX = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')

def parse_text(text):
    ips = set(IP_PORT_REGEX.findall(text))
    hosts = set(DOMAIN_REGEX.findall(text))
    # Убираем мусор из хостов
    hosts = {h for h in hosts if len(h) < 50 and not h.replace('.', '').isdigit()}
    return ips, hosts
