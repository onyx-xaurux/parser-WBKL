import urllib.request
import yaml
from pathlib import Path
from config import WHITELIST_IPS, WHITELIST_SNI

URL = "https://raw.githubusercontent.com/openlibrecommunity/rewl/refs/heads/master/data/pub/ru.sni.yaml"

def main():
    print("Downloading whitelist...")
    try:
        req = urllib.request.Request(URL, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=60) as response:
            data = yaml.safe_load(response.read().decode('utf-8'))
    except Exception as e:
        print(f"Failed to download: {e}")
        return

    if not data or "names" not in data:
        print("Invalid YAML format")
        return

    sni_set = set()
    ip_set = set()

    for item in data["names"]:
        if "name" in item:
            sni_set.add(item["name"].strip().lower())
        for ip in item.get("ips", []):
            ip_set.add(ip.strip())

    WHITELIST_SNI.write_text("\n".join(sorted(sni_set)), encoding="utf-8")
    WHITELIST_IPS.write_text("\n".join(sorted(ip_set)), encoding="utf-8")

    print(f"Saved {len(sni_set)} SNI and {len(ip_set)} IPs.")

if __name__ == "__main__":
    main()
