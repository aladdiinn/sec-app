#!/usr/bin/env python3
"""
GeoLite2-City Database Downloader for SecurePulse SOC
Downloads the latest free offline MaxMind GeoLite2-City database into ./data/GeoLite2-City.mmdb.
"""

import os
import sys
import urllib.request

MIRROR_URLS = [
    "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb",
    "https://raw.githubusercontent.com/aladdiinn/sec-app/main/data/GeoLite2-City.mmdb"
]

def download_geoip_db(target_dir=None):
    if target_dir is None:
        target_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data")

    os.makedirs(target_dir, exist_ok=True)
    dest_path = os.path.join(target_dir, "GeoLite2-City.mmdb")

    if os.path.isfile(dest_path) and os.path.getsize(dest_path) > 10000000:
        print(f"[INFO] GeoLite2-City database already present at {dest_path} ({os.path.getsize(dest_path)/(1024*1024):.1f} MB)")
        return dest_path

    print(f"[*] Downloading offline GeoLite2-City.mmdb to {dest_path}...")
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

    for url in MIRROR_URLS:
        try:
            print(f"    Fetching from: {url}")
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=60) as resp, open(dest_path + ".tmp", "wb") as out_f:
                total_len = resp.getheader("content-length")
                total_bytes = int(total_len) if total_len and total_len.isdigit() else 0
                downloaded = 0
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    out_f.write(chunk)
                    downloaded += len(chunk)
                    if total_bytes > 0:
                        percent = (downloaded / total_bytes) * 100
                        sys.stdout.write(f"\r    Downloaded: {downloaded/(1024*1024):.1f}MB / {total_bytes/(1024*1024):.1f}MB ({percent:.1f}%)")
                    else:
                        sys.stdout.write(f"\r    Downloaded: {downloaded/(1024*1024):.1f}MB")
                    sys.stdout.flush()
                print("")

            if os.path.getsize(dest_path + ".tmp") > 10000000:
                os.replace(dest_path + ".tmp", dest_path)
                print(f"✅ Successfully downloaded GeoLite2 database ({os.path.getsize(dest_path)/(1024*1024):.1f} MB)")
                return dest_path
            else:
                try: os.remove(dest_path + ".tmp")
                except Exception: pass
        except Exception as e:
            print(f"    Failed from {url}: {e}")
            try: os.remove(dest_path + ".tmp")
            except Exception: pass

    print("⚠️  Could not download GeoLite2 database automatically. Built-in heuristic fallback will be used.")
    return None

if __name__ == "__main__":
    download_geoip_db()
