import csv
import requests
import os
import sys
from dotenv import load_dotenv

load_dotenv()

NAUTOBOT_URL = os.getenv("NAUTOBOT_URL")
TOKEN = os.getenv("NAUTOBOT_TOKEN")

if not NAUTOBOT_URL:
    print("ERROR: NAUTOBOT_URL is not set in .env")
    sys.exit(1)
if not TOKEN:
    print("ERROR: NAUTOBOT_TOKEN is not set in .env")
    sys.exit(1)

if len(sys.argv) < 2:
    print("Usage: python3 patch_lag_members.py <csv_file>")
    sys.exit(1)

csv_file = sys.argv[1]

headers = {
    "Authorization": f"Token {TOKEN}",
    "Content-Type": "application/json",
}

ok = 0
err = 0

with open(csv_file, encoding="utf-8") as f:
    reader = csv.DictReader(f)
    for row in reader:
        iface_id = row["id"]
        lag_value = row["lag"] or None
        payload = {"lag": lag_value}
        r = requests.patch(
            f"{NAUTOBOT_URL}/api/dcim/interfaces/{iface_id}/",
            json=payload,
            headers=headers,
            timeout=30,
        )
        if r.status_code == 200:
            print(f"OK  {row['name']}")
            ok += 1
        else:
            print(f"ERR {row['name']} — {r.status_code}: {r.text}")
            err += 1

print(f"\nDone: {ok} updated, {err} errors")