import requests
import os
from dotenv import load_dotenv

load_dotenv()

NAUTOBOT_URL = os.getenv("NAUTOBOT_URL")
TOKEN = os.getenv("NAUTOBOT_TOKEN")

LOCATION = {
    "id": "1d7c7d5d-cb67-4b74-9bd8-b9e193b43784",
    "name": "ESDA Lab",
    "slug": "esda-lab_1d7c",
}

headers = {
    "Authorization": f"Token {TOKEN}",
    "Content-Type": "application/json",
}

ok = 0
err = 0
next_url = f"{NAUTOBOT_URL}/api/ipam/prefixes/?limit=100"

while next_url:
    r = requests.get(next_url, headers=headers)
    r.raise_for_status()
    data = r.json()

    for prefix in data["results"]:
        prefix_id = prefix["id"]
        prefix_name = prefix["prefix"]
        payload = {"location": LOCATION["id"]}
        patch = requests.patch(
            f"{NAUTOBOT_URL}/api/ipam/prefixes/{prefix_id}/",
            json=payload,
            headers=headers,
        )
        if patch.status_code == 200:
            print(f"OK  {prefix_name}")
            ok += 1
        else:
            print(f"ERR {prefix_name} — {patch.status_code}: {patch.text}")
            err += 1

    next_url = data.get("next")

print(f"\nDone: {ok} updated, {err} errors")
