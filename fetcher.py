"""
fetcher.py — Pulls all relevant data from Nautobot 2.x API.

Fetches: Devices, VMs, Interfaces, Cables, IP Addresses, Prefixes,
         Device Roles, Platforms, Sites, Clusters.

Loads secrets from .env, config from config.yaml.
"""

import logging
import os

import requests
import yaml
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------

def load_config(path: str = "config.yaml") -> dict:
    with open(path, "r") as f:
        return yaml.safe_load(f)


# ---------------------------------------------------------------------------
# Nautobot API client
# ---------------------------------------------------------------------------

class NautobotClient:
    def __init__(self, config: dict):
        self.base_url = os.getenv("NAUTOBOT_URL", "").rstrip("/")
        if not self.base_url:
            raise EnvironmentError("NAUTOBOT_URL is not set in .env")
        self.token = os.getenv("NAUTOBOT_TOKEN")
        if not self.token:
            raise EnvironmentError("NAUTOBOT_TOKEN is not set in .env")
        self.verify_ssl = config["nautobot"].get("verify_ssl", True)
        self.timeout = config["nautobot"].get("timeout", 30)
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Token {self.token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        })

    def _build_params(self, params: dict) -> list:
        """
        Convert dict to list of tuples to support repeated keys.
        e.g. {"status": ["active", "staged"]} -> [("status", "active"), ("status", "staged")]

        requests.get(params=dict) collapses list values into a single
        comma-separated string, which Nautobot does not accept.  Passing
        a list of tuples keeps each value as a separate query parameter,
        which is the correct way to send multi-value filters to Nautobot.
        """
        result = []
        for key, value in params.items():
            if isinstance(value, list):
                for v in value:
                    result.append((key, v))
            else:
                result.append((key, value))
        return result

    def _get(self, endpoint: str, params: dict = None) -> list:
        """
        Paginated GET. Nautobot 2.x uses:
          { "count": N, "next": "url|null", "results": [...] }
        """
        url = f"{self.base_url}/api/{endpoint.lstrip('/')}/"
        params = params or {}
        params.setdefault("limit", 200)
        results = []

        # First request uses our params as tuples (supports repeated keys)
        param_tuples = self._build_params(params)

        while url:
            logger.debug(f"GET {url} params={param_tuples}")
            resp = self.session.get(url, params=param_tuples, verify=self.verify_ssl, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
            results.extend(data.get("results", []))
            url = data.get("next")   # next page URL already embeds pagination params
            param_tuples = []        # don't re-append our params on subsequent pages

        logger.debug(f"Fetched {len(results)} records from {endpoint}")
        return results


# ---------------------------------------------------------------------------
# Fetch functions
# ---------------------------------------------------------------------------

def fetch_devices(client: NautobotClient, config: dict) -> list:
    """Fetch physical devices. Filters by status and optionally primary IP."""
    params = {}
    devices = client._get("dcim/devices", params)
    if config["nautobot"].get("require_primary_ip", True):
        devices = [d for d in devices if d.get("primary_ip4") or d.get("primary_ip6")]
    # For debugging: print first device with all fields to inspect structure
    # import json
    # if devices:
    #     print(json.dumps(devices[0], indent=2))
    logger.info(f"Fetched {len(devices)} devices")
    return devices


def fetch_virtual_machines(client: NautobotClient, config: dict) -> list:
    """Fetch VMs. Filters by status and optionally primary IP."""
    params = {}
    vms = client._get("virtualization/virtual-machines", params)
    if config["nautobot"].get("require_primary_ip", True):
        vms = [d for d in vms if d.get("primary_ip4") or d.get("primary_ip6")]
    # For debugging: print first VM with all fields to inspect structure
    # import json
    # if vms:
    #     print(json.dumps(vms[0], indent=2))
    logger.info(f"Fetched {len(vms)} virtual machines")
    return vms


def fetch_interfaces(client: NautobotClient, config: dict) -> list:
    """
    Fetch device interfaces.
    If interfaces_connected_only is True, only return interfaces that have
    a cable attached (i.e. connected to another device).
    """
    params = {}
    if config["nautobot"].get("interfaces_connected_only", True):
        params["connected"] = "true"
    interfaces = client._get("dcim/interfaces", params)
    logger.info(f"Fetched {len(interfaces)} interfaces (connected only: {config['nautobot'].get('interfaces_connected_only', True)})")
    return interfaces


def fetch_vm_interfaces(client: NautobotClient) -> list:
    """Fetch VM interfaces."""
    interfaces = client._get("virtualization/interfaces")
    logger.info(f"Fetched {len(interfaces)} VM interfaces")
    return interfaces


def fetch_cables(client: NautobotClient) -> list:
    """Fetch all cables (physical connections between interfaces)."""
    cables = client._get("dcim/cables")
    logger.info(f"Fetched {len(cables)} cables")
    return cables


def fetch_ip_addresses(client: NautobotClient) -> list:
    """Fetch all IP addresses."""
    ips = client._get("ipam/ip-addresses")
    logger.info(f"Fetched {len(ips)} IP addresses")
    return ips


def fetch_device_roles(client: NautobotClient) -> list:
    """Fetch all device roles (used for SNMP/NRPE/ping classification)."""
    roles = client._get("extras/roles")
    logger.info(f"Fetched {len(roles)} device roles")
    return roles


def fetch_platforms(client: NautobotClient) -> list:
    """Fetch platforms (OS info — used to determine NRPE eligibility for VMs)."""
    platforms = client._get("dcim/platforms")
    logger.info(f"Fetched {len(platforms)} platforms")
    return platforms


def fetch_sites(client: NautobotClient) -> list:
    """Fetch locations (Nautobot 2.x uses locations instead of sites)."""
    locations = client._get("dcim/locations")
    logger.info(f"Fetched {len(locations)} locations")
    return locations


def fetch_clusters(client: NautobotClient) -> list:
    """Fetch VM clusters (used for VM hostgroup mapping)."""
    clusters = client._get("virtualization/clusters")
    logger.info(f"Fetched {len(clusters)} clusters")
    return clusters




# ---------------------------------------------------------------------------
# Main fetch orchestrator — returns all data in one dict
# ---------------------------------------------------------------------------

def fetch_all(config: dict) -> dict:
    """
    Fetches all required data from Nautobot.
    Returns a dict with all objects, ready for transformer.py.
    """
    client = NautobotClient(config)

    logger.info("Starting Nautobot data fetch...")

    data = {
        "devices":       fetch_devices(client, config),
        "vms":           fetch_virtual_machines(client, config),
        "interfaces":    fetch_interfaces(client, config),
        "vm_interfaces": fetch_vm_interfaces(client),
        "cables":        fetch_cables(client),
        "ip_addresses":  fetch_ip_addresses(client),
        "roles":         fetch_device_roles(client),
        "platforms":     fetch_platforms(client),
        "sites":         fetch_sites(client),
        "clusters":      fetch_clusters(client),
    }

    # Build lookup dicts for fast access in transformer.py
    data["_roles_by_id"]     = {r["id"]: r for r in data["roles"]}
    data["_platforms_by_id"] = {p["id"]: p for p in data["platforms"]}
    data["_sites_by_id"]     = {s["id"]: s for s in data["sites"]}
    data["_clusters_by_id"]  = {c["id"]: c for c in data["clusters"]}
    data["_ips_by_id"]       = {ip["id"]: ip for ip in data["ip_addresses"]}

    # Build interface lookup by device id
    data["_interfaces_by_device"] = {}
    for iface in data["interfaces"]:
        dev_id = iface.get("device", {}).get("id")
        if dev_id:
            data["_interfaces_by_device"].setdefault(dev_id, []).append(iface)

    # Build VM interface lookup by VM id
    data["_vm_interfaces_by_vm"] = {}
    for iface in data["vm_interfaces"]:
        vm_id = iface.get("virtual_machine", {}).get("id")
        if vm_id:
            data["_vm_interfaces_by_vm"].setdefault(vm_id, []).append(iface)

    logger.info("Nautobot data fetch complete.")
    _log_summary(data)

    return data


def _log_summary(data: dict):
    logger.info(
        f"Summary — Devices: {len(data['devices'])}, "
        f"VMs: {len(data['vms'])}, "
        f"Interfaces: {len(data['interfaces'])}, "
        f"Cables: {len(data['cables'])}, "
        f"IPs: {len(data['ip_addresses'])}"
    )


# ---------------------------------------------------------------------------
# CLI test — run directly to verify connectivity
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json

    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(message)s")
    cfg = load_config()
    data = fetch_all(cfg)

    print("\n=== FETCH SUMMARY ===")
    for key in ["devices", "vms", "interfaces", "vm_interfaces", "cables", "ip_addresses", "roles", "platforms", "sites", "clusters"]:
        print(f"  {key}: {len(data[key])} records")

    # Dump first device for field inspection
    if data["devices"]:
        print("\n=== FIRST DEVICE (raw) ===")
        print(json.dumps(data["devices"][0], indent=2))

    # Dump first interface for field inspection
    if data["interfaces"]:
        print("\n=== FIRST INTERFACE (raw) ===")
        print(json.dumps(data["interfaces"][0], indent=2))