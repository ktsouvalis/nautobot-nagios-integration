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
# SNMP ifIndex map builder
# ---------------------------------------------------------------------------

from utils import normalize_ifname as _normalize_ifname


def _walk_ifnames_ssh(
    ip: str,
    community: str,
    timeout: int = 10,
    retries: int = 1,
    use_v3: bool = False,
) -> dict:
    """
    Run snmpwalk via SSH on the Nagios VM to get ifName -> ifIndex mapping.
    Returns { ifname: ifindex }. Silently returns empty dict on failure.

    When use_v3=True, credentials are read from env vars:
      SNMP_V3_USER, SNMP_V3_SEC_LEVEL, SNMP_V3_AUTH_PROTO, SNMP_V3_AUTH_PASS,
      SNMP_V3_PRIV_PROTO, SNMP_V3_PRIV_PASS
    """
    from utils import get_ssh_client
    result = {}
    ifname_oid = "1.3.6.1.2.1.31.1.1.1.1"
    try:
        client = get_ssh_client(timeout=timeout)
        try:
            if use_v3:
                user       = os.getenv("SNMP_V3_USER", "nagios")
                sec_level  = os.getenv("SNMP_V3_SEC_LEVEL", "authPriv")
                auth_proto = os.getenv("SNMP_V3_AUTH_PROTO", "SHA")
                auth_pass  = os.getenv("SNMP_V3_AUTH_PASS", "")
                priv_proto = os.getenv("SNMP_V3_PRIV_PROTO", "AES")
                priv_pass  = os.getenv("SNMP_V3_PRIV_PASS", "")
                cmd = (
                    f'snmpwalk -v3 -l {sec_level} -u {user} '
                    f'-a {auth_proto} -A "{auth_pass}" '
                    f'-x {priv_proto} -X "{priv_pass}" '
                    f'-t {timeout} -r {retries} {ip} {ifname_oid}'
                )
            else:
                cmd = f'snmpwalk -v2c -c "{community}" -t {timeout} -r {retries} {ip} {ifname_oid}'
            _, stdout, _ = client.exec_command(cmd)
            output = stdout.read().decode()
        finally:
            client.close()
        for line in output.splitlines():
            if "STRING:" not in line:
                continue
            parts = line.split("=")
            if len(parts) != 2:
                continue
            oid_part   = parts[0].strip()
            value_part = parts[1].strip()
            ifindex    = int(oid_part.split(".")[-1])
            ifname     = value_part.replace("STRING:", "").strip().strip('"')
            result[ifname] = ifindex
    except Exception as e:
        logger.debug(f"SSH snmpwalk failed for {ip}: {e}")
    return result


def fetch_ifindex_map(devices: list, ips_by_id: dict, roles_by_id: dict, config: dict) -> dict:
    """
    For each SNMP-capable device, walk ifName via SSH snmpwalk and build:
      { device_id: { normalized_nautobot_ifname: ifindex } }
    Silently skips devices that don't respond.
    """
    snmp_roles        = [r.lower() for r in config["nautobot"].get("snmp_roles", [])]
    cisco_roles       = [r.lower() for r in config["snmp"].get("cisco_roles", [])]
    v3_roles          = [r.lower() for r in config["snmp"].get("v3_roles", [])]
    community_cisco   = os.getenv("SNMP_COMMUNITY_CISCO", "public")
    community_default = os.getenv("SNMP_COMMUNITY_DEFAULT", "public")
    timeout           = config["snmp"].get("timeout", 10)
    retries           = config["snmp"].get("retries", 1)

    result  = {}
    targets = []

    for device in devices:
        role_obj = device.get("role", {})
        role_id  = role_obj.get("id") if role_obj else None
        role     = roles_by_id.get(role_id, {}).get("name", "").lower().replace(" ", "-") if role_id else ""

        if not any(r in role for r in snmp_roles):
            continue

        ip_obj = device.get("primary_ip4") or device.get("primary_ip6")
        if not ip_obj:
            continue

        ip_id  = ip_obj.get("id")
        ip_rec = ips_by_id.get(ip_id, {})
        ip     = ip_rec.get("address", "").split("/")[0]
        if not ip:
            continue

        use_v3    = bool(v3_roles) and any(r in role for r in v3_roles)
        community = community_cisco if any(r in role for r in cisco_roles) else community_default
        targets.append((device["id"], ip, community, use_v3))

    for dev_id, ip, community, use_v3 in targets:
        logger.info(f"SNMP ifName walk (via SSH): {ip} {'v3' if use_v3 else 'v2c'}")
        raw = _walk_ifnames_ssh(ip, community, timeout, retries, use_v3)
        if raw:
            normalized = {}
            for ifname, ifindex in raw.items():
                # Store both the raw SNMP name AND the normalized Nautobot-style name so
                # transformer.py can resolve ifIndex regardless of naming convention.
                # MikroTik reports "ether1" (raw matches Nautobot).
                # Cisco reports "Gi1/0/1" but Nautobot stores "GigabitEthernet1/0/1",
                # so normalize_ifname("GigabitEthernet1/0/1") → "Gi1/0/1" for lookup.
                normalized[ifname] = ifindex                    # raw  (as the device reports via SNMP)
                normalized[_normalize_ifname(ifname)] = ifindex # abbreviated (matches Nautobot long names)
            result[dev_id] = normalized
            logger.info(f"  → {len(raw)} interfaces indexed")
        else:
            logger.warning(f"  → No SNMP response from {ip}, skipping")

    return result



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

    # Build SNMP ifIndex map: { device_id: { ifname: ifindex } }
    logger.info("Building SNMP ifIndex map for network devices...")
    data["_ifindex_map"] = fetch_ifindex_map(
        data["devices"],
        data["_ips_by_id"],
        data["_roles_by_id"],
        config,
    )
    logger.info(f"ifIndex map built for {len(data['_ifindex_map'])} devices")

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