"""
transformer.py — Maps Nautobot data to Nagios configuration objects.

Takes the dict from fetcher.fetch_all() and produces:
  - hosts (devices + VMs)
  - hostgroups (by role, location, cluster)
  - services (ping, snmp, nrpe — based on device role)

Uses field names confirmed from live Nautobot 2.x API output.
"""

import logging
import os

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_ip(ip_obj: dict, ips_by_id: dict) -> str | None:
    """
    Resolve primary_ip4 object (which only has id/url) to actual address string.
    Strips the prefix length e.g. '10.10.1.1/24' -> '10.10.1.1'
    """
    if not ip_obj:
        return None
    ip_id = ip_obj.get("id")
    if not ip_id:
        return None
    full_ip = ips_by_id.get(ip_id)
    if not full_ip:
        return None
    address = full_ip.get("address", "")
    return address.split("/")[0] if address else None


def _get_role_slug(role_obj: dict, roles_by_id: dict) -> str:
    """Resolve role object to its slug."""
    if not role_obj:
        return "unknown"
    role_id = role_obj.get("id")
    if not role_id:
        return "unknown"
    role = roles_by_id.get(role_id, {})
    return role.get("name", "unknown").lower().replace(" ", "-")


def _get_location_name(location_obj: dict, sites_by_id: dict) -> str:
    """Resolve location object to its name."""
    if not location_obj:
        return "unknown"
    loc_id = location_obj.get("id")
    if not loc_id:
        return "unknown"
    loc = sites_by_id.get(loc_id, {})
    return loc.get("name", "unknown")


def _get_cluster_name(cluster_obj: dict, clusters_by_id: dict) -> str:
    """Resolve cluster object to its name."""
    if not cluster_obj:
        return "unknown"
    cluster_id = cluster_obj.get("id")
    if not cluster_id:
        return "unknown"
    cluster = clusters_by_id.get(cluster_id, {})
    return cluster.get("name", "unknown")


def _safe_hostname(name: str) -> str:
    """Convert display name to Nagios-safe hostname (no spaces/special chars)."""
    return name.strip().replace(" ", "_").replace("/", "_").replace(":", "_")


def _determine_check_method(role_slug: str, config: dict) -> str:
    """
    Determine monitoring method based on device role slug.
    Returns: 'snmp', 'nrpe', or 'ping'
    """
    snmp_roles = [r.lower() for r in config["nautobot"].get("snmp_roles", [])]
    nrpe_roles = [r.lower() for r in config["nautobot"].get("nrpe_roles", [])]
    phone_roles = [r.lower() for r in config["nautobot"].get("phone_roles", [])]

    if any(r in role_slug for r in snmp_roles):
        return "snmp"
    if any(r in role_slug for r in nrpe_roles):
        return "nrpe"
    if any(r in role_slug for r in phone_roles):
        return "ping"
    return "ping"  # default fallback


# ---------------------------------------------------------------------------
# Host builders
# ---------------------------------------------------------------------------

def _build_device_host(device: dict, data: dict, config: dict) -> dict | None:
    """Build a Nagios host dict from a Nautobot device."""
    ip = _extract_ip(device.get("primary_ip4"), data["_ips_by_id"])
    if not ip:
        ip = _extract_ip(device.get("primary_ip6"), data["_ips_by_id"])
    if not ip:
        logger.warning(f"Device {device['name']} has no resolvable IP, skipping")
        return None

    role_slug = _get_role_slug(device.get("role"), data["_roles_by_id"])
    location = _get_location_name(device.get("location"), data["_sites_by_id"])
    check_method = _determine_check_method(role_slug, config)
    hostname = _safe_hostname(device["name"])

    return {
        "hostname":     hostname,
        "display":      device["display"],
        "address":      ip,
        "role":         role_slug,
        "location":     location,
        "check_method": check_method,
        "type":         "device",
        "nautobot_id":  device["id"],
        "comments":     device.get("comments", ""),
    }


def _build_vm_host(vm: dict, data: dict, config: dict) -> dict | None:
    """Build a Nagios host dict from a Nautobot VM."""
    ip = _extract_ip(vm.get("primary_ip4"), data["_ips_by_id"])
    if not ip:
        ip = _extract_ip(vm.get("primary_ip6"), data["_ips_by_id"])
    if not ip:
        logger.warning(f"VM {vm['name']} has no resolvable IP, skipping")
        return None

    role_slug = _get_role_slug(vm.get("role"), data["_roles_by_id"])
    cluster = _get_cluster_name(vm.get("cluster"), data["_clusters_by_id"])
    hostname = _safe_hostname(vm["name"])

    # VMs default to nrpe unless role says otherwise
    check_method = _determine_check_method(role_slug, config) if role_slug != "unknown" else "nrpe"

    return {
        "hostname":     hostname,
        "display":      vm["display"],
        "address":      ip,
        "role":         role_slug,
        "cluster":      cluster,
        "check_method": check_method,
        "type":         "vm",
        "nautobot_id":  vm["id"],
        "comments":     vm.get("comments", ""),
    }


# ---------------------------------------------------------------------------
# Service builders
# ---------------------------------------------------------------------------

def _build_services(host: dict, config: dict) -> list:
    """Build Nagios service dicts for a host based on its check_method."""
    services = []
    hostname = host["hostname"]
    snmp_community = os.getenv("SNMP_COMMUNITY", "public")
    snmp_version   = config["snmp"].get("version", "2c")
    nrpe_port      = config["nrpe"].get("port", 5666)

    # Every host gets a ping check
    services.append({
        "hostname":    hostname,
        "service":     "PING",
        "check":       "check_ping!100.0,20%!500.0,60%",
        "description": "Host Reachability",
    })

    if host["check_method"] == "snmp":
        services += [
            {
                "hostname":    hostname,
                "service":     "SNMP-UPTIME",
                "check":       f"check_snmp!-C {snmp_community} -v {snmp_version} -o .1.3.6.1.2.1.1.3.0",
                "description": "SNMP Uptime",
            },
            {
                "hostname":    hostname,
                "service":     "SNMP-CPU",
                "check":       f"check_snmp!-C {snmp_community} -v {snmp_version} -o .1.3.6.1.4.1.9.2.1.58.0 -w 80 -c 90",
                "description": "SNMP CPU Load Cisco",
            },
        ]

    elif host["check_method"] == "nrpe":
        services += [
            {
                "hostname":    hostname,
                "service":     "NRPE-CPU",
                "check":       f"check_nrpe!-H {host['address']} -p {nrpe_port} -c check_load",
                "description": "CPU Load NRPE",
            },
            {
                "hostname":    hostname,
                "service":     "NRPE-DISK",
                "check":       f"check_nrpe!-H {host['address']} -p {nrpe_port} -c check_disk",
                "description": "Disk Usage NRPE",
            },
            {
                "hostname":    hostname,
                "service":     "NRPE-MEMORY",
                "check":       f"check_nrpe!-H {host['address']} -p {nrpe_port} -c check_mem",
                "description": "Memory Usage NRPE",
            },
        ]

    return services


# ---------------------------------------------------------------------------
# Hostgroup builder
# ---------------------------------------------------------------------------

def _build_hostgroups(hosts: list) -> dict:
    """
    Build hostgroup dicts from host list.
    Groups by: role, location (devices), cluster (VMs), type (devices/vms/phones)
    Returns dict of { hostgroup_name: { name, alias, members[] } }
    """
    groups = {}

    def _add(group_name: str, alias: str, hostname: str):
        if group_name not in groups:
            groups[group_name] = {"name": group_name, "alias": alias, "members": []}
        groups[group_name]["members"].append(hostname)

    for host in hosts:
        hostname = host["hostname"]
        role     = host.get("role", "unknown")
        htype    = host.get("type", "device")

        # Group by type
        if htype == "device":
            _add("all-devices", "All Physical Devices", hostname)
        elif htype == "vm":
            _add("all-vms", "All Virtual Machines", hostname)

        # Group by role
        if role and role != "unknown":
            _add(f"role-{role}", f"Role: {role.title()}", hostname)

        # Group by location (devices)
        location = host.get("location")
        if location and location != "unknown":
            loc_slug = location.lower().replace(" ", "-")
            _add(f"location-{loc_slug}", f"Location: {location}", hostname)

        # Group by cluster (VMs)
        cluster = host.get("cluster")
        if cluster and cluster != "unknown":
            cluster_slug = cluster.lower().replace(" ", "-")
            _add(f"cluster-{cluster_slug}", f"Cluster: {cluster}", hostname)

        # Phone group
        role_slug = host.get("role", "")
        phone_roles = ["ip-phone", "voip-phone", "phone"]
        if any(p in role_slug for p in phone_roles):
            _add("all-phones", "All IP Phones", hostname)

    return groups


# ---------------------------------------------------------------------------
# Main transform orchestrator
# ---------------------------------------------------------------------------

def transform(data: dict, config: dict) -> dict:
    """
    Takes fetcher data dict, returns Nagios config objects:
      {
        "hosts":      [ {hostname, address, role, check_method, ...} ],
        "services":   [ {hostname, service, check, description} ],
        "hostgroups": { name: {name, alias, members[]} }
      }
    """
    hosts    = []
    services = []

    # --- Devices ---
    for device in data["devices"]:
        host = _build_device_host(device, data, config)
        if host:
            hosts.append(host)
            services.extend(_build_services(host, config))

    # --- VMs ---
    for vm in data["vms"]:
        host = _build_vm_host(vm, data, config)
        if host:
            hosts.append(host)
            services.extend(_build_services(host, config))

    hostgroups = _build_hostgroups(hosts)

    logger.info(
        f"Transformed {len(hosts)} hosts, "
        f"{len(services)} services, "
        f"{len(hostgroups)} hostgroups"
    )

    return {
        "hosts":      hosts,
        "services":   services,
        "hostgroups": hostgroups,
    }


# ---------------------------------------------------------------------------
# CLI test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json
    import yaml
    from dotenv import load_dotenv
    from fetcher import fetch_all, load_config

    load_dotenv()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    cfg  = load_config()
    data = fetch_all(cfg)
    result = transform(data, cfg)

    print(f"\n=== TRANSFORM SUMMARY ===")
    print(f"  Hosts:      {len(result['hosts'])}")
    print(f"  Services:   {len(result['services'])}")
    print(f"  Hostgroups: {len(result['hostgroups'])}")

    print(f"\n=== FIRST HOST ===")
    print(json.dumps(result["hosts"][0], indent=2))

    print(f"\n=== HOSTGROUPS ===")
    for name, hg in result["hostgroups"].items():
        print(f"  {name} ({len(hg['members'])} members)")

    print(f"\n=== SERVICES FOR FIRST HOST ===")
    first = result["hosts"][0]["hostname"]
    for svc in result["services"]:
        if svc["hostname"] == first:
            print(f"  {svc['service']}: {svc['check']}")