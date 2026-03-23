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
import re
import subprocess

logger = logging.getLogger(__name__)

_ifindex_cache: dict = {}  # {(host_ip, community): {ifname: ifindex}}
_IFINDEX_LINE_RE = re.compile(r".*?\.(\d+)\s*=\s*STRING:\s*\"?(.*?)\"?\s*$")


# ---------------------------------------------------------------------------
# SNMP auth helper
# ---------------------------------------------------------------------------

def _snmp_auth_args(role: str, config: dict, for_snmp_int: bool = False) -> str:
    """
    Return SNMP authentication CLI args for a given device role.

    for_snmp_int=False (default) → check_snmp plugin flags:
      SNMPv3: -U (uppercase) for username; v2c: -P <version>
    for_snmp_int=True → check_snmp_int.pl (manubulon) plugin flags:
      SNMPv3: -u (lowercase) for username; v2c: -2 (manubulon -v means verbose)

    Credentials are read from env vars:
      SNMP_V3_USER, SNMP_V3_SEC_LEVEL, SNMP_V3_AUTH_PROTO, SNMP_V3_AUTH_PASS,
      SNMP_V3_PRIV_PROTO, SNMP_V3_PRIV_PASS, SNMP_COMMUNITY_CISCO,
      SNMP_COMMUNITY_DEFAULT
    """
    snmp_cfg    = config.get("snmp", {})
    v3_roles    = [r.lower() for r in snmp_cfg.get("v3_roles", [])]
    cisco_roles = [r.lower() for r in snmp_cfg.get("cisco_roles", [])]

    if v3_roles and role in v3_roles:
        user       = os.getenv("SNMP_V3_USER", "nagios")
        sec_level  = os.getenv("SNMP_V3_SEC_LEVEL", "authPriv")
        auth_proto = os.getenv("SNMP_V3_AUTH_PROTO", "SHA")
        auth_pass  = os.getenv("SNMP_V3_AUTH_PASS", "")
        priv_proto = os.getenv("SNMP_V3_PRIV_PROTO", "AES")
        priv_pass  = os.getenv("SNMP_V3_PRIV_PASS", "")
        u_flag = "-u" if for_snmp_int else "-U"
        return (
            f"-v 3 -l {sec_level} {u_flag} {user} "
            f"-a {auth_proto} -A {auth_pass} "
            f"-x {priv_proto} -X {priv_pass}"
        )

    community = _get_snmp_community(role, config)
    if for_snmp_int:
        version = snmp_cfg.get("version", "2c")
        return f"-C {community} -2" if version == "2c" else f"-C {community}"
    version = snmp_cfg.get("version", "2c")
    return f"-C {community} -P {version}"


# ---------------------------------------------------------------------------
# SNMP ifIndex discovery (exact interface matching, avoids substring false positives)
# ---------------------------------------------------------------------------

def _get_snmp_community(role: str, config: dict) -> str:
    """Return the SNMPv2c community string for the role, or '' for v3 devices."""
    snmp_cfg = config.get("snmp", {})
    v3_roles = [r.lower() for r in snmp_cfg.get("v3_roles", [])]
    if role in v3_roles:
        return ""  # v3 — snmpwalk command-line args differ, skip discovery
    cisco_roles = [r.lower() for r in snmp_cfg.get("cisco_roles", [])]
    cisco_community_roles = [r.lower() for r in snmp_cfg.get("cisco_community_roles", cisco_roles)]
    return (
        os.getenv("SNMP_COMMUNITY_CISCO", "public")
        if role in cisco_community_roles
        else os.getenv("SNMP_COMMUNITY_DEFAULT", "public")
    )


def _discover_ifindex_map(host_ip: str, community: str) -> dict:
    """
    Walk ifDescr (.1.3.6.1.2.1.2.2.1.2) via snmpwalk and return {ifname: ifindex}.

    Using ifIndex with check_snmp_int -i avoids substring false positives:
    e.g. filter "GigabitEthernet1/0/1" would otherwise also match
    GigabitEthernet1/0/10 through 1/0/19.

    Returns empty dict on any failure so the caller can fall back to -n name filter.
    Results are cached per (host_ip, community) for the lifetime of the process.
    """
    cache_key = (host_ip, community)
    if cache_key in _ifindex_cache:
        return _ifindex_cache[cache_key]

    mapping = {}
    try:
        result = subprocess.run(
            ["snmpwalk", "-v2c", "-c", community, host_ip, ".1.3.6.1.2.1.2.2.1.2"],
            capture_output=True, text=True, timeout=30,
        )
        for line in result.stdout.splitlines():
            m = _IFINDEX_LINE_RE.match(line)
            if m:
                ifname = m.group(2).strip()
                ifindex = int(m.group(1))
                if ifname:
                    mapping[ifname] = ifindex
        logger.debug(f"ifIndex discovery: {host_ip} → {len(mapping)} interfaces mapped")
    except FileNotFoundError:
        logger.debug("snmpwalk not found — falling back to name-based interface filter")
    except Exception as e:
        logger.debug(f"ifIndex discovery failed for {host_ip}: {e}")

    _ifindex_cache[cache_key] = mapping
    return mapping


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


def _extract_notes_url(obj: dict, config: dict) -> str:
    """
    Read Nautobot custom_fields on a device or VM and return a notes_url value.

    The field names to check are configured in config.yaml under
    custom_fields.notes_url_fields (checked in order; first non-empty wins).
    Defaults to ["nagios_notes_url", "runbook_url", "wiki_url"].
    """
    field_names = config.get("custom_fields", {}).get(
        "notes_url_fields", ["nagios_notes_url", "runbook_url", "wiki_url"]
    )
    custom_fields = obj.get("custom_fields") or {}
    for field in field_names:
        value = custom_fields.get(field)
        if value and isinstance(value, str) and value.strip():
            return value.strip()
    return ""


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
        "notes_url":    _extract_notes_url(device, config),
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
        "notes_url":    _extract_notes_url(vm, config),
    }


# ---------------------------------------------------------------------------
# Service builders
# ---------------------------------------------------------------------------

def _build_services(host: dict, config: dict) -> list:
    """Build Nagios service dicts for a host based on its check_method."""
    services = []
    hostname    = host["hostname"]
    cisco_roles = config["snmp"].get("cisco_roles", [])
    snmp_args   = _snmp_auth_args(host["role"], config)

    # Every host gets a ping check
    services.append({
        "hostname":    hostname,
        "service":     "PING",
        "check":       "check_ping!100.0,20%!500.0,60%",
        "description": "Host Reachability",
    })

    if host["check_method"] == "snmp" and host["type"] != "vm":
        snmp_services = [
            {
                "hostname":    hostname,
                "service":     "SNMP-UPTIME",
                "check":       f"check_snmp!{snmp_args} -o .1.3.6.1.2.1.1.3.0",
                "description": "SNMP Uptime",
            },
        ]
        # Cisco-specific CPU OID — only for cisco_roles
        if host["role"] in cisco_roles:
            snmp_services.append({
                "hostname":    hostname,
                "service":     "SNMP-CPU",
                "check":       f"check_snmp!{snmp_args} -o .1.3.6.1.4.1.9.2.1.58.0 -w 80 -c 90",
                "description": "SNMP CPU Load - Cisco",
            })
        services += snmp_services

    elif host["check_method"] == "nrpe":
        # check_nrpe uses $HOSTADDRESS$ and port from the command definition;
        # we pass only the NRPE command name as $ARG1$
        services += [
            {
                "hostname":    hostname,
                "service":     "NRPE-CPU",
                "check":       "check_nrpe!check_load",
                "description": "CPU Load NRPE",
            },
            {
                "hostname":    hostname,
                "service":     "NRPE-DISK",
                "check":       "check_nrpe!check_disk",
                "description": "Disk Usage NRPE",
            },
            {
                "hostname":    hostname,
                "service":     "NRPE-MEMORY",
                "check":       "check_nrpe!check_mem",
                "description": "Memory Usage NRPE",
            },
        ]

    return services


def _build_ssl_services(host: dict, config: dict) -> list:
    """
    Build SSL certificate expiry checks for NRPE hosts.

    Uses check_http with -S --sni -C <warn_days>,<crit_days> which alerts
    when the certificate expires within the threshold.  Runs directly from
    the Nagios server (not via NRPE) against the host's address.

    Ports to check are configured in ssl.ports (default: [443]).
    Roles that should be checked are configured in ssl.check_roles.
    """
    ssl_cfg    = config.get("ssl", {})
    check_roles = [r.lower() for r in ssl_cfg.get("check_roles", ["server", "hypervisor"])]
    ports       = ssl_cfg.get("ports", [443])
    warn_days   = ssl_cfg.get("warn_days", 30)
    crit_days   = ssl_cfg.get("crit_days", 14)

    if host["check_method"] != "nrpe":
        return []
    if not any(r in host["role"] for r in check_roles):
        return []

    hostname = host["hostname"]
    address  = host["address"]
    services = []

    for port in ports:
        services.append({
            "hostname":    hostname,
            "service":     f"SSL-CERT-{port}",
            "check":       f"check_http!-H {address} -p {port} -S --sni -C {warn_days},{crit_days}",
            "description": f"SSL Certificate Expiry port {port}",
        })

    return services


def _ifname_to_snmp_filter(ifname: str, hostname: str, config: dict) -> str:
    """
    Return the check_snmp_int -n filter string for an interface.

    The value is treated as a Perl regex by check_snmp_int.pl, so anchors are
    included to prevent substring false-positives (e.g. "1/0/1" matching 1/0/10…19).

    Most devices (Cisco etc.) expose ifDescr matching the Nautobot name directly.
    These get ^name$ anchors for exact matching.

    Some vendors (e.g. D-Link) use "Unit: X Slot: Y Port: Z Type - Level" in
    ifDescr.  List those device hostnames in snmp.unit_slot_port_devices and this
    function will convert GigabitEthernetU/S/P → "Unit: U Slot: S Port: P Gigabit",
    TenGigabitEthernetU/S/P → "Unit: U Slot: S Port: P 10G",
    Port-channelN → "Link Aggregate N".
    For these devices the ifDescr has trailing text ("- Level: N") so only a ^
    prefix anchor is used (no $ suffix).
    """
    usp_devices = [d.upper() for d in config.get("snmp", {}).get("unit_slot_port_devices", [])]
    if hostname.upper() not in usp_devices:
        return f"^{ifname}$"

    m = re.match(r"^(GigabitEthernet|TenGigabitEthernet|FastEthernet)(\d+)/(\d+)/(\d+)$", ifname)
    if m:
        prefix, unit, slot, port = m.group(1), m.group(2), m.group(3), m.group(4)
        type_str = {"GigabitEthernet": "Gigabit", "TenGigabitEthernet": "10G", "FastEthernet": "Fast Ethernet"}.get(prefix, prefix)
        return f"^Unit: {unit} Slot: {slot} Port: {port} {type_str}"

    return f"^{ifname}$"


def _build_interface_services(host: dict, data: dict, config: dict) -> list:
    """
    Build check_snmp_int interface services for SNMP-capable devices.

    Uses check_snmp_int.pl (manubulon) instead of raw check_snmp, which gives:
    - Automatic ifIndex resolution by interface name (no pre-walk needed)
    - On-disk state storage (-k) so the plugin computes bytes/sec internally
    - Performance data output (-f): traffic_in=<bytes/s>B/s traffic_out=<bytes/s>B/s

    One service per interface replaces the former STATUS + IN + OUT triple.
    The service alerts CRITICAL if ifOperStatus is not Up (replaces STATUS check)
    and emits traffic rates for the network map tooltip (replaces IN/OUT checks).
    """
    if host["check_method"] != "snmp" or host["type"] != "device":
        return []

    device_id  = host["nautobot_id"]
    interfaces = data.get("_interfaces_by_device", {}).get(device_id, [])
    if not interfaces:
        return []

    snmp_args = _snmp_auth_args(host["role"], config, for_snmp_int=True)
    hostname  = host["hostname"]
    services  = []
    # Bandwidth thresholds (bytes/sec, in and out).  Defaults are set very high
    # so the check only alerts on interface down, not on bandwidth saturation.
    warn_bps  = config["snmp"].get("int_warn_bps", 999999999)
    crit_bps  = config["snmp"].get("int_crit_bps", 999999999)
    iface_name_by_id = data.get("_iface_name_by_id", {})

    # Pre-discover ifIndex for exact interface matching (avoids substring false positives).
    # Falls back to name-based filter if snmpwalk is unavailable or times out.
    community  = _get_snmp_community(host["role"], config)
    ifindex_map = _discover_ifindex_map(host["address"], community) if community else {}

    for iface in interfaces:
        ifname = iface.get("name", "")
        if not ifname:
            continue
        # Port-channel (LAG) interfaces are skipped — their membership is already
        # noted in the description of each member interface ("LAG: Port-channelN").
        if re.match(r"^[Pp]ort-[Cc]hannel\d+$", ifname):
            continue
        safe_name = ifname.replace("/", "-").replace(" ", "_")
        lag_id   = (iface.get("lag") or {}).get("id", "")
        lag_name = iface_name_by_id.get(lag_id, "")
        description = f"Interface {ifname} Traffic" + (f" (LAG: {lag_name})" if lag_name else "")

        ifindex = ifindex_map.get(ifname)
        if ifindex:
            check = f"check_snmp_int_index!{snmp_args} -k -f -w {warn_bps},{warn_bps} -c {crit_bps},{crit_bps}!{ifindex}"
        else:
            snmp_filter = _ifname_to_snmp_filter(ifname, hostname, config)
            check = f"check_snmp_int!{snmp_args} -k -f -w {warn_bps},{warn_bps} -c {crit_bps},{crit_bps}!{snmp_filter}"

        services.append({
            "hostname":    hostname,
            "service":     f"IFACE-{safe_name}",
            "check":       check,
            "description": description,
        })

    return services


def _build_bgp_services(host: dict, data: dict, config: dict) -> list:
    """
    Build BGP peer state checks for router-role SNMP devices.

    Uses BGP4-MIB::bgpPeerState (.1.3.6.1.2.1.15.3.1.2.<peer_ip_as_oid>).
    State 6 = Established; anything else is a problem.

    Peer IPs are pulled from Nautobot IP addresses whose assigned interface
    belongs to this device and whose description matches 'bgp' (case-insensitive),
    supplemented by any statically configured peers in config.yaml under
    bgp.static_peers[hostname].
    """
    bgp_cfg = config.get("bgp", {})
    router_roles = [r.lower() for r in bgp_cfg.get("router_roles", ["router"])]

    if host["check_method"] != "snmp" or host["type"] != "device":
        return []
    if not any(r in host["role"] for r in router_roles):
        return []

    snmp_args = _snmp_auth_args(host["role"], config)
    hostname  = host["hostname"]
    device_id = host["nautobot_id"]

    # Collect peer IPs: from Nautobot IPs on this device's interfaces
    peer_ips = set()
    for iface in data.get("_interfaces_by_device", {}).get(device_id, []):
        desc = (iface.get("description") or "").lower()
        if "bgp" not in desc:
            continue
        # IPs assigned to this interface
        for ip_rec in data.get("ip_addresses", []):
            assigned = ip_rec.get("assigned_object", {}) or {}
            if assigned.get("id") == iface.get("id"):
                addr = ip_rec.get("address", "").split("/")[0]
                if addr:
                    peer_ips.add(addr)

    # Also include statically configured peers from config.yaml
    for peer in bgp_cfg.get("static_peers", {}).get(hostname, []):
        peer_ips.add(peer)

    services = []
    for peer_ip in sorted(peer_ips):
        # BGP4-MIB bgpPeerState OID suffix is the peer IP in dotted-decimal notation.
        # e.g. peer 10.0.0.1 → OID .1.3.6.1.2.1.15.3.1.2.10.0.0.1
        oid = f".1.3.6.1.2.1.15.3.1.2.{peer_ip}"
        safe_peer = peer_ip.replace(".", "-")
        # check_snmp flag meanings:
        #   -e 6        → expected string/value is "6" (Established state)
        #   -w 6:6      → warn if value outside range [6,6] (i.e. anything != 6)
        #   -c 6:6      → crit under same condition (we skip warning, go straight to critical)
        # BGP peer state integers: 1=Idle, 2=Connect, 3=Active, 4=OpenSent, 5=OpenConfirm, 6=Established
        services.append({
            "hostname":    hostname,
            "service":     f"BGP-PEER-{safe_peer}",
            "check":       f"check_snmp!{snmp_args} -o {oid} -e 6 -w 6:6 -c 6:6",
            "description": f"BGP Peer {peer_ip} State",
        })

    return services


def _build_ups_services(host: dict, config: dict) -> list:
    """
    Build UPS-MIB SNMP checks for UPS-role devices (RFC 1628).

    Checks:
      - Battery status      upsBatteryStatus (.1.3.6.1.2.1.33.1.2.1.0)
                            1=unknown, 2=batteryNormal, 3=batteryLow, 4=batteryDepleted
      - Estimated runtime   upsEstimatedMinutesRemaining (.1.3.6.1.2.1.33.1.2.3.0)
      - Battery charge %    upsEstimatedChargeRemaining (.1.3.6.1.2.1.33.1.2.4.0)
      - Output load %       upsOutputPercentLoad (.1.3.6.1.2.1.33.1.4.4.1.5.1)
    """
    ups_roles = [r.lower() for r in config.get("ups", {}).get("ups_roles", ["ups"])]

    if host["check_method"] != "snmp" or host["type"] != "device":
        return []
    if not any(r in host["role"] for r in ups_roles):
        return []

    snmp_args = _snmp_auth_args(host["role"], config)
    hostname  = host["hostname"]

    ups_cfg          = config.get("ups", {})
    warn_runtime     = ups_cfg.get("warn_runtime_minutes", 15)
    crit_runtime     = ups_cfg.get("crit_runtime_minutes", 5)
    warn_charge      = ups_cfg.get("warn_charge_pct", 50)
    crit_charge      = ups_cfg.get("crit_charge_pct", 20)
    warn_load        = ups_cfg.get("warn_load_pct", 80)
    crit_load        = ups_cfg.get("crit_load_pct", 95)

    return [
        {
            "hostname":    hostname,
            "service":     "UPS-BATTERY-STATUS",
            # upsBatteryStatus: 1=unknown, 2=batteryNormal, 3=batteryLow, 4=batteryDepleted
            # -e 2 / -w 2:2 / -c 2:2 → only value 2 (Normal) is OK
            "check":       f"check_snmp!{snmp_args} -o .1.3.6.1.2.1.33.1.2.1.0 -e 2 -w 2:2 -c 2:2",
            "description": "UPS Battery Status",
        },
        {
            "hostname":    hostname,
            "service":     "UPS-RUNTIME",
            # Trailing colon on -w/-c means "alert if below this value" (lower bound)
            # e.g. -w 15: → warn if minutes remaining < 15
            "check":       f"check_snmp!{snmp_args} -o .1.3.6.1.2.1.33.1.2.3.0 -w {warn_runtime}: -c {crit_runtime}:",
            "description": "UPS Estimated Runtime minutes",
        },
        {
            "hostname":    hostname,
            "service":     "UPS-CHARGE",
            # Same lower-bound pattern: warn if charge drops below warn_charge_pct
            "check":       f"check_snmp!{snmp_args} -o .1.3.6.1.2.1.33.1.2.4.0 -w {warn_charge}: -c {crit_charge}:",
            "description": "UPS Battery Charge pct",
        },
        {
            "hostname":    hostname,
            "service":     "UPS-OUTPUT-LOAD",
            "check":       f"check_snmp!{snmp_args} -o .1.3.6.1.2.1.33.1.4.4.1.5.1 -w {warn_load} -c {crit_load}",
            "description": "UPS Output Load pct",
        },
    ]


def _build_memory_services(host: dict, config: dict) -> list:
    """
    Build SNMP memory utilisation checks for network devices.

    Cisco devices (cisco_roles): uses ciscoMemoryPoolMIB
      - Largest free block in the processor pool
        OID: .1.3.6.1.4.1.9.9.48.1.1.1.6.1  (ciscoMemoryPoolLargestFree)
        We check the *used* ratio via the used/free pair and alert via check_snmp -w/-c.

    Non-Cisco SNMP devices: uses HOST-RESOURCES-MIB hrStorage (index 1 = RAM)
      - hrStorageUsed  .1.3.6.1.2.1.25.2.3.1.6.1
      - hrStorageSize  .1.3.6.1.2.1.25.2.3.1.5.1
      We use check_snmp with -o for used and warn/crit as raw units.
      For simplicity we emit two OID checks: used and size (operators can
      compute % in their graphing tool).  A future enhancement could use
      check_snmp_int or a custom plugin for true % thresholds.

    UPS and phone roles are excluded (they have their own service sets).
    """
    snmp_cfg   = config.get("snmp", {})
    skip_roles = set(snmp_cfg.get("memory_skip_roles", ["ups", "ip-phone", "voip-phone", "phone"]))

    if host["check_method"] != "snmp" or host["type"] != "device":
        return []
    if any(r in host["role"] for r in skip_roles):
        return []

    cisco_roles = config["snmp"].get("cisco_roles", [])
    is_cisco    = host["role"] in cisco_roles
    snmp_args   = _snmp_auth_args(host["role"], config)
    hostname    = host["hostname"]

    if is_cisco:
        # Cisco ciscoMemoryPoolLargestFree OID returns bytes (not KB, not KB×1024).
        # Thresholds must be set in bytes; 10 MB = 10 485 760, 4 MB = 4 194 304.
        # We alert when free bytes drop BELOW the threshold (hence trailing colon: -w N:).
        warn_free_bytes = snmp_cfg.get("cisco_mem_warn_free_bytes", 10485760)   # 10 MB
        crit_free_bytes = snmp_cfg.get("cisco_mem_crit_free_bytes", 4194304)   #  4 MB
        return [
            {
                "hostname":    hostname,
                "service":     "SNMP-MEMORY-CISCO",
                "check":       (
                    f"check_snmp!{snmp_args} "
                    f"-o .1.3.6.1.4.1.9.9.48.1.1.1.6.1 "
                    f"-w {warn_free_bytes}: -c {crit_free_bytes}: "
                    f"-l 'Processor Pool Free (bytes)'"
                ),
                "description": "Memory Free - Cisco Processor Pool",
            },
        ]
    else:
        # Generic: HOST-RESOURCES-MIB hrStorage index 1 (Physical Memory)
        return [
            {
                "hostname":    hostname,
                "service":     "SNMP-MEMORY-USED",
                "check":       (
                    f"check_snmp!{snmp_args} "
                    f"-o .1.3.6.1.2.1.25.2.3.1.6.1 "
                    f"-l 'RAM Used (allocation units)'"
                ),
                "description": "Memory Used - hrStorageUsed",
            },
            {
                "hostname":    hostname,
                "service":     "SNMP-MEMORY-SIZE",
                "check":       (
                    f"check_snmp!{snmp_args} "
                    f"-o .1.3.6.1.2.1.25.2.3.1.5.1 "
                    f"-l 'RAM Size (allocation units)'"
                ),
                "description": "Memory Size - hrStorageSize",
            },
        ]


# ---------------------------------------------------------------------------
# Hostgroup builder
# ---------------------------------------------------------------------------

def _build_hostgroups(hosts: list, config: dict = None) -> dict:
    """
    Build hostgroup dicts from host list.
    Groups by: role, location (devices), cluster (VMs), type (devices/vms/phones)
    Also builds named category groups from hostgroups config (e.g. network-devices, servers, storage).
    Returns dict of { hostgroup_name: { name, alias, members[] } }
    """
    groups = {}
    config = config or {}

    def _add(group_name: str, alias: str, hostname: str):
        if group_name not in groups:
            groups[group_name] = {"name": group_name, "alias": alias, "members": []}
        groups[group_name]["members"].append(hostname)

    # Build category lookup: role_slug -> (group_name, alias)
    category_by_role = {}
    for group_name, cfg in config.get("hostgroups", {}).items():
        alias = cfg.get("alias", group_name.replace("-", " ").title())
        for r in cfg.get("roles", []):
            category_by_role[r.lower()] = (group_name, alias)

    # Compute these once — used to decide whether location/cluster groups are meaningful
    location_names = {
        h.get("location") for h in hosts
        if h.get("type") == "device" and h.get("location") and h.get("location") != "unknown"
    }
    cluster_names = {
        h.get("cluster") for h in hosts
        if h.get("type") == "vm" and h.get("cluster") and h.get("cluster") != "unknown"
    }
    phone_roles = {"ip-phone", "voip-phone", "phone"}

    for host in hosts:
        hostname = host["hostname"]
        role     = host.get("role", "unknown")
        htype    = host.get("type", "device")

        # Group by type
        if htype == "device":
            _add("all-devices", "All Physical Devices", hostname)
        elif htype == "vm":
            _add("vms", "VMs", hostname)

        # Named category groups (network-devices, servers, storage, …)
        if role and role != "unknown":
            for cat_role, (group_name, alias) in category_by_role.items():
                if cat_role in role:
                    _add(group_name, alias, hostname)
                    break

        # Group by role
        if role and role != "unknown":
            _add(f"{role}", f"Role: {role.title()}", hostname)

        # Location groups are only useful when devices span more than one site.
        # A single-location deployment would get a group of all devices which is
        # redundant with "all-devices", so we suppress it.
        if len(location_names) > 1:
            location = host.get("location")
            if location and location != "unknown":
                loc_slug = location.lower().replace(" ", "-")
                _add(f"location-{loc_slug}", f"Location: {location}", hostname)

        # Same rationale for cluster groups — omit if all VMs are in the same cluster.
        if len(cluster_names) > 1:
            cluster = host.get("cluster")
            if cluster and cluster != "unknown":
                cluster_slug = cluster.lower().replace(" ", "-")
                _add(f"cluster-{cluster_slug}", f"Cluster: {cluster}", hostname)

        # Phone group
        if any(p in role for p in phone_roles):
            _add("all-phones", "All IP Phones", hostname)

    return groups


# ---------------------------------------------------------------------------
# Parent-child topology builder
# ---------------------------------------------------------------------------

def _build_parent_map(data: dict, hostname_by_device_id: dict) -> dict:
    """
    Parse cable data to build { child_hostname: parent_hostname } mapping.

    Logic: for each cable, the device with the higher-priority role
    (router > firewall > switch > other) is the parent.  If both ends
    are the same role tier, the one whose interface name sorts first is
    treated as parent (deterministic but arbitrary).

    Only physical device-to-device cables are considered; VM and
    unresolvable endpoints are skipped.
    """
    ROLE_TIER = {"router": 0, "firewall": 1, "switch": 2}
    roles_by_id = data.get("_roles_by_id", {})

    def _tier(device_id: str) -> int:
        # Find the device and resolve its role tier
        for dev in data.get("devices", []):
            if dev["id"] == device_id:
                role_obj = dev.get("role", {})
                role_id  = role_obj.get("id") if role_obj else None
                role     = roles_by_id.get(role_id, {}).get("name", "").lower().replace(" ", "-") if role_id else ""
                for key, t in ROLE_TIER.items():
                    if key in role:
                        return t
                return 99
        return 99

    parent_map = {}  # { child_hostname: parent_hostname }

    for cable in data.get("cables", []):
        # Nautobot 2.x cable terminations
        a_terms = cable.get("a_terminations", [])
        b_terms = cable.get("b_terminations", [])
        if not a_terms or not b_terms:
            continue

        a = a_terms[0]
        b = b_terms[0]

        # Only device interfaces (not circuits, console ports, etc.)
        if a.get("object_type") != "dcim.interface" or b.get("object_type") != "dcim.interface":
            continue

        a_dev_id = a.get("object", {}).get("device", {}).get("id")
        b_dev_id = b.get("object", {}).get("device", {}).get("id")

        if not a_dev_id or not b_dev_id or a_dev_id == b_dev_id:
            continue

        a_host = hostname_by_device_id.get(a_dev_id)
        b_host = hostname_by_device_id.get(b_dev_id)
        if not a_host or not b_host:
            continue

        a_tier = _tier(a_dev_id)
        b_tier = _tier(b_dev_id)

        if a_tier < b_tier:
            parent, child = a_host, b_host
        elif b_tier < a_tier:
            parent, child = b_host, a_host
        else:
            # Same tier — use alphabetical order for determinism
            parent, child = sorted([a_host, b_host])

        # setdefault means: if the child already has a parent assigned (from a
        # previous cable), keep the first one found and don't overwrite it.
        # This prevents a switch from having multiple parents if it uplinks to
        # more than one router (the first cable processed "wins").
        parent_map.setdefault(child, parent)

    logger.info(f"Built parent map: {len(parent_map)} child→parent relationships")
    return parent_map


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
            services.extend(_build_interface_services(host, data, config))
            services.extend(_build_bgp_services(host, data, config))
            services.extend(_build_ups_services(host, config))
            services.extend(_build_memory_services(host, config))
            services.extend(_build_ssl_services(host, config))

    # --- VMs ---
    for vm in data["vms"]:
        host = _build_vm_host(vm, data, config)
        if host:
            hosts.append(host)
            services.extend(_build_services(host, config))
            services.extend(_build_ssl_services(host, config))

    # --- Parent-child topology ---
    hostname_by_device_id = {h["nautobot_id"]: h["hostname"] for h in hosts if h["type"] == "device"}
    parent_map = _build_parent_map(data, hostname_by_device_id)
    for host in hosts:
        host["parents"] = parent_map.get(host["hostname"], "")

    hostgroups = _build_hostgroups(hosts, config)

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