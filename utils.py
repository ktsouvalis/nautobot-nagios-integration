"""
utils.py — Shared utilities for nautobot-nagios-sync.
"""

CISCO_IF_ABBREV = {
    "GigabitEthernet":      "Gi",
    "FastEthernet":         "Fa",
    "TenGigabitEthernet":   "Te",
    "TwentyFiveGigE":       "Twe",
    "FortyGigabitEthernet": "Fo",
    "HundredGigE":          "Hu",
    "Ethernet":             "Et",
    "Loopback":             "Lo",
    "Vlan":                 "Vl",
    "Port-channel":         "Po",
}


def normalize_ifname(name: str) -> str:
    """Normalize Nautobot interface name to SNMP ifName format (for ifIndex lookup)."""
    for full, abbrev in CISCO_IF_ABBREV.items():
        if name.startswith(full):
            return abbrev + name[len(full):]
    return name


def shorten_ifname(name: str) -> str:
    """Shorten interface name for display (e.g. GigabitEthernet1/0/1 → Gi1/0/1)."""
    return normalize_ifname(name)