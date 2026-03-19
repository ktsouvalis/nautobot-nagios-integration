"""
utils.py — Shared utilities for nautobot-nagios-sync.
"""

import logging
import os

import paramiko

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Shared SSH client factory
# ---------------------------------------------------------------------------

def get_ssh_client(timeout: int = 10) -> paramiko.SSHClient:
    """
    Build and connect a paramiko SSH client using env-var credentials.

    Host key policy:
      NAGIOS_SSH_VERIFY_HOST_KEYS=true  → RejectPolicy  (safe, requires known_hosts)
      NAGIOS_SSH_VERIFY_HOST_KEYS=false → AutoAddPolicy  (default, convenience for internal hosts)
    """
    host     = os.getenv("NAGIOS_SSH_HOST")
    user     = os.getenv("NAGIOS_SSH_USER")
    password = os.getenv("NAGIOS_SSH_PASSWORD")
    port     = int(os.getenv("NAGIOS_SSH_PORT", 22))

    if not all([host, user, password]):
        raise EnvironmentError(
            "NAGIOS_SSH_HOST, NAGIOS_SSH_USER, NAGIOS_SSH_PASSWORD must be set in .env"
        )

    verify = os.getenv("NAGIOS_SSH_VERIFY_HOST_KEYS", "false").lower() == "true"
    client = paramiko.SSHClient()
    if verify:
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    else:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    client.connect(hostname=host, port=port, username=user, password=password, timeout=timeout)
    logger.debug(f"SSH connected to {user}@{host}:{port} (verify_host_keys={verify})")
    return client


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