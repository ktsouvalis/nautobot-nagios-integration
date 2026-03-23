"""
status_reader.py — Reads Nagios status.dat via SSH and parses live host/service status.

Returns a dict of host statuses and service statuses for use by map_generator.py.
"""

import logging

import yaml
from dotenv import load_dotenv

from utils import get_ssh_client

load_dotenv()

logger = logging.getLogger(__name__)


def load_config(path: str = "config.yaml") -> dict:
    with open(path, "r") as f:
        return yaml.safe_load(f)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def _parse_status_dat(content: str) -> dict:
    """
    Parse Nagios status.dat content into structured dict.
    Returns:
    {
        "hosts": {
            "hostname": {
                "current_state": 0,        # 0=UP, 1=DOWN, 2=UNREACHABLE
                "plugin_output": "...",
                "last_check": "...",
                "state_type": 1,           # 0=SOFT, 1=HARD
                "notifications_enabled": 1,
            }
        },
        "services": {
            "hostname": {
                "service_description": {
                    "current_state": 0,    # 0=OK, 1=WARNING, 2=CRITICAL, 3=UNKNOWN
                    "plugin_output": "...",
                    "last_check": "...",
                    "state_type": 1,
                }
            }
        }
    }
    """
    result = {"hosts": {}, "services": {}}

    blocks = content.split("\n\n")

    for block in blocks:
        block = block.strip()
        if not block:
            continue

        lines = block.splitlines()
        if not lines:
            continue

        block_type = lines[0].strip().rstrip(" {")
        fields = {}

        for line in lines[1:]:
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                key, _, value = line.partition("=")
                fields[key.strip()] = value.strip()

        if block_type == "hoststatus":
            hostname = fields.get("host_name")
            if hostname:
                result["hosts"][hostname] = {
                    "current_state":          int(fields.get("current_state", 0)),
                    "plugin_output":          fields.get("plugin_output", ""),
                    "last_check":             fields.get("last_check", ""),
                    "state_type":             int(fields.get("state_type", 1)),
                    "notifications_enabled":  int(fields.get("notifications_enabled", 1)),
                    "scheduled_downtime_depth": int(fields.get("scheduled_downtime_depth", 0)),
                }

        elif block_type == "servicestatus":
            hostname = fields.get("host_name")
            svc_desc = fields.get("service_description")
            if hostname and svc_desc:
                result["services"].setdefault(hostname, {})[svc_desc] = {
                    "current_state": int(fields.get("current_state", 0)),
                    "plugin_output": fields.get("plugin_output", ""),
                    "last_check":    fields.get("last_check", ""),
                    "state_type":    int(fields.get("state_type", 1)),
                }

    return result


# ---------------------------------------------------------------------------
# State helpers
# ---------------------------------------------------------------------------

HOST_STATES  = {0: "UP", 1: "DOWN", 2: "UNREACHABLE", 3: "PENDING"}
SVC_STATES   = {0: "OK", 1: "WARNING", 2: "CRITICAL", 3: "UNKNOWN"}
STATE_COLORS = {
    # Host colors
    "UP":          "#2ecc71",
    "DOWN":        "#e74c3c",
    "UNREACHABLE": "#e67e22",
    "PENDING":     "#95a5a6",
    # Service colors
    "OK":          "#2ecc71",
    "WARNING":     "#f39c12",
    "CRITICAL":    "#e74c3c",
    "UNKNOWN":     "#9b59b6",
}


def get_host_state(status: dict, hostname: str) -> dict:
    """Get state info for a host. Returns UP/PENDING if not found."""
    host = status["hosts"].get(hostname)
    if not host:
        return {"state": "PENDING", "color": STATE_COLORS["PENDING"], "output": ""}
    state = HOST_STATES.get(host["current_state"], "UNKNOWN")
    return {
        "state":  state,
        "color":  STATE_COLORS.get(state, "#95a5a6"),
        "output": host["plugin_output"],
    }


def get_worst_service_state(status: dict, hostname: str) -> dict:
    """Get the worst service state for a host."""
    services = status["services"].get(hostname, {})
    if not services:
        return {"state": "PENDING", "color": STATE_COLORS["PENDING"]}

    worst = 0
    for svc in services.values():
        if svc["current_state"] > worst:
            worst = svc["current_state"]

    state = SVC_STATES.get(worst, "UNKNOWN")
    return {
        "state": state,
        "color": STATE_COLORS.get(state, "#95a5a6"),
    }


# ---------------------------------------------------------------------------
# Main reader
# ---------------------------------------------------------------------------

def read_status(config: dict) -> dict:
    """
    Reads status.dat from Nagios VM via SSH and returns parsed status dict.
    """
    status_dat = config["nagios"]["status_dat"]

    logger.info(f"Reading {status_dat} from Nagios VM...")
    ssh = get_ssh_client()

    try:
        stdin, stdout, stderr = ssh.exec_command(f"cat {status_dat}")
        content = stdout.read().decode("utf-8", errors="replace")
        exit_code = stdout.channel.recv_exit_status()

        if exit_code != 0:
            logger.error(f"Failed to read status.dat: {stderr.read().decode()}")
            return {"hosts": {}, "services": {}}

        status = _parse_status_dat(content)
        logger.info(
            f"Parsed status.dat: {len(status['hosts'])} hosts, "
            f"{sum(len(v) for v in status['services'].values())} services"
        )
        return status

    finally:
        ssh.close()


# ---------------------------------------------------------------------------
# CLI test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json
    from dotenv import load_dotenv
    load_dotenv()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    cfg    = load_config()
    status = read_status(cfg)

    print(f"\n=== STATUS SUMMARY ===")
    print(f"  Hosts:    {len(status['hosts'])}")
    print(f"  Services: {sum(len(v) for v in status['services'].values())}")

    print(f"\n=== HOST STATES ===")
    state_counts = {}
    for h, info in status["hosts"].items():
        state = HOST_STATES.get(info["current_state"], "UNKNOWN")
        state_counts[state] = state_counts.get(state, 0) + 1
    for state, count in sorted(state_counts.items()):
        print(f"  {state}: {count}")

    print(f"\n=== FIRST 5 HOSTS ===")
    for hostname, info in list(status["hosts"].items())[:5]:
        state = HOST_STATES.get(info["current_state"], "UNKNOWN")
        print(f"  {hostname}: {state} — {info['plugin_output'][:60]}")