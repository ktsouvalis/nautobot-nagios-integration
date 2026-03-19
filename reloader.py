"""
reloader.py — Validates Nagios config and reloads the service via SSH.

Connects to Nagios VM, runs nagios -v to validate, then reloads if clean.
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


def _run(ssh: paramiko.SSHClient, cmd: str) -> tuple[int, str, str]:
    """Run a command over SSH, return (exit_code, stdout, stderr)."""
    stdin, stdout, stderr = ssh.exec_command(cmd)
    exit_code = stdout.channel.recv_exit_status()
    return exit_code, stdout.read().decode(), stderr.read().decode()


def validate_and_reload(config: dict) -> bool:
    """
    SSH into Nagios VM, validate config, reload if valid.
    Returns True on success, False on failure.
    """
    nagios_bin = config["nagios"]["nagios_bin"]
    nagios_cfg = config["nagios"]["nagios_cfg"]
    reload_cmd = config["nagios"]["reload_command"]

    logger.info("Connecting to Nagios VM for validation...")
    ssh = get_ssh_client()

    try:
        # Step 1: Validate config
        validate_cmd = f"sudo {nagios_bin} -v {nagios_cfg}"
        logger.info(f"Running: {validate_cmd}")
        exit_code, stdout, stderr = _run(ssh, validate_cmd)

        if exit_code != 0 or "Total Errors:   0" not in stdout:
            logger.error("Nagios config validation FAILED:")
            # Log only error lines
            for line in stdout.splitlines():
                if "Error:" in line or "Warning:" in line or "Total" in line:
                    logger.error(f"  {line}")
            return False

        # Check for errors in output
        for line in stdout.splitlines():
            if "Total Errors:" in line:
                logger.info(f"Validation: {line.strip()}")
            if "Total Warnings:" in line:
                logger.info(f"Validation: {line.strip()}")

        logger.info("Nagios config validation passed.")

        # Step 2: Reload Nagios
        logger.info(f"Reloading Nagios: {reload_cmd}")
        exit_code, stdout, stderr = _run(ssh, f"sudo {reload_cmd}")

        if exit_code != 0:
            logger.error(f"Nagios reload FAILED: {stderr}")
            return False

        logger.info("Nagios reloaded successfully.")
        return True

    finally:
        ssh.close()


# ---------------------------------------------------------------------------
# CLI test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    cfg = load_config()
    success = validate_and_reload(cfg)
    print("\n=== RESULT ===")
    print("SUCCESS" if success else "FAILED")