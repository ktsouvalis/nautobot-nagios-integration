"""
main.py — Orchestrates the full Nautobot → Nagios sync pipeline.

Usage:
  python main.py --full        # fetch + transform + write + reload + maps
  python main.py --sync        # fetch + transform + write + reload
  python main.py --maps        # generate maps only
  python main.py --status      # read and print live Nagios status
  python main.py --dry-run     # fetch + transform only, no write/reload
"""

import argparse
import logging
import logging.handlers
import sys
import time

import yaml
from dotenv import load_dotenv

load_dotenv()


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def setup_logging(config: dict):
    log_cfg  = config.get("logging", {})
    level    = getattr(logging, log_cfg.get("level", "INFO"))
    log_file = log_cfg.get("file", "/var/log/nautobot-nagios-sync.log")
    max_bytes   = log_cfg.get("max_bytes", 10485760)
    backup_count = log_cfg.get("backup_count", 5)

    fmt = logging.Formatter("%(asctime)s %(levelname)-8s %(name)s — %(message)s")

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)

    # File handler (rotating) — only if we can write to the path
    handlers = [console]
    try:
        fh = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=max_bytes, backupCount=backup_count
        )
        fh.setFormatter(fmt)
        handlers.append(fh)
    except (PermissionError, FileNotFoundError):
        # Fall back to current dir if system log path not writable
        fallback = "nautobot-nagios-sync.log"
        fh = logging.handlers.RotatingFileHandler(
            fallback, maxBytes=max_bytes, backupCount=backup_count
        )
        fh.setFormatter(fmt)
        handlers.append(fh)

    logging.basicConfig(level=level, handlers=handlers)


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pipeline steps
# ---------------------------------------------------------------------------

def step_fetch(config: dict) -> dict:
    from fetcher import fetch_all
    logger.info("=== STEP 1: Fetching from Nautobot ===")
    data = fetch_all(config)
    return data


def step_transform(data: dict, config: dict) -> dict:
    from transformer import transform
    logger.info("=== STEP 2: Transforming data ===")
    result = transform(data, config)
    return result


def step_write(result: dict, config: dict):
    from writer import write
    logger.info("=== STEP 3: Writing Nagios config files ===")
    write(result, config)


def step_reload(config: dict) -> bool:
    from reloader import validate_and_reload
    logger.info("=== STEP 4: Validating and reloading Nagios ===")
    return validate_and_reload(config)


def step_maps(result: dict, data: dict, config: dict):
    from map_generator import generate_maps
    logger.info("=== STEP 5: Generating maps ===")
    generate_maps(result, data, config)


def step_status(config: dict):
    from status_reader import read_status, HOST_STATES, SVC_STATES
    logger.info("=== Reading live Nagios status ===")
    status = read_status(config)

    print(f"\n{'='*50}")
    print(f"  NAGIOS LIVE STATUS")
    print(f"{'='*50}")

    state_counts = {}
    for h, info in status["hosts"].items():
        state = HOST_STATES.get(info["current_state"], "UNKNOWN")
        state_counts[state] = state_counts.get(state, 0) + 1

    print(f"\nHost States:")
    for state, count in sorted(state_counts.items()):
        print(f"  {state:15s}: {count}")

    svc_counts = {}
    for hostname, svcs in status["services"].items():
        for svc, info in svcs.items():
            state = SVC_STATES.get(info["current_state"], "UNKNOWN")
            svc_counts[state] = svc_counts.get(state, 0) + 1

    print(f"\nService States:")
    for state, count in sorted(svc_counts.items()):
        print(f"  {state:15s}: {count}")

    print(f"\nDown/Critical Hosts:")
    for h, info in status["hosts"].items():
        if info["current_state"] != 0:
            state = HOST_STATES.get(info["current_state"], "UNKNOWN")
            print(f"  [{state}] {h}: {info['plugin_output'][:60]}")

    print(f"\nCritical Services:")
    for hostname, svcs in status["services"].items():
        for svc, info in svcs.items():
            if info["current_state"] == 2:
                print(f"  [CRITICAL] {hostname} / {svc}: {info['plugin_output'][:60]}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="Nautobot → Nagios sync tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --full      # Full sync + maps (use for cron)
  python main.py --sync      # Sync only, no maps
  python main.py --maps      # Regenerate maps only
  python main.py --status    # Print live Nagios status
  python main.py --dry-run   # Preview changes without applying
        """
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--full",    action="store_true", help="Fetch + transform + write + reload + maps")
    group.add_argument("--sync",    action="store_true", help="Fetch + transform + write + reload")
    group.add_argument("--maps",    action="store_true", help="Generate maps only")
    group.add_argument("--status",  action="store_true", help="Read and print live Nagios status")
    group.add_argument("--dry-run", action="store_true", help="Fetch + transform only, no write/reload")
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    return parser.parse_args()


def load_config(path: str) -> dict:
    with open(path, "r") as f:
        return yaml.safe_load(f)


def main():
    args   = parse_args()
    config = load_config(args.config)
    setup_logging(config)

    start = time.time()
    logger.info(f"Nautobot→Nagios sync starting — mode: {sys.argv[1]}")

    try:
        if args.status:
            step_status(config)

        elif args.dry_run:
            data   = step_fetch(config)
            result = step_transform(data, config)
            print(f"\n=== DRY RUN SUMMARY ===")
            print(f"  Hosts:      {len(result['hosts'])}")
            print(f"  Services:   {len(result['services'])}")
            print(f"  Hostgroups: {len(result['hostgroups'])}")
            print(f"\nNo files written. Run with --sync or --full to apply.")

        elif args.maps:
            data   = step_fetch(config)
            result = step_transform(data, config)
            step_maps(result, data, config)

        elif args.sync:
            data   = step_fetch(config)
            result = step_transform(data, config)
            step_write(result, config)
            success = step_reload(config)
            if not success:
                logger.error("Sync completed but Nagios reload FAILED — check config")
                sys.exit(1)

        elif args.full:
            data   = step_fetch(config)
            result = step_transform(data, config)
            step_write(result, config)
            success = step_reload(config)
            if not success:
                logger.error("Sync completed but Nagios reload FAILED — maps not generated")
                sys.exit(1)
            step_maps(result, data, config)

        elapsed = time.time() - start
        logger.info(f"Done in {elapsed:.1f}s")

    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()