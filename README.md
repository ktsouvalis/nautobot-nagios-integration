# nautobot-to-nagios

Automatically syncs your Nautobot 2.x inventory to a Nagios configuration.
Reads devices and VMs from Nautobot, generates `.cfg` files, uploads them to
your Nagios server via SSH/SFTP, validates the config, and reloads Nagios —
all in one command.

---

## Architecture

```
Nautobot API
    │
    ▼
fetcher.py          Pull devices, VMs, interfaces, cables, IPs, roles
    │               + walk SNMP ifIndex maps via SSH snmpwalk
    ▼
transformer.py      Map to Nagios hosts / services / hostgroups
    │               Role-based method: snmp | nrpe | ping
    ▼
writer.py           Render .cfg files → atomic write → SCP to Nagios VM
    │
    ▼
reloader.py         SSH: nagios -v (validate) → systemctl reload nagios
    │
    ▼
map_generator.py    Parse status.dat → generate HTML network maps
```

---

## Prerequisites

### On the machine running this script

- Python 3.10+
- pip packages (see `requirements.txt`)
- SSH access to the Nagios server (password or key-based)

```bash
pip install -r requirements.txt
```

### On the Nagios server

The following Nagios plugins must be installed and working:

| Plugin | Used for |
|--------|----------|
| `check_ping` | All hosts (reachability) |
| `check_snmp` | Network devices (uptime, CPU, interfaces, BGP, UPS, memory) |
| `check_nrpe` | Linux servers/VMs (CPU, disk, memory) |
| `check_http` | SSL certificate expiry |

The user that runs `check_nrpe` commands must have the NRPE daemon commands
defined on the target hosts:
- `check_load`
- `check_disk`
- `check_mem`

The Nagios command definitions for `check_nrpe`, `check_snmp`, `check_ping`,
and `check_http` must already exist in your base Nagios config.

The SSH user configured in `.env` needs `sudo` access for:
- `mkdir -p <config_dir>`
- `nagios -v <nagios.cfg>`
- `systemctl reload nagios`

Grant it without a password prompt via `/etc/sudoers`:

```
nagios-sync ALL=(ALL) NOPASSWD: /usr/local/nagios/bin/nagios -v *, /bin/systemctl reload nagios, /bin/mkdir -p *
```

For the SNMP ifIndex discovery, `snmpwalk` must be installed on the Nagios
server (package `snmp` on Debian/Ubuntu, `net-snmp-utils` on RHEL):

```bash
# Debian / Ubuntu
apt install snmp

# RHEL / CentOS
yum install net-snmp-utils
```

---

## Installation

```bash
git clone <repo>
cd nautobot-to-nagios
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your credentials (see below)
# Edit config.yaml with your roles and paths
```

---

## Configuration

### `.env` — secrets (never commit this file)

```dotenv
# Nautobot
NAUTOBOT_URL=https://nautobot.example.com
NAUTOBOT_TOKEN=your_nautobot_api_token

# SNMP community strings
SNMP_COMMUNITY_DEFAULT=public
SNMP_COMMUNITY_CISCO=cisco_community

# SSH credentials for the Nagios server
NAGIOS_SSH_HOST=nagios.example.com
NAGIOS_SSH_USER=nagios-sync
NAGIOS_SSH_PASSWORD=your_ssh_password
NAGIOS_SSH_PORT=22

# Set to true to enforce known_hosts verification (recommended in production)
NAGIOS_SSH_VERIFY_HOST_KEYS=false

# SNMPv3 credentials (only needed if snmp.v3_roles is non-empty in config.yaml)
SNMP_V3_USER=
SNMP_V3_SEC_LEVEL=authPriv
SNMP_V3_AUTH_PROTO=SHA
SNMP_V3_AUTH_PASS=
SNMP_V3_PRIV_PROTO=AES
SNMP_V3_PRIV_PASS=
```

### `config.yaml` — behaviour (safe to commit)

Key sections:

```yaml
nautobot:
  verify_ssl: true
  require_primary_ip: true          # Skip devices without a primary IP
  device_statuses: [active, staged]
  interfaces_connected_only: true   # Only include cabled interfaces

  # Role slugs → monitoring method
  snmp_roles:  [switch, router, firewall, access-point]
  nrpe_roles:  [server, hypervisor]
  phone_roles: [ip-phone]

nagios:
  config_dir: /usr/local/nagios/etc/conf.d/nautobot
  nagios_bin:  /usr/local/nagios/bin/nagios
  nagios_cfg:  /usr/local/nagios/etc/nagios.cfg
  reload_command: systemctl reload nagios
  host_template:    generic-host
  service_template: generic-service

snmp:
  version: 2c
  cisco_roles: [switch, san]      # Use SNMP_COMMUNITY_CISCO for these roles
  v3_roles: []                    # Roles that use SNMPv3 instead of v2c
  memory_skip_roles: [ups, ip-phone]
  cisco_mem_warn_free_bytes: 10485760   # 10 MB
  cisco_mem_crit_free_bytes: 4194304   #  4 MB

bgp:
  router_roles: [router]
  static_peers: {}                # Optional: {hostname: [peer_ip, ...]}

ups:
  ups_roles: [ups]
  warn_runtime_minutes: 15
  crit_runtime_minutes: 5
  warn_charge_pct: 50
  crit_charge_pct: 20

ssl:
  check_roles: [server, hypervisor]
  ports: [443]
  warn_days: 30
  crit_days: 14

custom_fields:
  notes_url_fields:
    - nagios_notes_url   # Checked in order; first non-empty value wins
    - runbook_url
    - wiki_url
```

---

## Usage

### Run modes

```bash
# Full sync (fetch + transform + write + reload + maps) — use for cron
python main.py --full

# Sync only — no map generation
python main.py --sync

# Regenerate maps from current Nagios status
python main.py --maps

# Preview what would be generated without writing anything
python main.py --dry-run

# Print live host/service states from Nagios
python main.py --status

# Use a custom config file
python main.py --full --config /etc/nautobot-nagios/config.yaml
```

### Cron (recommended)

Run a full sync every 15 minutes:

```cron
*/15 * * * * cd /opt/nautobot-to-nagios && python main.py --full >> /var/log/nautobot-nagios-cron.log 2>&1
```

---

## What gets generated

### Hosts (`nautobot_hosts.cfg`)

One `define host` block per device or VM with a primary IP. Each host carries:
- `use` — from `nagios.host_template`
- `address` — primary IPv4 (or IPv6 fallback)
- `parents` — derived from cable topology (router > firewall > switch)
- `notes_url` — from Nautobot custom fields (configurable field names)
- A comment line with `nautobot_id`, `role`, and `check_method` for traceability

### Services (`nautobot_services.cfg`)

Services generated per host depend on its role:

| check_method | Services generated |
|---|---|
| **ping** (ip-phone, unknown) | PING |
| **nrpe** (server, hypervisor) | PING, NRPE-CPU, NRPE-DISK, NRPE-MEMORY, SSL-CERT-443 |
| **snmp** (switch, router, …) | PING, SNMP-UPTIME, SNMP-CPU (Cisco only), IFACE-\*-STATUS/IN/OUT, SNMP-MEMORY, + role-specific (BGP, UPS) |

#### SNMP interface checks

For each physical interface with a cable, three services are created:
- `IFACE-<name>-STATUS` — ifOperStatus (1=up; warns/crits if not 1)
- `IFACE-<name>-IN` — ifInOctets (traffic counter, for graphing)
- `IFACE-<name>-OUT` — ifOutOctets

The ifIndex is resolved by running `snmpwalk` on the device via the Nagios
server at sync time, so no direct SNMP access from the monitoring machine is
required during normal operation.

#### BGP peer checks (routers)

Peer IPs are auto-discovered from Nautobot interface descriptions containing
"bgp". Additional peers can be pinned in `config.yaml` under `bgp.static_peers`.
Uses BGP4-MIB `bgpPeerState`; alerts whenever state is not Established (6).

#### UPS checks

Uses RFC 1628 UPS-MIB: battery status, estimated runtime (minutes), charge
percentage, and output load percentage.

#### Memory checks

- **Cisco**: `ciscoMemoryPoolLargestFree` — alerts when free bytes in the
  processor pool drop below configured thresholds.
- **Other SNMP**: HOST-RESOURCES-MIB `hrStorageUsed` and `hrStorageSize`
  (index 1 = physical RAM).

### Hostgroups (`nautobot_hostgroups.cfg`)

Automatically created for:
- `all-devices`, `all-vms`, `all-phones`
- `role-<slug>` — one per device role
- `location-<slug>` — one per site (only if multiple sites exist)
- `cluster-<slug>` — one per VM cluster (only if multiple clusters exist)

---

## Individual scripts (advanced use)

Each script can be run directly for testing:

```bash
# Test Nautobot connectivity and inspect raw data
python fetcher.py

# Test the transformation logic
python transformer.py

# Test writing and uploading config files
python writer.py

# Test Nagios validation and reload
python reloader.py

# Test status.dat parsing
python status_reader.py
```

---

## Troubleshooting

### "NAUTOBOT_URL is not set"
Make sure `.env` exists and is in the working directory (or set env vars directly).

### "Total Errors: N" in reloader output
Nagios found a config error in the generated files. Run `python main.py --dry-run`
to see which hosts/services are being generated, then check the Nagios logs on
the server for the exact error.

### SNMP ifIndex map empty for a device
- Confirm the device is reachable via SNMP from the Nagios server.
- Check `SNMP_COMMUNITY_DEFAULT` / `SNMP_COMMUNITY_CISCO` values.
- Try manually: `snmpwalk -v2c -c <community> <device_ip> 1.3.6.1.2.1.31.1.1.1.1`

### SSH connection refused / timeout
- Verify `NAGIOS_SSH_HOST`, `NAGIOS_SSH_PORT`, `NAGIOS_SSH_USER`, `NAGIOS_SSH_PASSWORD`.
- If `NAGIOS_SSH_VERIFY_HOST_KEYS=true`, ensure the host is in `~/.ssh/known_hosts`.

### Nagios reload fails after successful validation
- Check that the SSH user has passwordless sudo for `systemctl reload nagios`.
- Inspect `/var/log/nagios/nagios.log` on the Nagios server.

---

## Project structure

```
nautobot-to-nagios/
├── main.py              Orchestrator — CLI entry point
├── fetcher.py           Nautobot API client + SNMP ifIndex discovery
├── transformer.py       Nautobot → Nagios object mapping
├── writer.py            .cfg file rendering + SCP upload
├── reloader.py          Nagios config validation + service reload
├── status_reader.py     status.dat parser + state helpers
├── map_generator.py     HTML network map generation
├── utils.py             Shared SSH factory + interface name normalisation
├── config.yaml          Behaviour configuration (commit this)
├── .env.example         Secret variables template (copy to .env, don't commit)
├── requirements.txt
└── nautobot_imports_api/
    ├── patch_lag_members.py        One-off: bulk-set LAG assignments from CSV
    ├── patch_prefix_location.py    One-off: bulk-set prefix locations from CSV
    └── patch_shutdown_interfaces.py One-off: bulk-shutdown interfaces from CSV
```
