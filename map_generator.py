"""
map_generator.py — Generates interactive HTML topology maps using vis.js.

Creates 4 maps:
  - network-map.html — switches, routers, firewalls, APs, SAN with cable connections
  - vm-map.html      — VMs connected to their hypervisor parent
  - phone-map.html   — IP phones (auto-populates from Nautobot)
  - hosts-map.html   — NAS, UPS, servers, KVM, cameras, Raspberry Pi

Maps auto-refresh status colors every 60s via Nagios CGI API.
Topology (nodes/edges) is embedded at generation time from Nautobot data.
"""

import json
import logging
import os
import tempfile

import paramiko
import yaml
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


def load_config(path: str = "config.yaml") -> dict:
    with open(path, "r") as f:
        return yaml.safe_load(f)


def _get_ssh_client() -> paramiko.SSHClient:
    host     = os.getenv("NAGIOS_SSH_HOST")
    user     = os.getenv("NAGIOS_SSH_USER")
    password = os.getenv("NAGIOS_SSH_PASSWORD")
    port     = int(os.getenv("NAGIOS_SSH_PORT", 22))
    client   = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=host, port=port, username=user, password=password)
    return client


def _upload(sftp: paramiko.SFTPClient, local_path: str, remote_path: str):
    sftp.put(local_path, remote_path)
    logger.info(f"Uploaded: {remote_path}")


# ---------------------------------------------------------------------------
# Role → icon/color mapping
# ---------------------------------------------------------------------------

ROLE_STYLES = {
    "router":       {"color": "#e67e22", "shape": "diamond",  "icon": "🔷"},
    "switch":       {"color": "#3498db", "shape": "box",      "icon": "🔵"},
    "firewall":     {"color": "#e74c3c", "shape": "triangle", "icon": "🔴"},
    "access-point": {"color": "#1abc9c", "shape": "ellipse",  "icon": "📡"},
    "server":       {"color": "#2ecc71", "shape": "box",      "icon": "🟢"},
    "hypervisor":   {"color": "#9b59b6", "shape": "box",      "icon": "🟣"},
    "nas":          {"color": "#1abc9c", "shape": "box",      "icon": "🟦"},
    "san":          {"color": "#16a085", "shape": "box",      "icon": "🟦"},
    "ups":          {"color": "#f39c12", "shape": "box",      "icon": "🟡"},
    "kvm":          {"color": "#8e44ad", "shape": "box",      "icon": "🟣"},
    "raspberry-pi": {"color": "#e91e63", "shape": "ellipse",  "icon": "🍓"},
    "camera":       {"color": "#607d8b", "shape": "ellipse",  "icon": "📷"},
    "ip-phone":     {"color": "#27ae60", "shape": "ellipse",  "icon": "📞"},
    "vm":           {"color": "#9b59b6", "shape": "dot",      "icon": "💻"},
    "unknown":      {"color": "#95a5a6", "shape": "box",      "icon": "⬜"},
}

def _role_style(role: str) -> dict:
    for key in ROLE_STYLES:
        if key in role.lower():
            return ROLE_STYLES[key]
    return ROLE_STYLES["unknown"]


# ---------------------------------------------------------------------------
# Build nodes and edges from transformer result
# ---------------------------------------------------------------------------

def _build_network_graph(result: dict, data: dict, config: dict) -> tuple[list, list]:
    """Network devices (switches, routers, firewalls, APs, SAN) with cable edges."""
    network_roles = config["maps"].get("network_roles", [])
    nodes = []
    edges = []
    hostname_to_id = {}

    network_hosts = [
        h for h in result["hosts"]
        if h["type"] == "device" and any(r in h["role"] for r in network_roles)
    ]

    for i, host in enumerate(network_hosts):
        style = _role_style(host["role"])
        hostname_to_id[host["hostname"]] = i
        nodes.append({
            "id":       i,
            "label":    host["hostname"],
            "title":    f"{host['role']} | {host['address']}",
            "color":    style["color"],
            "shape":    style["shape"],
            "role":     host["role"],
            "address":  host["address"],
            "hostname": host["hostname"],
        })

    # interface_id → device_id
    iface_id_to_device_id = {}
    for iface in data.get("interfaces", []):
        iface_id_to_device_id[iface["id"]] = iface.get("device", {}).get("id")

    # nautobot device_id → hostname
    device_id_to_hostname = {h["nautobot_id"]: h["hostname"] for h in network_hosts}

    seen_edges = set()
    for cable in data.get("cables", []):
        iface_id_a = cable.get("termination_a_id")
        iface_id_b = cable.get("termination_b_id")
        if not iface_id_a or not iface_id_b:
            continue

        dev_id_a = iface_id_to_device_id.get(iface_id_a)
        dev_id_b = iface_id_to_device_id.get(iface_id_b)
        if not dev_id_a or not dev_id_b or dev_id_a == dev_id_b:
            continue

        hostname_a = device_id_to_hostname.get(dev_id_a)
        hostname_b = device_id_to_hostname.get(dev_id_b)
        if not hostname_a or not hostname_b:
            continue

        edge_key = tuple(sorted([hostname_a, hostname_b]))
        if edge_key in seen_edges:
            continue
        seen_edges.add(edge_key)

        id_a = hostname_to_id.get(hostname_a)
        id_b = hostname_to_id.get(hostname_b)
        if id_a is None or id_b is None:
            continue

        edges.append({
            "from":  id_a,
            "to":    id_b,
            "title": f"{hostname_a} ↔ {hostname_b}",
            "color": {"color": "#7f8c8d"},
            "width": 2,
        })

    return nodes, edges


def _build_hosts_graph(result: dict, data: dict, config: dict) -> tuple[list, list]:
    """Notable hosts: NAS, UPS, servers, KVM, cameras, Raspberry Pi.
    Also includes connected network devices as parent nodes with edges.
    Multiple cables between same device pair are shown as a single edge with link count.
    """
    hosts_roles    = config["maps"].get("hosts_roles", [])
    network_roles  = config["maps"].get("network_roles", [])
    nodes = []
    edges = []
    node_id = 0
    hostname_to_id = {}

    # Notable host nodes
    notable_hosts = [
        h for h in result["hosts"]
        if h["type"] == "device" and any(r in h["role"] for r in hosts_roles)
    ]
    notable_hostnames = {h["hostname"] for h in notable_hosts}

    for host in notable_hosts:
        style = _role_style(host["role"])
        hostname_to_id[host["hostname"]] = node_id
        nodes.append({
            "id":       node_id,
            "label":    host["hostname"],
            "title":    f"{host['role']} | {host['address']}",
            "color":    style["color"],
            "shape":    style["shape"],
            "role":     host["role"],
            "address":  host["address"],
            "hostname": host["hostname"],
        })
        node_id += 1

    # Build lookup dicts from raw data
    iface_id_to_device_id = {
        iface["id"]: iface.get("device", {}).get("id")
        for iface in data.get("interfaces", [])
    }
    all_devices = {h["nautobot_id"]: h for h in result["hosts"] if h["type"] == "device"}

    # Find which network devices are actually connected to notable hosts via cables
    # Count cables per device pair
    pair_counts = {}  # (hostname_a, hostname_b) → count
    for cable in data.get("cables", []):
        iface_id_a = cable.get("termination_a_id")
        iface_id_b = cable.get("termination_b_id")
        if not iface_id_a or not iface_id_b:
            continue

        dev_id_a = iface_id_to_device_id.get(iface_id_a)
        dev_id_b = iface_id_to_device_id.get(iface_id_b)
        if not dev_id_a or not dev_id_b or dev_id_a == dev_id_b:
            continue

        host_a = all_devices.get(dev_id_a)
        host_b = all_devices.get(dev_id_b)
        if not host_a or not host_b:
            continue

        hn_a = host_a["hostname"]
        hn_b = host_b["hostname"]

        # Only care about pairs where one side is a notable host
        if hn_a not in notable_hostnames and hn_b not in notable_hostnames:
            continue

        key = tuple(sorted([hn_a, hn_b]))
        pair_counts[key] = pair_counts.get(key, 0) + 1

    # Add network device nodes that are connected to notable hosts
    connected_network = {}  # hostname → host dict
    for (hn_a, hn_b), count in pair_counts.items():
        for hn in [hn_a, hn_b]:
            if hn not in notable_hostnames and hn not in connected_network:
                host = next((h for h in result["hosts"] if h["hostname"] == hn), None)
                if host and any(r in host["role"] for r in network_roles):
                    connected_network[hn] = host

    for hostname, host in connected_network.items():
        style = _role_style(host["role"])
        hostname_to_id[hostname] = node_id
        nodes.append({
            "id":       node_id,
            "label":    hostname,
            "title":    f"{host['role']} | {host['address']}",
            "color":    style["color"],
            "shape":    style["shape"],
            "role":     host["role"],
            "address":  host["address"],
            "hostname": hostname,
        })
        node_id += 1

    # Build edges with link count labels
    for (hn_a, hn_b), count in pair_counts.items():
        id_a = hostname_to_id.get(hn_a)
        id_b = hostname_to_id.get(hn_b)
        if id_a is None or id_b is None:
            continue

        label = f"{count}x" if count > 1 else ""
        edges.append({
            "from":  id_a,
            "to":    id_b,
            "title": f"{hn_a} ↔ {hn_b} ({count} link{'s' if count > 1 else ''})",
            "label": label,
            "color": {"color": "#7f8c8d"},
            "width": 1 + count,  # thicker for multi-link
            "font":  {"size": 10, "color": "#aaa", "align": "middle"},
        })

    return nodes, edges


def _build_vm_graph(result: dict, data: dict) -> tuple[list, list]:
    """VMs connected to their hypervisor parent node."""
    nodes = []
    edges = []
    node_id = 0
    hostname_to_id = {}

    hypervisor_roles = ["kvm", "hypervisor", "server"]
    hypervisors = {
        h["hostname"]: h for h in result["hosts"]
        if h["type"] == "device" and (
            any(r in h["role"] for r in hypervisor_roles) or
            "proxmox" in h["hostname"].lower()
        )
    }

    # Add hypervisor nodes first
    for hostname, host in hypervisors.items():
        style = _role_style(host["role"])
        hostname_to_id[hostname] = node_id
        nodes.append({
            "id":       node_id,
            "label":    hostname,
            "title":    f"Hypervisor | {host['address']}",
            "color":    style["color"],
            "shape":    "box",
            "role":     host["role"],
            "address":  host["address"],
            "hostname": hostname,
        })
        node_id += 1

    # Add VM nodes, connect to parent hypervisor via comments field
    for vm in [h for h in result["hosts"] if h["type"] == "vm"]:
        comment = vm.get("comments", "").strip()
        parent_hostname = None

        if comment:
            for hv_hostname in hypervisors:
                if (comment.lower() in hv_hostname.lower() or
                        hv_hostname.lower() in comment.lower()):
                    parent_hostname = hv_hostname
                    break

        style = _role_style("vm")
        vm_node_id = node_id
        hostname_to_id[vm["hostname"]] = vm_node_id
        nodes.append({
            "id":       vm_node_id,
            "label":    vm["hostname"],
            "title":    f"VM | {vm['address']} | {comment}",
            "color":    style["color"],
            "shape":    style["shape"],
            "role":     "vm",
            "address":  vm["address"],
            "hostname": vm["hostname"],
        })
        node_id += 1

        if parent_hostname and parent_hostname in hostname_to_id:
            edges.append({
                "from":   hostname_to_id[parent_hostname],
                "to":     vm_node_id,
                "color":  {"color": "#4a4a6a"},
                "width":  1,
                "dashes": True,
            })

    return nodes, edges


def _build_phone_graph(result: dict, config: dict) -> tuple[list, list]:
    """IP phones."""
    phone_roles = config["maps"].get("phone_roles", ["ip-phone"])
    nodes = []

    phone_hosts = [
        h for h in result["hosts"]
        if any(r in h.get("role", "") for r in phone_roles)
    ]

    for i, host in enumerate(phone_hosts):
        nodes.append({
            "id":       i,
            "label":    host["hostname"],
            "title":    f"IP Phone | {host['address']}",
            "color":    "#27ae60",
            "shape":    "ellipse",
            "role":     "ip-phone",
            "address":  host["address"],
            "hostname": host["hostname"],
        })

    return nodes, []


# ---------------------------------------------------------------------------
# HTML template
# ---------------------------------------------------------------------------

def _render_html(title: str, nodes: list, edges: list, nagios_url: str, refresh_interval: int) -> str:
    nodes_json = json.dumps(nodes, indent=2)
    edges_json = json.dumps(edges, indent=2)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title}</title>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.js"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.css"/>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: 'Segoe UI', sans-serif; background: #1a1a2e; color: #eee; }}
    #header {{
      display: flex; align-items: center; justify-content: space-between;
      padding: 12px 20px; background: #16213e; border-bottom: 2px solid #0f3460;
    }}
    #header h1 {{ font-size: 1.2rem; color: #e94560; }}
    #status-bar {{ font-size: 0.8rem; color: #aaa; }}
    #legend {{
      display: flex; gap: 16px; padding: 8px 20px;
      background: #16213e; border-bottom: 1px solid #0f3460; flex-wrap: wrap;
    }}
    .legend-item {{ display: flex; align-items: center; gap: 6px; font-size: 0.75rem; }}
    .legend-dot {{ width: 12px; height: 12px; border-radius: 50%; }}
    #network {{ width: 100%; height: calc(100vh - 110px); }}
    #tooltip {{
      position: fixed; background: #16213e; border: 1px solid #0f3460;
      padding: 8px 12px; border-radius: 6px; font-size: 0.8rem;
      pointer-events: none; display: none; z-index: 100; max-width: 300px;
    }}
    #controls {{
      position: fixed; bottom: 20px; right: 20px;
      display: flex; gap: 8px;
    }}
    button {{
      background: #0f3460; color: #eee; border: none; padding: 8px 14px;
      border-radius: 4px; cursor: pointer; font-size: 0.8rem;
    }}
    button:hover {{ background: #e94560; }}
    .up {{ color: #2ecc71; }} .down {{ color: #e74c3c; }}
    .warning {{ color: #f39c12; }} .unknown {{ color: #95a5a6; }}
  </style>
</head>
<body>
<div id="header">
  <h1>🖥️ {title}</h1>
  <div id="status-bar">
    <span id="host-counts"></span> &nbsp;|&nbsp;
    Last updated: <span id="last-updated">loading...</span> &nbsp;|&nbsp;
    Auto-refresh: {refresh_interval}s
  </div>
</div>
<div id="legend">
  <div class="legend-item"><div class="legend-dot" style="background:#2ecc71"></div> UP / OK</div>
  <div class="legend-item"><div class="legend-dot" style="background:#e74c3c"></div> DOWN / CRITICAL</div>
  <div class="legend-item"><div class="legend-dot" style="background:#f39c12"></div> WARNING</div>
  <div class="legend-item"><div class="legend-dot" style="background:#95a5a6"></div> PENDING / UNKNOWN</div>
  <div class="legend-item"><div class="legend-dot" style="background:#e67e22"></div> UNREACHABLE</div>
</div>
<div id="network"></div>
<div id="tooltip"></div>
<div id="controls">
  <button onclick="network.fit()">Fit</button>
  <button onclick="refreshStatus()">Refresh Now</button>
</div>

<script>
const NAGIOS_URL = "{nagios_url}";
const REFRESH_INTERVAL = {refresh_interval * 1000};
const NAGIOS_USER = "nagiosadmin";  // update if needed

// Topology data (from Nautobot, embedded at sync time)
const topoNodes = {nodes_json};
const topoEdges = {edges_json};

// vis.js dataset
const nodes = new vis.DataSet(topoNodes);
const edges = new vis.DataSet(topoEdges);

const container = document.getElementById("network");
const options = {{
  physics: {{
    enabled: true,
    stabilization: {{ iterations: 200 }},
    barnesHut: {{ gravitationalConstant: -8000, springLength: 150 }}
  }},
  interaction: {{ hover: true, tooltipDelay: 100 }},
  nodes: {{
    font: {{ color: "#eee", size: 12 }},
    borderWidth: 2,
    shadow: true,
  }},
  edges: {{
    smooth: {{ type: "continuous" }},
    shadow: true,
  }},
}};

const network = new vis.Network(container, {{ nodes, edges }}, options);

// Click node → open Nagios host page
network.on("click", function(params) {{
  if (params.nodes.length > 0) {{
    const node = nodes.get(params.nodes[0]);
    window.open(`${{NAGIOS_URL}}/cgi-bin/status.cgi?host=${{node.hostname}}`, "_blank");
  }}
}});

// ---------------------------------------------------------------------------
// Live status refresh via Nagios CGI
// ---------------------------------------------------------------------------

const STATE_COLORS = {{
  0: "#2ecc71",   // UP / OK
  1: "#e74c3c",   // DOWN / WARNING
  2: "#e74c3c",   // UNREACHABLE / CRITICAL
  3: "#95a5a6",   // UNKNOWN
}};

const HOST_STATE_COLORS = {{
  1: "#95a5a6",   // PENDING
  2: "#2ecc71",   // UP
  4: "#e74c3c",   // DOWN
  8: "#e67e22",   // UNREACHABLE
}};

async function refreshStatus() {{
  try {{
    const url = `${{NAGIOS_URL}}/cgi-bin/statusjson.cgi?query=hostlist&details=true`;
    const resp = await fetch(url, {{ credentials: "include" }});
    if (!resp.ok) throw new Error(`HTTP ${{resp.status}}`);
    const data = await resp.json();

    const hostlist = data.data?.hostlist || {{}};
    const updates = [];
    let up = 0, down = 0, unknown = 0;

    nodes.getIds().forEach(id => {{
      const node = nodes.get(id);
      const hostData = hostlist[node.hostname];
      if (hostData) {{
        const state = hostData.status;
        const color = HOST_STATE_COLORS[state] || "#95a5a6";
        updates.push({{
          id,
          color: {{ background: color, border: color }},
          title: `${{node.hostname}}\\n${{node.role}} | ${{node.address}}\\nState: ${{{{1:'PENDING',2:'UP',4:'DOWN',8:'UNREACHABLE'}}[state] || 'UNKNOWN'}}\\n${{hostData.plugin_output || ""}}`,
        }});
        if (state === 2) up++;
        else if (state === 4 || state === 8) down++;
        else unknown++;  // PENDING or UNREACHABLE
      }} else {{
        updates.push({{ id, color: {{ background: "#95a5a6", border: "#95a5a6" }} }});
        unknown++;
      }}
    }});

    nodes.update(updates);

    document.getElementById("host-counts").innerHTML =
      `<span class="up">▲ ${{up}} UP</span> &nbsp;
       <span class="down">▼ ${{down}} DOWN</span> &nbsp;
       <span class="unknown">? ${{unknown}} UNKNOWN</span>`;
    document.getElementById("last-updated").textContent = new Date().toLocaleTimeString();

  }} catch(e) {{
    console.error("Status refresh failed:", e);
    document.getElementById("last-updated").textContent = "refresh failed";
  }}
}}

// Initial load + periodic refresh
refreshStatus();
setInterval(refreshStatus, REFRESH_INTERVAL);
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Main generator
# ---------------------------------------------------------------------------

def generate_maps(result: dict, data: dict, config: dict):
    nagios_url       = os.getenv("NAGIOS_WEB_URL", "http://localhost/nagios").rstrip("/")
    refresh_interval = config["maps"]["refresh_interval"]
    output_dir       = config["maps"]["output_dir"]

    maps = [
        (
            config["maps"]["network_map"],
            "ESDA Lab — Network Map",
            *_build_network_graph(result, data, config),
        ),
        (
            config["maps"]["vm_map"],
            "ESDA Lab — VM Map",
            *_build_vm_graph(result, data),
        ),
        (
            config["maps"]["phone_map"],
            "ESDA Lab — IP Phone Map",
            *_build_phone_graph(result, config),
        ),
        (
            config["maps"]["hosts_map"],
            "ESDA Lab — Hosts Map",
            *_build_hosts_graph(result, data, config),
        ),
    ]

    ssh = _get_ssh_client()
    try:
        sftp = ssh.open_sftp()
        ssh.exec_command(f"sudo mkdir -p {output_dir} && sudo chown {os.getenv('NAGIOS_SSH_USER')} {output_dir}")

        with tempfile.TemporaryDirectory() as tmpdir:
            for fname, title, nodes, edges in maps:
                html        = _render_html(title, nodes, edges, nagios_url, refresh_interval)
                local_path  = os.path.join(tmpdir, fname)
                remote_path = f"{output_dir}/{fname}"

                with open(local_path, "w") as f:
                    f.write(html)

                _upload(sftp, local_path, remote_path)
                logger.info(f"Map '{title}': {len(nodes)} nodes, {len(edges)} edges")

        sftp.close()
    finally:
        ssh.close()

    logger.info(f"All maps generated → {output_dir}")


# ---------------------------------------------------------------------------
# CLI test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from dotenv import load_dotenv
    from fetcher import fetch_all, load_config
    from transformer import transform

    load_dotenv()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    cfg    = load_config()
    data   = fetch_all(cfg)
    result = transform(data, cfg)
    generate_maps(result, data, cfg)

    nagios_url = os.getenv("NAGIOS_WEB_URL", "").rstrip("/")
    print(f"\n=== MAPS AVAILABLE AT ===")
    for key in ["network_map", "vm_map", "phone_map", "hosts_map"]:
        print(f"  {nagios_url}/maps/{cfg['maps'][key]}")