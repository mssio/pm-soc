#!/usr/bin/env python3
"""
SOC Pi v10.0 - "The Profiler + Integrated Monitor"
Deep network discovery + OS/service profiling + device-type inference
Dashboard w/ charts, history, log tail, system info, vendor cache, Telegram alerts.

RUN:
  sudo python3 dashboard.py

DEPENDENCIES:
  sudo apt-get update
  sudo apt-get install -y nmap
  sudo pip3 install flask psutil requests

NOTES:
- Run with sudo/root for best results (MAC detection + OS detection).
- Telegram creds: set env vars or disable TELEGRAM["ENABLED"].
"""

import json
import time
import threading
import subprocess
import requests
import logging
import os
import re
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import psutil
from flask import Flask, jsonify, render_template_string

# ----------------------
# CONFIGURATION
# ----------------------
APP_PORT = int(os.getenv("SOCPI_PORT", "8080"))
NETWORK_CIDR = os.getenv("SOCPI_CIDR", "192.168.0.0/24")

SCAN_INTERVAL_SEC = int(os.getenv("SOCPI_SCAN_INTERVAL", "60"))        # host discovery cadence
PROFILE_TTL_SEC = int(os.getenv("SOCPI_PROFILE_TTL", "300"))           # re-profile same host after N seconds
NMAP_TOP_PORTS = int(os.getenv("SOCPI_TOP_PORTS", "50"))

SNAPSHOT_FILE = Path(os.getenv("SOCPI_SNAPSHOT_FILE", "scan_snapshot.json"))
HISTORY_FILE = Path(os.getenv("SOCPI_HISTORY_FILE", "history.jsonl"))
LOG_FILE = Path(os.getenv("SOCPI_LOG_FILE", "network_monitor.log"))
VENDOR_CACHE_FILE = Path(os.getenv("SOCPI_VENDOR_CACHE", "vendor_cache.json"))



# "Risk" heuristic ports (you can tune this)
RISKY_PORTS_CRITICAL = {"23", "2323", "3389", "5900", "445"}   # telnet, RDP, VNC, SMB
RISKY_PORTS_MEDIUM = {"22", "21", "8080", "8443", "3306"}      # ssh/ftp/webadmin/db-ish


# ----------------------
# LOGGING & APP
# ----------------------
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()],
)
app = Flask(__name__)

# ----------------------
# UI (Dashboard)
# ----------------------
HTML = r"""
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>SOC Pi v10 | Profiler + Monitor</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@300;500;700&display=swap" rel="stylesheet">
    <style>
        :root { --bg: #0b0e14; --card-bg: #151921; --accent: #00f2ff; --text: #e0e6ed; --danger: #ff4d4d; --warn: #ffab00; --success: #00e676; --border: #2d343f; }
        body { font-family: 'Inter', sans-serif; background: var(--bg); color: var(--text); margin:0; padding-bottom: 50px; }
        header { background: var(--card-bg); padding: 15px 30px; border-bottom: 2px solid var(--accent); display: flex; justify-content: space-between; align-items: center; box-shadow: 0 4px 20px rgba(0,0,0,0.5); }
        .scan-status { display: flex; align-items: center; gap: 10px; font-family: 'JetBrains Mono'; font-size: 0.8rem; color: var(--accent); }
        .pulse { width: 10px; height: 10px; background: var(--accent); border-radius: 50%; animation: blink 1.5s infinite; }
        @keyframes blink { 0%, 100% { opacity: 1; box-shadow: 0 0 10px var(--accent); } 50% { opacity: 0.2; } }
        .container { padding: 25px; max-width: 1600px; margin: auto; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; margin-bottom: 25px; }
        .card { background: var(--card-bg); border-radius: 12px; padding: 20px; border: 1px solid var(--border); transition: 0.3s; }
        .card:hover { border-color: var(--accent); transform: translateY(-3px); }
        .stat-label { font-size: 0.75rem; text-transform: uppercase; color: #8892b0; letter-spacing: 1px; }
        .stat-val { font-size: 2.2rem; font-weight: 700; color: var(--accent); font-family: 'JetBrains Mono'; }
        .table-container { background: var(--card-bg); border-radius: 12px; border: 1px solid var(--border); overflow: hidden; }
        table { width: 100%; border-collapse: collapse; }
        th { background: #1e2530; padding: 15px; text-align: left; font-size: 0.75rem; text-transform: uppercase; color: #8892b0; }
        td { padding: 14px 15px; border-bottom: 1px solid var(--border); font-family: 'JetBrains Mono'; font-size: 0.85rem; vertical-align: top; }
        tr:hover { background: rgba(0, 242, 255, 0.04); cursor: pointer; }
        .risk-high { color: var(--danger); border-left: 4px solid var(--danger); background: rgba(255, 77, 77, 0.03); }
        .risk-med { color: var(--warn); border-left: 4px solid var(--warn); }
        .risk-low { border-left: 4px solid var(--success); }
        input, select { background: #1e2530; border: 1px solid var(--border); color: white; padding: 10px; border-radius: 6px; font-family: 'Inter'; }
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: bold; display: inline-block; }
        .badge-danger { background: var(--danger); color: white; }
        .badge-warn { background: var(--warn); color: black; }
        .badge-success { background: var(--success); color: black; }
        .muted { color: #8892b0; font-family: 'Inter'; font-size: 0.85rem; }
        .pill { padding: 2px 8px; border: 1px solid var(--border); border-radius: 999px; font-size: 0.72rem; color: #cbd5e1; }
        .ports { color: #aab2c0; font-size: 0.78rem; font-family: 'JetBrains Mono'; }
    </style>
</head>
<body>
<header>
    <div>
        <h2 style="margin:0;">SOC Pi <span style="font-weight:300; color:var(--accent);">v10.0</span></h2>
        <small id="last-update" style="color:#8892b0;">Booting…</small>
    </div>
    <div class="scan-status"><div class="pulse"></div> ACTIVE MONITORING</div>
</header>

<div class="container">
    <div class="grid">
        <div class="card"><div class="stat-label">Total Devices</div><div class="stat-val" id="stat-seen">0</div></div>
        <div class="card"><div class="stat-label">New Devices</div><div class="stat-val" id="stat-new" style="color:var(--warn);">0</div></div>
        <div class="card"><div class="stat-label">Risk Level</div><div class="stat-val" id="stat-risk" style="color:var(--success);">LOW</div></div>
        <div class="card"><div class="stat-label">System Temp</div><div class="stat-val" id="stat-temp" style="color:var(--success);">0°C</div></div>
    </div>

    <div class="grid" style="grid-template-columns: 2fr 1fr;">
        <div class="card"><h4 style="margin-top:0;">Device Trend (Last 50 Scans)</h4><canvas id="trendChart" height="100"></canvas></div>
        <div class="card"><h4 style="margin-top:0;">Vendor Distribution</h4><canvas id="vendorChart" height="210"></canvas></div>
    </div>

    <div class="table-container">
        <div style="padding: 15px; display: flex; gap: 15px; background: #1e2530;">
            <input type="text" id="search" placeholder="Filter by IP, MAC, vendor, OS, type, or port…" style="flex: 2;">
            <select id="risk-filter" style="flex: 1;">
                <option value="">All Risk Levels</option>
                <option value="critical">Critical</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
            </select>
        </div>
        <table>
            <thead>
                <tr>
                    <th>IP</th>
                    <th>Identity</th>
                    <th>OS / Type</th>
                    <th>Open Services</th>
                    <th>Risk</th>
                </tr>
            </thead>
            <tbody id="device-table"></tbody>
        </table>
    </div>

    <div class="card" style="margin-top: 25px; border-color: #333;">
        <h4 style="margin: 0 0 10px 0; font-family: 'JetBrains Mono'; font-size: 0.8rem; color: var(--success);">&gt;_ SYSTEM_LOG_OUTPUT</h4>
        <pre id="log-output" style="font-family: 'JetBrains Mono'; font-size: 0.75rem; color: #aab2c0; max-height: 170px; overflow-y: auto; margin: 0;"></pre>
    </div>
</div>

<script>
let trendChart, vendorChart;

function badgeForRisk(risk){
  if(risk === "CRITICAL") return '<span class="badge badge-danger">CRITICAL</span>';
  if(risk === "MEDIUM") return '<span class="badge badge-warn">MEDIUM</span>';
  return '<span class="badge badge-success">LOW</span>';
}

async function refreshData() {
    try {
        const snap = await fetch("/api/snapshot").then(r => r.json());
        const hist = await fetch("/api/history").then(r => r.json());
        const logs = await fetch("/api/log_tail").then(r => r.json());
        const sys  = await fetch("/api/sys_info").then(r => r.json());

        updateStats(snap, sys);
        renderTable(snap.devices);
        updateCharts(hist.records, snap.devices);

        document.getElementById('log-output').textContent = logs.lines.join("\n");
        document.getElementById('last-update').innerText = "Last Scan: " + (snap.timestamp || "N/A") + " | Subnet: " + (snap.subnet || "N/A");
    } catch (e) { console.error("Sync Error:", e); }
}

function updateStats(snap, sys) {
    document.getElementById('stat-seen').innerText = (snap.counts && snap.counts.seen) || 0;
    document.getElementById('stat-new').innerText  = (snap.counts && snap.counts.new) || 0;

    const anyCritical = (snap.devices || []).some(d => (d.risk || "") === "CRITICAL");
    const riskText = anyCritical ? "CRITICAL" : "LOW";
    document.getElementById('stat-risk').innerText = riskText;
    document.getElementById('stat-risk').style.color = anyCritical ? "var(--danger)" : "var(--success)";

    document.getElementById('stat-temp').innerText = (sys.temp || 0) + "°C";
}

function renderTable(devices) {
    const q = (document.getElementById('search').value || "").toLowerCase();
    const riskFilter = document.getElementById('risk-filter').value;
    const tbody = document.getElementById('device-table');

    const filtered = (devices || []).filter(d => {
        const hay = [
          d.ip, d.mac, d.vendor, d.os, d.type,
          (d.ports||[]).join(" ")
        ].join(" ").toLowerCase();

        const riskOk = !riskFilter ||
          (riskFilter === "critical" && d.risk === "CRITICAL") ||
          (riskFilter === "medium" && d.risk === "MEDIUM") ||
          (riskFilter === "low" && d.risk === "LOW");

        return hay.includes(q) && riskOk;
    });

    tbody.innerHTML = filtered.map(d => {
        const riskClass = d.risk === "CRITICAL" ? "risk-high" : (d.risk === "MEDIUM" ? "risk-med" : "risk-low");
        const ports = (d.ports || []).slice(0, 12).join(", ");
        const more = (d.ports || []).length > 12 ? ` <span class="pill">+${(d.ports||[]).length-12} more</span>` : "";
        return `
          <tr class="${riskClass}">
            <td style="font-weight:700;">${d.ip || "N/A"}</td>
            <td>
              <div>${d.mac || "N/A"}</div>
              <div class="muted">${d.vendor || "Unknown"}</div>
              <div class="muted">Seen: ${d.last_seen || "—"}</div>
            </td>
            <td>
              <div style="font-weight:700;">${d.type || "Unknown"}</div>
              <div class="muted">${d.os || "Unknown OS"}</div>
              <div class="muted">${d.hostname ? ("Host: " + d.hostname) : ""}</div>
            </td>
            <td class="ports">${ports}${more}</td>
            <td>${badgeForRisk(d.risk || "LOW")}</td>
          </tr>
        `;
    }).join('');
}

function updateCharts(history, devices) {
    const trendCtx = document.getElementById('trendChart').getContext('2d');
    if (trendChart) trendChart.destroy();
    trendChart = new Chart(trendCtx, {
        type: 'line',
        data: {
            labels: (history || []).map(h => (h.ts || "").split('T')[1]?.split('.')[0] || ""),
            datasets: [{ label: 'Active Hosts', data: (history || []).map(h => h.seen || 0), borderColor: '#00f2ff', fill: true }]
        },
        options: { plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true } } }
    });

    const vendorCounts = (devices || []).reduce((acc, d) => {
        const v = d.vendor || "Unknown";
        acc[v] = (acc[v] || 0) + 1;
        return acc;
    }, {});
    const vendorCtx = document.getElementById('vendorChart').getContext('2d');
    if (vendorChart) vendorChart.destroy();
    vendorChart = new Chart(vendorCtx, {
        type: 'doughnut',
        data: { labels: Object.keys(vendorCounts), datasets: [{ data: Object.values(vendorCounts) }] },
        options: { plugins: { legend: { position: 'bottom', labels: { color: '#8892b0' } } } }
    });
}

setInterval(refreshData, 5000);
refreshData();

document.getElementById('search').addEventListener('input', refreshData);
document.getElementById('risk-filter').addEventListener('change', refreshData);
</script>
</body>
</html>
"""


# ----------------------
# JSON UTIL
# ----------------------
def load_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def save_json(path: Path, data: Any):
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


# ----------------------
# VENDOR LOOKUP (cached)
# ----------------------
def get_vendor(mac: str) -> str:
    """
    Tries:
      1) local cache by OUI prefix
      2) api.macvendors.com lookup
    """
    if not mac:
        return "Unknown"
    cache = load_json(VENDOR_CACHE_FILE, {})
    mac_prefix = mac[:8].upper()  # "AA:BB:CC"
    if mac_prefix in cache:
        return cache[mac_prefix]

    try:
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=3)
        if r.status_code == 200:
            vendor = r.text.strip()
            if vendor:
                cache[mac_prefix] = vendor
                save_json(VENDOR_CACHE_FILE, cache)
                return vendor
    except Exception:
        pass
    return "Unknown"


# ----------------------
# TELEGRAM
# ----------------------
def send_telegram(message: str):
    if not TELEGRAM["ENABLED"]:
        return
    if not TELEGRAM["TOKEN"] or not TELEGRAM["CHAT_ID"]:
        logging.warning("Telegram enabled but TOKEN/CHAT_ID not set.")
        return

    url = f"https://api.telegram.org/bot{TELEGRAM['TOKEN']}/sendMessage"
    try:
        requests.post(url, json={"chat_id": TELEGRAM["CHAT_ID"], "text": message}, timeout=10)
        logging.info("Telegram sent.")
    except Exception as e:
        logging.error(f"Telegram error: {e}")


# ----------------------
# CLUE ENGINE (from Code 1 + a bit more)
# ----------------------
def identify_device_type(vendor: str, os_guess: str, ports: List[str], hostname: str) -> str:
    vendor_u = (vendor or "Unknown").upper()
    os_l = (os_guess or "Unknown").lower()
    hn_l = (hostname or "").lower()
    port_nums = [p.split("/")[0] for p in ports]

    # 1) Raspberry Pi
    if "RASPBERRY" in vendor_u or re.search(r"\bpi\b", hn_l):
        return "Raspberry Pi"

    # 2) Apple
    if "APPLE" in vendor_u:
        if "62078" in port_nums:
            return "iPhone/iPad (Locked)"
        if "darwin" in os_l or "mac os" in os_l or "macos" in os_l:
            return "Mac (iMac/MacBook)"
        return "Apple Device"

    # 3) Smart TV / Media
    tv_vendors = ["SAMSUNG", "LG", "SONY", "VIZIO", "PANASONIC", "HISENSE", "TCL"]
    if any(v in vendor_u for v in tv_vendors):
        return "Smart TV"
    if any(p in port_nums for p in ["8008", "8009", "1900", "554", "2869"]):
        return "Smart TV / Media Player"

    # 4) Android-ish hints
    if any(p in port_nums for p in ["5555"]) and "linux" in os_l:
        return "Android / Debug (ADB)"

    # 5) General Linux server
    if "linux" in os_l and "22" in port_nums:
        return "Linux Server / SBC"

    if os_guess and os_guess != "Unknown":
        # keep it short
        if "windows" in os_l:
            return "Windows Device"
        if "linux" in os_l:
            return "Linux Device"

    return "Unknown Device"


def compute_risk(ports: List[str], os_guess: str) -> str:
    """
    Simple heuristic:
      - CRITICAL if any critical risky ports are open
      - MEDIUM if any medium risky ports are open OR OS is unknown
      - LOW otherwise
    """
    port_nums = {p.split("/")[0] for p in ports}
    if port_nums & RISKY_PORTS_CRITICAL:
        return "CRITICAL"
    if port_nums & RISKY_PORTS_MEDIUM:
        return "MEDIUM"
    if (os_guess or "").strip().lower() in ("", "unknown"):
        return "MEDIUM"
    return "LOW"


# ----------------------
# NMAP PARSERS
# ----------------------
def run_cmd(cmd: List[str]) -> Tuple[int, str, str]:
    res = subprocess.run(cmd, capture_output=True, text=True)
    return res.returncode, res.stdout, res.stderr


def parse_discovery_nmap(output: str) -> List[Dict[str, Any]]:
    """
    Parse `nmap -sn <CIDR>` output into list of {ip, hostname?, mac?, vendor?}.
    """
    hosts: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None

    # Typical lines:
    # "Nmap scan report for 192.168.0.10"
    # or "Nmap scan report for host (192.168.0.10)"
    # "MAC Address: AA:BB:CC:DD:EE:FF (Vendor)"
    for line in output.splitlines():
        line = line.strip()

        if line.startswith("Nmap scan report for"):
            # flush previous
            if current:
                hosts.append(current)
            current = {"ip": None, "hostname": "", "mac": None, "vendor": "Unknown"}

            target = line.split("for", 1)[1].strip()
            # target may be "name (ip)" or just "ip"
            m = re.match(r"(.+)\s+\(([\d\.]+)\)$", target)
            if m:
                current["hostname"] = m.group(1).strip()
                current["ip"] = m.group(2).strip()
            else:
                current["ip"] = target.strip("()")
                current["hostname"] = ""

        elif line.startswith("MAC Address:") and current:
            # "MAC Address: AA:BB:CC:DD:EE:FF (Vendor Name)"
            try:
                after = line.split("MAC Address:", 1)[1].strip()
                mac = after.split()[0].strip()
                current["mac"] = mac
                vendor = ""
                if "(" in after and ")" in after:
                    vendor = after.split("(", 1)[1].rsplit(")", 1)[0].strip()
                current["vendor"] = vendor or "Unknown"
            except Exception:
                pass

    if current:
        hosts.append(current)

    # keep only those with IP
    return [h for h in hosts if h.get("ip")]


def parse_profile_nmap(output: str) -> Dict[str, Any]:
    """
    Parse `nmap -O -sV --top-ports ... <ip>` output.
    Returns dict with mac, vendor, os_guess, ports(list), hostname.
    """
    mac = None
    vendor = "Unknown"
    os_guess = "Unknown"
    ports: List[str] = []
    hostname = ""

    for line in output.splitlines():
        s = line.strip()

        if s.startswith("Nmap scan report for"):
            target = s.split("for", 1)[1].strip()
            m = re.match(r"(.+)\s+\(([\d\.]+)\)$", target)
            hostname = (m.group(1).strip() if m else "")
        elif "MAC Address:" in s:
            try:
                after = s.split("MAC Address:", 1)[1].strip()
                mac = after.split()[0].strip()
                if "(" in after and ")" in after:
                    vendor = after.split("(", 1)[1].rsplit(")", 1)[0].strip() or vendor
            except Exception:
                pass
        elif s.startswith("OS details:"):
            os_guess = s.split("OS details:", 1)[1].strip() or os_guess
        elif s.startswith("Running:"):
            # sometimes more reliable than OS details
            running = s.split("Running:", 1)[1].strip()
            if running:
                os_guess = running
        elif "/tcp" in s and " open " in f" {s} ":
            # Example: "22/tcp open  ssh  OpenSSH 8.2p1 ..."
            ports.append(s)

    return {"mac": mac, "vendor": vendor, "os": os_guess, "ports": ports, "hostname": hostname}


# ----------------------
# INVENTORY + SCANNER LOOP
# ----------------------
inventory_lock = threading.Lock()
device_inventory: Dict[str, Dict[str, Any]] = {}  # key: MAC if present else "IP:<ip>"

# Track "new device" alerts so we don't spam
seen_keys: set = set()


def make_key(ip: str, mac: Optional[str]) -> str:
    return mac.upper() if mac else f"IP:{ip}"


def background_scanner():
    logging.info(f"Starting SOC Pi v10 scanner on {NETWORK_CIDR} (scan={SCAN_INTERVAL_SEC}s, profile_ttl={PROFILE_TTL_SEC}s)")

    last_report_date = None

    while True:
        start_ts = time.time()
        now = datetime.now()

        try:
            # 1) DISCOVERY
            logging.info("Discovery scan (-sn)…")
            rc, out, err = run_cmd(["nmap", "-sn", NETWORK_CIDR])
            if rc != 0:
                logging.warning(f"Discovery nmap returned code={rc}. stderr={err.strip()[:200]}")
            discovered = parse_discovery_nmap(out)

            # 2) PROFILE (deep) - only when new or stale
            new_devices = 0
            critical_devices = 0

            for host in discovered:
                ip = host["ip"]
                disc_mac = host.get("mac")
                disc_vendor = host.get("vendor") or "Unknown"
                disc_hostname = host.get("hostname") or ""

                key_guess = make_key(ip, disc_mac)
                do_profile = True

                with inventory_lock:
                    existing = device_inventory.get(key_guess)
                    if existing:
                        # profile only if stale
                        last_prof = existing.get("last_profile_epoch", 0)
                        do_profile = (time.time() - last_prof) >= PROFILE_TTL_SEC

                prof = {"mac": disc_mac, "vendor": disc_vendor, "os": "Unknown", "ports": [], "hostname": disc_hostname}

                if do_profile:
                    logging.info(f"Profiling {ip} (-O -sV top {NMAP_TOP_PORTS})…")
                    # OS detection & version detection often require sudo/root
                    cmd = ["nmap", "-O", "-sV", "--top-ports", str(NMAP_TOP_PORTS), "-T4", ip]
                    # If user runs as sudo, this is already root; don't double "sudo" here.
                    rc2, out2, err2 = run_cmd(cmd)
                    if rc2 != 0:
                        logging.warning(f"Profile nmap for {ip} returned code={rc2}. stderr={err2.strip()[:200]}")
                    parsed = parse_profile_nmap(out2)

                    # merge back: discovery can still be useful if profile fails
                    prof["mac"] = parsed.get("mac") or disc_mac
                    prof["vendor"] = parsed.get("vendor") or disc_vendor
                    prof["os"] = parsed.get("os") or "Unknown"
                    prof["ports"] = parsed.get("ports") or []
                    prof["hostname"] = parsed.get("hostname") or disc_hostname
                else:
                    # keep prior profile details
                    with inventory_lock:
                        if existing:
                            prof["os"] = existing.get("os", "Unknown")
                            prof["ports"] = existing.get("ports", [])
                            prof["hostname"] = existing.get("hostname", disc_hostname)

                # vendor enrichment if unknown
                vendor_final = prof["vendor"] or disc_vendor or "Unknown"
                mac_final = prof["mac"]
                if (vendor_final.strip().lower() in ("unknown", "unknown vendor", "")) and mac_final:
                    vendor_final = get_vendor(mac_final)

                # identify device type & risk
                dev_type = identify_device_type(vendor_final, prof["os"], prof["ports"], prof["hostname"])
                risk = compute_risk(prof["ports"], prof["os"])
                if risk == "CRITICAL":
                    critical_devices += 1

                key = make_key(ip, mac_final)
                first_seen = None

                with inventory_lock:
                    if key not in device_inventory:
                        new_devices += 1
                        first_seen = now.strftime("%Y-%m-%d %H:%M:%S")

                    prev = device_inventory.get(key, {})
                    device_inventory[key] = {
                        "ip": ip,
                        "mac": mac_final,
                        "vendor": vendor_final,
                        "hostname": prof["hostname"] or "",
                        "os": prof["os"] or "Unknown",
                        "type": dev_type,
                        "risk": risk,
                        "ports": prof["ports"],
                        "vulns": prev.get("vulns", []),  # placeholder for future CVE integration
                        "first_seen": prev.get("first_seen") or first_seen or now.strftime("%Y-%m-%d %H:%M:%S"),
                        "last_seen": now.strftime("%H:%M:%S"),
                        "last_profile_epoch": time.time(),
                    }

                # Telegram alert on first time we ever see a key
                if key not in seen_keys:
                    seen_keys.add(key)
                    if TELEGRAM["ENABLED"]:
                        msg = (
                            f"🛰️ NEW DEVICE DETECTED\n"
                            f"IP: {ip}\n"
                            f"MAC: {mac_final or 'N/A'}\n"
                            f"Vendor: {vendor_final}\n"
                            f"Type: {dev_type}\n"
                            f"OS: {prof['os']}\n"
                            f"Risk: {risk}\n"
                            f"Ports: {', '.join(prof['ports'][:10])}{'…' if len(prof['ports'])>10 else ''}"
                        )
                        send_telegram(msg)

            # 3) SAVE SNAPSHOT (sorted)
            with inventory_lock:
                devices_list = list(device_inventory.values())
            devices_list.sort(key=lambda d: d.get("ip", ""))

            snapshot = {
                "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
                "subnet": NETWORK_CIDR,
                "counts": {"seen": len(devices_list), "new": new_devices, "critical": critical_devices},
                "devices": devices_list,
            }
            save_json(SNAPSHOT_FILE, snapshot)

            # 4) HISTORY
            HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(HISTORY_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps({"seen": len(devices_list), "new": new_devices, "critical": critical_devices, "ts": now.isoformat()}) + "\n")

            # 5) DAILY TELEGRAM REPORT (9:00 PM)
            if TELEGRAM["ENABLED"] and now.hour == 0 and now.minute == 5:
                if last_report_date != now.date():
                    report = (
                        f"🌅 9PM DAILY REPORT\n"
                        f"Subnet: {NETWORK_CIDR}\n"
                        f"Devices Online: {len(devices_list)}\n"
                        f"Critical Devices: {critical_devices}\n"
                        f"System: OK"
                    )
                    send_telegram(report)
                    last_report_date = now.date()

        except Exception as e:
            logging.error(f"Scanner loop error: {e}")

        # Sleep remaining time
        elapsed = time.time() - start_ts
        sleep_for = max(3, SCAN_INTERVAL_SEC - int(elapsed))
        time.sleep(sleep_for)


# ----------------------
# FLASK ROUTES
# ----------------------
@app.route("/")
def home():
    return render_template_string(HTML)


@app.route("/api/snapshot")
def api_snapshot():
    default = {"timestamp": "", "subnet": NETWORK_CIDR, "counts": {"seen": 0, "new": 0, "critical": 0}, "devices": []}
    return jsonify(load_json(SNAPSHOT_FILE, default))


@app.route("/api/history")
def api_history():
    recs: List[Dict[str, Any]] = []
    if HISTORY_FILE.exists():
        lines = HISTORY_FILE.read_text(encoding="utf-8").splitlines()[-50:]
        for line in lines:
            try:
                recs.append(json.loads(line))
            except Exception:
                pass
    return jsonify({"records": recs})


@app.route("/api/log_tail")
def api_log_tail():
    lines = LOG_FILE.read_text(encoding="utf-8").splitlines()[-30:] if LOG_FILE.exists() else []
    return jsonify({"lines": lines})


@app.route("/api/sys_info")
def api_sys_info():
    temp = 0.0
    try:
        with open("/sys/class/thermal/thermal_zone0/temp", "r", encoding="utf-8") as f:
            temp = round(int(f.read().strip()) / 1000.0, 1)
    except Exception:
        pass
    return jsonify({
        "cpu": psutil.cpu_percent(interval=0.1),
        "ram_perc": psutil.virtual_memory().percent,
        "temp": temp
    })


# ----------------------
# MAIN
# ----------------------
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("⚠️  WARNING: Not running as root/sudo.")
        print("   Nmap OS detection and MAC/vendor visibility may be reduced.")
        print("   Recommended: sudo python3 dashboard.py")

    # Start background scanner
    t = threading.Thread(target=background_scanner, daemon=True)
    t.start()

    # Start web app
    app.run(host="0.0.0.0", port=APP_PORT, debug=False)
