#!/usr/bin/env python3
"""
SOC Pi v7.0 - Real-Time Network Intelligence Dashboard
Run with: sudo python3 dashboard.py
"""

import psutil
import json
import time
import threading
import subprocess
import requests
import logging
import os
from pathlib import Path
from datetime import datetime
from typing import Any, List
from flask import Flask, jsonify, render_template_string

# ----------------------
# CONFIGURATION
# ----------------------
APP_PORT = 8080
NETWORK_CIDR = "192.168.0.0/24"  # <-- VERIFY THIS MATCHES YOUR NETWORK
SNAPSHOT_FILE = Path("scan_snapshot.json")
HISTORY_FILE = Path("history.jsonl")
LOG_FILE = Path("network_monitor.log")
VENDOR_CACHE_FILE = Path("vendor_cache.json")
KNOWN_DEVICES_FILE = Path("known_devices.json")

# Telegram Settings
TELEGRAM = {
    "ENABLED": False,
    "TOKEN": "",
    "CHAT_ID": "",
}

# Vulnerability Mapping (Port: (Severity, Description))
VULN_DB = {
    21: ("HIGH", "FTP - Cleartext Credentials"),
    22: ("LOW", "SSH - Secure Shell"),
    23: ("CRITICAL", "Telnet - Insecure"),
    80: ("MEDIUM", "HTTP - Unencrypted"),
    443: ("LOW", "HTTPS - Secure"),
    445: ("HIGH", "SMB - Potential Exploit Target"),
    3389: ("MEDIUM", "RDP - Remote Desktop"),
}

# ----------------------
# LOGGING SETUP
# ----------------------
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
)

app = Flask(__name__)

# ----------------------
# DASHBOARD UI
# ----------------------
HTML = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Cyber-Pi SOC | Network Intelligence</title>
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
        td { padding: 14px 15px; border-bottom: 1px solid var(--border); font-family: 'JetBrains Mono'; font-size: 0.85rem; }
        tr:hover { background: rgba(0, 242, 255, 0.04); cursor: pointer; }
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: bold; }
        .badge-danger { background: var(--danger); color: white; }
        .badge-warn { background: var(--warn); color: black; }
        .badge-success { background: var(--success); color: black; }
        .port-tag { display: inline-block; background: #2d343f; padding: 2px 6px; border-radius: 4px; margin-right: 4px; font-size: 0.7rem; color: var(--accent); }
    </style>
</head>
<body>
<header>
    <div><h2 style="margin:0;">PI-SOC <span style="font-weight:300; color:var(--accent);">v7.0</span></h2><small id="last-update" style="color:#8892b0;">Systems Online</small></div>
    <div class="scan-status"><div class="pulse"></div> LIVE MONITORING</div>
</header>
<div class="container">
    <div class="grid">
        <div class="card"><div class="stat-label">Devices Online</div><div class="stat-val" id="stat-seen">0</div></div>
        <div class="card"><div class="stat-label">CPU Load</div><div class="stat-val" id="stat-cpu">0%</div></div>
        <div class="card"><div class="stat-label">Risk Level</div><div class="stat-val" id="stat-risk" style="color:var(--success);">LOW</div></div>
        <div class="card"><div class="stat-label">Pi Temperature</div><div class="stat-val" id="stat-temp" style="color:var(--success);">0°C</div></div>
    </div>
    <div class="table-container">
        <div style="padding: 15px; background: #1e2530;">
            <input type="text" id="search" placeholder="Filter by IP, MAC, or Vendor..." style="width: 100%; background: #0b0e14; border: 1px solid var(--border); color: white; padding: 10px; border-radius: 6px;">
        </div>
        <table>
            <thead><tr><th>IP Address</th><th>MAC Address</th><th>Vendor</th><th>Open Ports</th><th>Risk Rating</th></tr></thead>
            <tbody id="device-table"></tbody>
        </table>
    </div>
</div>
<script>
async function refreshData() {
    try {
        const snap = await fetch("/api/snapshot").then(r => r.json());
        const sys = await fetch("/api/sys_info").then(r => r.json());

        document.getElementById('stat-seen').innerText = snap.counts.seen;
        document.getElementById('stat-cpu').innerText = sys.cpu + "%";
        document.getElementById('stat-temp').innerText = sys.temp + "°C";
        document.getElementById('last-update').innerText = "Last Scan: " + snap.timestamp;

        const tbody = document.getElementById('device-table');
        tbody.innerHTML = snap.devices.map(d => {
            let badgeClass = "badge-success";
            if(d.risk === "CRITICAL" || d.risk === "HIGH") badgeClass = "badge-danger";
            else if(d.risk === "MEDIUM") badgeClass = "badge-warn";

            const ports = d.ports.map(p => `<span class="port-tag">${p}</span>`).join('') || "None";

            return `
                <tr>
                    <td style="font-weight:700;">${d.ip}</td>
                    <td>${d.mac || 'N/A'}</td>
                    <td>${d.vendor || 'Unknown'}</td>
                    <td>${ports}</td>
                    <td><span class="badge ${badgeClass}">${d.risk}</span></td>
                </tr>`;
        }).join('');
    } catch (e) { console.error("Sync Error:", e); }
}
setInterval(refreshData, 5000);
refreshData();
</script>
</body>
</html>
"""

# ----------------------
# BACKEND UTILITIES
# ----------------------

def load_json(path: Path, default: Any) -> Any:
    try: return json.loads(path.read_text(encoding="utf-8"))
    except: return default

def save_json(path: Path, data: Any):
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")

def send_telegram(message: str):
    if not TELEGRAM["ENABLED"]: return
    url = f"https://api.telegram.org/bot{TELEGRAM['TOKEN']}/sendMessage"
    try:
        requests.post(url, json={"chat_id": TELEGRAM["CHAT_ID"], "text": message, "parse_mode": "Markdown"}, timeout=10)
    except Exception as e:
        logging.error(f"Telegram Error: {e}")

def get_vendor(mac: str) -> str:
    if not mac: return "Unknown"
    cache = load_json(VENDOR_CACHE_FILE, {})
    prefix = mac[:8].upper()
    if prefix in cache: return cache[prefix]
    try:
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
        if r.status_code == 200:
            vendor = r.text.strip()
            cache[prefix] = vendor
            save_json(VENDOR_CACHE_FILE, cache)
            return vendor
    except: pass
    return "Unknown"

# ----------------------
# SCANNER CORE
# ----------------------

def background_scanner():
    logging.info("Deep Vulnerability Scanner Started...")
    known_macs = load_json(KNOWN_DEVICES_FILE, [])

    while True:
        try:
            # 1. RUN NMAP DISCOVERY & PORT SCAN
            # -F (Fast scan 100 ports), -sV (Service detection)
            cmd = ["nmap", "-sn", NETWORK_CIDR]
            res = subprocess.run(cmd, capture_output=True, text=True)
            
            ips = []
            for line in res.stdout.splitlines():
                if "Nmap scan report for" in line:
                    ips.append(line.split()[-1].strip("()"))

            found_devices = []
            for ip in ips:
                # Targeted port scan for found host
                port_cmd = ["nmap", "-F", ip]
                port_res = subprocess.run(port_cmd, capture_output=True, text=True)
                
                mac = ""
                ports = []
                risk = "LOW"
                vulnerabilities = []

                for line in port_res.stdout.splitlines():
                    if "MAC Address:" in line:
                        mac = line.split("MAC Address:")[1].split("(")[0].strip()
                    if "/tcp" in line and "open" in line:
                        p = int(line.split("/")[0])
                        ports.append(p)
                        if p in VULN_DB:
                            severity, desc = VULN_DB[p]
                            risk = severity
                            vulnerabilities.append(f"{p} ({desc})")

                vendor = get_vendor(mac)
                device = {"ip": ip, "mac": mac, "vendor": vendor, "ports": ports, "risk": risk}
                found_devices.append(device)

                # 2. TELEGRAM NOTIFICATION (NEW DEVICE OR VULN)
                if mac and mac not in known_macs:
                    msg = f"🛡 *SOC ALERT: NEW DEVICE*\nIP: `{ip}`\nMAC: `{mac}`\nVendor: {vendor}\nPorts: {ports}\nRisk: {risk}"
                    send_telegram(msg)
                    known_macs.append(mac)
                    save_json(KNOWN_DEVICES_FILE, known_macs)

            # 3. SAVE DATA
            snapshot = {
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "counts": {"seen": len(found_devices)},
                "devices": found_devices
            }
            save_json(SNAPSHOT_FILE, snapshot)
            time.sleep(45)

        except Exception as e:
            logging.error(f"Scanner Loop Error: {e}")
            time.sleep(10)

# ----------------------
# FLASK API
# ----------------------
@app.route("/")
def home(): return render_template_string(HTML)

@app.route("/api/snapshot")
def api_snapshot(): 
    return jsonify(load_json(SNAPSHOT_FILE, {"counts": {"seen": 0}, "devices": []}))

@app.route("/api/sys_info")
def api_sys_info():
    temp = 0
    try:
        with open("/sys/class/thermal/thermal_zone0/temp", "r") as f:
            temp = round(int(f.read()) / 1000, 1)
    except: pass
    return jsonify({"cpu": psutil.cpu_percent(), "temp": temp})

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("CRITICAL: Root privileges required for Nmap detection.")
        exit(1)

    threading.Thread(target=background_scanner, daemon=True).start()
    app.run(host="0.0.0.0", port=APP_PORT, debug=False)