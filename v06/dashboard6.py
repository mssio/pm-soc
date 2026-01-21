#!/usr/bin/env python3
"""
SOC Pi v0 - Integrated Monitor.
Run with: sudo python3 dashboard.py
"""

import psutil
import shutil
import json
import time
import threading
import subprocess
import re
import requests
import logging
import os
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List
from flask import Flask, jsonify, render_template_string

# ----------------------
# CONFIGURATION
# ----------------------
APP_PORT = 8080
NETWORK_CIDR = "192.168.0.0/24"  # CHANGE THIS to your subnet (e.g., 10.0.0.0/24)
SNAPSHOT_FILE = Path("scan_snapshot.json")
HISTORY_FILE = Path("history.jsonl")
LOG_FILE = Path("network_monitor.log")
VENDOR_CACHE_FILE = Path("vendor_cache.json")

TELEGRAM = {
    "ENABLED": False,
    "TOKEN": "",
    "CHAT_ID": "",
}

# ----------------------
# LOGGING & APP SETUP
# ----------------------
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
)

app = Flask(__name__)

# ----------------------
# DASHBOARD UI (The "Face")
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
        .risk-high { color: var(--danger); border-left: 4px solid var(--danger); background: rgba(255, 77, 77, 0.03); }
        .risk-med { color: var(--warn); border-left: 4px solid var(--warn); }
        .risk-low { border-left: 4px solid var(--success); }
        .modal { display: none; position: fixed; z-index: 100; left: 0; top: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.9); backdrop-filter: blur(8px); }
        .modal-content { background: var(--card-bg); margin: 5% auto; padding: 35px; width: 50%; border-radius: 15px; border: 1px solid var(--accent); box-shadow: 0 0 50px rgba(0, 242, 255, 0.2); }
        .close { float: right; font-size: 24px; cursor: pointer; color: var(--danger); }
        input, select { background: #1e2530; border: 1px solid var(--border); color: white; padding: 10px; border-radius: 6px; font-family: 'Inter'; }
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: bold; }
        .badge-danger { background: var(--danger); color: white; }
        .badge-success { background: var(--success); color: black; }
    </style>
</head>
<body>
<header>
    <div><h2 style="margin:0;">PI-SOC <span style="font-weight:300; color:var(--accent);">v5.1</span></h2><small id="last-update" style="color:#8892b0;">Systems Online</small></div>
    <div class="scan-status"><div class="pulse"></div> ACTIVE MONITORING</div>
</header>
<div class="container">
    <div class="grid">
        <div class="card"><div class="stat-label">Total Devices</div><div class="stat-val" id="stat-seen">0</div></div>
        <div class="card"><div class="stat-label">New Threats</div><div class="stat-val" id="stat-new" style="color:var(--warn);">0</div></div>
        <div class="card"><div class="stat-label">Risk Level</div><div class="stat-val" id="stat-risk" style="color:var(--danger);">LOW</div></div>
        <div class="card"><div class="stat-label">System Temp</div><div class="stat-val" id="stat-temp" style="color:var(--success);">0°C</div></div>
    </div>
    <div class="grid" style="grid-template-columns: 2fr 1fr;">
        <div class="card"><h4 style="margin-top:0;">Device Trend (Last 50 Scans)</h4><canvas id="trendChart" height="100"></canvas></div>
        <div class="card"><h4 style="margin-top:0;">Vendor Distribution</h4><canvas id="vendorChart" height="210"></canvas></div>
    </div>
    <div class="table-container">
        <div style="padding: 15px; display: flex; gap: 15px; background: #1e2530;">
            <input type="text" id="search" placeholder="Filter by IP, MAC, Port or Vendor..." style="flex: 2;">
            <select id="risk-filter" style="flex: 1;"><option value="">All Risk Levels</option><option value="high">Critical Only</option></select>
        </div>
        <table>
            <thead><tr><th>IP Address</th><th>MAC / HW Address</th><th>Vendor</th><th>Open Services</th><th>Status</th></tr></thead>
            <tbody id="device-table"></tbody>
        </table>
    </div>
    <div class="card" style="margin-top: 25px; border-color: #333;">
        <h4 style="margin: 0 0 10px 0; font-family: 'JetBrains Mono'; font-size: 0.8rem; color: var(--success);">&gt;_ SYSTEM_LOG_OUTPUT</h4>
        <pre id="log-output" style="font-family: 'JetBrains Mono'; font-size: 0.75rem; color: #aab2c0; max-height: 150px; overflow-y: auto; margin: 0;"></pre>
    </div>
</div>
<script>
let trendChart, vendorChart;
async function refreshData() {
    try {
        const snap = await fetch("/api/snapshot").then(r => r.json());
        const hist = await fetch("/api/history").then(r => r.json());
        const logs = await fetch("/api/log_tail").then(r => r.json());
        const sys = await fetch("/api/sys_info").then(r => r.json());

        updateStats(snap, sys);
        renderTable(snap.devices);
        updateCharts(hist.records, snap.devices);
        document.getElementById('log-output').textContent = logs.lines.join("\\n");
        document.getElementById('last-update').innerText = "Last Scan: " + snap.timestamp;
    } catch (e) { console.error("Sync Error:", e); }
}

function updateStats(snap, sys) {
    document.getElementById('stat-seen').innerText = snap.counts.seen;
    document.getElementById('stat-new').innerText = snap.counts.new || 0;
    const risk = snap.devices.some(d => (d.vulns||[]).length > 0) ? "CRITICAL" : "LOW";
    document.getElementById('stat-risk').innerText = risk;
    document.getElementById('stat-risk').style.color = risk === "CRITICAL" ? "var(--danger)" : "var(--success)";
    document.getElementById('stat-temp').innerText = sys.temp + "°C";
}

function renderTable(devices) {
    const query = document.getElementById('search').value.toLowerCase();
    const tbody = document.getElementById('device-table');
    tbody.innerHTML = devices.filter(d => d.ip.includes(query) || (d.mac||"").toLowerCase().includes(query) || (d.vendor||"").toLowerCase().includes(query))
        .map(d => {
            const hasVulns = (d.vulns || []).length > 0;
            return `
                <tr class="${hasVulns ? 'risk-high' : 'risk-low'}">
                    <td style="font-weight:700;">${d.ip}</td>
                    <td>${d.mac || 'N/A'}</td>
                    <td>${d.vendor || 'Unknown'}</td>
                    <td>${(d.ports || []).join(", ")}</td>
                    <td>${hasVulns ? '<span class="badge badge-danger">VULNERABLE</span>' : '<span class="badge badge-success">SECURE</span>'}</td>
                </tr>`;
        }).join('');
}
function updateCharts(history, devices) {
    const trendCtx = document.getElementById('trendChart').getContext('2d');
    if (trendChart) trendChart.destroy();
    trendChart = new Chart(trendCtx, {
        type: 'line',
        data: {
            labels: history.map(h => h.ts.split('T')[1].split('.')[0]),
            datasets: [{ label: 'Active Hosts', data: history.map(h => h.seen), borderColor: '#00f2ff', fill: true }]
        },
        options: { plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true } } }
    });
    const vendorCounts = devices.reduce((acc, d) => { const v = d.vendor || "Unknown"; acc[v] = (acc[v] || 0) + 1; return acc; }, {});
    const vendorCtx = document.getElementById('vendorChart').getContext('2d');
    if (vendorChart) vendorChart.destroy();
    vendorChart = new Chart(vendorCtx, {
        type: 'doughnut',
        data: { labels: Object.keys(vendorCounts), datasets: [{ data: Object.values(vendorCounts), backgroundColor: ['#00f2ff', '#00e676', '#ffab00', '#ff4d4d'] }] },
        options: { plugins: { legend: { position: 'bottom', labels: { color: '#8892b0' } } } }
    });
}
setInterval(refreshData, 5000);
refreshData();
</script>
</body>
</html>
"""

# ----------------------
# HELPER FUNCTIONS (The "Brain")
# ----------------------

def load_json(path: Path, default: Any) -> Any:
    try: return json.loads(path.read_text(encoding="utf-8"))
    except: return default

def save_json(path: Path, data: Any):
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")

def get_vendor(mac: str) -> str:
    """Uses Code 2's logic to find the vendor."""
    if not mac: return "Unknown"
    cache = load_json(VENDOR_CACHE_FILE, {})
    mac_prefix = mac[:8].upper()
    
    if mac_prefix in cache:
        return cache[mac_prefix]
    
    try:
        # Simple API lookup
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
        if r.status_code == 200:
            vendor = r.text.strip()
            cache[mac_prefix] = vendor
            save_json(VENDOR_CACHE_FILE, cache)
            return vendor
    except: pass
    return "Unknown"

def send_telegram(message: str):
    """Sends message to Telegram."""
    if not TELEGRAM["ENABLED"]: return
    url = f"https://api.telegram.org/bot{TELEGRAM['TOKEN']}/sendMessage"
    try:
        requests.post(url, json={"chat_id": TELEGRAM["CHAT_ID"], "text": message}, timeout=10)
        logging.info("Telegram Sent")
    except Exception as e:
        logging.error(f"Telegram Error: {e}")

# ----------------------
# BACKGROUND SCANNER LOOP
# ----------------------
def background_scanner():
    """Continuously scans and handles alerts."""
    last_report_date = None
    
    logging.info("Background Scanner Started...")

    while True:
        try:
            # 1. RUN NMAP
            cmd = ["nmap", "-sn", NETWORK_CIDR]
            res = subprocess.run(cmd, capture_output=True, text=True)
            
            devices = []
            for line in res.stdout.splitlines():
                if "Nmap scan report for" in line:
                    parts = line.split()
                    ip = parts[-1].strip("()")
                    current_device = {"ip": ip, "mac": None, "vendor": "Scanning...", "ports": [], "vulns": []}
                if "MAC Address:" in line:
                    mac = line.split("MAC Address:")[1].split("(")[0].strip()
                    current_device["mac"] = mac
                    current_device["vendor"] = get_vendor(mac)
                    devices.append(current_device)
                # If no MAC found (local device), add it anyway
                if "Nmap scan report" in line and not any(d['ip'] == ip for d in devices):
                     # Add simplified entry if it was the localhost or no MAC line appeared yet
                     pass 

            # Fix for localhost which has no MAC in nmap output
            if not devices:
                logging.warning("No devices found. Check sudo permissions.")

            # 2. SAVE SNAPSHOT
            snapshot = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "counts": {"seen": len(devices), "new": 0, "alert": 0},
                "devices": devices
            }
            save_json(SNAPSHOT_FILE, snapshot)

            # 3. UPDATE HISTORY
            with open(HISTORY_FILE, "a") as f:
                f.write(json.dumps({"seen": len(devices), "ts": datetime.now().isoformat()}) + "\n")

            # 4. DAILY TELEGRAM REPORT (5:00 AM)
            now = datetime.now()
            if now.hour == 5 and now.minute == 0:
                if last_report_date != now.date():
                    report = f"🌅 5AM DAILY REPORT\nDevices Online: {len(devices)}\nSystem Status: OK"
                    send_telegram(report)
                    last_report_date = now.date()

            time.sleep(60) # Scan every minute

        except Exception as e:
            logging.error(f"Scanner Loop Error: {e}")
            time.sleep(10)

# ----------------------
# FLASK ROUTES
# ----------------------
@app.route("/")
def home(): return render_template_string(HTML)

@app.route("/api/snapshot")
def api_snapshot(): return jsonify(load_json(SNAPSHOT_FILE, {"counts":{"seen":0},"devices":[]}))

@app.route("/api/history")
def api_history():
    recs = []
    if HISTORY_FILE.exists():
        lines = HISTORY_FILE.read_text().splitlines()[-50:]
        recs = [json.loads(line) for line in lines]
    return jsonify({"records": recs})

@app.route("/api/log_tail")
def api_log_tail():
    lines = LOG_FILE.read_text().splitlines()[-20:] if LOG_FILE.exists() else []
    return jsonify({"lines": lines})

@app.route("/api/sys_info")
def api_sys_info():
    temp = 0
    try:
        with open("/sys/class/thermal/thermal_zone0/temp", "r") as f:
            temp = round(int(f.read()) / 1000, 1)
    except: pass
    return jsonify({"cpu": psutil.cpu_percent(), "ram_perc": psutil.virtual_memory().percent, "temp": temp})

# ----------------------
# MAIN ENTRY POINT
# ----------------------
if __name__ == "__main__":
    # Check for Sudo (Crucial for MAC addresses)
    if os.geteuid() != 0:
        print("⚠️  WARNING: You are NOT running as root/sudo.")
        print("   Nmap will not detect MAC addresses or Vendors.")
        print("   Please restart with: sudo python3 dashboard.py")
    
    # Start the Scanner Thread
    t = threading.Thread(target=background_scanner, daemon=True)
    t.start()
    
    # Start the Web App
    app.run(host="0.0.0.0", port=APP_PORT, debug=False)
