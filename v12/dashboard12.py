#!/usr/bin/env python3
"""
SOC Pi v11.0 - "SOC Mode"
Real-SOC dashboard (no real-time messaging yet):
- Nmap discovery + deep profiling using XML parsing (reliable service/product/version extraction)
- Baseline + change detection: new device, offline, port/service changes, vendor/OS/hostname/risk changes
- Persistent Alerts (alerts.jsonl) + Alerts API + UI panel
- Device aliases/zones/notes (device_aliases.json)
- Exposure findings + recommendations (heuristics)
- Wi-Fi scan via `iw` (optional) + Bluetooth scan via `bluetoothctl` (optional) + events
- Charts/history/log tail/sysinfo + CSV export
"""

import csv
import io
import json
import logging
import os
import re
import socket
import subprocess
import threading
import time
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from xml.etree import ElementTree as ET

import psutil
import requests  # kept for vendor lookup (optional)
from flask import Flask, Response, jsonify, render_template_string

# ----------------------
# CONFIGURATION
# ----------------------
APP_PORT = int(os.getenv("SOCPI_PORT", "8080"))
NETWORK_CIDR = os.getenv("SOCPI_CIDR", "192.168.0.0/24")

SCAN_INTERVAL_SEC = int(os.getenv("SOCPI_SCAN_INTERVAL", "60"))
PROFILE_TTL_SEC = int(os.getenv("SOCPI_PROFILE_TTL", "300"))
NMAP_TOP_PORTS = int(os.getenv("SOCPI_TOP_PORTS", "50"))

OFFLINE_AFTER_SEC = int(os.getenv("SOCPI_OFFLINE_AFTER", "180"))

SNAPSHOT_FILE = Path(os.getenv("SOCPI_SNAPSHOT_FILE", "scan_snapshot.json"))
HISTORY_FILE = Path(os.getenv("SOCPI_HISTORY_FILE", "history.jsonl"))
LOG_FILE = Path(os.getenv("SOCPI_LOG_FILE", "network_monitor.log"))
VENDOR_CACHE_FILE = Path(os.getenv("SOCPI_VENDOR_CACHE", "vendor_cache.json"))

BASELINE_FILE = Path(os.getenv("SOCPI_BASELINE_FILE", "baseline.json"))
ALERTS_FILE = Path(os.getenv("SOCPI_ALERTS_FILE", "alerts.jsonl"))
ALIASES_FILE = Path(os.getenv("SOCPI_ALIASES_FILE", "device_aliases.json"))

# Optional Radio Sensors (DEFAULT ON per your request)
WIFI_ENABLED = os.getenv("SOCPI_WIFI_ENABLED", "true").lower() == "true"
WIFI_IFACE = os.getenv("SOCPI_WIFI_IFACE", "wlan0")
WIFI_SCAN_INTERVAL = int(os.getenv("SOCPI_WIFI_SCAN_INTERVAL", "30"))

BT_ENABLED = os.getenv("SOCPI_BT_ENABLED", "true").lower() == "true"
BT_SCAN_INTERVAL = int(os.getenv("SOCPI_BT_SCAN_INTERVAL", "30"))

# Risky ports (tune as you like)
RISKY_PORTS_CRITICAL = {"23", "2323", "3389", "5900", "445"}  # telnet, rdp, vnc, smb
RISKY_PORTS_MEDIUM = {"22", "21", "8080", "8443", "3306", "5432"}  # ssh/ftp/admin/db

# ----------------------
# LOGGING & APP
# ----------------------
logger = logging.getLogger("socpi")
logger.setLevel(logging.INFO)

_rot = RotatingFileHandler(LOG_FILE, maxBytes=2_000_000, backupCount=3)
_rot.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s"))
logger.addHandler(_rot)
logger.addHandler(logging.StreamHandler())

app = Flask(__name__)

# ----------------------
# STATE
# ----------------------
inventory_lock = threading.Lock()
device_inventory: Dict[str, Dict[str, Any]] = {}  # key: MAC if present else "IP:<ip>"

radio_lock = threading.Lock()
wifi_state: Dict[str, Any] = {"ts": "", "aps": []}
bt_state: Dict[str, Any] = {"ts": "", "devices": []}

scan_lock = threading.Lock()
scan_status: Dict[str, Any] = {"state": "IDLE", "last_start": "", "last_end": "", "last_err": ""}

# ----------------------
# UI (Dashboard)
# ----------------------
HTML = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>SOC Pi v11 | SOC Mode</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@300;500;700&display=swap" rel="stylesheet">
  <style>
    :root { --bg:#0b0e14; --card:#151921; --accent:#00f2ff; --text:#e0e6ed; --danger:#ff4d4d; --warn:#ffab00; --success:#00e676; --border:#2d343f; }
    * { box-sizing: border-box; }
    body { font-family:Inter,sans-serif; background:var(--bg); color:var(--text); margin:0; padding-bottom:42px; }
    header { background:var(--card); padding:10px 14px; border-bottom:2px solid var(--accent); display:flex; justify-content:space-between; align-items:center; gap:12px; position:sticky; top:0; z-index:100; }
    .lefthead h2 { margin:0; font-size:1.05rem; }
    .lefthead small { color:#8892b0; }
    .topbar { display:flex; gap:10px; align-items:center; flex-wrap:wrap; justify-content:flex-end; }
    .scan-status { display:flex; align-items:center; gap:8px; font-family:'JetBrains Mono'; font-size:.75rem; color:var(--accent); }
    .pulse { width:9px; height:9px; background:var(--accent); border-radius:50%; animation:blink 1.5s infinite; }
    @keyframes blink { 0%,100%{opacity:1; box-shadow:0 0 10px var(--accent);} 50%{opacity:.2;} }

    .pill { padding:3px 8px; border:1px solid var(--border); border-radius:999px; font-size:.72rem; color:#cbd5e1; font-family:'JetBrains Mono'; }
    .pill b { color: var(--accent); font-weight:700; }

    .btn { border:1px solid var(--border); background:#1e2530; color:var(--text); padding:7px 10px; border-radius:10px; font-family:'JetBrains Mono'; font-size:.75rem; cursor:pointer; text-decoration:none; }
    .btn:hover { border-color:var(--accent); }

    .container { padding:12px; max-width:1600px; margin:auto; }
    .grid { display:grid; grid-template-columns:repeat(auto-fit, minmax(220px, 1fr)); gap:12px; margin-bottom:12px; }
    .card { background:var(--card); border-radius:12px; padding:14px; border:1px solid var(--border); transition:.2s; }
    .card:hover { border-color:var(--accent); transform:translateY(-1px); }
    .stat-label { font-size:.72rem; text-transform:uppercase; color:#8892b0; letter-spacing:1px; }
    .stat-val { font-size:1.8rem; font-weight:700; color:var(--accent); font-family:'JetBrains Mono'; line-height:1.1; }

    .row { display:grid; grid-template-columns: 1.4fr .6fr; gap:12px; }
    @media (max-width: 980px){ .row { grid-template-columns: 1fr; } }
    @media (max-width: 520px){ header { padding:10px 10px; } .container { padding:10px; } .stat-val{ font-size:1.55rem; } }

    .table-container { background:var(--card); border-radius:12px; border:1px solid var(--border); overflow:hidden; }
    .filters { padding:12px; display:flex; gap:10px; background:#1e2530; position:sticky; top:56px; z-index:50; flex-wrap:wrap; }
    input, select { background:#1e2530; border:1px solid var(--border); color:white; padding:9px 10px; border-radius:10px; font-family:Inter; }
    input { flex: 1; min-width: 220px; }
    select { min-width: 170px; }

    table { width:100%; border-collapse:collapse; }
    th { background:#1e2530; padding:12px; text-align:left; font-size:.72rem; text-transform:uppercase; color:#8892b0; }
    td { padding:10px 12px; border-bottom:1px solid var(--border); font-family:'JetBrains Mono'; font-size:.83rem; vertical-align:top; }
    tr:hover { background:rgba(0,242,255,.04); cursor:pointer; }
    .risk-high { color:var(--danger); border-left:4px solid var(--danger); background:rgba(255,77,77,.03); }
    .risk-med { color:var(--warn); border-left:4px solid var(--warn); }
    .risk-low { border-left:4px solid var(--success); }

    .badge { padding:4px 8px; border-radius:6px; font-size:.7rem; font-weight:bold; display:inline-block; }
    .badge-danger { background:var(--danger); color:white; }
    .badge-warn { background:var(--warn); color:black; }
    .badge-success { background:var(--success); color:black; }

    .muted { color:#8892b0; font-family:Inter; font-size:.84rem; }
    .ports { color:#aab2c0; font-size:.78rem; font-family:'JetBrains Mono'; }

    .section-title { margin:0 0 10px 0; font-family:'JetBrains Mono'; font-size:.8rem; color:var(--success); }
    .compact { padding:12px; }

    pre { white-space: pre-wrap; word-wrap: break-word; }

    .modal { display:none; position:fixed; z-index:200; left:0; top:0; width:100%; height:100%; background:rgba(0,0,0,.85); backdrop-filter: blur(6px); }
    .modal-content { background:var(--card); margin:4% auto; padding:20px; width:min(900px, 92%); border-radius:15px; border:1px solid var(--accent); box-shadow:0 0 50px rgba(0,242,255,.15); }
    .close { float:right; font-size:22px; cursor:pointer; color:var(--danger); }
    .kv { display:grid; grid-template-columns: 1fr 2fr; gap:8px 14px; font-family:'JetBrains Mono'; font-size:.84rem; }
    .kv div:nth-child(odd) { color:#8892b0; }
    .list { margin:10px 0 0 0; padding-left:18px; font-family:'JetBrains Mono'; font-size:.82rem; color:#aab2c0; }
  </style>
</head>
<body>
<header>
  <div class="lefthead">
    <h2>SOC Pi <span style="font-weight:300; color:var(--accent);">v11.0</span></h2>
    <small id="last-update">Booting…</small>
  </div>

  <div class="topbar">
    <span class="pill">CPU <b id="h-cpu">0%</b></span>
    <span class="pill">RAM <b id="h-ram">0%</b></span>
    <span class="pill">TEMP <b id="h-temp">0°C</b></span>

    <a class="btn" href="/api/export.csv" target="_blank">Export CSV</a>
    <div class="scan-status"><div class="pulse"></div><span id="scan-state">IDLE</span></div>
  </div>
</header>

<div class="container">
  <div class="grid">
    <div class="card"><div class="stat-label">Total Devices</div><div class="stat-val" id="stat-seen">0</div></div>
    <div class="card"><div class="stat-label">New Devices</div><div class="stat-val" id="stat-new" style="color:var(--warn);">0</div></div>
    <div class="card"><div class="stat-label">Critical Devices</div><div class="stat-val" id="stat-crit" style="color:var(--danger);">0</div></div>
  </div>

  <div class="row">
    <div class="card compact">
      <h4 style="margin-top:0; margin-bottom:10px;">Device Trend (Last 50 Scans)</h4>
      <canvas id="trendChart" height="95"></canvas>
    </div>
    <div class="card compact">
      <h4 style="margin-top:0; margin-bottom:10px;">Vendor Distribution</h4>
      <canvas id="vendorChart" height="155"></canvas>
    </div>
  </div>

  <div class="row" style="margin-top:12px;">
    <div class="table-container">
      <div class="filters">
        <input type="text" id="search" placeholder="Filter by name, IP, MAC, vendor, OS, type, or port…">
        <select id="risk-filter">
          <option value="">All</option>
          <option value="critical">Critical</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="offline">Offline</option>
        </select>
      </div>
      <table>
        <thead>
          <tr>
            <th>IP</th>
            <th>Identity</th>
            <th>OS / Type</th>
            <th>Open Services</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody id="device-table"></tbody>
      </table>
    </div>

    <div>
      <div class="card compact">
        <h4 style="margin-top:0; margin-bottom:8px;">Radio Sensors</h4>
        <div class="muted" id="radio-meta">Wi-Fi/BT: loading…</div>

        <div style="margin-top:10px;">
          <div class="section-title">&gt;_ WIFI_APS</div>
          <div class="muted" id="wifi-list"></div>
        </div>

        <div style="margin-top:12px;">
          <div class="section-title">&gt;_ BLUETOOTH</div>
          <div class="muted" id="bt-list"></div>
        </div>
      </div>

      <div class="card" style="margin-top:12px; border-color:#333;">
        <h4 class="section-title" style="margin-top:0;">&gt;_ SYSTEM_LOG_OUTPUT</h4>
        <pre id="log-output" style="font-family:'JetBrains Mono'; font-size:.75rem; color:#aab2c0; max-height:170px; overflow-y:auto; margin:0;"></pre>
      </div>
    </div>
  </div>
</div>

<div id="modal" class="modal">
  <div class="modal-content">
    <span class="close" onclick="closeModal()">×</span>
    <h3 style="margin:0 0 6px 0;" id="m-title">Device</h3>
    <div class="muted" id="m-sub"></div>
    <hr style="border:0; border-top:1px solid var(--border); margin:12px 0;">
    <div class="kv" id="m-kv"></div>

    <div style="margin-top:16px;">
      <div class="section-title">&gt;_ EXPOSURES / FINDINGS</div>
      <ul class="list" id="m-findings"></ul>
    </div>

    <div style="margin-top:16px;">
      <div class="section-title">&gt;_ RECOMMENDATIONS</div>
      <ul class="list" id="m-recs"></ul>
    </div>

    <div style="margin-top:16px;">
      <div class="section-title">&gt;_ OPEN SERVICES</div>
      <ul class="list" id="m-ports"></ul>
    </div>
  </div>
</div>

<script>
let trendChart, vendorChart;
let lastSnapshot = null;

function badgeForState(d){
  if(d.state === "OFFLINE") return '<span class="badge badge-warn">OFFLINE</span>';
  if(d.risk === "CRITICAL") return '<span class="badge badge-danger">CRITICAL</span>';
  if(d.risk === "MEDIUM") return '<span class="badge badge-warn">MEDIUM</span>';
  return '<span class="badge badge-success">LOW</span>';
}
function riskClass(d){
  if(d.state === "OFFLINE") return "risk-med";
  if(d.risk === "CRITICAL") return "risk-high";
  if(d.risk === "MEDIUM") return "risk-med";
  return "risk-low";
}

function openModal(device){
  document.getElementById("modal").style.display = "block";
  document.getElementById("m-title").innerText = device.display_name || device.ip || "Device";
  document.getElementById("m-sub").innerText = `${device.ip || "N/A"} | ${device.mac || "N/A"} | ${device.vendor || "Unknown"}`;

  const kv = [
    ["Zone", device.zone || "Unassigned"],
    ["Owner", device.owner || ""],
    ["Type", device.type || "Unknown"],
    ["OS", device.os || "Unknown"],
    ["Hostname", device.hostname || ""],
    ["Risk", device.risk || "LOW"],
    ["State", device.state || "ONLINE"],
    ["First Seen", device.first_seen || ""],
    ["Last Seen", device.last_seen || ""],
  ];
  document.getElementById("m-kv").innerHTML = kv.map(([k,v]) => `<div>${k}</div><div>${(v||"").toString()}</div>`).join("");

  document.getElementById("m-findings").innerHTML = (device.findings || []).map(x => `<li>${x}</li>`).join("") || "<li>None</li>";
  document.getElementById("m-recs").innerHTML = (device.recommendations || []).map(x => `<li>${x}</li>`).join("") || "<li>None</li>";
  document.getElementById("m-ports").innerHTML = (device.services || []).map(s => `<li>${s}</li>`).join("") || "<li>None</li>";
}

function closeModal(){ document.getElementById("modal").style.display = "none"; }
window.onclick = function(e){ if(e.target === document.getElementById("modal")) closeModal(); }

function renderTable(devices) {
  const q = (document.getElementById('search').value || "").toLowerCase();
  const rf = document.getElementById('risk-filter').value;
  const tbody = document.getElementById('device-table');

  const filtered = devices.filter(d => {
    const hay = [
      d.display_name, d.alias, d.ip, d.mac, d.vendor, d.os, d.type, d.zone, d.owner,
      (d.services || []).join(" ")
    ].join(" ").toLowerCase();

    let riskOk = true;
    if(rf === "offline") riskOk = d.state === "OFFLINE";
    else if(rf === "critical") riskOk = d.risk === "CRITICAL" && d.state !== "OFFLINE";
    else if(rf === "medium") riskOk = d.risk === "MEDIUM" && d.state !== "OFFLINE";
    else if(rf === "low") riskOk = d.risk === "LOW" && d.state !== "OFFLINE";

    return hay.includes(q) && riskOk;
  });

  tbody.innerHTML = filtered.map(d => {
    const ports = (d.services || []).slice(0, 10).join(", ");
    const more = (d.services || []).length > 10 ? ` <span class="pill">+${(d.services||[]).length-10} more</span>` : "";
    return `
      <tr class="${riskClass(d)}" onclick='openModal(${JSON.stringify(d).replace(/</g,"\\u003c")})'>
        <td style="font-weight:700;">${d.ip || "N/A"}</td>
        <td>
          <div style="font-weight:700;">${d.display_name || d.ip || "Device"}</div>
          <div class="muted">${d.mac || "N/A"} | ${d.vendor || "Unknown"}</div>
          <div class="muted">Zone: ${d.zone || "Unassigned"} ${d.owner ? ("| Owner: " + d.owner) : ""}</div>
        </td>
        <td>
          <div style="font-weight:700;">${d.type || "Unknown"}</div>
          <div class="muted">${d.os || "Unknown OS"}</div>
          <div class="muted">${d.hostname ? ("Host: " + d.hostname) : ""}</div>
        </td>
        <td class="ports">${ports}${more}</td>
        <td>${badgeForState(d)}</td>
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
      labels: history.map(h => (h.ts || "").split('T')[1]?.split('.')[0] || ""),
      datasets: [{ label:'Active Hosts', data: history.map(h => h.seen || 0), borderColor:'#00f2ff', fill:true }]
    },
    options: { plugins:{ legend:{ display:false } }, scales:{ y:{ beginAtZero:true } } }
  });

  const vendorCounts = devices.reduce((acc, d) => {
    const v = d.vendor || "Unknown";
    acc[v] = (acc[v] || 0) + 1;
    return acc;
  }, {});
  const vendorCtx = document.getElementById('vendorChart').getContext('2d');
  if (vendorChart) vendorChart.destroy();
  vendorChart = new Chart(vendorCtx, {
    type: 'doughnut',
    data: { labels: Object.keys(vendorCounts), datasets: [{ data: Object.values(vendorCounts) }] },
    options: { plugins:{ legend:{ position:'bottom', labels:{ color:'#8892b0' } } } }
  });
}

function renderRadio(r){
  const meta = document.getElementById("radio-meta");
  meta.innerText = `Wi-Fi: ${r.wifi?.enabled ? "enabled" : "disabled"} (${r.wifi?.ts || "—"}) | BT: ${r.bt?.enabled ? "enabled" : "disabled"} (${r.bt?.ts || "—"})`;

  const wifiList = document.getElementById("wifi-list");
  const aps = r.wifi?.aps || [];
  wifiList.innerHTML = aps.length
    ? aps.slice(0,6).map(a => `<div style="font-family:JetBrains Mono; font-size:.8rem; margin-bottom:6px;">${a.ssid || "<hidden>"} <span class="pill">${a.bssid}</span> <span class="pill">${a.signal || ""}</span></div>`).join("")
    : `<div class="muted">No AP data.</div>`;

  const btList = document.getElementById("bt-list");
  const devs = r.bt?.devices || [];
  btList.innerHTML = devs.length
    ? devs.slice(0,6).map(d => `<div style="font-family:JetBrains Mono; font-size:.8rem; margin-bottom:6px;">${d.name || "Unknown"} <span class="pill">${d.mac}</span></div>`).join("")
    : `<div class="muted">No BT data.</div>`;
}

async function refreshFast() {
  try {
    const sys = await fetch("/api/sys_info").then(r => r.json());
    const logs = await fetch("/api/log_tail").then(r => r.json());
    const radio = await fetch("/api/radio").then(r => r.json());
    const status = await fetch("/api/status").then(r => r.json());

    document.getElementById('h-cpu').innerText = (sys.cpu ?? 0) + "%";
    document.getElementById('h-ram').innerText = (sys.ram_perc ?? 0) + "%";
    document.getElementById('h-temp').innerText = (sys.temp ?? 0) + "°C";

    document.getElementById('log-output').textContent = (logs.lines || []).join("\n");
    document.getElementById('scan-state').innerText = status.state || "IDLE";
    renderRadio(radio);
  } catch (e) { /* ignore */ }
}

async function refreshSlow() {
  try {
    const snap = await fetch("/api/snapshot").then(r => r.json());
    const hist = await fetch("/api/history").then(r => r.json());
    const status = await fetch("/api/status").then(r => r.json());

    lastSnapshot = snap;

    document.getElementById('stat-seen').innerText = snap.counts?.seen || 0;
    document.getElementById('stat-new').innerText  = snap.counts?.new || 0;
    document.getElementById('stat-crit').innerText = snap.counts?.critical || 0;

    document.getElementById('last-update').innerText =
      `Last Scan: ${snap.timestamp || "N/A"} | Subnet: ${snap.subnet || "N/A"} | scan=${status.scan_interval || "?"}s`;

    renderTable(snap.devices || []);
    updateCharts(hist.records || [], snap.devices || []);
  } catch (e) { console.error("Slow sync error:", e); }
}

setInterval(refreshFast, 1000);
setInterval(refreshSlow, 3000);
refreshFast();
refreshSlow();

document.getElementById('search').addEventListener('input', refreshSlow);
document.getElementById('risk-filter').addEventListener('change', refreshSlow);
</script>
</body>
</html>
"""

# ----------------------
# UTIL: JSON + TIME
# ----------------------
def load_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def save_json(path: Path, data: Any):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def now_ts() -> str:
    return datetime.now().isoformat(timespec="seconds")


# ----------------------
# ALERTS / EVENTS
# ----------------------
def emit_event(kind: str, severity: str, title: str, details: Optional[dict] = None):
    evt = {
        "ts": now_ts(),
        "kind": kind,
        "severity": severity,  # INFO / MEDIUM / CRITICAL
        "title": title,
        "details": details or {},
    }
    logger.info(f"EVENT {severity} {kind}: {title} | {evt['details']}")
    ALERTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(ALERTS_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(evt) + "\n")


def tail_events(limit: int = 25) -> List[dict]:
    if not ALERTS_FILE.exists():
        return []
    lines = ALERTS_FILE.read_text(encoding="utf-8").splitlines()[-limit:]
    out = []
    for ln in reversed(lines):
        try:
            out.append(json.loads(ln))
        except Exception:
            pass
    return out


# ----------------------
# ALIASES (friendly names / zones)
# ----------------------
def load_aliases() -> Dict[str, dict]:
    data = load_json(ALIASES_FILE, {})
    return data if isinstance(data, dict) else {}


def apply_alias(key: str, d: dict, aliases: Dict[str, dict]) -> dict:
    a = aliases.get(key) or {}
    if d.get("mac"):
        a = a or aliases.get(d["mac"].upper(), {}) or aliases.get(d["mac"].lower(), {}) or {}
    name = a.get("name") or a.get("alias") or ""
    d["alias"] = name
    d["zone"] = a.get("zone", "")
    d["owner"] = a.get("owner", "")
    d["notes"] = a.get("notes", "")
    d["display_name"] = name or d.get("hostname") or d.get("ip") or "Device"
    return d


# ----------------------
# VENDOR LOOKUP (cached; optional)
# ----------------------
def get_vendor(mac: str) -> str:
    if not mac:
        return "Unknown"
    cache = load_json(VENDOR_CACHE_FILE, {})
    mac_prefix = mac[:8].upper()
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
# DEVICE TYPE + RISK + FINDINGS
# ----------------------
def identify_device_type(vendor: str, os_guess: str, hostname: str, open_ports: List[str]) -> str:
    vendor_u = (vendor or "Unknown").upper()
    os_l = (os_guess or "Unknown").lower()
    hn_l = (hostname or "").lower()
    port_set = set(open_ports)

    if "RASPBERRY" in vendor_u or re.search(r"\bpi\b", hn_l):
        return "Raspberry Pi"
    if "APPLE" in vendor_u:
        if "62078" in port_set:
            return "iPhone/iPad (Locked)"
        if "darwin" in os_l or "mac os" in os_l or "macos" in os_l:
            return "Mac (iMac/MacBook)"
        return "Apple Device"
    tv_vendors = ["SAMSUNG", "LG", "SONY", "VIZIO", "PANASONIC", "HISENSE", "TCL"]
    if any(v in vendor_u for v in tv_vendors):
        return "Smart TV"
    if port_set.intersection({"8008", "8009", "1900", "554", "2869"}):
        return "Smart TV / Media Player"
    if "windows" in os_l:
        return "Windows Device"
    if "linux" in os_l:
        if "22" in port_set:
            return "Linux Server / SBC"
        return "Linux Device"
    return "Unknown Device"


def compute_risk(open_ports: List[str], os_guess: str, state: str) -> str:
    if state == "OFFLINE":
        return "MEDIUM"
    ps = set(open_ports)
    if ps & RISKY_PORTS_CRITICAL:
        return "CRITICAL"
    if ps & RISKY_PORTS_MEDIUM:
        return "MEDIUM"
    if (os_guess or "").strip().lower() in ("", "unknown"):
        return "MEDIUM"
    return "LOW"


def build_findings_and_recs(open_ports: List[str], services: List[dict], os_guess: str) -> Tuple[List[str], List[str]]:
    findings: List[str] = []
    recs: List[str] = []
    port_set = set(open_ports)

    if "23" in port_set or "2323" in port_set:
        findings.append("Telnet exposed (unencrypted remote access).")
        recs.append("Disable Telnet; use SSH with keys and restrict by firewall.")
    if "445" in port_set:
        findings.append("SMB exposed (port 445).")
        recs.append("Restrict SMB to trusted subnets; disable SMBv1; patch Windows/Samba.")
    if "3389" in port_set:
        findings.append("RDP exposed (port 3389).")
        recs.append("Restrict RDP via firewall/VPN; enable NLA; enforce MFA if possible.")
    if "5900" in port_set:
        findings.append("VNC exposed (port 5900).")
        recs.append("Restrict VNC to LAN/VPN; require strong auth; prefer SSH tunneling.")

    if "22" in port_set:
        findings.append("SSH exposed.")
        recs.append("Use key-based auth, disable password auth, limit users, and rate-limit.")
    if "21" in port_set:
        findings.append("FTP exposed (often plaintext).")
        recs.append("Prefer SFTP/FTPS; disable FTP if not required.")
    if "3306" in port_set or "5432" in port_set:
        findings.append("Database port exposed (MySQL/Postgres).")
        recs.append("Bind DB to localhost or trusted subnet; require auth; firewall the port.")
    if "80" in port_set or "8080" in port_set or "8443" in port_set:
        findings.append("HTTP/admin web port exposed (possible management UI).")
        recs.append("Disable unused admin UIs; enforce auth; patch; restrict access by IP/VLAN.")

    if (os_guess or "").strip().lower() in ("", "unknown"):
        findings.append("OS fingerprint is unknown (could be blocked or unusual).")
        recs.append("Enable ICMP responses (if appropriate) and allow Nmap OS detection internally; verify device manually.")

    for s in services:
        prod = (s.get("product") or "").strip()
        ver = (s.get("version") or "").strip()
        if prod and ver:
            findings.append(f"Service detected: {prod} {ver} ({s.get('port')}/{s.get('proto')}).")

    findings = list(dict.fromkeys(findings))
    recs = list(dict.fromkeys(recs))
    return findings, recs


# ----------------------
# NMAP RUN + PARSE (XML)
# ----------------------
def have_cmd(cmd: str) -> bool:
    from shutil import which
    return which(cmd) is not None


def run_cmd(cmd: List[str], timeout: int = 120) -> Tuple[int, str, str]:
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return res.returncode, res.stdout, res.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:
        return 1, "", str(e)


def nmap_discovery_xml(cidr: str) -> List[dict]:
    rc, out, err = run_cmd(["nmap", "-sn", "-oX", "-", cidr], timeout=180)
    if rc != 0:
        logger.warning(f"Discovery nmap error code={rc}: {err[:200]}")
        return []

    hosts: List[dict] = []
    try:
        root = ET.fromstring(out)
        for h in root.findall("host"):
            status = h.find("status")
            if status is None or status.attrib.get("state") != "up":
                continue

            ip = ""
            mac = None
            vendor = "Unknown"
            for addr in h.findall("address"):
                if addr.attrib.get("addrtype") == "ipv4":
                    ip = addr.attrib.get("addr", "")
                if addr.attrib.get("addrtype") == "mac":
                    mac = addr.attrib.get("addr")
                    vendor = addr.attrib.get("vendor", vendor) or vendor

            hostname = ""
            hn = h.find("hostnames")
            if hn is not None:
                hne = hn.find("hostname")
                if hne is not None:
                    hostname = hne.attrib.get("name", "")

            if ip:
                hosts.append({"ip": ip, "mac": mac, "vendor": vendor, "hostname": hostname})
    except Exception as e:
        logger.error(f"Discovery XML parse failed: {e}")
        return []
    return hosts


def nmap_profile_xml(ip: str) -> dict:
    cmd = ["nmap", "-O", "-sV", "--top-ports", str(NMAP_TOP_PORTS), "-T4", "-oX", "-", ip]
    rc, out, err = run_cmd(cmd, timeout=240)
    if rc != 0:
        logger.warning(f"Profile nmap {ip} error code={rc}: {err[:200]}")
        return {"mac": None, "vendor": "Unknown", "hostname": "", "os": "Unknown", "ports": [], "services": []}

    mac = None
    vendor = "Unknown"
    hostname = ""
    os_guess = "Unknown"
    open_ports: List[str] = []
    services: List[dict] = []

    try:
        root = ET.fromstring(out)
        h0 = root.find("host")
        if h0 is not None:
            hn = h0.find("hostnames")
            if hn is not None:
                hne = hn.find("hostname")
                if hne is not None:
                    hostname = hne.attrib.get("name", "") or ""

            for addr in h0.findall("address"):
                if addr.attrib.get("addrtype") == "mac":
                    mac = addr.attrib.get("addr")
                    vendor = addr.attrib.get("vendor", vendor) or vendor

            os_el = h0.find("os")
            if os_el is not None:
                best = None
                best_acc = -1
                for m in os_el.findall("osmatch"):
                    acc = int(m.attrib.get("accuracy", "0"))
                    if acc > best_acc:
                        best_acc = acc
                        best = m.attrib.get("name", "")
                if best:
                    os_guess = best

            ports_el = h0.find("ports")
            if ports_el is not None:
                for p in ports_el.findall("port"):
                    proto = p.attrib.get("protocol", "tcp")
                    portid = p.attrib.get("portid", "")
                    st = p.find("state")
                    if st is None or st.attrib.get("state") != "open":
                        continue
                    open_ports.append(portid)

                    svc = p.find("service")
                    svc_name = (svc.attrib.get("name") if svc is not None else "") or ""
                    product = (svc.attrib.get("product") if svc is not None else "") or ""
                    version = (svc.attrib.get("version") if svc is not None else "") or ""
                    extrainfo = (svc.attrib.get("extrainfo") if svc is not None else "") or ""

                    services.append({
                        "port": portid,
                        "proto": proto,
                        "name": svc_name,
                        "product": product,
                        "version": version,
                        "extrainfo": extrainfo
                    })
    except Exception as e:
        logger.error(f"Profile XML parse failed for {ip}: {e}")

    return {
        "mac": mac,
        "vendor": vendor,
        "hostname": hostname,
        "os": os_guess or "Unknown",
        "ports": open_ports,
        "services": services
    }


def reverse_dns(ip: str) -> str:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return ""


# ----------------------
# BASELINE + DIFF
# ----------------------
def load_baseline() -> Dict[str, dict]:
    data = load_json(BASELINE_FILE, {})
    return data if isinstance(data, dict) else {}


def save_baseline(b: Dict[str, dict]):
    save_json(BASELINE_FILE, b)


def make_key(ip: str, mac: Optional[str]) -> str:
    return mac.upper() if mac else f"IP:{ip}"


def service_strings(services: List[dict]) -> List[str]:
    out = []
    for s in services:
        bits = [f"{s.get('port')}/{s.get('proto')}", s.get("name", "")]
        pv = " ".join([s.get("product", ""), s.get("version", "")]).strip()
        if pv:
            bits.append(pv)
        if s.get("extrainfo"):
            bits.append(f"({s['extrainfo']})")
        out.append(" ".join([b for b in bits if b]).strip())
    return out


def diff_and_emit_events(key: str, curr: dict, prev: Optional[dict]):
    if prev is None:
        emit_event(
            kind="NEW_DEVICE",
            severity=curr.get("risk", "INFO"),
            title=f"New device: {curr.get('display_name')}",
            details={"ip": curr.get("ip"), "mac": curr.get("mac"), "vendor": curr.get("vendor"), "zone": curr.get("zone")}
        )
        return

    if prev.get("state") != curr.get("state"):
        sev = "MEDIUM" if curr.get("state") == "OFFLINE" else "INFO"
        emit_event(
            kind="STATE_CHANGE",
            severity=sev,
            title=f"{curr.get('display_name')} is now {curr.get('state')}",
            details={"ip": curr.get("ip"), "mac": curr.get("mac"), "from": prev.get("state"), "to": curr.get("state")}
        )

    if prev.get("risk") != curr.get("risk") and curr.get("state") != "OFFLINE":
        sev = "CRITICAL" if curr.get("risk") == "CRITICAL" else "MEDIUM"
        emit_event(
            kind="RISK_CHANGE",
            severity=sev,
            title=f"Risk changed for {curr.get('display_name')}: {prev.get('risk')} → {curr.get('risk')}",
            details={"ip": curr.get("ip"), "mac": curr.get("mac")}
        )

    prev_ports = set(prev.get("ports", []))
    curr_ports = set(curr.get("ports", []))
    if prev_ports != curr_ports and curr.get("state") != "OFFLINE":
        added = sorted(curr_ports - prev_ports)
        removed = sorted(prev_ports - curr_ports)
        sev = "CRITICAL" if set(added) & RISKY_PORTS_CRITICAL else "MEDIUM"
        emit_event(
            kind="PORT_CHANGE",
            severity=sev,
            title=f"Port change on {curr.get('display_name')}",
            details={"ip": curr.get("ip"), "mac": curr.get("mac"), "added": added, "removed": removed}
        )

    if prev.get("vendor") and curr.get("vendor") and prev.get("vendor") != curr.get("vendor"):
        emit_event(
            kind="VENDOR_CHANGE",
            severity="MEDIUM",
            title=f"Vendor changed for {curr.get('display_name')}",
            details={"ip": curr.get("ip"), "mac": curr.get("mac"), "from": prev.get("vendor"), "to": curr.get("vendor")}
        )

    if (prev.get("hostname") or "") != (curr.get("hostname") or "") and curr.get("hostname"):
        emit_event(
            kind="HOSTNAME_CHANGE",
            severity="INFO",
            title=f"Hostname changed for {curr.get('display_name')}",
            details={"ip": curr.get("ip"), "mac": curr.get("mac"), "from": prev.get("hostname"), "to": curr.get("hostname")}
        )

    if (prev.get("os") or "") != (curr.get("os") or "") and curr.get("os") not in ("", "Unknown"):
        emit_event(
            kind="OS_CHANGE",
            severity="MEDIUM",
            title=f"OS fingerprint changed for {curr.get('display_name')}",
            details={"ip": curr.get("ip"), "mac": curr.get("mac"), "from": prev.get("os"), "to": curr.get("os")}
        )


# ----------------------
# RADIO SENSORS (Wi-Fi / BT)
# ----------------------
def wifi_scan_iw(iface: str) -> List[dict]:
    if not have_cmd("iw"):
        return []
    rc, out, _ = run_cmd(["iw", "dev", iface, "scan"], timeout=40)
    if rc != 0:
        return []

    aps: List[dict] = []
    bssid = None
    ssid = None
    signal = None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("BSS "):
            if bssid:
                aps.append({"bssid": bssid, "ssid": ssid or "", "signal": signal or ""})
            bssid = line.split()[1].split("(")[0]
            ssid = ""
            signal = ""
        elif line.startswith("SSID:"):
            ssid = line.split("SSID:", 1)[1].strip()
        elif "signal:" in line:
            parts = line.split("signal:", 1)[1].strip()
            signal = parts.split()[0] + " dBm" if parts else ""
    if bssid:
        aps.append({"bssid": bssid, "ssid": ssid or "", "signal": signal or ""})

    seen = set()
    uniq = []
    for a in aps:
        if a["bssid"] in seen:
            continue
        seen.add(a["bssid"])
        uniq.append(a)
    return uniq


def bt_scan_bluetoothctl() -> List[dict]:
    if not have_cmd("bluetoothctl"):
        return []
    run_cmd(["bluetoothctl", "--timeout", "8", "scan", "on"], timeout=15)
    rc, out, _ = run_cmd(["bluetoothctl", "devices"], timeout=15)
    if rc != 0:
        return []

    devs = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("Device "):
            continue
        parts = line.split()
        if len(parts) >= 3:
            mac = parts[1].strip()
            name = " ".join(parts[2:]).strip()
            devs.append({"mac": mac, "name": name})
    return devs


def radio_thread():
    logger.info(f"Radio thread started (Wi-Fi={WIFI_ENABLED}, BT={BT_ENABLED})")
    prev_wifi_bssids = set()
    prev_bt_macs = set()
    next_wifi = 0.0
    next_bt = 0.0

    while True:
        t = time.time()
        try:
            if WIFI_ENABLED and t >= next_wifi:
                aps = wifi_scan_iw(WIFI_IFACE)
                ts = now_ts()
                with radio_lock:
                    wifi_state["ts"] = ts
                    wifi_state["aps"] = aps

                bssids = {a["bssid"] for a in aps}
                new = sorted(bssids - prev_wifi_bssids)
                if new:
                    emit_event("WIFI_NEW_AP", "INFO", f"New Wi-Fi AP(s) detected: {len(new)}", {"bssids": new[:20]})
                prev_wifi_bssids = bssids
                next_wifi = t + max(30, WIFI_SCAN_INTERVAL)

            if BT_ENABLED and t >= next_bt:
                devs = bt_scan_bluetoothctl()
                ts = now_ts()
                with radio_lock:
                    bt_state["ts"] = ts
                    bt_state["devices"] = devs

                macs = {d["mac"] for d in devs}
                new = sorted(macs - prev_bt_macs)
                if new:
                    emit_event("BT_NEW_DEVICE", "INFO", f"New Bluetooth device(s) detected: {len(new)}", {"macs": new[:20]})
                prev_bt_macs = macs
                next_bt = t + max(30, BT_SCAN_INTERVAL)

        except Exception as e:
            logger.error(f"Radio thread error: {e}")

        time.sleep(5)


# ----------------------
# SCANNER LOOP
# ----------------------
def background_scanner():
    logger.info(
        f"Starting SOC Pi v11 scanner on {NETWORK_CIDR} "
        f"(scan={SCAN_INTERVAL_SEC}s, profile_ttl={PROFILE_TTL_SEC}s, offline_after={OFFLINE_AFTER_SEC}s)"
    )

    baseline = load_baseline()
    aliases = load_aliases()

    while True:
        start_ts = time.time()
        now = datetime.now()

        # mark scanning start
        with scan_lock:
            scan_status["state"] = "SCANNING"
            scan_status["last_start"] = now_ts()
            scan_status["last_err"] = ""

        last_err: str = ""

        try:
            discovered = nmap_discovery_xml(NETWORK_CIDR)
            new_devices = 0
            critical_devices = 0

            # NOTE: do not force state here; OFFLINE detection happens later via last_seen_epoch

            for host in discovered:
                ip = host["ip"]
                disc_mac = host.get("mac")
                disc_vendor = host.get("vendor") or "Unknown"
                disc_hostname = host.get("hostname") or ""

                key_guess = make_key(ip, disc_mac)

                # decide whether to re-profile
                existing = None
                do_profile = True
                with inventory_lock:
                    existing = device_inventory.get(key_guess)
                    if existing:
                        last_prof = existing.get("last_profile_epoch", 0.0)
                        do_profile = (time.time() - last_prof) >= PROFILE_TTL_SEC

                prof = {
                    "mac": disc_mac,
                    "vendor": disc_vendor,
                    "hostname": disc_hostname,
                    "os": "Unknown",
                    "ports": [],
                    "services": [],
                }

                if do_profile:
                    logger.info(f"Profiling {ip} (XML)…")
                    prof.update(nmap_profile_xml(ip))
                else:
                    # reuse previous profile data
                    if existing:
                        prof["os"] = existing.get("os", "Unknown")
                        prof["ports"] = existing.get("ports", [])
                        prof["services"] = existing.get("services_raw", [])
                        prof["hostname"] = existing.get("hostname", disc_hostname) or disc_hostname

                # hostname enrichment
                if not prof.get("hostname"):
                    rdns = reverse_dns(ip)
                    if rdns:
                        prof["hostname"] = rdns

                # vendor enrichment if unknown
                vendor_final = prof.get("vendor") or disc_vendor or "Unknown"
                mac_final = prof.get("mac")
                if (vendor_final.strip().lower() in ("unknown", "unknown vendor", "")) and mac_final:
                    vendor_final = get_vendor(mac_final)

                open_ports = prof.get("ports", []) or []
                services_raw = prof.get("services", []) or []
                services_str = service_strings(services_raw)

                state = "ONLINE"
                dev_type = identify_device_type(vendor_final, prof.get("os", "Unknown"), prof.get("hostname", ""), open_ports)
                risk = compute_risk(open_ports, prof.get("os", "Unknown"), state)
                if risk == "CRITICAL":
                    critical_devices += 1

                findings, recs = build_findings_and_recs(open_ports, services_raw, prof.get("os", "Unknown"))

                key = make_key(ip, mac_final)

                baseline_prev = baseline.get(key)
                first_seen = baseline_prev.get("first_seen") if baseline_prev else None
                if not first_seen:
                    first_seen = now.strftime("%Y-%m-%d %H:%M:%S")
                    new_devices += 1

                device = {
                    "key": key,
                    "ip": ip,
                    "mac": mac_final,
                    "vendor": vendor_final,
                    "hostname": prof.get("hostname") or "",
                    "os": prof.get("os") or "Unknown",
                    "type": dev_type,
                    "state": "ONLINE",
                    "risk": risk,
                    "ports": open_ports,
                    "services_raw": services_raw,
                    "services": services_str,
                    "findings": findings,
                    "recommendations": recs,
                    "first_seen": first_seen,
                    "last_seen": now.strftime("%H:%M:%S"),
                    "last_seen_epoch": time.time(),
                    "last_profile_epoch": (time.time() if do_profile else (existing.get("last_profile_epoch", time.time()) if existing else time.time())),
                }

                device = apply_alias(key, device, aliases)

                with inventory_lock:
                    device_inventory[key] = device

                diff_and_emit_events(key, device, baseline_prev)

                baseline[key] = {
                    "key": key,
                    "mac": mac_final,
                    "vendor": vendor_final,
                    "hostname": device.get("hostname", ""),
                    "os": device.get("os", "Unknown"),
                    "type": dev_type,
                    "risk": risk,
                    "state": "ONLINE",
                    "ports": open_ports,
                    "first_seen": first_seen,
                    "last_seen": now.strftime("%Y-%m-%d %H:%M:%S"),
                    "last_seen_epoch": time.time(),
                    "zone": device.get("zone", ""),
                    "owner": device.get("owner", ""),
                    "alias": device.get("alias", ""),
                }

            # OFFLINE detection
            with inventory_lock:
                for k, d in device_inventory.items():
                    last_epoch = d.get("last_seen_epoch", 0.0)
                    if (time.time() - last_epoch) >= OFFLINE_AFTER_SEC:
                        if d.get("state") != "OFFLINE":
                            d["state"] = "OFFLINE"
                            prev = baseline.get(k, {})
                            curr = {
                                **prev,
                                "state": "OFFLINE",
                                "display_name": d.get("display_name", d.get("ip", "Device")),
                                "ip": d.get("ip"),
                                "mac": d.get("mac"),
                            }
                            diff_and_emit_events(k, curr, prev if prev else None)
                            if k in baseline:
                                baseline[k]["state"] = "OFFLINE"

            save_baseline(baseline)

            with inventory_lock:
                devices_list = list(device_inventory.values())

            # enforce OFFLINE risk adjust
            for d in devices_list:
                if d.get("state") == "OFFLINE":
                    d["risk"] = "MEDIUM"

            devices_list.sort(key=lambda d: (d.get("state") == "OFFLINE", d.get("ip", "")))

            snapshot = {
                "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
                "subnet": NETWORK_CIDR,
                "offline_after": OFFLINE_AFTER_SEC,
                "counts": {
                    "seen": len(devices_list),
                    "new": new_devices,
                    "critical": sum(1 for d in devices_list if d.get("risk") == "CRITICAL" and d.get("state") != "OFFLINE"),
                },
                "devices": devices_list,
            }
            save_json(SNAPSHOT_FILE, snapshot)

            HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(HISTORY_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "seen": snapshot["counts"]["seen"],
                    "new": snapshot["counts"]["new"],
                    "critical": snapshot["counts"]["critical"],
                    "ts": now.isoformat()
                }) + "\n")

        except Exception as e:
            last_err = str(e)[:200]
            logger.error(f"Scanner loop error: {e}")

        finally:
            with scan_lock:
                scan_status["state"] = "IDLE"
                scan_status["last_end"] = now_ts()
                scan_status["last_err"] = last_err

            elapsed = time.time() - start_ts
            time.sleep(max(3, SCAN_INTERVAL_SEC - int(elapsed)))


# ----------------------
# FLASK ROUTES
# ----------------------
@app.route("/")
def home():
    return render_template_string(HTML)


@app.route("/api/snapshot")
def api_snapshot():
    default = {"timestamp": "", "subnet": NETWORK_CIDR, "offline_after": OFFLINE_AFTER_SEC,
               "counts": {"seen": 0, "new": 0, "critical": 0}, "devices": []}
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


@app.route("/api/status")
def api_status():
    with scan_lock:
        s = dict(scan_status)
    return jsonify({
        **s,
        "scan_interval": SCAN_INTERVAL_SEC,
        "profile_ttl": PROFILE_TTL_SEC,
        "offline_after": OFFLINE_AFTER_SEC
    })


@app.route("/api/alerts")
def api_alerts():
    try:
        limit = int(os.getenv("SOCPI_ALERTS_LIMIT", "25"))
    except Exception:
        limit = 25
    try:
        from flask import request
        limit = int(request.args.get("limit", limit))
    except Exception:
        pass
    return jsonify({"events": tail_events(max(1, min(200, limit)))})


@app.route("/api/radio")
def api_radio():
    with radio_lock:
        w = dict(wifi_state)
        b = dict(bt_state)
    return jsonify({
        "wifi": {"enabled": WIFI_ENABLED, **w},
        "bt": {"enabled": BT_ENABLED, **b}
    })


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


@app.route("/api/export.csv")
def api_export_csv():
    snap = load_json(SNAPSHOT_FILE, {"devices": []})
    devices = snap.get("devices", [])

    output = io.StringIO()
    w = csv.writer(output)
    w.writerow(["display_name", "ip", "mac", "vendor", "hostname", "os", "type", "zone", "owner", "state", "risk", "ports", "services"])
    for d in devices:
        w.writerow([
            d.get("display_name", ""),
            d.get("ip", ""),
            d.get("mac", ""),
            d.get("vendor", ""),
            d.get("hostname", ""),
            d.get("os", ""),
            d.get("type", ""),
            d.get("zone", ""),
            d.get("owner", ""),
            d.get("state", ""),
            d.get("risk", ""),
            " ".join(d.get("ports", []) or []),
            " | ".join(d.get("services", []) or []),
        ])
    return Response(output.getvalue(), mimetype="text/csv")


# ----------------------
# MAIN
# ----------------------
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("⚠️  WARNING: Not running as root/sudo.")
        print("   Nmap OS detection + MAC vendor visibility + iw scans may be reduced.")
        print("   Recommended: sudo python3 dashboard.py")

    if not have_cmd("nmap"):
        raise SystemExit("nmap is not installed. Install it: sudo apt-get install -y nmap")

    t = threading.Thread(target=background_scanner, daemon=True)
    t.start()

    if WIFI_ENABLED or BT_ENABLED:
        rt = threading.Thread(target=radio_thread, daemon=True)
        rt.start()

    app.run(host="0.0.0.0", port=APP_PORT, debug=False)
