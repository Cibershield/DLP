#!/usr/bin/env python3
"""
Consola DLP - Surveillance Center con MS Entra ID & GitHub API
"""

import json
import socket
import threading
import logging
import time
import os
import requests
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Set
from dataclasses import dataclass
from collections import deque
from functools import wraps

from flask import Flask, render_template_string, jsonify, Response, redirect, url_for, session, request
from flask_cors import CORS
from flask_session import Session  # Requires: pip install Flask-Session
import msal  # Requires: pip install msal

# --- CONFIGURACIÓN ---
CONSOLE_CONFIG = {
    "tcp_port": 5555,
    "web_port": 8080,
    "max_events": 2000,
    "log_file": "console.log"
}

# SECRETOS (Deberían ser variables de entorno en producción)
# Rellena estos valores para activar las funcionalidades reales
SECRETS = {
    # Microsoft Entra ID (Azure AD)
    "CLIENT_ID": os.getenv("AZURE_CLIENT_ID", "ENTER_YOUR_CLIENT_ID"),
    "CLIENT_SECRET": os.getenv("AZURE_CLIENT_SECRET", "ENTER_YOUR_CLIENT_SECRET"),
    "TENANT_ID": os.getenv("AZURE_TENANT_ID", "ENTER_YOUR_TENANT_ID"),
    "AUTHORITY": f"https://login.microsoftonline.com/{os.getenv('AZURE_TENANT_ID', 'common')}",
    "REDIRECT_PATH": "/getAToken",
    "SCOPE": ["User.Read"],
    
    # GitHub API
    "GITHUB_TOKEN": os.getenv("GITHUB_TOKEN", "ENTER_YOUR_GITHUB_TOKEN"), 
    "GITHUB_ORG": os.getenv("GITHUB_ORG", "Cibershield") # O el usuario/org a monitorear
}

# Whitelist de usuarios autorizados
AUTHORIZED_USERS = ["Gabriel Umana", "Luis Mercado"]

# --- ESTADO GLOBAL ---
events_store: deque = deque(maxlen=CONSOLE_CONFIG["max_events"])
events_lock = threading.Lock()

stats = {
    "total_events": 0,
    "blocked_events": 0,
    "allowed_events": 0,
    "unique_users": set(),
    "unique_hosts": set(),
    "git_commands": 0,
    "network_connections": 0,
    "delfix_events": 0,
    "compliance_violations": 0,
    "critical_alerts": 0
}

agent_metrics: Dict[str, Dict] = {}

# Datos de GitHub (cache en memoria)
github_data = {
    "repos_count": 0,
    "public_repos": 0,
    "last_sync": None,
    "status": "Offline",  # Offline, Syncing, Online, Error
    "top_repos": []
}

# --- FLASK APP ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("FLASK_SECRET_KEY", "super-secret-key-change-me")
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)
CORS(app)

# Template HTML dashboard
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CiberShield DLP - Surveillance Center</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&family=Fira+Code:wght@400;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-dark: #09090b;
            --bg-panel: #18181b;
            --primary: #3b82f6;
            --primary-glow: rgba(59, 130, 246, 0.5);
            --danger: #ef4444;
            --success: #10b981;
            --warning: #f59e0b;
            --text-main: #e4e4e7;
            --text-muted: #a1a1aa;
            --border: #27272a;
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Outfit', sans-serif;
            background: var(--bg-dark);
            color: var(--text-main);
            min-height: 100vh;
            overflow-x: hidden;
        }
        
        /* Layout Grid */
        .dashboard-container {
            display: grid;
            grid-template-columns: 280px 1fr;
            height: 100vh;
        }
        
        /* Sidebar */
        .sidebar {
            background: var(--bg-panel);
            border-right: 1px solid var(--border);
            padding: 24px;
            display: flex;
            flex-direction: column;
            gap: 30px;
        }
        
        .brand {
            font-size: 1.5rem;
            font-weight: 700;
            color: white;
            display: flex;
            align-items: center;
            gap: 12px;
            letter-spacing: -0.5px;
        }
        
        .user-profile {
            padding: 15px;
            background: rgba(255,255,255,0.03);
            border-radius: 12px;
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 0.9rem;
        }
        
        .compliance-score {
            background: linear-gradient(145deg, rgba(16, 185, 129, 0.1), rgba(16, 185, 129, 0.05));
            border: 1px solid rgba(16, 185, 129, 0.2);
            padding: 20px;
            border-radius: 16px;
            text-align: center;
        }
        
        .score-value { font-size: 3rem; font-weight: 700; color: var(--success); line-height: 1; }
        
        .github-widget {
            background: #0d1117;
            border: 1px solid #30363d;
            padding: 15px;
            border-radius: 12px;
        }
        
        /* Main Content */
        .main {
            padding: 32px;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            gap: 24px;
        }
        
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        
        .live-indicator {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 6px 12px;
            background: rgba(16, 185, 129, 0.1);
            border-radius: 20px;
            color: var(--success);
            font-size: 0.85rem;
            font-weight: 600;
        }
        
        .live-dot {
            width: 8px;
            height: 8px;
            background: var(--success);
            border-radius: 50%;
            animation: blink 1.5s infinite;
        }
        
        @keyframes blink { 50% { opacity: 0.4; } }
        
        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
        }
        
        .stat-card {
            background: var(--bg-panel);
            border: 1px solid var(--border);
            padding: 20px;
            border-radius: 12px;
            transition: transform 0.2s;
        }
        
        .stat-card:hover { transform: translateY(-2px); border-color: var(--primary); }
        .stat-val { font-size: 2rem; font-weight: 700; color: white; margin-bottom: 4px; }
        .stat-lbl { color: var(--text-muted); font-size: 0.85rem; }
        
        /* Charts Section */
        .charts-row {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 24px;
            height: 300px;
        }
        
        .chart-container {
            background: var(--bg-panel);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            position: relative;
        }
        
        /* Events Table */
        .table-container {
            background: var(--bg-panel);
            border: 1px solid var(--border);
            border-radius: 12px;
            overflow: hidden;
            margin-top: 20px;
        }
        
        table { width: 100%; border-collapse: collapse; }
        th { text-align: left; padding: 16px 24px; color: var(--text-muted); font-size: 0.85rem; border-bottom: 1px solid var(--border); }
        td { padding: 14px 24px; border-bottom: 1px solid rgba(255,255,255,0.03); font-size: 0.9rem; }
        
        .tag { padding: 4px 10px; border-radius: 6px; font-size: 0.75rem; font-weight: 600; display: inline-block; }
        .tag.crit { background: rgba(239, 68, 68, 0.2); color: var(--danger); border: 1px solid rgba(239, 68, 68, 0.3); }
        .tag.block { background: rgba(245, 158, 11, 0.2); color: var(--warning); border: 1px solid rgba(245, 158, 11, 0.3); }
        .tag.allow { background: rgba(16, 185, 129, 0.2); color: var(--success); border: 1px solid rgba(16, 185, 129, 0.3); }
        
        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: var(--bg-dark); }
        ::-webkit-scrollbar-thumb { background: #333; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="dashboard-container">
        <!-- Sidebar -->
        <aside class="sidebar">
            <div class="brand"><span>🛡️</span> CiberShield</div>
            
            {% if user %}
            <div class="user-profile">
                <div style="width: 32px; height: 32px; background: var(--primary); border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: bold;">
                    {{ user.get("name", "U")[0] }}
                </div>
                <div>
                    <div style="color: white; font-weight: 600;">{{ user.get("name") }}</div>
                    <div style="color: var(--text-muted); font-size: 0.75rem;">Admin</div>
                </div>
            </div>
            {% endif %}
            
            <div class="compliance-score">
                <div class="score-value" id="comp-score">100%</div>
                <div style="color: var(--text-muted); font-size: 0.8rem;">CUMPLIMIENTO</div>
            </div>
            
            <div class="github-widget">
                <h3 style="color: white; font-size: 0.9rem; margin-bottom: 10px; display: flex; align-items: center; gap: 8px;">
                    <svg height="20" width="20" viewBox="0 0 16 16" fill="white"><path d="M8 0c4.42 0 8 3.58 8 8a8.013 8.013 0 0 1-5.45 7.59c-.4.08-.55-.17-.55-.38 0-.27.01-1.13.01-2.2 0-.75-.25-1.23-.54-1.48 1.78-.2 3.65-.88 3.65-3.95 0-.88-.31-1.59-.82-2.15.08-.2.36-1.02-.08-2.12 0 0-.67-.22-2.2.82-.64-.18-1.32-.27-2-.27-.68 0-1.36.09-2 .27-1.53-1.03-2.2-.82-2.2-.82-.44 1.1-.16 1.92-.08 2.12-.51.56-.82 1.28-.82 2.15 0 3.06 1.86 3.75 3.64 3.95-.23.2-.44.55-.51 1.07-.46.12-1.61.55-2.33-.66-.15-.24-.6-.83-1.23-.82-.67.01-.27.38.01.53.34.19.73.9.82 1.13.16.45.68 1.31 2.69.94 0 .67.01 1.3.01 1.49 0 .21-.15.45-.55.38A7.995 7.995 0 0 1 0 8c0-4.42 3.58-8 8-8Z"></path></svg>
                    GitHub Monitor
                </h3>
                <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                    <span style="color: var(--text-muted); font-size: 0.8rem;">Estado:</span>
                    <span id="gh-status" style="color: var(--success); font-weight: 600; font-size: 0.8rem;">Online</span>
                </div>
                <div style="display: flex; justify-content: space-between;">
                    <span style="color: var(--text-muted); font-size: 0.8rem;">Total Repos:</span>
                    <span id="gh-repos" style="color: white; font-weight: 600; font-size: 0.8rem;">0</span>
                </div>
                 <div style="display: flex; justify-content: space-between; margin-top: 5px;">
                    <span style="color: var(--text-muted); font-size: 0.8rem;">Públicos:</span>
                    <span id="gh-public" style="color: var(--warning); font-weight: 600; font-size: 0.8rem;">0</span>
                </div>
            </div>
            
            <a href="/logout" style="margin-top: auto; color: var(--text-muted); font-size: 0.9rem; text-decoration: none; padding: 10px;">cerrar sesión -></a>
        </aside>
        
        <!-- Main Area -->
        <main class="main">
            <header class="header">
                <div>
                    <h1 style="font-size: 1.8rem; font-weight: 600;">Centro de Vigilancia</h1>
                </div>
                <div class="live-indicator"><span class="live-dot"></span> EN VIVO</div>
            </header>
            
            <!-- KPIs -->
            <div class="stats-grid">
                <div class="stat-card"><div class="stat-val" id="total-ev">0</div><div class="stat-lbl">Eventos Totales</div></div>
                <div class="stat-card" style="border-left: 4px solid var(--danger);"><div class="stat-val" id="blocked-ev" style="color: var(--danger);">0</div><div class="stat-lbl">Bloqueos</div></div>
                <div class="stat-card" style="border-left: 4px solid var(--primary);"><div class="stat-val" id="git-ev">0</div><div class="stat-lbl">Ops Git</div></div>
                <div class="stat-card" style="border-left: 4px solid var(--warning);"><div class="stat-val" id="delfix-ev">0</div><div class="stat-lbl">Acceso Delfix-CR</div></div>
            </div>
            
            <!-- Charts -->
            <div class="charts-row">
                <div class="chart-container"><canvas id="mainChart"></canvas></div>
                <div class="chart-container"><canvas id="pieChart"></canvas></div>
            </div>
            
            <!-- Table -->
            <div class="table-container">
                <table>
                    <thead><tr><th>HORA</th><th>ESTADO</th><th>USUARIO / HOST</th><th>ACCIÓN</th><th>DETALLE</th></tr></thead>
                    <tbody id="events-body"></tbody>
                </table>
            </div>
        </main>
    </div>
    
    <script>
        // Init Charts (Simplified for brevity)
        const ctx1 = document.getElementById('mainChart').getContext('2d');
        const mainChart = new Chart(ctx1, {
            type: 'line',
            data: { labels: [], datasets: [{ label: 'Eventos', data: [], borderColor: '#3b82f6', tension: 0.4 }] },
            options: { responsive: true, plugins: { legend: { display: false } }, scales: { x: { display: false } } }
        });
        
        // Update function
        function update() {
            fetch('/api/events').then(r => r.json()).then(data => {
                // KPIs
                document.getElementById('total-ev').textContent = data.stats.total_events;
                document.getElementById('blocked-ev').textContent = data.stats.blocked_events;
                document.getElementById('git-ev').textContent = data.stats.git_commands;
                document.getElementById('delfix-ev').textContent = data.stats.delfix_events;
                document.getElementById('comp-score').textContent = data.compliance.score + '%';
                
                // GitHub Widget
                document.getElementById('gh-status').textContent = data.github.status;
                document.getElementById('gh-status').style.color = data.github.status === 'Online' ? '#10b981' : '#ef4444';
                document.getElementById('gh-repos').textContent = data.github.repos_count;
                document.getElementById('gh-public').textContent = data.github.public_repos;
                
                // Table
                const tbody = document.getElementById('events-body');
                tbody.innerHTML = data.events.slice(0, 15).map(ev => `
                    <tr>
                        <td style="color:#a1a1aa; font-size:0.8rem;">${new Date(ev.timestamp).toLocaleTimeString()}</td>
                        <td>${ev.compliance_violation ? '<span class="tag crit">CRIT</span>' : ev.is_allowed ? '<span class="tag allow">OK</span>' : '<span class="tag block">BLK</span>'}</td>
                        <td style="color:white; font-weight:600;">${ev.username}<br><span style="color:#52525b; font-weight:400; font-size:0.75rem;">${ev.hostname}</span></td>
                        <td style="color:#3b82f6;">${ev.event_type}</td>
                        <td style="font-family:'Fira Code'; font-size:0.8rem; color:#a5b4fc;">${ev.command_line || ev.process_name || '-'}</td>
                    </tr>
                `).join('');
                
                // Chart update (fake data for movement)
                const now = new Date().toLocaleTimeString();
                if(mainChart.data.labels.length > 20) { mainChart.data.labels.shift(); mainChart.data.datasets[0].data.shift(); }
                mainChart.data.labels.push(now);
                mainChart.data.datasets[0].data.push(Math.random() * 5 + (data.events.length > 0 ? 1 : 0));
                mainChart.update();
            });
        }
        setInterval(update, 2000);
        update();
    </script>
</body>
</html>
"""

# --- LOGIN & AUTH LOGIC ---

def load_auth_config():
    return {
        "client_id": SECRETS["CLIENT_ID"],
        "authority": SECRETS["AUTHORITY"],
        "client_secret": SECRETS["CLIENT_SECRET"],
    }

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/login")
def login():
    # En entorno de dev/test sin credenciales reales, bypass temporal (comentar en prod real)
    # return _fake_login() 
    
    if "ENTER_YOUR" in SECRETS["CLIENT_ID"]:
        return "Error: Azure Credentials not configured in SECRETS dict."

    config = load_auth_config()
    cca = msal.ConfidentialClientApplication(
        config["client_id"], authority=config["authority"],
        client_credential=config["client_secret"]
    )
    auth_url = cca.get_authorization_request_url(SECRETS["SCOPE"], redirect_uri=url_for("authorized", _external=True))
    return redirect(auth_url)

def _fake_login():
    """Solo para pruebas si no hay Azure creds"""
    session["user"] = {"name": "Gabriel Umana Test"}
    return redirect(url_for("dashboard"))

@app.route(SECRETS["REDIRECT_PATH"])
def authorized():
    if request.args.get('error'):
        return f"Login Error: {request.args.get('error_description')}"
        
    config = load_auth_config()
    cca = msal.ConfidentialClientApplication(
        config["client_id"], authority=config["authority"],
        client_credential=config["client_secret"]
    )
    
    token = cca.acquire_token_by_authorization_code(
        request.args.get('code'), scopes=SECRETS["SCOPE"], # Misspelled scope in original replacement fixed
        redirect_uri=url_for("authorized", _external=True)
    )
    
    if "error" in token:
        return f"Token Error: {token.get('error_description')}"
        
    user_info = token.get("id_token_claims")
    user_name = user_info.get("name")
    
    # Whitelist Check
    if user_name not in AUTHORIZED_USERS:
        return "ACCESO DENEGADO: Usuario no autorizado.", 403
        
    session["user"] = user_info
    return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        f"{SECRETS['AUTHORITY']}/oauth2/v2.0/logout?post_logout_redirect_uri={url_for('dashboard', _external=True)}"
    )

# --- FIN AUTH LOGIC ---

# --- GITHUB MONITORING LOGIC ---
def github_monitor_loop():
    """Hilo secundario para monitorear GitHub"""
    logger.info("Iniciando GitHub Monitor...")
    while True:
        try:
            if "ENTER_YOUR" in SECRETS["GITHUB_TOKEN"]:
                github_data["status"] = "No Config"
                time.sleep(60)
                continue
                
            headers = {
                "Authorization": f"token {SECRETS['GITHUB_TOKEN']}",
                "Accept": "application/vnd.github.v3+json"
            }
            
            # 1. Fetch Repos
            url = f"https://api.github.com/orgs/{SECRETS['GITHUB_ORG']}/repos"
            # Si el token es de usuario y no org, usaria /user/repos
            if SECRETS["GITHUB_ORG"] == "Cibershield": # Default check
                 pass # keep url
            
            r = requests.get(url, headers=headers)
            if r.status_code == 200:
                repos = r.json()
                github_data["repos_count"] = len(repos)
                github_data["public_repos"] = sum(1 for repo in repos if not repo.get("private"))
                github_data["status"] = "Online"
                github_data["last_sync"] = datetime.now().isoformat()
            else:
                github_data["status"] = f"Error {r.status_code}"
                
            time.sleep(300) # Poll cada 5 minutos
        except Exception as e:
            logger.error(f"GitHub Monitor Error: {e}")
            github_data["status"] = "Error"
            time.sleep(60)


# --- GENERAL BACKEND ---

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(name)s] %(levelname)s: %(message)s')
logger = logging.getLogger("DLPConsole")

def check_compliance_rules(event: Dict) -> bool:
    is_violation = False
    if event.get("is_delfix_repo"): is_violation = True
    if "git clone" in event.get("command_line", "").lower() and "github.com" not in event.get("command_line", "").lower():
        is_violation = True
    return is_violation

def tcp_receiver():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(('0.0.0.0', CONSOLE_CONFIG["tcp_port"]))
        server.listen(10)
        logger.info(f"TCP Receiver listening on {CONSOLE_CONFIG['tcp_port']}")
        while True:
            client, addr = server.accept()
            threading.Thread(target=handle_client, args=(client, addr), daemon=True).start()
    except Exception as e:
        logger.critical(f"TCP Fail: {e}")

def handle_client(client, addr):
    try:
        data = b""
        while True:
            chunk = client.recv(4096)
            if not chunk: break
            data += chunk
        if data:
            for line in data.decode().strip().split('\n'):
                if line:
                    try: process_event(json.loads(line))
                    except: pass
    except: pass
    finally: client.close()

def process_event(event_data: Dict):
    global stats
    event_type = event_data.get("event_type", "unknown")
    with events_lock:
        if event_type == "agent_metrics":
            agent_metrics[event_data.get("hostname")] = event_data
            return

        is_critical = check_compliance_rules(event_data)
        event_data["compliance_violation"] = is_critical
        events_store.appendleft(event_data)
        
        stats["total_events"] += 1
        if event_data.get("is_allowed"): stats["allowed_events"] += 1
        else: stats["blocked_events"] += 1
        
        if is_critical:
            stats["critical_alerts"] += 1
            stats["compliance_violations"] += 1
        
        if event_type == "git_command": stats["git_commands"] += 1
        if event_data.get("is_delfix_repo"): stats["delfix_events"] += 1
        
        stats["unique_users"].add(event_data.get("username", "unknown"))
        stats["unique_hosts"].add(event_data.get("hostname", "unknown"))

    if is_critical: logger.critical(f"CRITICAL: {event_data.get('username')}")

@app.route('/')
@login_required # Protegido por Entra ID
def dashboard():
    return render_template_string(DASHBOARD_HTML, user=session.get("user"))

@app.route('/api/events')
@login_required # Protegido por Entra ID, aunque la UI lo llama via ajax
def api_events():
    with events_lock:
        total = stats["total_events"]
        score = max(0, 100 - int((stats["compliance_violations"] / (total if total > 0 else 1)) * 1000))
        return jsonify({
            "events": list(events_store),
            "stats": {
                "total_events": stats["total_events"],
                "blocked_events": stats["blocked_events"],
                "git_commands": stats["git_commands"],
                "delfix_events": stats["delfix_events"],
                "unique_users": len(stats["unique_users"]),
            },
            "compliance": { "score": score, "critical_violations": stats["compliance_violations"] },
            "github": github_data
        })

def main():
    print("=" * 60)
    print("🛡️  CiberShield Surveillance (Entra ID + GitHub API)")
    print("=" * 60)
    threading.Thread(target=tcp_receiver, daemon=True).start()
    threading.Thread(target=github_monitor_loop, daemon=True).start() # GitHub Thread
    app.run(host='0.0.0.0', port=CONSOLE_CONFIG["web_port"], debug=False, threaded=True)

if __name__ == "__main__":
    main()
