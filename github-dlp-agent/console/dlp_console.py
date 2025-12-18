#!/usr/bin/env python3
"""
Consola DLP - Recibe y visualiza eventos de los agentes
"""

import json
import socket
import threading
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass
from collections import deque

from flask import Flask, render_template_string, jsonify, Response
from flask_cors import CORS

# Configuración
CONSOLE_CONFIG = {
    "tcp_port": 5555,
    "web_port": 8080,
    "max_events": 1000,
    "log_file": "console.log"
}

# Almacén de eventos en memoria
events_store: deque = deque(maxlen=CONSOLE_CONFIG["max_events"])
events_lock = threading.Lock()

# Estadísticas
stats = {
    "total_events": 0,
    "blocked_events": 0,
    "allowed_events": 0,
    "unique_users": set(),
    "unique_hosts": set(),
    "git_commands": 0,
    "network_connections": 0,
    "repos_detected": 0,
}

# Métricas de agentes
agent_metrics: Dict[str, Dict] = {}  # hostname -> últimas métricas

app = Flask(__name__)
CORS(app)

# Template HTML para el dashboard
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GitHub DLP Console</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: #0f0f23;
            color: #e0e0e0;
            min-height: 100vh;
        }
        
        .header {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            padding: 20px 30px;
            border-bottom: 1px solid #333;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .header h1 {
            color: #00d4ff;
            font-size: 1.5rem;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .header h1::before {
            content: "🛡️";
        }
        
        .status {
            display: flex;
            align-items: center;
            gap: 8px;
            color: #00ff88;
        }
        
        .status-dot {
            width: 10px;
            height: 10px;
            background: #00ff88;
            border-radius: 50%;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        .stats-bar {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            padding: 20px 30px;
            background: #1a1a2e;
        }
        
        .stat-card {
            background: #16213e;
            padding: 15px;
            border-radius: 10px;
            border-left: 4px solid #00d4ff;
        }
        
        .stat-card.alert {
            border-left-color: #ff4757;
        }
        
        .stat-card.success {
            border-left-color: #00ff88;
        }
        
        .stat-card.network {
            border-left-color: #ffa502;
        }
        
        .stat-card.metric {
            border-left-color: #a29bfe;
        }
        
        .stat-value {
            font-size: 1.8rem;
            font-weight: bold;
            color: #fff;
        }
        
        .stat-label {
            color: #888;
            font-size: 0.8rem;
            margin-top: 5px;
        }
        
        .agent-metrics {
            padding: 15px 30px;
            background: #12122a;
            border-bottom: 1px solid #333;
        }
        
        .agent-metrics h3 {
            color: #a29bfe;
            font-size: 0.9rem;
            margin-bottom: 10px;
        }
        
        .metrics-grid {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
        }
        
        .agent-card {
            background: #1a1a2e;
            padding: 12px 16px;
            border-radius: 8px;
            min-width: 200px;
        }
        
        .agent-card .hostname {
            color: #00d4ff;
            font-weight: 600;
            font-size: 0.9rem;
        }
        
        .agent-card .metrics {
            display: flex;
            gap: 15px;
            margin-top: 8px;
            font-size: 0.8rem;
        }
        
        .agent-card .metric-item {
            display: flex;
            align-items: center;
            gap: 5px;
        }
        
        .agent-card .metric-item.warning {
            color: #ffa502;
        }
        
        .agent-card .metric-item.ok {
            color: #00ff88;
        }
        
        .throttle-badge {
            background: #ff4757;
            color: white;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 0.7rem;
            margin-left: 10px;
        }
        
        .main-content {
            padding: 20px 30px;
        }
        
        .section-title {
            color: #00d4ff;
            margin-bottom: 15px;
            font-size: 1.2rem;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .events-table {
            width: 100%;
            border-collapse: collapse;
            background: #1a1a2e;
            border-radius: 10px;
            overflow: hidden;
        }
        
        .events-table th {
            background: #16213e;
            padding: 12px;
            text-align: left;
            color: #00d4ff;
            font-weight: 600;
            font-size: 0.85rem;
            border-bottom: 2px solid #333;
        }
        
        .events-table td {
            padding: 10px 12px;
            border-bottom: 1px solid #2a2a4a;
            font-size: 0.85rem;
        }
        
        .events-table tr:hover {
            background: #252545;
        }
        
        .badge {
            padding: 3px 8px;
            border-radius: 20px;
            font-size: 0.7rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .badge.blocked {
            background: rgba(255, 71, 87, 0.2);
            color: #ff4757;
            border: 1px solid #ff4757;
        }
        
        .badge.allowed {
            background: rgba(0, 255, 136, 0.2);
            color: #00ff88;
            border: 1px solid #00ff88;
        }
        
        .badge.network {
            background: rgba(255, 165, 2, 0.2);
            color: #ffa502;
            border: 1px solid #ffa502;
        }
        
        .badge.metric {
            background: rgba(162, 155, 254, 0.2);
            color: #a29bfe;
            border: 1px solid #a29bfe;
        }
        
        .command-cell {
            max-width: 250px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            font-family: 'Fira Code', monospace;
            font-size: 0.8rem;
            color: #ffa502;
        }
        
        .command-cell:hover {
            white-space: normal;
            word-break: break-all;
        }
        
        .url-cell {
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            color: #70a1ff;
        }
        
        .url-cell a {
            color: inherit;
            text-decoration: none;
        }
        
        .url-cell a:hover {
            text-decoration: underline;
        }
        
        .time-cell {
            color: #888;
            font-size: 0.8rem;
            white-space: nowrap;
        }
        
        .no-events {
            text-align: center;
            padding: 50px;
            color: #666;
        }
        
        .refresh-info {
            text-align: right;
            color: #666;
            font-size: 0.8rem;
            margin-top: 10px;
        }
        
        .filters {
            display: flex;
            gap: 10px;
            margin-bottom: 15px;
            flex-wrap: wrap;
        }
        
        .filter-btn {
            padding: 6px 14px;
            border: 1px solid #333;
            background: transparent;
            color: #e0e0e0;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.3s;
            font-size: 0.85rem;
        }
        
        .filter-btn:hover, .filter-btn.active {
            background: #00d4ff;
            color: #000;
            border-color: #00d4ff;
        }
        
        .ip-cell {
            font-family: 'Fira Code', monospace;
            font-size: 0.8rem;
            color: #a29bfe;
        }

        .footer {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            padding: 15px 30px;
            text-align: center;
            border-top: 1px solid #333;
            margin-top: 30px;
        }

        .footer p {
            color: #888;
            font-size: 0.85rem;
            margin: 0;
        }

        .footer strong {
            color: #00d4ff;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>DLP Console v0.8</h1>
        <div class="status">
            <span class="status-dot"></span>
            <span>Monitoreando</span>
        </div>
    </div>
    
    <div class="stats-bar">
        <div class="stat-card">
            <div class="stat-value" id="total-events">0</div>
            <div class="stat-label">Total Eventos</div>
        </div>
        <div class="stat-card alert">
            <div class="stat-value" id="blocked-events">0</div>
            <div class="stat-label">🚨 Alertas</div>
        </div>
        <div class="stat-card success">
            <div class="stat-value" id="allowed-events">0</div>
            <div class="stat-label">✓ Permitidos</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" id="git-commands">0</div>
            <div class="stat-label">📦 Git Commands</div>
        </div>
        <div class="stat-card network">
            <div class="stat-value" id="network-connections">0</div>
            <div class="stat-label">🌐 Conexiones</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" id="unique-users">0</div>
            <div class="stat-label">👤 Usuarios</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" id="unique-hosts">0</div>
            <div class="stat-label">🖥️ Hosts</div>
        </div>
    </div>
    
    <div class="agent-metrics" id="agent-metrics-section" style="display: none;">
        <h3>📊 Estado de Agentes</h3>
        <div class="metrics-grid" id="agents-grid">
        </div>
    </div>
    
    <div class="main-content">
        <h2 class="section-title">📋 Eventos Recientes</h2>
        
        <div class="filters">
            <button class="filter-btn active" onclick="filterEvents('all')">Todos</button>
            <button class="filter-btn" onclick="filterEvents('blocked')">Solo Alertas</button>
            <button class="filter-btn" onclick="filterEvents('allowed')">Permitidos</button>
            <button class="filter-btn" onclick="filterEvents('git_command')">Git Commands</button>
            <button class="filter-btn" onclick="filterEvents('network_connection')">Red</button>
        </div>
        
        <table class="events-table">
            <thead>
                <tr>
                    <th>Hora</th>
                    <th>Estado</th>
                    <th>Tipo</th>
                    <th>Usuario</th>
                    <th>Host</th>
                    <th>Proceso</th>
                    <th>Comando/IP</th>
                    <th>Destino</th>
                </tr>
            </thead>
            <tbody id="events-body">
                <tr class="no-events">
                    <td colspan="8">Esperando eventos...</td>
                </tr>
            </tbody>
        </table>
        
        <div class="refresh-info">
            Auto-refresh cada 1 segundo | Último update: <span id="last-update">-</span>
        </div>
    </div>

    <footer class="footer">
        <p>Desarrollado por <strong>Cibershield R.L.</strong> 2025. Todos los derechos reservados. | Versión 0.8</p>
    </footer>

    <script>
        let currentFilter = 'all';
        let allEvents = [];
        let agentMetrics = {};
        
        function formatTime(isoString) {
            const date = new Date(isoString);
            return date.toLocaleTimeString('es-ES', { 
                hour: '2-digit', 
                minute: '2-digit',
                second: '2-digit'
            });
        }
        
        function filterEvents(filter) {
            currentFilter = filter;
            document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            renderEvents();
        }
        
        function getEventBadge(event) {
            if (event.event_type === 'agent_metrics') {
                return '<span class="badge metric">📊 METRICS</span>';
            }
            if (event.event_type === 'network_connection') {
                if (event.is_allowed) {
                    return '<span class="badge allowed">🌐 OK</span>';
                }
                return '<span class="badge network">🌐 RED</span>';
            }
            if (event.is_allowed) {
                return '<span class="badge allowed">✓ OK</span>';
            }
            return '<span class="badge blocked">🚨 ALERTA</span>';
        }
        
        function getCommandDisplay(event) {
            if (event.event_type === 'network_connection' && event.remote_ip) {
                return `<span class="ip-cell">${event.remote_ip}:${event.remote_port || 443}</span>`;
            }
            if (event.command_line) {
                return `<span class="command-cell" title="${event.command_line}">${event.command_line}</span>`;
            }
            return '-';
        }
        
        function renderEvents() {
            const tbody = document.getElementById('events-body');
            
            // Filtrar eventos (excluir métricas de la lista principal)
            let filtered = allEvents.filter(e => e.event_type !== 'agent_metrics');
            
            if (currentFilter === 'blocked') {
                filtered = filtered.filter(e => !e.is_allowed);
            } else if (currentFilter === 'allowed') {
                filtered = filtered.filter(e => e.is_allowed);
            } else if (currentFilter === 'git_command') {
                filtered = filtered.filter(e => e.event_type === 'git_command');
            } else if (currentFilter === 'network_connection') {
                filtered = filtered.filter(e => e.event_type === 'network_connection');
            }
            
            if (filtered.length === 0) {
                tbody.innerHTML = '<tr class="no-events"><td colspan="8">No hay eventos</td></tr>';
                return;
            }
            
            tbody.innerHTML = filtered.slice(0, 100).map(event => `
                <tr>
                    <td class="time-cell">${formatTime(event.timestamp)}</td>
                    <td>${getEventBadge(event)}</td>
                    <td>${event.event_type}</td>
                    <td>${event.username}</td>
                    <td>${event.hostname}</td>
                    <td>${event.process_name || '-'}</td>
                    <td>${getCommandDisplay(event)}</td>
                    <td class="url-cell">
                        ${event.target_url ? `<a href="${event.target_url}" target="_blank">${event.target_url}</a>` : (event.parent_process || '-')}
                    </td>
                </tr>
            `).join('');
        }
        
        function renderAgentMetrics() {
            const section = document.getElementById('agent-metrics-section');
            const grid = document.getElementById('agents-grid');
            
            const hosts = Object.keys(agentMetrics);
            if (hosts.length === 0) {
                section.style.display = 'none';
                return;
            }
            
            section.style.display = 'block';
            
            grid.innerHTML = hosts.map(hostname => {
                const m = agentMetrics[hostname];
                const cpuClass = m.agent_cpu > 5 ? 'warning' : 'ok';
                const memClass = m.agent_memory_mb > 100 ? 'warning' : 'ok';
                const throttled = m.reason && m.reason.includes('throttled=True');
                
                return `
                    <div class="agent-card">
                        <span class="hostname">${hostname}</span>
                        ${throttled ? '<span class="throttle-badge">THROTTLED</span>' : ''}
                        <div class="metrics">
                            <span class="metric-item ${cpuClass}">CPU: ${(m.agent_cpu || 0).toFixed(1)}%</span>
                            <span class="metric-item ${memClass}">RAM: ${(m.agent_memory_mb || 0).toFixed(1)}MB</span>
                            <span class="metric-item">Sys: ${(m.system_cpu || 0).toFixed(0)}%</span>
                        </div>
                    </div>
                `;
            }).join('');
        }
        
        async function fetchEvents() {
            try {
                const response = await fetch('/api/events');
                const data = await response.json();
                
                allEvents = data.events;
                agentMetrics = data.agent_metrics || {};
                
                // Actualizar stats
                document.getElementById('total-events').textContent = data.stats.total_events;
                document.getElementById('blocked-events').textContent = data.stats.blocked_events;
                document.getElementById('allowed-events').textContent = data.stats.allowed_events;
                document.getElementById('git-commands').textContent = data.stats.git_commands || 0;
                document.getElementById('network-connections').textContent = data.stats.network_connections || 0;
                document.getElementById('unique-users').textContent = data.stats.unique_users;
                document.getElementById('unique-hosts').textContent = data.stats.unique_hosts;
                
                renderEvents();
                renderAgentMetrics();
                
                document.getElementById('last-update').textContent = new Date().toLocaleTimeString('es-ES');
            } catch (error) {
                console.error('Error fetching events:', error);
            }
        }
        
        // Fetch inicial y luego cada 1 segundo (tiempo real)
        fetchEvents();
        setInterval(fetchEvents, 1000);
    </script>
</body>
</html>
"""

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(name)s] %(levelname)s: %(message)s'
)
logger = logging.getLogger("DLPConsole")


def tcp_receiver():
    """Recibe eventos de los agentes via TCP"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', CONSOLE_CONFIG["tcp_port"]))
    server.listen(10)
    
    logger.info(f"TCP Receiver escuchando en puerto {CONSOLE_CONFIG['tcp_port']}")
    
    while True:
        try:
            client, addr = server.accept()
            threading.Thread(target=handle_client, args=(client, addr), daemon=True).start()
        except Exception as e:
            logger.error(f"Error en TCP receiver: {e}")


def handle_client(client: socket.socket, addr):
    """Maneja un cliente conectado"""
    try:
        data = b""
        while True:
            chunk = client.recv(4096)
            if not chunk:
                break
            data += chunk
        
        if data:
            for line in data.decode().strip().split('\n'):
                if line:
                    process_event(json.loads(line))
    except Exception as e:
        logger.error(f"Error procesando cliente {addr}: {e}")
    finally:
        client.close()


def process_event(event_data: Dict):
    """Procesa un evento recibido"""
    global stats, agent_metrics
    
    event_type = event_data.get("event_type", "unknown")
    
    with events_lock:
        # Manejar métricas de agente por separado
        if event_type == "agent_metrics":
            hostname = event_data.get("hostname", "unknown")
            agent_metrics[hostname] = event_data
            return  # No contar en estadísticas generales
        
        events_store.appendleft(event_data)
        
        stats["total_events"] += 1
        if event_data.get("is_allowed"):
            stats["allowed_events"] += 1
        else:
            stats["blocked_events"] += 1
        
        # Contar por tipo
        if event_type == "git_command":
            stats["git_commands"] += 1
        elif event_type == "network_connection":
            stats["network_connections"] += 1
        elif event_type == "new_repo_detected":
            stats["repos_detected"] += 1
        
        stats["unique_users"].add(event_data.get("username", "unknown"))
        stats["unique_hosts"].add(event_data.get("hostname", "unknown"))
    
    # Log del evento
    if event_type == "network_connection":
        if not event_data.get("is_allowed"):
            logger.warning(f"🌐 Red: {event_data.get('username')}@{event_data.get('hostname')} -> {event_data.get('remote_ip')}")
    elif event_data.get("is_allowed"):
        logger.info(f"✓ Permitido: {event_data.get('username')}@{event_data.get('hostname')} - {event_type}")
    else:
        logger.warning(f"🚨 ALERTA: {event_data.get('username')}@{event_data.get('hostname')} - {event_data.get('command_line', '')[:50]}")


@app.route('/')
def dashboard():
    """Página principal del dashboard"""
    return render_template_string(DASHBOARD_HTML)


@app.route('/api/events')
def api_events():
    """API endpoint para obtener eventos"""
    with events_lock:
        return jsonify({
            "events": list(events_store),
            "agent_metrics": agent_metrics,
            "stats": {
                "total_events": stats["total_events"],
                "blocked_events": stats["blocked_events"],
                "allowed_events": stats["allowed_events"],
                "git_commands": stats["git_commands"],
                "network_connections": stats["network_connections"],
                "repos_detected": stats["repos_detected"],
                "unique_users": len(stats["unique_users"]),
                "unique_hosts": len(stats["unique_hosts"]),
            }
        })


@app.route('/api/stats')
def api_stats():
    """API endpoint para estadísticas"""
    with events_lock:
        return jsonify({
            "total_events": stats["total_events"],
            "blocked_events": stats["blocked_events"],
            "allowed_events": stats["allowed_events"],
            "unique_users": list(stats["unique_users"]),
            "unique_hosts": list(stats["unique_hosts"]),
        })


def main():
    """Punto de entrada principal"""
    print("=" * 60)
    print("🛡️  DLP Console v0.8")
    print("   Desarrollado por Cibershield R.L. 2025")
    print("   Todos los derechos reservados.")
    print("=" * 60)
    print(f"📡 TCP Receiver: puerto {CONSOLE_CONFIG['tcp_port']}")
    print(f"🌐 Web Dashboard: http://localhost:{CONSOLE_CONFIG['web_port']}")
    print("=" * 60)
    
    # Iniciar receiver TCP en thread separado
    tcp_thread = threading.Thread(target=tcp_receiver, daemon=True)
    tcp_thread.start()
    
    # Iniciar servidor web Flask
    app.run(
        host='0.0.0.0',
        port=CONSOLE_CONFIG["web_port"],
        debug=False,
        threaded=True
    )


if __name__ == "__main__":
    main()
