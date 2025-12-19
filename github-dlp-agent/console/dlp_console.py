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

from flask import Flask, render_template_string, jsonify, Response, redirect, url_for
from flask_cors import CORS
from flask_login import current_user

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

# Inicializar autenticación (Microsoft Entra / Google Workspace)
AUTH_ENABLED = False
try:
    from auth import init_auth, is_auth_enabled
    init_auth(app)
    AUTH_ENABLED = True
except ImportError:
    def is_auth_enabled():
        return False

# Template HTML para el dashboard
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Administración GitHub - Cibershield</title>
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

        .user-info {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 8px 16px;
            background: rgba(0, 212, 255, 0.1);
            border-radius: 8px;
            margin-left: 20px;
        }

        .user-info img {
            width: 32px;
            height: 32px;
            border-radius: 50%;
            border: 2px solid #00d4ff;
        }

        .user-info .user-name {
            color: #e0e0e0;
            font-size: 0.9rem;
        }

        .user-info .user-provider {
            color: #888;
            font-size: 0.7rem;
            text-transform: uppercase;
        }

        .logout-btn {
            padding: 6px 12px;
            background: transparent;
            color: #ff4757;
            border: 1px solid #ff4757;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.8rem;
            transition: all 0.3s;
            text-decoration: none;
        }

        .logout-btn:hover {
            background: #ff4757;
            color: white;
        }

        .header-right {
            display: flex;
            align-items: center;
            gap: 15px;
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

        .repo-link {
            color: #00d4ff;
            text-decoration: none;
            font-weight: 500;
        }

        .repo-link:hover {
            text-decoration: underline;
        }

        .repo-cell {
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .path-cell {
            font-family: 'Fira Code', monospace;
            font-size: 0.75rem;
            color: #888;
            max-width: 150px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .op-badge {
            display: inline-block;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.8rem;
            background: rgba(0, 212, 255, 0.1);
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

        /* Navigation tabs */
        .nav-tabs {
            display: flex;
            gap: 0;
            background: #1a1a2e;
            padding: 0 30px;
            border-bottom: 1px solid #333;
        }

        .nav-tab {
            padding: 15px 25px;
            background: transparent;
            border: none;
            color: #888;
            cursor: pointer;
            font-size: 0.95rem;
            border-bottom: 3px solid transparent;
            transition: all 0.3s;
        }

        .nav-tab:hover {
            color: #e0e0e0;
            background: rgba(0, 212, 255, 0.1);
        }

        .nav-tab.active {
            color: #00d4ff;
            border-bottom-color: #00d4ff;
        }

        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
        }

        /* Repository cards */
        .repo-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
            gap: 20px;
            margin-top: 15px;
        }

        .repo-card {
            background: #1a1a2e;
            border-radius: 10px;
            padding: 20px;
            border-left: 4px solid #00d4ff;
        }

        .repo-card.warning {
            border-left-color: #ff4757;
        }

        .repo-card-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 15px;
        }

        .repo-card-header h3 {
            color: #00d4ff;
            font-size: 1rem;
            margin: 0;
        }

        .repo-card-header h3 a {
            color: inherit;
            text-decoration: none;
        }

        .repo-card-header h3 a:hover {
            text-decoration: underline;
        }

        .repo-stats {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 10px;
            margin-bottom: 15px;
        }

        .repo-stat {
            text-align: center;
            padding: 8px;
            background: #16213e;
            border-radius: 6px;
        }

        .repo-stat-value {
            font-size: 1.3rem;
            font-weight: bold;
            color: #fff;
        }

        .repo-stat-label {
            font-size: 0.7rem;
            color: #888;
            margin-top: 2px;
        }

        .repo-users {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
        }

        .user-tag {
            background: rgba(0, 212, 255, 0.2);
            color: #00d4ff;
            padding: 3px 10px;
            border-radius: 15px;
            font-size: 0.75rem;
        }

        .alert-tag {
            background: rgba(255, 71, 87, 0.2);
            color: #ff4757;
            padding: 3px 10px;
            border-radius: 15px;
            font-size: 0.75rem;
        }

        /* Agents section */
        .agents-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }

        .agent-info-card {
            background: #1a1a2e;
            border-radius: 10px;
            padding: 15px;
            border-left: 4px solid #00ff88;
        }

        .agent-info-card h4 {
            color: #00ff88;
            margin: 0 0 10px 0;
            font-size: 0.95rem;
        }

        .agent-info-card p {
            color: #888;
            font-size: 0.8rem;
            margin: 5px 0;
        }

        .agent-info-card .ip {
            font-family: 'Fira Code', monospace;
            color: #a29bfe;
        }

        /* Unauthorized section */
        .unauthorized-list {
            margin-top: 15px;
        }

        .unauthorized-item {
            background: #1a1a2e;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 10px;
            border-left: 4px solid #ff4757;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .unauthorized-item .details {
            flex: 1;
        }

        .unauthorized-item .repo {
            color: #00d4ff;
            font-weight: 600;
        }

        .unauthorized-item .info {
            color: #888;
            font-size: 0.85rem;
            margin-top: 5px;
        }

        .unauthorized-item .time {
            color: #666;
            font-size: 0.8rem;
        }

        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }

        .section-header h2 {
            color: #00d4ff;
            font-size: 1.2rem;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .count-badge {
            background: #ff4757;
            color: white;
            padding: 3px 10px;
            border-radius: 15px;
            font-size: 0.8rem;
        }

        /* Collaborators section */
        .collab-section {
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid #333;
        }

        .collab-section h4 {
            color: #888;
            font-size: 0.8rem;
            margin-bottom: 10px;
        }

        .collab-list {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }

        .collab-item {
            display: flex;
            align-items: center;
            gap: 6px;
            background: #16213e;
            padding: 5px 10px;
            border-radius: 6px;
            font-size: 0.8rem;
        }

        .collab-item img {
            width: 20px;
            height: 20px;
            border-radius: 50%;
        }

        .collab-role {
            font-size: 0.7rem;
            padding: 2px 6px;
            border-radius: 3px;
            margin-left: 5px;
        }

        .collab-role.admin { background: #ff4757; color: white; }
        .collab-role.write { background: #ffa502; color: black; }
        .collab-role.read { background: #2ed573; color: black; }
        .collab-role.maintainer { background: #a29bfe; color: black; }

        /* Clone locations */
        .clone-section {
            margin-top: 12px;
            padding-top: 12px;
            border-top: 1px solid #333;
        }

        .clone-section h4 {
            color: #888;
            font-size: 0.8rem;
            margin-bottom: 8px;
        }

        .clone-item {
            background: #16213e;
            padding: 8px 12px;
            border-radius: 6px;
            margin-bottom: 6px;
            font-size: 0.8rem;
        }

        .clone-item .path {
            font-family: 'Fira Code', monospace;
            color: #ffa502;
            font-size: 0.75rem;
        }

        .clone-item .meta {
            color: #666;
            font-size: 0.7rem;
            margin-top: 4px;
        }

        .clone-item.no-agent {
            border-left: 3px solid #ff4757;
        }

        .clone-item.with-agent {
            border-left: 3px solid #00ff88;
        }

        .no-token-msg {
            color: #888;
            font-size: 0.8rem;
            font-style: italic;
        }

        /* Responsive Design */
        @media (max-width: 768px) {
            .header {
                padding: 15px;
                flex-direction: column;
                gap: 10px;
                text-align: center;
            }

            .header h1 {
                font-size: 1.2rem;
            }

            .stats-bar {
                padding: 15px;
                grid-template-columns: repeat(2, 1fr);
                gap: 10px;
            }

            .stat-card {
                padding: 10px;
            }

            .stat-value {
                font-size: 1.4rem;
            }

            .stat-label {
                font-size: 0.7rem;
            }

            .nav-tabs {
                padding: 0 10px;
                overflow-x: auto;
                flex-wrap: nowrap;
            }

            .nav-tab {
                padding: 12px 15px;
                font-size: 0.8rem;
                white-space: nowrap;
            }

            .main-content {
                padding: 15px;
            }

            .section-title {
                font-size: 1rem;
            }

            .filters {
                flex-wrap: wrap;
            }

            .filter-btn {
                padding: 5px 10px;
                font-size: 0.75rem;
            }

            .events-table {
                font-size: 0.75rem;
            }

            .events-table th,
            .events-table td {
                padding: 8px 6px;
            }

            .command-cell {
                max-width: 120px;
            }

            .repo-grid {
                grid-template-columns: 1fr;
            }

            .repo-card {
                padding: 15px;
            }

            .repo-stats {
                grid-template-columns: repeat(2, 1fr);
            }

            .agents-grid {
                grid-template-columns: 1fr;
            }

            .collab-list {
                flex-direction: column;
            }

            .collab-item {
                width: 100%;
            }

            .footer {
                padding: 10px 15px;
            }

            .footer p {
                font-size: 0.75rem;
            }

            /* Organization tab mobile */
            #org-name-input {
                width: 100% !important;
                margin-bottom: 10px;
            }

            #repo-search-input {
                width: 100% !important;
            }

            .repo-card-header {
                flex-direction: column;
                gap: 8px;
            }

            .repo-card-header h3 {
                font-size: 0.9rem;
            }

            .unauthorized-item {
                flex-direction: column;
                align-items: flex-start;
                gap: 10px;
            }
        }

        @media (max-width: 480px) {
            .stats-bar {
                grid-template-columns: repeat(2, 1fr);
            }

            .stat-value {
                font-size: 1.2rem;
            }

            .events-table th:nth-child(6),
            .events-table td:nth-child(6),
            .events-table th:nth-child(7),
            .events-table td:nth-child(7),
            .events-table th:nth-child(8),
            .events-table td:nth-child(8) {
                display: none;
            }

            .repo-stats {
                grid-template-columns: repeat(2, 1fr);
                gap: 6px;
            }

            .repo-stat {
                padding: 6px;
            }

            .repo-stat-value {
                font-size: 1rem;
            }

            .repo-stat-label {
                font-size: 0.6rem;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Administración GitHub</h1>
        <div class="header-right">
            <div class="status">
                <span class="status-dot"></span>
                <span>Monitoreando</span>
            </div>
            <div id="user-info-container" style="display: none;">
                <div class="user-info">
                    <img id="user-avatar" src="" alt="Avatar" style="display: none;">
                    <div>
                        <div class="user-name" id="user-name"></div>
                        <div class="user-provider" id="user-provider"></div>
                    </div>
                </div>
                <a href="/logout" class="logout-btn">Cerrar Sesión</a>
            </div>
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

    <!-- Navigation Tabs -->
    <div class="nav-tabs">
        <button class="nav-tab active" onclick="switchTab('events')">📋 Eventos</button>
        <button class="nav-tab" onclick="switchTab('history')">📊 Historial</button>
        <button class="nav-tab" onclick="switchTab('repositories')">📦 Repositorios DLP</button>
        <button class="nav-tab" onclick="switchTab('organization')">🏢 Organización GitHub</button>
        <button class="nav-tab" onclick="switchTab('traffic')">📈 Clones/Tráfico</button>
        <button class="nav-tab" onclick="switchTab('correlation')">🔗 Correlación</button>
        <button class="nav-tab" onclick="switchTab('agents')">🖥️ Agentes DLP</button>
        <button class="nav-tab" onclick="switchTab('unauthorized')">🚨 Accesos No Autorizados <span id="unauthorized-badge" class="count-badge" style="display:none;">0</span></button>
    </div>

    <!-- Tab: Events -->
    <div id="tab-events" class="tab-content active">
    <div class="main-content">
        <h2 class="section-title">📋 Eventos Recientes</h2>

        <div class="filters">
            <button class="filter-btn active" onclick="filterEvents('all')">Todos</button>
            <button class="filter-btn" onclick="filterEvents('blocked')">🚨 Alertas</button>
            <button class="filter-btn" onclick="filterEvents('allowed')">✓ Permitidos</button>
            <button class="filter-btn" onclick="filterEvents('git')">📦 Git</button>
            <button class="filter-btn" onclick="filterEvents('network')">🌐 Red</button>
        </div>
        
        <table class="events-table">
            <thead>
                <tr>
                    <th>Hora</th>
                    <th>Estado</th>
                    <th>Operación</th>
                    <th>Repositorio</th>
                    <th>Usuario</th>
                    <th>Host / IP</th>
                    <th>Rama</th>
                    <th>Ruta Local</th>
                </tr>
            </thead>
            <tbody id="events-body">
                <tr class="no-events">
                    <td colspan="8">Esperando eventos...</td>
                </tr>
            </tbody>
        </table>
        
        <div class="refresh-info">
            Último update: <span id="last-update">-</span>
        </div>
    </div>
    </div>

    <!-- Tab: Repositories -->
    <div id="tab-repositories" class="tab-content">
    <div class="main-content">
        <div class="section-header">
            <h2>📦 Repositorios Monitoreados</h2>
        </div>
        <div class="repo-grid" id="repos-grid">
            <p style="color: #666; grid-column: 1/-1; text-align: center; padding: 40px;">Cargando repositorios...</p>
        </div>
    </div>
    </div>

    <!-- Tab: Organization -->
    <div id="tab-organization" class="tab-content">
    <div class="main-content">
        <div class="section-header">
            <h2>🏢 Organización GitHub</h2>
        </div>
        <div style="margin-bottom: 20px;">
            <input type="text" id="org-name-input" placeholder="Nombre de la organización (ej: Delfix-CR)"
                   style="padding: 10px 15px; border: 1px solid #333; background: #1a1a2e; color: #e0e0e0; border-radius: 6px; width: 300px; margin-right: 10px;">
            <button onclick="fetchOrganization()" style="padding: 10px 20px; background: #00d4ff; color: #000; border: none; border-radius: 6px; cursor: pointer; font-weight: 600;">Cargar Organización</button>
        </div>
        <div id="org-info" style="display: none; background: #1a1a2e; padding: 20px; border-radius: 10px; margin-bottom: 20px;">
        </div>
        <!-- Búsqueda de repos -->
        <div id="repo-search-container" style="display: none; margin-bottom: 20px;">
            <input type="text" id="repo-search-input" placeholder="🔍 Buscar repositorio..."
                   onkeyup="filterRepos()"
                   style="padding: 10px 15px; border: 1px solid #333; background: #1a1a2e; color: #e0e0e0; border-radius: 6px; width: 100%; max-width: 400px;">
            <span id="repo-count" style="margin-left: 15px; color: #888;"></span>
        </div>
        <div id="org-repos-grid" class="repo-grid">
            <p style="color: #666; grid-column: 1/-1; text-align: center; padding: 40px;">Ingrese el nombre de una organización para ver sus repositorios.</p>
        </div>
    </div>
    </div>

    <!-- Tab: Traffic Statistics -->
    <div id="tab-traffic" class="tab-content">
    <div class="main-content">
        <div class="section-header">
            <h2>📈 Estadísticas de Clones y Tráfico</h2>
        </div>
        <p style="color: #888; margin-bottom: 15px;">Estadísticas de clones y visitas de los últimos 14 días (datos de GitHub Traffic API).</p>

        <div style="margin-bottom: 20px;">
            <input type="text" id="traffic-org-input" placeholder="Nombre de la organización (ej: Delfix-CR)"
                   style="padding: 10px 15px; border: 1px solid #333; background: #1a1a2e; color: #e0e0e0; border-radius: 6px; width: 300px; margin-right: 10px;">
            <button onclick="fetchTrafficStats()" style="padding: 10px 20px; background: #00d4ff; color: #000; border: none; border-radius: 6px; cursor: pointer; font-weight: 600;">Cargar Estadísticas</button>
        </div>

        <!-- Stats Summary -->
        <div id="traffic-summary" style="display: none; margin-bottom: 20px;">
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px;">
                <div class="stat-card">
                    <div class="stat-value" id="traffic-total-clones">0</div>
                    <div class="stat-label">Total Clones</div>
                </div>
                <div class="stat-card success">
                    <div class="stat-value" id="traffic-unique-cloners">0</div>
                    <div class="stat-label">Clonadores Únicos</div>
                </div>
                <div class="stat-card network">
                    <div class="stat-value" id="traffic-total-views">0</div>
                    <div class="stat-label">Total Visitas</div>
                </div>
                <div class="stat-card metric">
                    <div class="stat-value" id="traffic-unique-visitors">0</div>
                    <div class="stat-label">Visitantes Únicos</div>
                </div>
            </div>
        </div>

        <!-- Daily Chart -->
        <div id="traffic-daily-chart" style="display: none; background: #1a1a2e; padding: 20px; border-radius: 10px; margin-bottom: 20px;">
            <h3 style="color: #00d4ff; margin-bottom: 15px;">Clones por Día (últimos 14 días)</h3>
            <div id="daily-chart-bars" style="display: flex; align-items: flex-end; gap: 8px; height: 150px; padding: 10px 0;"></div>
        </div>

        <!-- Top Repos Table -->
        <div id="traffic-repos-section" style="display: none;">
            <h3 style="color: #00d4ff; margin-bottom: 15px;">Repositorios con más Clones</h3>
            <table class="events-table">
                <thead>
                    <tr>
                        <th>Repositorio</th>
                        <th>Tipo</th>
                        <th>Clones</th>
                        <th>Clonadores</th>
                        <th>Visitas</th>
                        <th>Visitantes</th>
                    </tr>
                </thead>
                <tbody id="traffic-repos-body">
                </tbody>
            </table>
        </div>

        <!-- Loading/Error -->
        <div id="traffic-loading" style="display: none; text-align: center; padding: 40px; color: #00d4ff;">
            Cargando estadísticas...
        </div>
        <div id="traffic-error" style="display: none; text-align: center; padding: 40px; color: #ff4757;">
        </div>
        <div id="traffic-empty" style="text-align: center; padding: 40px; color: #666;">
            Ingrese el nombre de una organización para ver las estadísticas de tráfico.
        </div>
    </div>
    </div>

    <!-- Tab: Correlation -->
    <div id="tab-correlation" class="tab-content">
    <div class="main-content">
        <div class="section-header">
            <h2>🔗 Correlación de Accesos</h2>
        </div>
        <p style="color: #888; margin-bottom: 15px;">Correlaciona clones por fecha con los usuarios que tienen acceso a cada repositorio.</p>

        <div style="margin-bottom: 20px;">
            <input type="text" id="correlation-org-input" placeholder="Nombre de la organización (ej: Delfix-CR)"
                   style="padding: 10px 15px; border: 1px solid #333; background: #1a1a2e; color: #e0e0e0; border-radius: 6px; width: 300px; margin-right: 10px;">
            <button onclick="fetchCorrelation()" style="padding: 10px 20px; background: #00d4ff; color: #000; border: none; border-radius: 6px; cursor: pointer; font-weight: 600;">Analizar Correlación</button>
        </div>

        <!-- Alertas de actividad sospechosa -->
        <div id="correlation-alerts" style="display: none; margin-bottom: 20px;">
            <h3 style="color: #ff4757; margin-bottom: 10px;">🚨 Alertas de Actividad</h3>
            <div id="correlation-alerts-list" style="background: #2a1a1a; padding: 15px; border-radius: 10px; border: 1px solid #ff4757;"></div>
        </div>

        <!-- Tabla de correlación por fecha -->
        <div id="correlation-table-section" style="display: none;">
            <h3 style="color: #00d4ff; margin-bottom: 15px;">Actividad por Fecha</h3>
            <table class="events-table">
                <thead>
                    <tr>
                        <th>Fecha</th>
                        <th>Día</th>
                        <th>Repositorio</th>
                        <th>Tipo</th>
                        <th>Clones</th>
                        <th>Usuarios con Acceso</th>
                    </tr>
                </thead>
                <tbody id="correlation-table-body">
                </tbody>
            </table>
        </div>

        <!-- Loading/Error -->
        <div id="correlation-loading" style="display: none; text-align: center; padding: 40px; color: #00d4ff;">
            Analizando correlación de accesos...
        </div>
        <div id="correlation-error" style="display: none; text-align: center; padding: 40px; color: #ff4757;">
        </div>
        <div id="correlation-empty" style="text-align: center; padding: 40px; color: #666;">
            Ingrese el nombre de una organización para analizar la correlación de accesos.
        </div>
    </div>
    </div>

    <!-- Tab: Agents -->
    <div id="tab-agents" class="tab-content">
    <div class="main-content">
        <div class="section-header">
            <h2>🖥️ Agentes DLP Registrados</h2>
        </div>
        <p style="color: #888; margin-bottom: 15px;">Equipos con el agente DLP instalado que han reportado actividad.</p>
        <div class="agents-grid" id="dlp-agents-grid">
            <p style="color: #666;">Cargando agentes...</p>
        </div>
    </div>
    </div>

    <!-- Tab: History -->
    <div id="tab-history" class="tab-content">
    <div class="main-content">
        <div class="section-header">
            <h2>📊 Historial de Eventos</h2>
        </div>
        <p style="color: #888; margin-bottom: 15px;">Consulta el historial completo de eventos con filtros avanzados.</p>

        <!-- Filtros -->
        <div class="history-filters" style="background: #1a1a2e; padding: 20px; border-radius: 10px; margin-bottom: 20px;">
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px;">
                <div>
                    <label style="color: #888; font-size: 0.8rem; display: block; margin-bottom: 5px;">Fecha Desde</label>
                    <input type="date" id="filter-date-from" style="width: 100%; padding: 8px; background: #0f0f23; color: #e0e0e0; border: 1px solid #333; border-radius: 5px;">
                </div>
                <div>
                    <label style="color: #888; font-size: 0.8rem; display: block; margin-bottom: 5px;">Fecha Hasta</label>
                    <input type="date" id="filter-date-to" style="width: 100%; padding: 8px; background: #0f0f23; color: #e0e0e0; border: 1px solid #333; border-radius: 5px;">
                </div>
                <div>
                    <label style="color: #888; font-size: 0.8rem; display: block; margin-bottom: 5px;">Hora Desde</label>
                    <select id="filter-hour-from" style="width: 100%; padding: 8px; background: #0f0f23; color: #e0e0e0; border: 1px solid #333; border-radius: 5px;">
                        <option value="">Todas</option>
                        <option value="0">00:00</option><option value="1">01:00</option><option value="2">02:00</option>
                        <option value="3">03:00</option><option value="4">04:00</option><option value="5">05:00</option>
                        <option value="6">06:00</option><option value="7">07:00</option><option value="8">08:00</option>
                        <option value="9">09:00</option><option value="10">10:00</option><option value="11">11:00</option>
                        <option value="12">12:00</option><option value="13">13:00</option><option value="14">14:00</option>
                        <option value="15">15:00</option><option value="16">16:00</option><option value="17">17:00</option>
                        <option value="18">18:00</option><option value="19">19:00</option><option value="20">20:00</option>
                        <option value="21">21:00</option><option value="22">22:00</option><option value="23">23:00</option>
                    </select>
                </div>
                <div>
                    <label style="color: #888; font-size: 0.8rem; display: block; margin-bottom: 5px;">Hora Hasta</label>
                    <select id="filter-hour-to" style="width: 100%; padding: 8px; background: #0f0f23; color: #e0e0e0; border: 1px solid #333; border-radius: 5px;">
                        <option value="">Todas</option>
                        <option value="0">00:00</option><option value="1">01:00</option><option value="2">02:00</option>
                        <option value="3">03:00</option><option value="4">04:00</option><option value="5">05:00</option>
                        <option value="6">06:00</option><option value="7">07:00</option><option value="8">08:00</option>
                        <option value="9">09:00</option><option value="10">10:00</option><option value="11">11:00</option>
                        <option value="12">12:00</option><option value="13">13:00</option><option value="14">14:00</option>
                        <option value="15">15:00</option><option value="16">16:00</option><option value="17">17:00</option>
                        <option value="18">18:00</option><option value="19">19:00</option><option value="20">20:00</option>
                        <option value="21">21:00</option><option value="22">22:00</option><option value="23">23:00</option>
                    </select>
                </div>
                <div>
                    <label style="color: #888; font-size: 0.8rem; display: block; margin-bottom: 5px;">Usuario</label>
                    <input type="text" id="filter-username" placeholder="Nombre de usuario" style="width: 100%; padding: 8px; background: #0f0f23; color: #e0e0e0; border: 1px solid #333; border-radius: 5px;">
                </div>
                <div>
                    <label style="color: #888; font-size: 0.8rem; display: block; margin-bottom: 5px;">Repositorio</label>
                    <input type="text" id="filter-repo" placeholder="Nombre del repo" style="width: 100%; padding: 8px; background: #0f0f23; color: #e0e0e0; border: 1px solid #333; border-radius: 5px;">
                </div>
                <div>
                    <label style="color: #888; font-size: 0.8rem; display: block; margin-bottom: 5px;">Operación Git</label>
                    <select id="filter-operation" style="width: 100%; padding: 8px; background: #0f0f23; color: #e0e0e0; border: 1px solid #333; border-radius: 5px;">
                        <option value="">Todas</option>
                        <option value="clone">Clone</option>
                        <option value="push">Push</option>
                        <option value="pull">Pull</option>
                        <option value="fetch">Fetch</option>
                        <option value="commit">Commit</option>
                    </select>
                </div>
                <div>
                    <label style="color: #888; font-size: 0.8rem; display: block; margin-bottom: 5px;">Límite</label>
                    <select id="filter-limit" style="width: 100%; padding: 8px; background: #0f0f23; color: #e0e0e0; border: 1px solid #333; border-radius: 5px;">
                        <option value="50">50 eventos</option>
                        <option value="100" selected>100 eventos</option>
                        <option value="200">200 eventos</option>
                        <option value="500">500 eventos</option>
                    </select>
                </div>
            </div>
            <div style="margin-top: 15px; display: flex; gap: 10px;">
                <button onclick="searchHistory()" style="padding: 10px 25px; background: #00d4ff; color: #000; border: none; border-radius: 5px; cursor: pointer; font-weight: 600;">
                    🔍 Buscar
                </button>
                <button onclick="clearFilters()" style="padding: 10px 25px; background: #333; color: #e0e0e0; border: none; border-radius: 5px; cursor: pointer;">
                    Limpiar Filtros
                </button>
                <button onclick="exportHistory()" style="padding: 10px 25px; background: #00ff88; color: #000; border: none; border-radius: 5px; cursor: pointer; font-weight: 600;">
                    📥 Exportar CSV
                </button>
            </div>
        </div>

        <!-- Estadísticas rápidas -->
        <div id="history-stats" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 20px;">
        </div>

        <!-- Resultados -->
        <div id="history-results">
            <p style="color: #666; text-align: center; padding: 40px;">Usa los filtros para buscar eventos en el historial.</p>
        </div>

        <!-- Paginación -->
        <div id="history-pagination" style="display: none; margin-top: 20px; text-align: center;">
            <button id="btn-prev-page" onclick="historyPrevPage()" style="padding: 8px 20px; background: #333; color: #e0e0e0; border: none; border-radius: 5px; cursor: pointer; margin-right: 10px;">← Anterior</button>
            <span id="history-page-info" style="color: #888;"></span>
            <button id="btn-next-page" onclick="historyNextPage()" style="padding: 8px 20px; background: #333; color: #e0e0e0; border: none; border-radius: 5px; cursor: pointer; margin-left: 10px;">Siguiente →</button>
        </div>
    </div>
    </div>

    <!-- Tab: Unauthorized -->
    <div id="tab-unauthorized" class="tab-content">
    <div class="main-content">
        <div class="section-header">
            <h2>🚨 Accesos desde Equipos Sin Agente DLP</h2>
        </div>
        <p style="color: #888; margin-bottom: 15px;">Actividad detectada desde equipos sin agente DLP: clones, pushes, y cualquier operación Git desde terminal, IDE, o cualquier herramienta.</p>
        <div class="unauthorized-list" id="unauthorized-list">
            <p style="color: #666;">No se han detectado accesos no autorizados.</p>
        </div>
    </div>
    </div>

    <footer class="footer">
        <p>Desarrollado por <strong>Cibershield R.L.</strong> 2025. Todos los derechos reservados.</p>
    </footer>

    <script>
        let currentFilter = 'all';
        let allEvents = [];
        let agentMetrics = {};
        let repositoriesData = [];
        let dlpAgentsData = {};
        let unauthorizedData = [];
        let currentTab = 'events';
        let orgReposData = [];
        let currentOrgName = '';
        let currentUser = null;

        // Verificar estado de autenticación
        async function checkAuthStatus() {
            try {
                const response = await fetch('/api/auth/status');
                const data = await response.json();

                if (data.enabled && data.authenticated && data.user) {
                    currentUser = data.user;
                    const container = document.getElementById('user-info-container');
                    const nameEl = document.getElementById('user-name');
                    const providerEl = document.getElementById('user-provider');
                    const avatarEl = document.getElementById('user-avatar');

                    nameEl.textContent = data.user.name || data.user.email;
                    providerEl.textContent = data.user.provider === 'microsoft' ? 'Microsoft' : 'Google';

                    if (data.user.avatar) {
                        avatarEl.src = data.user.avatar;
                        avatarEl.style.display = 'block';
                    }

                    container.style.display = 'flex';
                }
            } catch (error) {
                console.log('Auth status check:', error.message);
            }
        }

        // Verificar auth al cargar
        checkAuthStatus();

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

        function getOperationBadge(event) {
            const opIcons = {
                'git_clone': '📥 Clone',
                'git_push': '📤 Push',
                'git_pull': '📩 Pull',
                'git_commit': '💾 Commit',
                'git_fetch': '🔄 Fetch',
                'new_repo_detected': '📂 Nuevo Repo',
                'network_connection': '🌐 Red',
                'git_command': '📦 Git'
            };
            return opIcons[event.event_type] || event.git_operation || event.event_type;
        }

        function getRepoDisplay(event) {
            if (event.repo_name) {
                const url = event.repo_url || `https://github.com/${event.repo_name}`;
                return `<a href="${url}" target="_blank" class="repo-link">${event.repo_name}</a>`;
            }
            if (event.target_url) {
                const parts = event.target_url.replace('https://github.com/', '').split('/');
                return `<a href="${event.target_url}" target="_blank" class="repo-link">${parts.slice(0,2).join('/')}</a>`;
            }
            return '-';
        }

        function truncatePath(path) {
            if (!path) return '-';
            if (path.length <= 25) return path;
            return '...' + path.slice(-22);
        }

        function renderEvents() {
            const tbody = document.getElementById('events-body');
            
            // Filtrar eventos (excluir métricas de la lista principal)
            let filtered = allEvents.filter(e => e.event_type !== 'agent_metrics');
            
            if (currentFilter === 'blocked') {
                filtered = filtered.filter(e => !e.is_allowed);
            } else if (currentFilter === 'allowed') {
                filtered = filtered.filter(e => e.is_allowed);
            } else if (currentFilter === 'git') {
                // Incluir todos los eventos relacionados con Git
                filtered = filtered.filter(e =>
                    e.event_type === 'git_command' ||
                    e.event_type === 'new_repo_detected' ||
                    (e.command_line && e.command_line.includes('git'))
                );
            } else if (currentFilter === 'network') {
                filtered = filtered.filter(e =>
                    e.event_type === 'network_connection' ||
                    e.event_type.startsWith('kernel_')
                );
            }
            
            if (filtered.length === 0) {
                tbody.innerHTML = '<tr class="no-events"><td colspan="8">No hay eventos</td></tr>';
                return;
            }
            
            tbody.innerHTML = filtered.slice(0, 100).map(event => `
                <tr>
                    <td class="time-cell">${formatTime(event.timestamp)}</td>
                    <td>${getEventBadge(event)}</td>
                    <td>${getOperationBadge(event)}</td>
                    <td class="repo-cell">${getRepoDisplay(event)}</td>
                    <td>${event.username || 'unknown'}</td>
                    <td class="ip-cell">${event.hostname}<br/><small>${event.source_ip || ''}</small></td>
                    <td>${event.branch || '-'}</td>
                    <td class="path-cell" title="${event.repo_path || event.working_directory || ''}">${truncatePath(event.repo_path || event.working_directory)}</td>
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

        // También actualizar datos de repos/unauthorized periódicamente para el badge
        setInterval(fetchUnauthorizedCount, 5000);
        fetchUnauthorizedCount();

        async function fetchUnauthorizedCount() {
            try {
                const response = await fetch('/api/unauthorized');
                const data = await response.json();
                unauthorizedData = data.unauthorized || [];
                const badge = document.getElementById('unauthorized-badge');
                if (unauthorizedData.length > 0) {
                    badge.style.display = 'inline';
                    badge.textContent = unauthorizedData.length;
                } else {
                    badge.style.display = 'none';
                }
            } catch (error) {
                console.error('Error fetching unauthorized:', error);
            }
        }

        async function fetchRepositories() {
            const grid = document.getElementById('repos-grid');
            try {
                const response = await fetch('/api/repositories');
                const data = await response.json();
                if (data.error) {
                    grid.innerHTML = '<p style="color: #ff4757; grid-column: 1/-1; text-align: center; padding: 40px;">Error: ' + data.error + '</p>';
                    return;
                }
                repositoriesData = Array.isArray(data.repositories) ? data.repositories : [];
                renderRepositories();
            } catch (error) {
                console.error('Error fetching repositories:', error);
                grid.innerHTML = '<p style="color: #ff4757; grid-column: 1/-1; text-align: center; padding: 40px;">Error de conexión: ' + error.message + '</p>';
            }
        }

        function renderRepositories() {
            const grid = document.getElementById('repos-grid');
            if (!repositoriesData || repositoriesData.length === 0) {
                grid.innerHTML = '<p style="color: #666; grid-column: 1/-1; text-align: center; padding: 40px;">No hay repositorios monitoreados aún.</p>';
                return;
            }

            grid.innerHTML = repositoriesData.map(repo => {
                const hasUnauthorized = repo.unauthorized_count > 0;

                // Renderizar colaboradores de GitHub
                let collabHtml = '';
                if (repo.collaborators && repo.collaborators.length > 0) {
                    collabHtml = `
                        <div class="collab-section">
                            <h4>👥 Colaboradores GitHub (${repo.collaborators.length})</h4>
                            <div class="collab-list">
                                ${repo.collaborators.map(c => `
                                    <div class="collab-item">
                                        <img src="${c.avatar}" alt="${c.username}">
                                        <span>${c.username}</span>
                                        <span class="collab-role ${c.role.toLowerCase()}">${c.role}</span>
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                    `;
                } else {
                    collabHtml = `
                        <div class="collab-section">
                            <h4>👥 Colaboradores GitHub</h4>
                            <p class="no-token-msg">Configure GITHUB_TOKEN para ver colaboradores</p>
                        </div>
                    `;
                }

                // Renderizar ubicaciones de clonación
                let cloneHtml = '';
                if (repo.clone_locations && repo.clone_locations.length > 0) {
                    cloneHtml = `
                        <div class="clone-section">
                            <h4>📍 Ubicaciones de Clonación (${repo.clone_locations.length})</h4>
                            ${repo.clone_locations.map(c => `
                                <div class="clone-item ${c.is_from_agent ? 'with-agent' : 'no-agent'}">
                                    <div class="path">${c.path || 'Ruta desconocida'}</div>
                                    <div class="meta">
                                        🖥️ ${c.hostname || '?'} (${c.ip || '?'}) •
                                        👤 ${c.username || '?'} •
                                        📅 ${formatDateTime(c.timestamp)}
                                        ${c.is_from_agent ? ' ✓ Con Agente' : ' ⚠️ Sin Agente'}
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    `;
                }

                return `
                    <div class="repo-card ${hasUnauthorized ? 'warning' : ''}">
                        <div class="repo-card-header">
                            <h3><a href="${repo.url || '#'}" target="_blank">${repo.name}</a></h3>
                            ${hasUnauthorized ? '<span class="alert-tag">⚠️ ' + repo.unauthorized_count + ' sin agente</span>' : ''}
                        </div>
                        <div class="repo-stats">
                            <div class="repo-stat">
                                <div class="repo-stat-value">${repo.total_clones}</div>
                                <div class="repo-stat-label">Clones</div>
                            </div>
                            <div class="repo-stat">
                                <div class="repo-stat-value">${repo.total_pushes}</div>
                                <div class="repo-stat-label">Pushes</div>
                            </div>
                            <div class="repo-stat">
                                <div class="repo-stat-value">${repo.total_pulls}</div>
                                <div class="repo-stat-label">Pulls</div>
                            </div>
                            <div class="repo-stat">
                                <div class="repo-stat-value">${repo.total_commits}</div>
                                <div class="repo-stat-label">Commits</div>
                            </div>
                        </div>
                        <div class="repo-users">
                            <small style="color:#666;">Usuarios DLP:</small>
                            ${repo.users.map(u => '<span class="user-tag">👤 ' + u + '</span>').join('')}
                        </div>
                        ${collabHtml}
                        ${cloneHtml}
                    </div>
                `;
            }).join('');
        }

        async function fetchDLPAgents() {
            const grid = document.getElementById('dlp-agents-grid');
            try {
                const response = await fetch('/api/agents');
                const data = await response.json();
                if (data.error) {
                    grid.innerHTML = '<p style="color: #ff4757;">Error: ' + data.error + '</p>';
                    return;
                }
                dlpAgentsData = data.agents || {};
                renderDLPAgents();
            } catch (error) {
                console.error('Error fetching agents:', error);
                grid.innerHTML = '<p style="color: #ff4757;">Error de conexión: ' + error.message + '</p>';
            }
        }

        function renderDLPAgents() {
            const grid = document.getElementById('dlp-agents-grid');
            const agents = Object.values(dlpAgentsData);

            if (agents.length === 0) {
                grid.innerHTML = '<p style="color: #666;">No hay agentes DLP registrados aún. Los agentes aparecerán cuando envíen su primer evento.</p>';
                return;
            }

            grid.innerHTML = agents.map(agent => `
                <div class="agent-info-card">
                    <h4>🖥️ ${agent.hostname}</h4>
                    <p>IP: <span class="ip">${agent.ip}</span></p>
                    <p>Primera vez: ${formatDateTime(agent.first_seen)}</p>
                    <p>Última actividad: ${formatDateTime(agent.last_seen)}</p>
                </div>
            `).join('');
        }

        async function fetchUnauthorized() {
            const list = document.getElementById('unauthorized-list');
            try {
                const response = await fetch('/api/unauthorized');
                const data = await response.json();
                if (data.error) {
                    list.innerHTML = '<p style="color: #ff4757;">Error: ' + data.error + '</p>';
                    return;
                }
                unauthorizedData = data.unauthorized || [];
                renderUnauthorized();
            } catch (error) {
                console.error('Error fetching unauthorized:', error);
                list.innerHTML = '<p style="color: #ff4757;">Error de conexión: ' + error.message + '</p>';
            }
        }

        function renderUnauthorized() {
            const list = document.getElementById('unauthorized-list');

            if (unauthorizedData.length === 0) {
                list.innerHTML = '<p style="color: #00ff88; padding: 20px; text-align: center;">✓ No se han detectado accesos desde equipos sin agente DLP.</p>';
                return;
            }

            list.innerHTML = unauthorizedData.map(item => {
                const isWebhook = item.source === 'github_webhook';
                const sourceIcon = isWebhook ? '🌐' : '🖥️';
                const sourceLabel = isWebhook ? 'GitHub Webhook' : 'Agente DLP';
                const eventType = item.event_type === 'push' ? '📤 Push' : '📥 Clone';

                return `
                    <div class="unauthorized-item">
                        <div class="details">
                            <span class="repo">${eventType} ${item.repo_name}</span>
                            <div class="info">
                                👤 ${item.username || 'unknown'}
                                ${!isWebhook ? ` desde <strong>${item.hostname || 'desconocido'}</strong> (${item.source_ip || 'IP desconocida'})` : ''}
                                ${item.email ? ` - ${item.email}` : ''}
                                ${item.commits_count ? ` - ${item.commits_count} commits` : ''}
                            </div>
                            <div style="margin-top: 5px;">
                                <span style="background: ${isWebhook ? '#ffa502' : '#a29bfe'}; color: #000; padding: 2px 8px; border-radius: 10px; font-size: 0.7rem;">
                                    ${sourceIcon} ${sourceLabel}
                                </span>
                                ${item.message ? `<span style="color: #888; font-size: 0.75rem; margin-left: 10px;">${item.message}</span>` : ''}
                            </div>
                        </div>
                        <div class="time">${formatDateTime(item.timestamp)}</div>
                    </div>
                `;
            }).join('');
        }

        function formatDateTime(isoString) {
            if (!isoString) return '-';
            const date = new Date(isoString);
            return date.toLocaleString('es-ES', {
                day: '2-digit',
                month: '2-digit',
                year: '2-digit',
                hour: '2-digit',
                minute: '2-digit'
            });
        }

        async function fetchOrganization() {
            const orgName = document.getElementById('org-name-input').value.trim();
            if (!orgName) {
                alert('Ingrese el nombre de la organización');
                return;
            }

            currentOrgName = orgName;
            const infoDiv = document.getElementById('org-info');
            const reposGrid = document.getElementById('org-repos-grid');
            const searchContainer = document.getElementById('repo-search-container');

            searchContainer.style.display = 'none';
            reposGrid.innerHTML = '<p style="color: #00d4ff; grid-column: 1/-1; text-align: center; padding: 40px;">⏳ Cargando organización ' + orgName + '...</p>';

            try {
                const response = await fetch('/api/github/org/' + encodeURIComponent(orgName));
                const data = await response.json();

                if (data.error) {
                    infoDiv.style.display = 'none';
                    reposGrid.innerHTML = '<p style="color: #ff4757; grid-column: 1/-1; text-align: center; padding: 40px;">Error: ' + data.error + '</p>';
                    return;
                }

                // Mostrar info de la organización
                const org = data.organization;
                infoDiv.style.display = 'block';
                infoDiv.innerHTML = `
                    <div style="display: flex; align-items: center; gap: 20px;">
                        <img src="${org.avatar}" style="width: 60px; height: 60px; border-radius: 10px;">
                        <div>
                            <h3 style="color: #00d4ff; margin: 0;">${org.name || org.login}</h3>
                            <p style="color: #888; margin: 5px 0;">${org.description || ''}</p>
                            <div style="display: flex; gap: 20px; margin-top: 10px;">
                                <span style="color: #00ff88;">📦 ${data.total_repos} repositorios</span>
                                <span style="color: #ffa502;">👥 ${data.members.length} miembros</span>
                                <span style="color: #a29bfe;">📋 Plan: ${org.plan || 'N/A'}</span>
                            </div>
                        </div>
                    </div>
                `;

                // Guardar repos para filtrar
                orgReposData = data.repositories;
                searchContainer.style.display = 'block';
                document.getElementById('repo-count').textContent = orgReposData.length + ' repositorios';

                // Mostrar repositorios
                if (data.repositories.length === 0) {
                    reposGrid.innerHTML = '<p style="color: #666; grid-column: 1/-1; text-align: center; padding: 40px;">No hay repositorios en esta organización.</p>';
                    return;
                }

                renderOrgRepos(orgReposData);
            } catch (error) {
                console.error('Error fetching organization:', error);
                reposGrid.innerHTML = '<p style="color: #ff4757; grid-column: 1/-1; text-align: center; padding: 40px;">Error de conexión: ' + error.message + '</p>';
            }
        }

        // Permitir Enter en el input
        document.addEventListener('DOMContentLoaded', function() {
            const input = document.getElementById('org-name-input');
            if (input) {
                input.addEventListener('keypress', function(e) {
                    if (e.key === 'Enter') fetchOrganization();
                });
            }
        });

        async function addCollaborator(org, repoName) {
            const username = document.getElementById('new-collab-' + repoName).value.trim();
            const permission = document.getElementById('new-collab-perm-' + repoName).value;

            if (!username) {
                alert('Ingrese el nombre de usuario de GitHub');
                return;
            }

            try {
                const response = await fetch('/api/github/org/' + encodeURIComponent(org) + '/repo/' + encodeURIComponent(repoName) + '/collaborators/' + encodeURIComponent(username), {
                    method: 'PUT',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({permission: permission})
                });
                const data = await response.json();

                if (data.error) {
                    alert('Error: ' + data.error);
                } else {
                    alert('Colaborador agregado exitosamente. Se enviará una invitación.');
                    loadCollaborators(org, repoName);
                }
            } catch (error) {
                alert('Error: ' + error.message);
            }
        }

        async function removeCollaborator(org, repoName, username) {
            if (!confirm('¿Eliminar a ' + username + ' como colaborador de ' + repoName + '?')) {
                return;
            }

            try {
                const response = await fetch('/api/github/org/' + encodeURIComponent(org) + '/repo/' + encodeURIComponent(repoName) + '/collaborators/' + encodeURIComponent(username), {
                    method: 'DELETE'
                });
                const data = await response.json();

                if (data.error) {
                    alert('Error: ' + data.error);
                } else {
                    alert('Colaborador eliminado');
                    loadCollaborators(org, repoName);
                }
            } catch (error) {
                alert('Error: ' + error.message);
            }
        }

        async function updatePermission(org, repoName, username, permission) {
            try {
                const response = await fetch('/api/github/org/' + encodeURIComponent(org) + '/repo/' + encodeURIComponent(repoName) + '/collaborators/' + encodeURIComponent(username), {
                    method: 'PUT',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({permission: permission})
                });
                const data = await response.json();

                if (data.error) {
                    alert('Error: ' + data.error);
                    loadCollaborators(org, repoName); // Recargar para mostrar estado correcto
                } else {
                    // Mostrar confirmación sutil
                    const container = document.getElementById('collabs-' + repoName);
                    const msg = document.createElement('span');
                    msg.style.cssText = 'color: #00ff88; font-size: 0.75rem; margin-left: 10px;';
                    msg.textContent = '✓ Permiso actualizado';
                    container.querySelector('h4').appendChild(msg);
                    setTimeout(() => msg.remove(), 2000);
                }
            } catch (error) {
                alert('Error: ' + error.message);
            }
        }

        // ============================================
        // Organization Repos - Sorting and Pagination
        // ============================================
        let orgRepoPage = 0;
        const REPOS_PER_PAGE = 10;
        let loadingCollaborators = {}; // Lock para evitar doble carga

        function sortOrgRepos(repos) {
            return repos.sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()));
        }

        function getAlphabetLetters(repos) {
            const letters = new Set();
            repos.forEach(repo => {
                const firstLetter = repo.name.charAt(0).toUpperCase();
                if (/[A-Z]/.test(firstLetter)) {
                    letters.add(firstLetter);
                } else {
                    letters.add('#'); // Para repos que empiezan con número o símbolo
                }
            });
            return Array.from(letters).sort();
        }

        function renderOrgRepos(repos) {
            const reposGrid = document.getElementById('org-repos-grid');

            if (repos.length === 0) {
                reposGrid.innerHTML = '<p style="color: #666; grid-column: 1/-1; text-align: center; padding: 40px;">No se encontraron repositorios.</p>';
                return;
            }

            // Ordenar alfabéticamente
            const sortedRepos = sortOrgRepos(repos);

            // Calcular paginación
            const totalPages = Math.ceil(sortedRepos.length / REPOS_PER_PAGE);
            if (orgRepoPage >= totalPages) orgRepoPage = 0;
            const start = orgRepoPage * REPOS_PER_PAGE;
            const end = start + REPOS_PER_PAGE;
            const pageRepos = sortedRepos.slice(start, end);

            // Obtener letras del alfabeto disponibles
            const letters = getAlphabetLetters(sortedRepos);

            // Generar menú alfabético
            const alphabetMenu = `
                <div style="grid-column: 1/-1; margin-bottom: 15px; display: flex; flex-wrap: wrap; gap: 5px; justify-content: center;">
                    ${letters.map(letter => `
                        <button onclick="jumpToLetter('${letter}')"
                                style="padding: 6px 12px; background: #16213e; color: #00d4ff; border: 1px solid #333; border-radius: 4px; cursor: pointer; font-weight: bold; min-width: 35px;">
                            ${letter}
                        </button>
                    `).join('')}
                </div>
            `;

            // Generar paginación
            const pagination = `
                <div style="grid-column: 1/-1; margin-top: 20px; display: flex; justify-content: center; align-items: center; gap: 15px;">
                    <button onclick="prevOrgRepoPage()" ${orgRepoPage === 0 ? 'disabled' : ''}
                            style="padding: 8px 20px; background: ${orgRepoPage === 0 ? '#333' : '#00d4ff'}; color: ${orgRepoPage === 0 ? '#666' : '#000'}; border: none; border-radius: 5px; cursor: ${orgRepoPage === 0 ? 'not-allowed' : 'pointer'};">
                        Anterior
                    </button>
                    <span style="color: #888;">Página ${orgRepoPage + 1} de ${totalPages} (${sortedRepos.length} repos)</span>
                    <button onclick="nextOrgRepoPage()" ${orgRepoPage >= totalPages - 1 ? 'disabled' : ''}
                            style="padding: 8px 20px; background: ${orgRepoPage >= totalPages - 1 ? '#333' : '#00d4ff'}; color: ${orgRepoPage >= totalPages - 1 ? '#666' : '#000'}; border: none; border-radius: 5px; cursor: ${orgRepoPage >= totalPages - 1 ? 'not-allowed' : 'pointer'};">
                        Siguiente
                    </button>
                </div>
            `;

            // Renderizar repos de la página actual
            const reposHtml = pageRepos.map((repo, index) => {
                return `
                    <div class="repo-card ${repo.private ? '' : 'public'}" id="repo-card-${repo.name}" data-letter="${repo.name.charAt(0).toUpperCase()}">
                        <div class="repo-card-header">
                            <h3><a href="${repo.url}" target="_blank">${repo.name}</a></h3>
                            <span class="${repo.private ? 'alert-tag' : 'user-tag'}">${repo.private ? 'Privado' : 'Público'}</span>
                        </div>
                        <p style="color: #888; font-size: 0.85rem; margin: 10px 0;">${repo.description || 'Sin descripción'}</p>
                        <div style="display: flex; gap: 15px; font-size: 0.8rem; color: #666; margin-bottom: 10px;">
                            <span>Creado: ${formatDateTime(repo.created_at)}</span>
                            <span>Último push: ${formatDateTime(repo.pushed_at)}</span>
                        </div>
                        <div style="font-size: 0.8rem; color: #888; margin-bottom: 10px;">
                            <span>Branch: ${repo.default_branch}</span>
                            ${repo.archived ? '<span style="color: #ff4757; margin-left: 10px;">Archivado</span>' : ''}
                        </div>
                        <div class="collab-section" id="collabs-${repo.name}">
                            <button onclick="loadCollaborators('${currentOrgName}', '${repo.name}')"
                                    id="btn-collabs-${repo.name}"
                                    style="padding: 6px 12px; background: #16213e; color: #00d4ff; border: 1px solid #00d4ff; border-radius: 4px; cursor: pointer; font-size: 0.8rem;">
                                Ver/Gestionar Colaboradores
                            </button>
                        </div>
                    </div>
                `;
            }).join('');

            reposGrid.innerHTML = alphabetMenu + reposHtml + pagination;
        }

        function prevOrgRepoPage() {
            if (orgRepoPage > 0) {
                orgRepoPage--;
                const searchTerm = document.getElementById('repo-search-input').value.toLowerCase();
                const filtered = searchTerm ? orgReposData.filter(repo =>
                    repo.name.toLowerCase().includes(searchTerm) ||
                    (repo.description && repo.description.toLowerCase().includes(searchTerm))
                ) : orgReposData;
                renderOrgRepos(filtered);
            }
        }

        function nextOrgRepoPage() {
            const searchTerm = document.getElementById('repo-search-input').value.toLowerCase();
            const filtered = searchTerm ? orgReposData.filter(repo =>
                repo.name.toLowerCase().includes(searchTerm) ||
                (repo.description && repo.description.toLowerCase().includes(searchTerm))
            ) : orgReposData;
            const totalPages = Math.ceil(filtered.length / REPOS_PER_PAGE);
            if (orgRepoPage < totalPages - 1) {
                orgRepoPage++;
                renderOrgRepos(filtered);
            }
        }

        function jumpToLetter(letter) {
            const sortedRepos = sortOrgRepos(orgReposData);
            let targetIndex = 0;

            for (let i = 0; i < sortedRepos.length; i++) {
                const repoLetter = sortedRepos[i].name.charAt(0).toUpperCase();
                const isMatch = (letter === '#' && !/[A-Z]/.test(repoLetter)) || repoLetter === letter;
                if (isMatch) {
                    targetIndex = i;
                    break;
                }
            }

            orgRepoPage = Math.floor(targetIndex / REPOS_PER_PAGE);
            renderOrgRepos(orgReposData);
        }

        function filterRepos() {
            orgRepoPage = 0; // Reset to first page when filtering
            const searchTerm = document.getElementById('repo-search-input').value.toLowerCase();
            const filtered = orgReposData.filter(repo =>
                repo.name.toLowerCase().includes(searchTerm) ||
                (repo.description && repo.description.toLowerCase().includes(searchTerm))
            );
            document.getElementById('repo-count').textContent = filtered.length + ' de ' + orgReposData.length + ' repositorios';
            renderOrgRepos(filtered);
        }

        // Función loadCollaborators con protección contra doble-click
        async function loadCollaborators(org, repoName) {
            // Prevenir doble carga
            if (loadingCollaborators[repoName]) {
                return;
            }
            loadingCollaborators[repoName] = true;

            const container = document.getElementById('collabs-' + repoName);
            const btn = document.getElementById('btn-collabs-' + repoName);
            if (btn) btn.disabled = true;

            container.innerHTML = '<span style="color: #00d4ff; font-size: 0.8rem;">Cargando...</span>';

            try {
                const response = await fetch('/api/github/org/' + encodeURIComponent(org) + '/repo/' + encodeURIComponent(repoName) + '/collaborators');
                const data = await response.json();

                if (data.error) {
                    container.innerHTML = '<span style="color: #ff4757; font-size: 0.8rem;">Error: ' + data.error + '</span>';
                    loadingCollaborators[repoName] = false;
                    return;
                }

                // Limpiar contenido previo completamente
                container.innerHTML = '';

                let collabsHtml = '';
                if (data.collaborators && data.collaborators.length > 0) {
                    // Usar Set para evitar duplicados
                    const uniqueCollabs = [];
                    const seenUsernames = new Set();
                    data.collaborators.forEach(c => {
                        if (!seenUsernames.has(c.username)) {
                            seenUsernames.add(c.username);
                            uniqueCollabs.push(c);
                        }
                    });

                    collabsHtml = uniqueCollabs.map(c => `
                        <div class="collab-item" style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px; padding: 8px; background: #16213e; border-radius: 6px;">
                            <img src="${c.avatar}" alt="${c.username}" style="width: 24px; height: 24px; border-radius: 50%;">
                            <span style="flex: 1;">${c.username}</span>
                            <select onchange="updatePermission('${org}', '${repoName}', '${c.username}', this.value)"
                                    style="padding: 4px 8px; background: #1a1a2e; color: #e0e0e0; border: 1px solid #333; border-radius: 4px; font-size: 0.75rem;">
                                <option value="pull" ${c.role === 'Read' ? 'selected' : ''}>Read</option>
                                <option value="triage" ${c.role === 'Triage' ? 'selected' : ''}>Triage</option>
                                <option value="push" ${c.role === 'Write' ? 'selected' : ''}>Write</option>
                                <option value="maintain" ${c.role === 'Maintainer' ? 'selected' : ''}>Maintain</option>
                                <option value="admin" ${c.role === 'Admin' ? 'selected' : ''}>Admin</option>
                            </select>
                            <button onclick="removeCollaborator('${org}', '${repoName}', '${c.username}')"
                                    style="padding: 4px 8px; background: #ff4757; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.75rem;"
                                    title="Eliminar colaborador">X</button>
                        </div>
                    `).join('');
                } else {
                    collabsHtml = '<p style="color: #888; font-size: 0.8rem;">Sin colaboradores directos</p>';
                }

                container.innerHTML = `
                    <h4 style="color: #888; font-size: 0.8rem; margin-bottom: 10px;">Colaboradores (${data.collaborators ? data.collaborators.length : 0})</h4>
                    ${collabsHtml}
                    <div style="margin-top: 12px; padding-top: 12px; border-top: 1px solid #333;">
                        <h5 style="color: #888; font-size: 0.75rem; margin-bottom: 8px;">Agregar colaborador:</h5>
                        <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                            <input type="text" id="new-collab-${repoName}" placeholder="Usuario GitHub"
                                   style="padding: 6px 10px; background: #1a1a2e; color: #e0e0e0; border: 1px solid #333; border-radius: 4px; font-size: 0.8rem; width: 150px;">
                            <select id="new-collab-perm-${repoName}"
                                    style="padding: 6px 10px; background: #1a1a2e; color: #e0e0e0; border: 1px solid #333; border-radius: 4px; font-size: 0.8rem;">
                                <option value="pull">Read</option>
                                <option value="triage">Triage</option>
                                <option value="push" selected>Write</option>
                                <option value="maintain">Maintain</option>
                                <option value="admin">Admin</option>
                            </select>
                            <button onclick="addCollaborator('${org}', '${repoName}')"
                                    style="padding: 6px 12px; background: #00ff88; color: #000; border: none; border-radius: 4px; cursor: pointer; font-size: 0.8rem; font-weight: 600;">
                                Agregar
                            </button>
                        </div>
                    </div>
                `;
            } catch (error) {
                container.innerHTML = '<span style="color: #ff4757; font-size: 0.8rem;">Error: ' + error.message + '</span>';
            } finally {
                loadingCollaborators[repoName] = false;
            }
        }

        // ============================================
        // History Tab Functions
        // ============================================
        let historyData = [];
        let historyPage = 0;
        const HISTORY_PAGE_SIZE = 50;

        async function searchHistory() {
            const resultsDiv = document.getElementById('history-results');
            const statsDiv = document.getElementById('history-stats');
            const paginationDiv = document.getElementById('history-pagination');

            resultsDiv.innerHTML = '<p style="color: #00d4ff; text-align: center; padding: 40px;">Buscando...</p>';
            statsDiv.innerHTML = '';
            paginationDiv.style.display = 'none';
            historyPage = 0;

            // Recoger filtros
            const params = new URLSearchParams();

            const dateFrom = document.getElementById('filter-date-from').value;
            const dateTo = document.getElementById('filter-date-to').value;
            const hourFrom = document.getElementById('filter-hour-from').value;
            const hourTo = document.getElementById('filter-hour-to').value;
            const username = document.getElementById('filter-username').value.trim();
            const repo = document.getElementById('filter-repo').value.trim();
            const operation = document.getElementById('filter-operation').value;
            const limit = document.getElementById('filter-limit').value;

            if (dateFrom) params.append('date_from', dateFrom);
            if (dateTo) params.append('date_to', dateTo);
            if (hourFrom) params.append('hour_from', hourFrom);
            if (hourTo) params.append('hour_to', hourTo);
            if (username) params.append('username', username);
            if (repo) params.append('repo_name', repo);
            if (operation) params.append('git_operation', operation);
            params.append('limit', limit);

            try {
                const response = await fetch('/api/db/events?' + params.toString());
                const data = await response.json();

                if (data.error) {
                    resultsDiv.innerHTML = '<p style="color: #ff4757; text-align: center; padding: 40px;">Error: ' + data.error + '</p>';
                    return;
                }

                historyData = data.events || [];

                // Mostrar estadísticas
                if (data.stats) {
                    statsDiv.innerHTML = `
                        <div class="stat-card">
                            <div class="stat-value">${data.stats.total || historyData.length}</div>
                            <div class="stat-label">Total Eventos</div>
                        </div>
                        <div class="stat-card success">
                            <div class="stat-value">${data.stats.unique_users || '-'}</div>
                            <div class="stat-label">Usuarios</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value">${data.stats.unique_repos || '-'}</div>
                            <div class="stat-label">Repositorios</div>
                        </div>
                    `;
                }

                renderHistoryResults();
            } catch (error) {
                resultsDiv.innerHTML = '<p style="color: #ff4757; text-align: center; padding: 40px;">Error de conexión: ' + error.message + '</p>';
            }
        }

        function renderHistoryResults() {
            const resultsDiv = document.getElementById('history-results');
            const paginationDiv = document.getElementById('history-pagination');

            if (historyData.length === 0) {
                resultsDiv.innerHTML = '<p style="color: #666; text-align: center; padding: 40px;">No se encontraron eventos con los filtros seleccionados.</p>';
                paginationDiv.style.display = 'none';
                return;
            }

            // Paginación
            const totalPages = Math.ceil(historyData.length / HISTORY_PAGE_SIZE);
            const start = historyPage * HISTORY_PAGE_SIZE;
            const end = start + HISTORY_PAGE_SIZE;
            const pageData = historyData.slice(start, end);

            // Tabla de resultados
            resultsDiv.innerHTML = `
                <table class="events-table">
                    <thead>
                        <tr>
                            <th>Fecha/Hora</th>
                            <th>Usuario</th>
                            <th>Operación</th>
                            <th>Repositorio</th>
                            <th>Host</th>
                            <th>IP</th>
                            <th>Rama</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${pageData.map(e => `
                            <tr>
                                <td class="time-cell">${formatDateTime(e.timestamp)}</td>
                                <td>${e.username || '-'}</td>
                                <td><span class="op-badge">${e.git_operation || e.event_type || '-'}</span></td>
                                <td class="repo-cell">${e.repo_name ? `<a href="https://github.com/${e.repo_name}" target="_blank" class="repo-link">${e.repo_name}</a>` : '-'}</td>
                                <td>${e.hostname || '-'}</td>
                                <td class="ip-cell">${e.source_ip || '-'}</td>
                                <td>${e.branch || '-'}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            `;

            // Mostrar paginación si hay más de una página
            if (totalPages > 1) {
                paginationDiv.style.display = 'block';
                document.getElementById('history-page-info').textContent = `Página ${historyPage + 1} de ${totalPages} (${historyData.length} eventos)`;
                document.getElementById('btn-prev-page').disabled = historyPage === 0;
                document.getElementById('btn-next-page').disabled = historyPage >= totalPages - 1;
            } else {
                paginationDiv.style.display = 'none';
            }
        }

        function historyPrevPage() {
            if (historyPage > 0) {
                historyPage--;
                renderHistoryResults();
            }
        }

        function historyNextPage() {
            const totalPages = Math.ceil(historyData.length / HISTORY_PAGE_SIZE);
            if (historyPage < totalPages - 1) {
                historyPage++;
                renderHistoryResults();
            }
        }

        function clearFilters() {
            document.getElementById('filter-date-from').value = '';
            document.getElementById('filter-date-to').value = '';
            document.getElementById('filter-hour-from').value = '';
            document.getElementById('filter-hour-to').value = '';
            document.getElementById('filter-username').value = '';
            document.getElementById('filter-repo').value = '';
            document.getElementById('filter-operation').value = '';
            document.getElementById('filter-limit').value = '100';

            historyData = [];
            historyPage = 0;
            document.getElementById('history-results').innerHTML = '<p style="color: #666; text-align: center; padding: 40px;">Usa los filtros para buscar eventos en el historial.</p>';
            document.getElementById('history-stats').innerHTML = '';
            document.getElementById('history-pagination').style.display = 'none';
        }

        function exportHistory() {
            if (historyData.length === 0) {
                alert('No hay datos para exportar. Realice una búsqueda primero.');
                return;
            }

            // Crear CSV
            const headers = ['Fecha/Hora', 'Usuario', 'Operación', 'Repositorio', 'Host', 'IP', 'Rama'];
            const rows = historyData.map(e => [
                e.timestamp || '',
                e.username || '',
                e.git_operation || e.event_type || '',
                e.repo_name || '',
                e.hostname || '',
                e.source_ip || '',
                e.branch || ''
            ]);

            let csv = headers.join(',') + '\\n';
            rows.forEach(row => {
                csv += row.map(cell => '"' + String(cell).replace(/"/g, '""') + '"').join(',') + '\\n';
            });

            // Descargar
            const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
            const link = document.createElement('a');
            link.href = URL.createObjectURL(blob);
            link.download = 'historial_dlp_' + new Date().toISOString().slice(0,10) + '.csv';
            link.click();
        }

        // ============================================
        // Traffic Statistics Functions
        // ============================================
        let trafficData = null;

        async function fetchTrafficStats() {
            const orgName = document.getElementById('traffic-org-input').value.trim();
            if (!orgName) {
                alert('Ingrese el nombre de la organización');
                return;
            }

            // Mostrar loading
            document.getElementById('traffic-loading').style.display = 'block';
            document.getElementById('traffic-empty').style.display = 'none';
            document.getElementById('traffic-error').style.display = 'none';
            document.getElementById('traffic-summary').style.display = 'none';
            document.getElementById('traffic-daily-chart').style.display = 'none';
            document.getElementById('traffic-repos-section').style.display = 'none';

            try {
                const response = await fetch('/api/github/org/' + encodeURIComponent(orgName) + '/traffic');
                const data = await response.json();

                document.getElementById('traffic-loading').style.display = 'none';

                if (data.error) {
                    document.getElementById('traffic-error').textContent = 'Error: ' + data.error;
                    document.getElementById('traffic-error').style.display = 'block';
                    return;
                }

                trafficData = data;
                renderTrafficStats();
            } catch (error) {
                document.getElementById('traffic-loading').style.display = 'none';
                document.getElementById('traffic-error').textContent = 'Error de conexión: ' + error.message;
                document.getElementById('traffic-error').style.display = 'block';
            }
        }

        function renderTrafficStats() {
            if (!trafficData) return;

            // Mostrar resumen
            document.getElementById('traffic-total-clones').textContent = trafficData.total_clones || 0;
            document.getElementById('traffic-unique-cloners').textContent = trafficData.total_unique_cloners || 0;
            document.getElementById('traffic-total-views').textContent = trafficData.total_views || 0;
            document.getElementById('traffic-unique-visitors').textContent = trafficData.total_unique_visitors || 0;
            document.getElementById('traffic-summary').style.display = 'block';

            // Gráfica de clones diarios
            const dailyData = trafficData.daily_clones_list || [];
            if (dailyData.length > 0) {
                const maxCount = Math.max(...dailyData.map(d => d.count), 1);
                const chartHtml = dailyData.map(d => {
                    const height = Math.max((d.count / maxCount) * 120, 5);
                    const date = d.date.slice(5); // MM-DD
                    return `
                        <div style="display: flex; flex-direction: column; align-items: center; flex: 1;">
                            <div style="background: linear-gradient(to top, #00d4ff, #00ff88); width: 100%; height: ${height}px; border-radius: 4px 4px 0 0; min-width: 20px;" title="${d.count} clones"></div>
                            <div style="font-size: 0.7rem; color: #888; margin-top: 5px; writing-mode: vertical-rl; transform: rotate(180deg);">${date}</div>
                            <div style="font-size: 0.75rem; color: #00d4ff; font-weight: bold;">${d.count}</div>
                        </div>
                    `;
                }).join('');
                document.getElementById('daily-chart-bars').innerHTML = chartHtml;
                document.getElementById('traffic-daily-chart').style.display = 'block';
            }

            // Tabla de repos
            const repos = trafficData.repos_with_traffic || [];
            if (repos.length > 0) {
                const tbody = document.getElementById('traffic-repos-body');
                tbody.innerHTML = repos.map(r => `
                    <tr>
                        <td><a href="${r.url}" target="_blank" class="repo-link">${r.name}</a></td>
                        <td><span class="${r.private ? 'badge blocked' : 'badge allowed'}">${r.private ? 'Privado' : 'Público'}</span></td>
                        <td style="font-weight: bold; color: #00d4ff;">${r.clones}</td>
                        <td>${r.unique_cloners}</td>
                        <td>${r.views}</td>
                        <td>${r.unique_visitors}</td>
                    </tr>
                `).join('');
                document.getElementById('traffic-repos-section').style.display = 'block';
            }
        }

        // Permitir Enter en el input de tráfico
        document.addEventListener('DOMContentLoaded', function() {
            const trafficInput = document.getElementById('traffic-org-input');
            if (trafficInput) {
                trafficInput.addEventListener('keypress', function(e) {
                    if (e.key === 'Enter') fetchTrafficStats();
                });
            }
            const correlationInput = document.getElementById('correlation-org-input');
            if (correlationInput) {
                correlationInput.addEventListener('keypress', function(e) {
                    if (e.key === 'Enter') fetchCorrelation();
                });
            }
        });

        // ============================================
        // Correlation Functions
        // ============================================
        let correlationData = null;
        const dayNames = ['Domingo', 'Lunes', 'Martes', 'Miércoles', 'Jueves', 'Viernes', 'Sábado'];

        async function fetchCorrelation() {
            const orgName = document.getElementById('correlation-org-input').value.trim();
            if (!orgName) {
                alert('Ingrese el nombre de la organización');
                return;
            }

            // Mostrar loading
            document.getElementById('correlation-loading').style.display = 'block';
            document.getElementById('correlation-empty').style.display = 'none';
            document.getElementById('correlation-error').style.display = 'none';
            document.getElementById('correlation-alerts').style.display = 'none';
            document.getElementById('correlation-table-section').style.display = 'none';

            try {
                const response = await fetch('/api/github/org/' + encodeURIComponent(orgName) + '/correlation');
                const data = await response.json();

                document.getElementById('correlation-loading').style.display = 'none';

                if (data.error) {
                    document.getElementById('correlation-error').textContent = 'Error: ' + data.error;
                    document.getElementById('correlation-error').style.display = 'block';
                    return;
                }

                correlationData = data;
                renderCorrelation();
            } catch (error) {
                document.getElementById('correlation-loading').style.display = 'none';
                document.getElementById('correlation-error').textContent = 'Error de conexión: ' + error.message;
                document.getElementById('correlation-error').style.display = 'block';
            }
        }

        function renderCorrelation() {
            if (!correlationData) return;

            // Mostrar alertas si hay
            const alerts = correlationData.alerts || [];
            if (alerts.length > 0) {
                const alertsHtml = alerts.map(a => `
                    <div style="margin-bottom: 10px; padding: 10px; background: #1a1a2e; border-radius: 6px; border-left: 3px solid #ff4757;">
                        <strong style="color: #ff4757;">${a.message}</strong><br>
                        <span style="color: #888;">Repo: ${a.repo} | Fecha: ${a.date}</span><br>
                        <span style="color: #ffa502;">Usuarios con acceso: ${a.collaborators.join(', ') || 'N/A'}</span>
                    </div>
                `).join('');
                document.getElementById('correlation-alerts-list').innerHTML = alertsHtml;
                document.getElementById('correlation-alerts').style.display = 'block';
            }

            // Tabla de correlación
            const dates = correlationData.dates_sorted || [];
            const byDate = correlationData.by_date || {};

            let tableHtml = '';
            for (const date of dates) {
                const entries = byDate[date] || [];
                for (const entry of entries) {
                    const dateObj = new Date(date + 'T12:00:00');
                    const dayName = dayNames[dateObj.getDay()];
                    const isWeekend = entry.is_weekend;

                    const collabsDisplay = entry.collaborators.length > 3
                        ? entry.collaborators.slice(0, 3).join(', ') + ` +${entry.collaborators.length - 3} más`
                        : entry.collaborators.join(', ') || 'N/A';

                    tableHtml += `
                        <tr style="${isWeekend ? 'background: #2a1a1a;' : ''}">
                            <td style="font-weight: bold;">${date}</td>
                            <td style="${isWeekend ? 'color: #ff4757; font-weight: bold;' : ''}">${dayName}${isWeekend ? ' ⚠️' : ''}</td>
                            <td><a href="${entry.repo_url}" target="_blank" class="repo-link">${entry.repo}</a></td>
                            <td><span class="${entry.private ? 'badge blocked' : 'badge allowed'}">${entry.private ? 'Privado' : 'Público'}</span></td>
                            <td style="font-weight: bold; color: #00d4ff;">${entry.clones} <span style="color: #888; font-weight: normal;">(${entry.unique_cloners} únicos)</span></td>
                            <td style="font-size: 0.85rem;" title="${entry.collaborators.join(', ')}">${collabsDisplay}</td>
                        </tr>
                    `;
                }
            }

            if (tableHtml) {
                document.getElementById('correlation-table-body').innerHTML = tableHtml;
                document.getElementById('correlation-table-section').style.display = 'block';
            } else {
                document.getElementById('correlation-table-section').style.display = 'none';
                document.getElementById('correlation-empty').textContent = 'No se encontró actividad de clones en los últimos 14 días.';
                document.getElementById('correlation-empty').style.display = 'block';
            }
        }

        // ============================================
        // Preload Organization on Tab Switch
        // ============================================
        const DEFAULT_ORG = 'Delfix-CR';

        function switchTab(tabName) {
            currentTab = tabName;
            document.querySelectorAll('.nav-tab').forEach(btn => btn.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
            event.target.classList.add('active');
            document.getElementById('tab-' + tabName).classList.add('active');

            // Cargar datos de la pestaña
            if (tabName === 'repositories') fetchRepositories();
            if (tabName === 'agents') fetchDLPAgents();
            if (tabName === 'unauthorized') fetchUnauthorized();
            if (tabName === 'organization') {
                // Precargar organización por defecto si no hay datos
                if (orgReposData.length === 0) {
                    document.getElementById('org-name-input').value = DEFAULT_ORG;
                    fetchOrganization();
                }
            }
            if (tabName === 'traffic') {
                // Precargar organización por defecto si no hay datos
                if (!trafficData) {
                    document.getElementById('traffic-org-input').value = DEFAULT_ORG;
                    fetchTrafficStats();
                }
            }
            if (tabName === 'correlation') {
                // Precargar organización por defecto si no hay datos
                if (!correlationData) {
                    document.getElementById('correlation-org-input').value = DEFAULT_ORG;
                    fetchCorrelation();
                }
            }
        }
    </script>
</body>
</html>
"""

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(name)s] %(levelname)s: %(message)s'
)
logger = logging.getLogger("DLPConsole")

# Importar tracking de repositorios
try:
    from github_integration import repo_tracker, github_api
    REPO_TRACKING_ENABLED = True
    logger.info(f"✓ Repository tracking habilitado. Data dir: {repo_tracker.data_dir}")
except ImportError as e:
    REPO_TRACKING_ENABLED = False
    repo_tracker = None
    github_api = None
    logger.warning(f"Repository tracking deshabilitado: {e}")
except Exception as e:
    REPO_TRACKING_ENABLED = False
    repo_tracker = None
    github_api = None
    logger.error(f"Error cargando github_integration: {e}")

# Importar webhook handler
try:
    from github_webhook import webhook_handler
    WEBHOOK_ENABLED = True
    logger.info("✓ GitHub Webhook handler habilitado")
except ImportError as e:
    WEBHOOK_ENABLED = False
    webhook_handler = None
    logger.warning(f"GitHub Webhook deshabilitado: {e}")

# Importar base de datos
try:
    from database import db as dlp_db
    DATABASE_ENABLED = True
    logger.info("✓ Base de datos SQLite habilitada")
except ImportError as e:
    DATABASE_ENABLED = False
    dlp_db = None
    logger.warning(f"Base de datos deshabilitada: {e}")


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

        # Contar por tipo (incluir nuevos tipos git_*)
        if event_type.startswith("git_") or event_type == "git_command":
            stats["git_commands"] += 1
        elif event_type == "network_connection":
            stats["network_connections"] += 1
        elif event_type == "new_repo_detected":
            stats["repos_detected"] += 1

        stats["unique_users"].add(event_data.get("username", "unknown"))
        stats["unique_hosts"].add(event_data.get("hostname", "unknown"))

    # Tracking de repositorios
    if REPO_TRACKING_ENABLED and repo_tracker:
        try:
            repo_tracker.track_event(event_data)
        except Exception as e:
            logger.error(f"Error en repo tracking: {e}")

    # Guardar en base de datos
    if DATABASE_ENABLED and dlp_db:
        try:
            dlp_db.insert_dlp_event(event_data)
        except Exception as e:
            logger.error(f"Error guardando en base de datos: {e}")
    
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
    # Si auth está habilitado y usuario no autenticado, redirigir a login
    if AUTH_ENABLED and is_auth_enabled():
        if not current_user.is_authenticated:
            return redirect('/login')
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


@app.route('/api/status')
def api_status():
    """API endpoint para estado del sistema"""
    return jsonify({
        "repo_tracking_enabled": REPO_TRACKING_ENABLED,
        "github_api_configured": github_api.is_configured() if github_api else False,
        "data_dir": str(repo_tracker.data_dir) if repo_tracker else None,
        "repos_count": len(repo_tracker.repositories) if repo_tracker else 0,
        "agents_count": len(repo_tracker.known_agents) if repo_tracker else 0,
    })


@app.route('/api/repositories')
def api_repositories():
    """API endpoint para repositorios rastreados"""
    if not REPO_TRACKING_ENABLED or not repo_tracker:
        return jsonify({"error": "Repository tracking not enabled", "repositories": {}})

    repos = repo_tracker.get_all_repositories()
    # Formatear para el frontend
    formatted = []
    for name, data in repos.items():
        # Obtener colaboradores de GitHub si está configurado
        collaborators = []
        if github_api and github_api.is_configured() and '/' in name:
            parts = name.split('/')
            if len(parts) >= 2:
                owner, repo = parts[0], parts[1]
                collaborators = github_api.get_repo_collaborators(owner, repo)

        # Obtener ubicaciones de clonación
        clone_locations = []
        for clone in data.get("clone_events", []):
            clone_locations.append({
                "path": clone.get("repo_path"),
                "hostname": clone.get("hostname"),
                "ip": clone.get("source_ip"),
                "username": clone.get("username"),
                "timestamp": clone.get("timestamp"),
                "is_from_agent": clone.get("is_from_agent", False)
            })

        formatted.append({
            "name": name,
            "url": data.get("repo_url"),
            "first_seen": data.get("first_seen"),
            "total_clones": data.get("total_clones", 0),
            "total_pushes": data.get("total_pushes", 0),
            "total_pulls": data.get("total_pulls", 0),
            "total_commits": data.get("total_commits", 0),
            "users": list(data.get("users", {}).keys()),
            "user_count": len(data.get("users", {})),
            "unauthorized_count": len(data.get("unauthorized_access", [])),
            "recent_activity": data.get("activity", [])[-10:],
            "collaborators": collaborators,
            "clone_locations": clone_locations
        })
    return jsonify({"repositories": formatted})


@app.route('/api/repositories/<path:repo_name>')
def api_repository_detail(repo_name):
    """API endpoint para detalle de un repositorio"""
    if not REPO_TRACKING_ENABLED or not repo_tracker:
        return jsonify({"error": "Repository tracking not enabled"})

    repo = repo_tracker.get_repository_summary(repo_name)
    if not repo:
        return jsonify({"error": "Repository not found"}), 404

    return jsonify(repo)


@app.route('/api/agents')
def api_agents():
    """API endpoint para agentes conocidos"""
    if not REPO_TRACKING_ENABLED or not repo_tracker:
        return jsonify({"agents": {}})

    return jsonify({"agents": repo_tracker.get_known_agents()})


@app.route('/api/unauthorized')
def api_unauthorized():
    """API endpoint para clones no autorizados (incluye datos de webhook)"""
    unauthorized = []

    # Obtener clones no autorizados desde agentes DLP
    if REPO_TRACKING_ENABLED and repo_tracker:
        for item in repo_tracker.get_unauthorized_clones():
            item["source"] = "dlp_agent"
            unauthorized.append(item)

    # Obtener pushes no autorizados desde webhook de GitHub
    if WEBHOOK_ENABLED and webhook_handler:
        for item in webhook_handler.get_unauthorized_pushes():
            item["source"] = "github_webhook"
            unauthorized.append(item)

    # Ordenar por timestamp
    unauthorized.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

    return jsonify({"unauthorized": unauthorized})


@app.route('/api/github/repo/<owner>/<repo>')
def api_github_repo(owner, repo):
    """API endpoint para info de GitHub"""
    if not REPO_TRACKING_ENABLED or not github_api or not github_api.is_configured():
        return jsonify({"error": "GitHub API not configured. Set GITHUB_TOKEN environment variable."})

    info = github_api.get_repo_info(owner, repo)
    collaborators = github_api.get_repo_collaborators(owner, repo)
    traffic = github_api.get_repo_traffic(owner, repo)

    return jsonify({
        "info": info,
        "collaborators": collaborators,
        "traffic": traffic
    })


@app.route('/api/github/org/<org>')
def api_github_org(org):
    """API endpoint para información de organización GitHub"""
    if not github_api or not github_api.is_configured():
        return jsonify({"error": "GitHub API not configured. Set GITHUB_TOKEN environment variable."})

    org_info = github_api.get_org_info(org)
    if not org_info:
        return jsonify({"error": f"Organization '{org}' not found or no access"})

    repos = github_api.get_org_repos(org)
    members = github_api.get_org_members(org)

    # NO cargar colaboradores automáticamente (muy lento para muchos repos)
    # Los colaboradores se cargan bajo demanda con /api/github/repo/<owner>/<repo>

    return jsonify({
        "organization": org_info,
        "repositories": repos,
        "members": members,
        "total_repos": len(repos)
    })


@app.route('/api/github/org/<org>/repo/<repo>/collaborators')
def api_github_repo_collaborators(org, repo):
    """API endpoint para colaboradores de un repo específico"""
    if not github_api or not github_api.is_configured():
        return jsonify({"error": "GitHub API not configured"})

    collaborators = github_api.get_repo_collaborators(org, repo)
    return jsonify({"collaborators": collaborators})


@app.route('/api/github/org/<org>/repo/<repo>/collaborators/<username>', methods=['PUT'])
def api_add_collaborator(org, repo, username):
    """API endpoint para agregar colaborador"""
    if not github_api or not github_api.is_configured():
        return jsonify({"error": "GitHub API not configured"})

    from flask import request
    data = request.get_json() or {}
    permission = data.get('permission', 'push')

    result = github_api.add_collaborator(org, repo, username, permission)
    return jsonify(result)


@app.route('/api/github/org/<org>/repo/<repo>/collaborators/<username>', methods=['DELETE'])
def api_remove_collaborator(org, repo, username):
    """API endpoint para eliminar colaborador"""
    if not github_api or not github_api.is_configured():
        return jsonify({"error": "GitHub API not configured"})

    result = github_api.remove_collaborator(org, repo, username)
    return jsonify(result)


@app.route('/api/github/org/<org>/repo/<repo>/collaborators/<username>/permission', methods=['PUT'])
def api_update_collaborator_permission(org, repo, username):
    """API endpoint para actualizar permiso de colaborador"""
    if not github_api or not github_api.is_configured():
        return jsonify({"error": "GitHub API not configured"})

    from flask import request
    data = request.get_json() or {}
    permission = data.get('permission')

    if not permission:
        return jsonify({"error": "Se requiere el campo 'permission'"})

    result = github_api.update_collaborator_permission(org, repo, username, permission)
    return jsonify(result)


# ============== GitHub Traffic Statistics Endpoints ==============

@app.route('/api/github/org/<org>/traffic')
def api_org_traffic(org):
    """API endpoint para obtener estadísticas de tráfico de la organización"""
    if not github_api or not github_api.is_configured():
        return jsonify({"error": "GitHub API not configured. Set GITHUB_TOKEN environment variable."})

    try:
        traffic_data = github_api.get_org_traffic_summary(org)
        return jsonify(traffic_data)
    except Exception as e:
        logger.error(f"Error obteniendo tráfico de {org}: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/github/repo/<owner>/<repo>/traffic')
def api_repo_traffic(owner, repo):
    """API endpoint para obtener estadísticas de tráfico de un repositorio específico"""
    if not github_api or not github_api.is_configured():
        return jsonify({"error": "GitHub API not configured. Set GITHUB_TOKEN environment variable."})

    try:
        traffic_data = github_api.get_repo_traffic(owner, repo)
        traffic_data["repo"] = f"{owner}/{repo}"
        traffic_data["timestamp"] = datetime.now().isoformat()
        return jsonify(traffic_data)
    except Exception as e:
        logger.error(f"Error obteniendo tráfico de {owner}/{repo}: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/github/org/<org>/correlation')
def api_access_correlation(org):
    """API endpoint para correlación de accesos - muestra clones por fecha con colaboradores"""
    if not github_api or not github_api.is_configured():
        return jsonify({"error": "GitHub API not configured. Set GITHUB_TOKEN environment variable."})

    try:
        correlation_data = github_api.get_access_correlation(org)

        # Guardar en histórico de base de datos (persistencia permanente)
        if DATABASE_ENABLED and dlp_db:
            try:
                traffic_entries = []
                by_date = correlation_data.get('by_date', {})

                for date_str, entries in by_date.items():
                    for entry in entries:
                        traffic_entries.append({
                            'date': date_str,
                            'repo_name': entry.get('repo'),
                            'repo_url': entry.get('repo_url'),
                            'is_private': entry.get('private', False),
                            'clones': entry.get('clones', 0),
                            'unique_cloners': entry.get('unique_cloners', 0),
                            'collaborators': entry.get('collaborators', []),
                            'is_weekend': entry.get('is_weekend', False)
                        })

                saved = dlp_db.save_traffic_data(org, traffic_entries)

                # Guardar alertas nuevas
                for alert in correlation_data.get('alerts', []):
                    dlp_db.save_access_alert({
                        'date': alert.get('date'),
                        'organization': org,
                        'repo_name': alert.get('repo'),
                        'alert_type': alert.get('type'),
                        'clones': alert.get('clones', 0),
                        'message': alert.get('message'),
                        'collaborators': alert.get('collaborators', [])
                    })

                correlation_data['saved_to_history'] = saved
                logger.info(f"✓ Guardados {saved} registros en histórico para {org}")
            except Exception as e:
                logger.error(f"Error guardando en histórico: {e}")

        return jsonify(correlation_data)
    except Exception as e:
        logger.error(f"Error obteniendo correlación de {org}: {e}")
        return jsonify({"error": str(e)}), 500


# ============== Traffic History Endpoints ==============

@app.route('/api/traffic/history')
def api_traffic_history():
    """API endpoint para consultar histórico de tráfico (datos guardados permanentemente)"""
    if not DATABASE_ENABLED or not dlp_db:
        return jsonify({"error": "Database not enabled"}), 503

    from flask import request

    filters = {}
    if request.args.get('organization'):
        filters['organization'] = request.args.get('organization')
    if request.args.get('repo_name'):
        filters['repo_name'] = request.args.get('repo_name')
    if request.args.get('date_from'):
        filters['date_from'] = request.args.get('date_from')
    if request.args.get('date_to'):
        filters['date_to'] = request.args.get('date_to')
    if request.args.get('is_weekend'):
        filters['is_weekend'] = request.args.get('is_weekend') == 'true'

    limit = int(request.args.get('limit', 500))

    history = dlp_db.get_traffic_history(filters, limit)
    return jsonify({
        "history": history,
        "count": len(history),
        "filters": filters
    })


@app.route('/api/traffic/stats')
def api_traffic_stats():
    """API endpoint para estadísticas del histórico de tráfico (último año)"""
    if not DATABASE_ENABLED or not dlp_db:
        return jsonify({"error": "Database not enabled"}), 503

    from flask import request

    organization = request.args.get('organization')
    days = int(request.args.get('days', 365))

    stats = dlp_db.get_traffic_stats(organization, days)
    return jsonify(stats)


@app.route('/api/traffic/alerts')
def api_traffic_alerts():
    """API endpoint para alertas de acceso (fines de semana, etc)"""
    if not DATABASE_ENABLED or not dlp_db:
        return jsonify({"error": "Database not enabled"}), 503

    from flask import request

    filters = {}
    if request.args.get('organization'):
        filters['organization'] = request.args.get('organization')
    if request.args.get('date_from'):
        filters['date_from'] = request.args.get('date_from')
    if request.args.get('date_to'):
        filters['date_to'] = request.args.get('date_to')
    if request.args.get('alert_type'):
        filters['alert_type'] = request.args.get('alert_type')

    limit = int(request.args.get('limit', 100))

    alerts = dlp_db.get_access_alerts(filters, limit)
    return jsonify({
        "alerts": alerts,
        "count": len(alerts)
    })


# ============== GitHub Webhook Endpoints ==============

@app.route('/webhook/github', methods=['POST'])
def github_webhook():
    """Endpoint para recibir webhooks de GitHub"""
    if not WEBHOOK_ENABLED or not webhook_handler:
        return jsonify({"error": "Webhook handler not enabled"}), 503

    from flask import request

    # Verificar firma del webhook
    signature = request.headers.get('X-Hub-Signature-256') or request.headers.get('X-Hub-Signature')
    if not webhook_handler.verify_signature(request.data, signature):
        logger.warning("🚨 Webhook con firma inválida rechazado")
        return jsonify({"error": "Invalid signature"}), 401

    # Obtener tipo de evento
    event_type = request.headers.get('X-GitHub-Event', 'unknown')

    # Obtener IP de origen
    source_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if source_ip and ',' in source_ip:
        source_ip = source_ip.split(',')[0].strip()

    # Procesar evento
    try:
        payload = request.get_json()
        result = webhook_handler.process_webhook(event_type, payload, source_ip)
        logger.info(f"📨 Webhook recibido: {event_type} - Autorizado: {result.get('is_authorized', 'N/A')}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error procesando webhook: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/webhook/stats')
def api_webhook_stats():
    """API endpoint para estadísticas de webhooks"""
    if not WEBHOOK_ENABLED or not webhook_handler:
        return jsonify({"enabled": False})

    stats = webhook_handler.get_stats()
    stats["enabled"] = True
    return jsonify(stats)


@app.route('/api/webhook/events')
def api_webhook_events():
    """API endpoint para ver eventos de webhook recientes"""
    if not WEBHOOK_ENABLED or not webhook_handler:
        return jsonify({"events": []})

    return jsonify({"events": webhook_handler.get_webhook_events(100)})


@app.route('/api/webhook/register-user', methods=['POST'])
def api_register_github_user():
    """Registra un usuario de GitHub asociado a un agente DLP"""
    if not WEBHOOK_ENABLED or not webhook_handler:
        return jsonify({"error": "Webhook handler not enabled"}), 503

    from flask import request
    data = request.get_json() or {}

    hostname = data.get('hostname')
    ip = data.get('ip')
    github_user = data.get('github_user')

    if not all([hostname, ip, github_user]):
        return jsonify({"error": "Se requieren hostname, ip y github_user"}), 400

    webhook_handler.register_github_user(hostname, ip, github_user)
    return jsonify({"success": True, "message": f"Usuario {github_user} registrado para {hostname}"})


@app.route('/api/dlp/git-event', methods=['POST'])
def api_dlp_git_event():
    """
    Endpoint para que los agentes DLP reporten eventos Git.
    Soporta: push, clone, pull, fetch, checkout
    Esto permite correlacionar con webhooks de GitHub para detectar
    actividad desde máquinas sin agente.
    """
    if not WEBHOOK_ENABLED or not webhook_handler:
        return jsonify({"error": "Webhook handler not enabled"}), 503

    from flask import request
    data = request.get_json() or {}

    github_user = data.get('github_user')
    repo_name = data.get('repo_name')
    hostname = data.get('hostname')
    ip = data.get('ip') or request.remote_addr
    operation = data.get('operation', 'push')  # push, clone, pull, fetch
    branch = data.get('branch', '')

    if not all([github_user, repo_name, hostname]):
        return jsonify({"error": "Se requieren github_user, repo_name y hostname"}), 400

    webhook_handler.record_dlp_git_event(github_user, repo_name, hostname, ip, operation, branch)
    return jsonify({
        "success": True,
        "message": f"{operation.upper()} registrado: {github_user} -> {repo_name} desde {hostname}"
    })


# ============== Database API Endpoints ==============

@app.route('/api/db/events')
def api_db_events():
    """
    API para consultar eventos con filtros.
    Parámetros:
    - date_from, date_to: Rango de fechas (ISO format)
    - hour_from, hour_to: Rango de horas (0-23)
    - username: Filtrar por usuario
    - hostname: Filtrar por hostname
    - repo_name: Filtrar por repositorio
    - event_type: Filtrar por tipo de evento
    - git_operation: Filtrar por operación git
    - limit, offset: Paginación
    """
    if not DATABASE_ENABLED or not dlp_db:
        return jsonify({"error": "Database not enabled"}), 503

    from flask import request

    filters = {}

    # Parsear filtros de fecha
    if request.args.get('date_from'):
        filters['date_from'] = request.args.get('date_from')
    if request.args.get('date_to'):
        filters['date_to'] = request.args.get('date_to')

    # Parsear filtros de hora
    if request.args.get('hour_from'):
        filters['hour_from'] = int(request.args.get('hour_from'))
    if request.args.get('hour_to'):
        filters['hour_to'] = int(request.args.get('hour_to'))

    # Otros filtros
    for key in ['username', 'hostname', 'repo_name', 'event_type', 'git_operation']:
        if request.args.get(key):
            filters[key] = request.args.get(key)

    limit = int(request.args.get('limit', 100))
    offset = int(request.args.get('offset', 0))

    events = dlp_db.get_dlp_events(filters, limit, offset)
    return jsonify({"events": events, "count": len(events), "filters": filters})


@app.route('/api/db/stats')
def api_db_stats():
    """Obtiene estadísticas de la base de datos"""
    if not DATABASE_ENABLED or not dlp_db:
        return jsonify({"error": "Database not enabled"}), 503

    from flask import request
    days = int(request.args.get('days', 7))

    stats = dlp_db.get_stats(days)
    return jsonify(stats)


@app.route('/api/db/user/<username>')
def api_db_user_activity(username):
    """Obtiene actividad de un usuario específico"""
    if not DATABASE_ENABLED or not dlp_db:
        return jsonify({"error": "Database not enabled"}), 503

    from flask import request
    days = int(request.args.get('days', 30))

    activity = dlp_db.get_user_activity(username, days)
    return jsonify(activity)


@app.route('/api/db/repo/<path:repo_name>')
def api_db_repo_activity(repo_name):
    """Obtiene actividad de un repositorio específico"""
    if not DATABASE_ENABLED or not dlp_db:
        return jsonify({"error": "Database not enabled"}), 503

    from flask import request
    days = int(request.args.get('days', 30))

    activity = dlp_db.get_repo_activity(repo_name, days)
    return jsonify(activity)


@app.route('/api/db/unauthorized')
def api_db_unauthorized():
    """Obtiene eventos no autorizados con filtros"""
    if not DATABASE_ENABLED or not dlp_db:
        return jsonify({"error": "Database not enabled"}), 503

    from flask import request

    filters = {}
    if request.args.get('date_from'):
        filters['date_from'] = request.args.get('date_from')
    if request.args.get('date_to'):
        filters['date_to'] = request.args.get('date_to')
    if request.args.get('github_user'):
        filters['github_user'] = request.args.get('github_user')
    if request.args.get('alert_type'):
        filters['alert_type'] = request.args.get('alert_type')

    limit = int(request.args.get('limit', 100))

    events = dlp_db.get_unauthorized_events(filters, limit)
    return jsonify({"unauthorized": events, "count": len(events)})


def main():
    """Punto de entrada principal"""
    print("=" * 60)
    print("🛡️  Administración GitHub")
    print("   Desarrollado por Cibershield R.L. 2025")
    print("   Todos los derechos reservados.")
    print("=" * 60)
    print(f"📡 TCP Receiver: puerto {CONSOLE_CONFIG['tcp_port']}")
    print(f"🌐 Web Dashboard: http://localhost:{CONSOLE_CONFIG['web_port']}")

    # Estado de autenticación
    if AUTH_ENABLED and is_auth_enabled():
        print("🔐 Autenticación: HABILITADA")
        import os
        if os.getenv('MICROSOFT_CLIENT_ID'):
            print("   ✓ Microsoft Entra configurado")
        if os.getenv('GOOGLE_CLIENT_ID'):
            print("   ✓ Google Workspace configurado")
    else:
        print("🔓 Autenticación: DESHABILITADA (acceso libre)")
        print("   Para habilitar, configure variables de entorno:")
        print("   - MICROSOFT_CLIENT_ID, MICROSOFT_CLIENT_SECRET, MICROSOFT_TENANT_ID")
        print("   - GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET")
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
