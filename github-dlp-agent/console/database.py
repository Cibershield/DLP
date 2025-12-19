#!/usr/bin/env python3
"""
Database Module for DLP Console
Cibershield R.L. 2025

Almacenamiento persistente de eventos con filtros por fecha, hora y usuario.
"""

import sqlite3
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from pathlib import Path
from contextlib import contextmanager

logger = logging.getLogger("DLPDatabase")


class DLPDatabase:
    """Base de datos SQLite para almacenar eventos DLP"""

    def __init__(self, db_path: str = None):
        # Directorio de datos
        if db_path:
            self.db_path = Path(db_path)
        elif Path("/app/data").exists() or Path("/app").exists():
            self.db_path = Path("/app/data/dlp_events.db")
        else:
            self.db_path = Path(__file__).parent / "data" / "dlp_events.db"

        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()

    @contextmanager
    def get_connection(self):
        """Context manager para conexiones de base de datos"""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()

    def _init_database(self):
        """Inicializa las tablas de la base de datos"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Tabla de eventos DLP (del agente)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS dlp_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    event_type TEXT NOT NULL,
                    username TEXT,
                    hostname TEXT,
                    source_ip TEXT,
                    repo_name TEXT,
                    repo_url TEXT,
                    git_operation TEXT,
                    branch TEXT,
                    command_line TEXT,
                    is_allowed BOOLEAN DEFAULT 1,
                    extra_data TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Tabla de webhooks de GitHub
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS webhook_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    event_type TEXT NOT NULL,
                    github_user TEXT,
                    email TEXT,
                    repo_name TEXT,
                    repo_url TEXT,
                    ref TEXT,
                    commits_count INTEGER DEFAULT 0,
                    source_ip TEXT,
                    is_authorized BOOLEAN DEFAULT 0,
                    alert_type TEXT,
                    message TEXT,
                    extra_data TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Tabla de usuarios registrados
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS registered_users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    github_user TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    ip TEXT,
                    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    active BOOLEAN DEFAULT 1,
                    UNIQUE(github_user, hostname)
                )
            ''')

            # Tabla de repositorios rastreados
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS repositories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    repo_name TEXT UNIQUE NOT NULL,
                    repo_url TEXT,
                    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_activity DATETIME,
                    total_clones INTEGER DEFAULT 0,
                    total_pushes INTEGER DEFAULT 0,
                    total_pulls INTEGER DEFAULT 0
                )
            ''')

            # Índices para búsquedas rápidas
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_dlp_timestamp ON dlp_events(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_dlp_username ON dlp_events(username)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_dlp_repo ON dlp_events(repo_name)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_webhook_timestamp ON webhook_events(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_webhook_user ON webhook_events(github_user)')

            logger.info(f"✓ Base de datos inicializada: {self.db_path}")

    # ============== Eventos DLP ==============

    def insert_dlp_event(self, event_data: Dict) -> int:
        """Inserta un evento del agente DLP"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Extraer campos conocidos
            extra_data = {k: v for k, v in event_data.items()
                          if k not in ['event_type', 'username', 'hostname', 'source_ip',
                                       'repo_name', 'repo_url', 'git_operation', 'branch',
                                       'command_line', 'is_allowed', 'timestamp']}

            cursor.execute('''
                INSERT INTO dlp_events
                (timestamp, event_type, username, hostname, source_ip, repo_name,
                 repo_url, git_operation, branch, command_line, is_allowed, extra_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                event_data.get('timestamp', datetime.now().isoformat()),
                event_data.get('event_type', 'unknown'),
                event_data.get('username'),
                event_data.get('hostname'),
                event_data.get('source_ip'),
                event_data.get('repo_name'),
                event_data.get('repo_url'),
                event_data.get('git_operation'),
                event_data.get('branch'),
                event_data.get('command_line'),
                event_data.get('is_allowed', True),
                json.dumps(extra_data) if extra_data else None
            ))

            # Actualizar repositorio si aplica
            if event_data.get('repo_name'):
                self._update_repository_stats(conn, event_data)

            return cursor.lastrowid

    def _update_repository_stats(self, conn, event_data: Dict):
        """Actualiza estadísticas del repositorio"""
        repo_name = event_data.get('repo_name')
        operation = event_data.get('git_operation', event_data.get('event_type', ''))

        cursor = conn.cursor()

        # Insertar o actualizar repositorio
        cursor.execute('''
            INSERT INTO repositories (repo_name, repo_url, last_activity)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(repo_name) DO UPDATE SET
                last_activity = CURRENT_TIMESTAMP,
                total_clones = total_clones + CASE WHEN ? IN ('clone', 'new_repo_detected') THEN 1 ELSE 0 END,
                total_pushes = total_pushes + CASE WHEN ? = 'push' THEN 1 ELSE 0 END,
                total_pulls = total_pulls + CASE WHEN ? = 'pull' THEN 1 ELSE 0 END
        ''', (repo_name, event_data.get('repo_url'), operation, operation, operation))

    def get_dlp_events(self, filters: Dict = None, limit: int = 100, offset: int = 0) -> List[Dict]:
        """Obtiene eventos DLP con filtros opcionales"""
        filters = filters or {}

        query = "SELECT * FROM dlp_events WHERE 1=1"
        params = []

        # Filtros de fecha
        if filters.get('date_from'):
            query += " AND timestamp >= ?"
            params.append(filters['date_from'])
        if filters.get('date_to'):
            query += " AND timestamp <= ?"
            params.append(filters['date_to'])

        # Filtros de hora
        if filters.get('hour_from') is not None:
            query += " AND CAST(strftime('%H', timestamp) AS INTEGER) >= ?"
            params.append(filters['hour_from'])
        if filters.get('hour_to') is not None:
            query += " AND CAST(strftime('%H', timestamp) AS INTEGER) <= ?"
            params.append(filters['hour_to'])

        # Filtros de usuario/host
        if filters.get('username'):
            query += " AND username LIKE ?"
            params.append(f"%{filters['username']}%")
        if filters.get('hostname'):
            query += " AND hostname LIKE ?"
            params.append(f"%{filters['hostname']}%")

        # Filtros de repositorio
        if filters.get('repo_name'):
            query += " AND repo_name LIKE ?"
            params.append(f"%{filters['repo_name']}%")

        # Filtros de operación
        if filters.get('event_type'):
            query += " AND event_type = ?"
            params.append(filters['event_type'])
        if filters.get('git_operation'):
            query += " AND git_operation = ?"
            params.append(filters['git_operation'])

        # Ordenar y limitar
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    # ============== Eventos Webhook ==============

    def insert_webhook_event(self, event_data: Dict) -> int:
        """Inserta un evento de webhook de GitHub"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            extra_data = {k: v for k, v in event_data.items()
                          if k not in ['event_type', 'github_user', 'email', 'repo_name',
                                       'repo_url', 'ref', 'commits_count', 'source_ip',
                                       'is_authorized', 'alert_type', 'message', 'timestamp']}

            cursor.execute('''
                INSERT INTO webhook_events
                (timestamp, event_type, github_user, email, repo_name, repo_url,
                 ref, commits_count, source_ip, is_authorized, alert_type, message, extra_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                event_data.get('timestamp', datetime.now().isoformat()),
                event_data.get('event_type', 'unknown'),
                event_data.get('github_user') or event_data.get('username'),
                event_data.get('email'),
                event_data.get('repo_name'),
                event_data.get('repo_url'),
                event_data.get('ref'),
                event_data.get('commits_count', 0),
                event_data.get('source_ip'),
                event_data.get('is_authorized', False),
                event_data.get('alert_type'),
                event_data.get('message'),
                json.dumps(extra_data) if extra_data else None
            ))

            return cursor.lastrowid

    def get_webhook_events(self, filters: Dict = None, limit: int = 100, offset: int = 0) -> List[Dict]:
        """Obtiene eventos webhook con filtros"""
        filters = filters or {}

        query = "SELECT * FROM webhook_events WHERE 1=1"
        params = []

        if filters.get('date_from'):
            query += " AND timestamp >= ?"
            params.append(filters['date_from'])
        if filters.get('date_to'):
            query += " AND timestamp <= ?"
            params.append(filters['date_to'])

        if filters.get('github_user'):
            query += " AND github_user LIKE ?"
            params.append(f"%{filters['github_user']}%")

        if filters.get('repo_name'):
            query += " AND repo_name LIKE ?"
            params.append(f"%{filters['repo_name']}%")

        if filters.get('is_authorized') is not None:
            query += " AND is_authorized = ?"
            params.append(filters['is_authorized'])

        if filters.get('alert_type'):
            query += " AND alert_type = ?"
            params.append(filters['alert_type'])

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def get_unauthorized_events(self, filters: Dict = None, limit: int = 100) -> List[Dict]:
        """Obtiene solo eventos no autorizados"""
        filters = filters or {}
        filters['is_authorized'] = False
        return self.get_webhook_events(filters, limit)

    # ============== Usuarios Registrados ==============

    def register_user(self, github_user: str, hostname: str, ip: str = None):
        """Registra o actualiza un usuario"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO registered_users (github_user, hostname, ip, last_seen)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(github_user, hostname) DO UPDATE SET
                    ip = ?,
                    last_seen = CURRENT_TIMESTAMP,
                    active = 1
            ''', (github_user, hostname, ip, ip))

    def get_registered_users(self) -> List[Dict]:
        """Obtiene todos los usuarios registrados"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM registered_users WHERE active = 1 ORDER BY last_seen DESC')
            return [dict(row) for row in cursor.fetchall()]

    def is_user_registered(self, github_user: str) -> bool:
        """Verifica si un usuario está registrado"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM registered_users WHERE github_user = ? AND active = 1', (github_user,))
            return cursor.fetchone()[0] > 0

    # ============== Estadísticas ==============

    def get_stats(self, days: int = 7) -> Dict:
        """Obtiene estadísticas de los últimos N días"""
        since = (datetime.now() - timedelta(days=days)).isoformat()

        with self.get_connection() as conn:
            cursor = conn.cursor()

            stats = {}

            # Total de eventos DLP
            cursor.execute('SELECT COUNT(*) FROM dlp_events WHERE timestamp >= ?', (since,))
            stats['total_dlp_events'] = cursor.fetchone()[0]

            # Total de webhooks
            cursor.execute('SELECT COUNT(*) FROM webhook_events WHERE timestamp >= ?', (since,))
            stats['total_webhook_events'] = cursor.fetchone()[0]

            # Eventos no autorizados
            cursor.execute('SELECT COUNT(*) FROM webhook_events WHERE timestamp >= ? AND is_authorized = 0', (since,))
            stats['unauthorized_events'] = cursor.fetchone()[0]

            # Usuarios únicos
            cursor.execute('SELECT COUNT(DISTINCT username) FROM dlp_events WHERE timestamp >= ?', (since,))
            stats['unique_users'] = cursor.fetchone()[0]

            # Repositorios activos
            cursor.execute('SELECT COUNT(DISTINCT repo_name) FROM dlp_events WHERE timestamp >= ? AND repo_name IS NOT NULL', (since,))
            stats['active_repos'] = cursor.fetchone()[0]

            # Eventos por día
            cursor.execute('''
                SELECT DATE(timestamp) as day, COUNT(*) as count
                FROM dlp_events
                WHERE timestamp >= ?
                GROUP BY DATE(timestamp)
                ORDER BY day
            ''', (since,))
            stats['events_by_day'] = [{'day': row[0], 'count': row[1]} for row in cursor.fetchall()]

            # Eventos por hora (últimas 24h)
            since_24h = (datetime.now() - timedelta(hours=24)).isoformat()
            cursor.execute('''
                SELECT CAST(strftime('%H', timestamp) AS INTEGER) as hour, COUNT(*) as count
                FROM dlp_events
                WHERE timestamp >= ?
                GROUP BY hour
                ORDER BY hour
            ''', (since_24h,))
            stats['events_by_hour'] = [{'hour': row[0], 'count': row[1]} for row in cursor.fetchall()]

            # Top usuarios
            cursor.execute('''
                SELECT username, COUNT(*) as count
                FROM dlp_events
                WHERE timestamp >= ? AND username IS NOT NULL
                GROUP BY username
                ORDER BY count DESC
                LIMIT 10
            ''', (since,))
            stats['top_users'] = [{'username': row[0], 'count': row[1]} for row in cursor.fetchall()]

            # Top repositorios
            cursor.execute('''
                SELECT repo_name, COUNT(*) as count
                FROM dlp_events
                WHERE timestamp >= ? AND repo_name IS NOT NULL
                GROUP BY repo_name
                ORDER BY count DESC
                LIMIT 10
            ''', (since,))
            stats['top_repos'] = [{'repo_name': row[0], 'count': row[1]} for row in cursor.fetchall()]

            return stats

    def get_user_activity(self, username: str, days: int = 30) -> Dict:
        """Obtiene actividad de un usuario específico"""
        since = (datetime.now() - timedelta(days=days)).isoformat()

        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Eventos del usuario
            cursor.execute('''
                SELECT * FROM dlp_events
                WHERE username = ? AND timestamp >= ?
                ORDER BY timestamp DESC
                LIMIT 100
            ''', (username, since))
            events = [dict(row) for row in cursor.fetchall()]

            # Estadísticas
            cursor.execute('''
                SELECT
                    COUNT(*) as total_events,
                    COUNT(DISTINCT repo_name) as repos_accessed,
                    COUNT(DISTINCT hostname) as machines_used
                FROM dlp_events
                WHERE username = ? AND timestamp >= ?
            ''', (username, since))
            row = cursor.fetchone()

            return {
                'username': username,
                'total_events': row[0],
                'repos_accessed': row[1],
                'machines_used': row[2],
                'recent_events': events
            }

    def get_repo_activity(self, repo_name: str, days: int = 30) -> Dict:
        """Obtiene actividad de un repositorio específico"""
        since = (datetime.now() - timedelta(days=days)).isoformat()

        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Eventos del repositorio
            cursor.execute('''
                SELECT * FROM dlp_events
                WHERE repo_name LIKE ? AND timestamp >= ?
                ORDER BY timestamp DESC
                LIMIT 100
            ''', (f"%{repo_name}%", since))
            events = [dict(row) for row in cursor.fetchall()]

            # Usuarios que accedieron
            cursor.execute('''
                SELECT username, COUNT(*) as count
                FROM dlp_events
                WHERE repo_name LIKE ? AND timestamp >= ? AND username IS NOT NULL
                GROUP BY username
                ORDER BY count DESC
            ''', (f"%{repo_name}%", since))
            users = [{'username': row[0], 'count': row[1]} for row in cursor.fetchall()]

            return {
                'repo_name': repo_name,
                'total_events': len(events),
                'users': users,
                'recent_events': events
            }


# Instancia global
db = DLPDatabase()
