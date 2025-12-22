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

# Límites de seguridad
MAX_QUERY_LIMIT = 1000
DEFAULT_QUERY_LIMIT = 100


def escape_sql_like(value: str) -> str:
    """
    Escapa caracteres especiales para consultas LIKE en SQLite.
    Previene ataques de wildcard DoS.
    """
    if not value:
        return value
    # Escapar los caracteres especiales de LIKE
    return (value
            .replace('\\', '\\\\')
            .replace('%', '\\%')
            .replace('_', '\\_'))


def safe_limit(limit: int) -> int:
    """Aplica límites seguros a las consultas"""
    if limit <= 0:
        return DEFAULT_QUERY_LIMIT
    return min(limit, MAX_QUERY_LIMIT)


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

            # Tabla de histórico de tráfico (clones/views de GitHub API)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS traffic_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date DATE NOT NULL,
                    organization TEXT NOT NULL,
                    repo_name TEXT NOT NULL,
                    repo_url TEXT,
                    is_private BOOLEAN DEFAULT 0,
                    clones INTEGER DEFAULT 0,
                    unique_cloners INTEGER DEFAULT 0,
                    views INTEGER DEFAULT 0,
                    unique_visitors INTEGER DEFAULT 0,
                    collaborators TEXT,
                    is_weekend BOOLEAN DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(date, organization, repo_name)
                )
            ''')

            # Tabla de alertas de acceso (fines de semana, fuera de horario, etc)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS access_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date DATE NOT NULL,
                    organization TEXT,
                    repo_name TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    clones INTEGER DEFAULT 0,
                    message TEXT,
                    collaborators TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Índices para histórico de tráfico
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_traffic_date ON traffic_history(date)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_traffic_org ON traffic_history(organization)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_traffic_repo ON traffic_history(repo_name)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_date ON access_alerts(date)')

            # Tabla de accesos temporales a repositorios
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS access_grants (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    github_user TEXT NOT NULL,
                    organization TEXT NOT NULL,
                    repo_name TEXT NOT NULL,
                    permission TEXT DEFAULT 'pull',
                    granted_by TEXT,
                    granted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    expires_at DATETIME NOT NULL,
                    status TEXT DEFAULT 'active',
                    revoked_at DATETIME,
                    revoke_reason TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Índices para accesos temporales
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_grants_user ON access_grants(github_user)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_grants_repo ON access_grants(organization, repo_name)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_grants_expires ON access_grants(expires_at)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_grants_status ON access_grants(status)')

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

        # Aplicar límites seguros
        limit = safe_limit(limit)
        offset = max(0, offset)

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

        # Filtros de usuario/host (con escape de wildcards)
        if filters.get('username'):
            query += " AND username LIKE ? ESCAPE '\\'"
            params.append(f"%{escape_sql_like(filters['username'])}%")
        if filters.get('hostname'):
            query += " AND hostname LIKE ? ESCAPE '\\'"
            params.append(f"%{escape_sql_like(filters['hostname'])}%")

        # Filtros de repositorio (con escape de wildcards)
        if filters.get('repo_name'):
            query += " AND repo_name LIKE ? ESCAPE '\\'"
            params.append(f"%{escape_sql_like(filters['repo_name'])}%")

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

    # ============== Histórico de Tráfico ==============

    def save_traffic_data(self, organization: str, traffic_entries: List[Dict]):
        """
        Guarda datos de tráfico de GitHub en el histórico.
        Solo guarda si no existen ya (evita duplicados).
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()

            saved_count = 0
            for entry in traffic_entries:
                try:
                    cursor.execute('''
                        INSERT OR IGNORE INTO traffic_history
                        (date, organization, repo_name, repo_url, is_private,
                         clones, unique_cloners, views, unique_visitors,
                         collaborators, is_weekend)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        entry.get('date'),
                        organization,
                        entry.get('repo_name'),
                        entry.get('repo_url'),
                        entry.get('is_private', False),
                        entry.get('clones', 0),
                        entry.get('unique_cloners', 0),
                        entry.get('views', 0),
                        entry.get('unique_visitors', 0),
                        json.dumps(entry.get('collaborators', [])),
                        entry.get('is_weekend', False)
                    ))
                    if cursor.rowcount > 0:
                        saved_count += 1
                except Exception as e:
                    logger.error(f"Error guardando tráfico: {e}")

            logger.info(f"✓ Guardados {saved_count} nuevos registros de tráfico para {organization}")
            return saved_count

    def save_access_alert(self, alert_data: Dict):
        """Guarda una alerta de acceso (fin de semana, fuera de horario, etc)"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO access_alerts
                (date, organization, repo_name, alert_type, clones, message, collaborators)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert_data.get('date'),
                alert_data.get('organization'),
                alert_data.get('repo_name'),
                alert_data.get('alert_type'),
                alert_data.get('clones', 0),
                alert_data.get('message'),
                json.dumps(alert_data.get('collaborators', []))
            ))

            return cursor.lastrowid

    def get_traffic_history(self, filters: Dict = None, limit: int = 500) -> List[Dict]:
        """
        Obtiene histórico de tráfico con filtros.
        Filtros: organization, repo_name, date_from, date_to, is_weekend
        """
        filters = filters or {}

        query = "SELECT * FROM traffic_history WHERE 1=1"
        params = []

        if filters.get('organization'):
            query += " AND organization = ?"
            params.append(filters['organization'])

        if filters.get('repo_name'):
            query += " AND repo_name LIKE ?"
            params.append(f"%{filters['repo_name']}%")

        if filters.get('date_from'):
            query += " AND date >= ?"
            params.append(filters['date_from'])

        if filters.get('date_to'):
            query += " AND date <= ?"
            params.append(filters['date_to'])

        if filters.get('is_weekend') is not None:
            query += " AND is_weekend = ?"
            params.append(filters['is_weekend'])

        query += " ORDER BY date DESC LIMIT ?"
        params.append(limit)

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)

            results = []
            for row in cursor.fetchall():
                entry = dict(row)
                # Parsear collaborators de JSON
                if entry.get('collaborators'):
                    try:
                        entry['collaborators'] = json.loads(entry['collaborators'])
                    except:
                        entry['collaborators'] = []
                results.append(entry)

            return results

    def get_access_alerts(self, filters: Dict = None, limit: int = 100) -> List[Dict]:
        """Obtiene alertas de acceso con filtros"""
        filters = filters or {}

        query = "SELECT * FROM access_alerts WHERE 1=1"
        params = []

        if filters.get('organization'):
            query += " AND organization = ?"
            params.append(filters['organization'])

        if filters.get('repo_name'):
            query += " AND repo_name LIKE ?"
            params.append(f"%{filters['repo_name']}%")

        if filters.get('date_from'):
            query += " AND date >= ?"
            params.append(filters['date_from'])

        if filters.get('date_to'):
            query += " AND date <= ?"
            params.append(filters['date_to'])

        if filters.get('alert_type'):
            query += " AND alert_type = ?"
            params.append(filters['alert_type'])

        query += " ORDER BY date DESC, created_at DESC LIMIT ?"
        params.append(limit)

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)

            results = []
            for row in cursor.fetchall():
                entry = dict(row)
                if entry.get('collaborators'):
                    try:
                        entry['collaborators'] = json.loads(entry['collaborators'])
                    except:
                        entry['collaborators'] = []
                results.append(entry)

            return results

    def get_traffic_stats(self, organization: str = None, days: int = 365) -> Dict:
        """Obtiene estadísticas del histórico de tráfico"""
        since = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')

        with self.get_connection() as conn:
            cursor = conn.cursor()

            base_filter = "WHERE date >= ?"
            params = [since]

            if organization:
                base_filter += " AND organization = ?"
                params.append(organization)

            # Total de clones
            cursor.execute(f'SELECT SUM(clones), SUM(unique_cloners) FROM traffic_history {base_filter}', params)
            row = cursor.fetchone()
            total_clones = row[0] or 0
            total_unique = row[1] or 0

            # Clones en fin de semana
            cursor.execute(f'SELECT SUM(clones) FROM traffic_history {base_filter} AND is_weekend = 1', params)
            weekend_clones = cursor.fetchone()[0] or 0

            # Repos más clonados
            cursor.execute(f'''
                SELECT repo_name, SUM(clones) as total
                FROM traffic_history
                {base_filter}
                GROUP BY repo_name
                ORDER BY total DESC
                LIMIT 10
            ''', params)
            top_repos = [{'repo': row[0], 'clones': row[1]} for row in cursor.fetchall()]

            # Clones por mes
            cursor.execute(f'''
                SELECT strftime('%Y-%m', date) as month, SUM(clones) as total
                FROM traffic_history
                {base_filter}
                GROUP BY month
                ORDER BY month
            ''', params)
            by_month = [{'month': row[0], 'clones': row[1]} for row in cursor.fetchall()]

            # Total de alertas
            cursor.execute(f'SELECT COUNT(*) FROM access_alerts {base_filter}', params)
            total_alerts = cursor.fetchone()[0]

            return {
                'period_days': days,
                'organization': organization,
                'total_clones': total_clones,
                'total_unique_cloners': total_unique,
                'weekend_clones': weekend_clones,
                'weekend_percentage': round((weekend_clones / total_clones * 100) if total_clones > 0 else 0, 1),
                'top_repos': top_repos,
                'clones_by_month': by_month,
                'total_alerts': total_alerts
            }

    # ============== Accesos Temporales ==============

    def create_access_grant(self, github_user: str, organization: str, repo_name: str,
                           permission: str, expires_at: str, granted_by: str = None) -> int:
        """
        Crea un nuevo acceso temporal a un repositorio.

        Args:
            github_user: Usuario de GitHub
            organization: Nombre de la organización
            repo_name: Nombre del repositorio
            permission: Tipo de permiso (pull, push, admin, maintain, triage)
            expires_at: Fecha de expiración (formato ISO)
            granted_by: Usuario que otorgó el acceso

        Returns:
            ID del registro creado
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO access_grants
                (github_user, organization, repo_name, permission, expires_at, granted_by)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (github_user, organization, repo_name, permission, expires_at, granted_by))

            logger.info(f"✓ Acceso temporal creado: {github_user} -> {organization}/{repo_name} (expira: {expires_at})")
            return cursor.lastrowid

    def get_access_grants(self, filters: Dict = None, limit: int = 100) -> List[Dict]:
        """
        Obtiene accesos temporales con filtros opcionales.

        Filtros: organization, repo_name, github_user, status
        """
        filters = filters or {}

        query = "SELECT * FROM access_grants WHERE 1=1"
        params = []

        if filters.get('organization'):
            query += " AND organization = ?"
            params.append(filters['organization'])

        if filters.get('repo_name'):
            query += " AND repo_name = ?"
            params.append(filters['repo_name'])

        if filters.get('github_user'):
            query += " AND github_user = ?"
            params.append(filters['github_user'])

        if filters.get('status'):
            query += " AND status = ?"
            params.append(filters['status'])
        else:
            # Por defecto solo mostrar activos
            query += " AND status = 'active'"

        query += " ORDER BY expires_at ASC LIMIT ?"
        params.append(limit)

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def get_active_access_grants(self) -> List[Dict]:
        """Obtiene todos los accesos temporales activos"""
        return self.get_access_grants({'status': 'active'})

    def get_expired_access_grants(self) -> List[Dict]:
        """Obtiene accesos activos que ya expiraron"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM access_grants
                WHERE status = 'active' AND expires_at <= datetime('now')
                ORDER BY expires_at ASC
            ''')
            return [dict(row) for row in cursor.fetchall()]

    def get_access_grant_by_id(self, grant_id: int) -> Optional[Dict]:
        """Obtiene un acceso temporal por su ID"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM access_grants WHERE id = ?', (grant_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def mark_grant_expired(self, grant_id: int, reason: str = "Expirado automáticamente"):
        """Marca un acceso como expirado"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE access_grants
                SET status = 'expired', revoked_at = datetime('now'), revoke_reason = ?
                WHERE id = ?
            ''', (reason, grant_id))
            logger.info(f"✓ Acceso temporal {grant_id} marcado como expirado")

    def revoke_access_grant(self, grant_id: int, reason: str = "Revocado manualmente"):
        """Revoca un acceso temporal manualmente"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE access_grants
                SET status = 'revoked', revoked_at = datetime('now'), revoke_reason = ?
                WHERE id = ?
            ''', (reason, grant_id))
            logger.info(f"✓ Acceso temporal {grant_id} revocado: {reason}")

    def extend_access_grant(self, grant_id: int, new_expires_at: str):
        """Extiende la fecha de expiración de un acceso"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE access_grants
                SET expires_at = ?
                WHERE id = ? AND status = 'active'
            ''', (new_expires_at, grant_id))
            logger.info(f"✓ Acceso temporal {grant_id} extendido hasta {new_expires_at}")

    def get_user_active_grants(self, github_user: str) -> List[Dict]:
        """Obtiene todos los accesos activos de un usuario"""
        return self.get_access_grants({'github_user': github_user, 'status': 'active'})

    def get_repo_active_grants(self, organization: str, repo_name: str) -> List[Dict]:
        """Obtiene todos los accesos activos de un repositorio"""
        return self.get_access_grants({
            'organization': organization,
            'repo_name': repo_name,
            'status': 'active'
        })

    def get_grants_expiring_soon(self, hours: int = 24) -> List[Dict]:
        """Obtiene accesos que expiran pronto (para alertas)"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM access_grants
                WHERE status = 'active'
                  AND expires_at > datetime('now')
                  AND expires_at <= datetime('now', '+' || ? || ' hours')
                ORDER BY expires_at ASC
            ''', (hours,))
            return [dict(row) for row in cursor.fetchall()]


# Instancia global
db = DLPDatabase()
