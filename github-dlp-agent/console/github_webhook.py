#!/usr/bin/env python3
"""
GitHub Webhook Handler for DLP Console
Cibershield R.L. 2025

Detecta actividad en repositorios GitHub y compara con agentes DLP conocidos.
"""

import os
import hmac
import hashlib
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path

logger = logging.getLogger("GitHubWebhook")


class GitHubWebhookHandler:
    """Maneja webhooks de GitHub para detectar actividad no autorizada"""

    def __init__(self, data_dir: str = None):
        self.webhook_secret = os.getenv('GITHUB_WEBHOOK_SECRET', '')

        # Directorio de datos
        if data_dir:
            self.data_dir = Path(data_dir)
        elif Path("/app/data").exists() or Path("/app").exists():
            self.data_dir = Path("/app/data")
        else:
            self.data_dir = Path(__file__).parent / "data"

        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.webhook_events_file = self.data_dir / "webhook_events.json"
        self.unauthorized_pushes_file = self.data_dir / "unauthorized_pushes.json"

        # Cargar datos existentes
        self.webhook_events = self._load_json(self.webhook_events_file, [])
        self.unauthorized_pushes = self._load_json(self.unauthorized_pushes_file, [])

        # Lista de IPs/usuarios conocidos de agentes DLP (se sincroniza con repo_tracker)
        self.known_agents_file = self.data_dir / "known_agents.json"
        self.known_agents = self._load_json(self.known_agents_file, {})

        # Eventos Git reportados por agentes DLP (para correlación)
        self.dlp_git_events_file = self.data_dir / "dlp_git_events.json"
        self.dlp_git_events = self._load_json(self.dlp_git_events_file, [])

        # Ventana de tiempo para correlación (5 minutos)
        self.correlation_window_seconds = 300

    def _load_json(self, path: Path, default) -> any:
        """Carga un archivo JSON o retorna el default"""
        try:
            if path.exists():
                return json.loads(path.read_text())
        except Exception as e:
            logger.error(f"Error cargando {path}: {e}")
        return default

    def _save_json(self, path: Path, data):
        """Guarda datos en archivo JSON"""
        try:
            path.write_text(json.dumps(data, indent=2, default=str))
        except Exception as e:
            logger.error(f"Error guardando {path}: {e}")

    def verify_signature(self, payload: bytes, signature: str) -> bool:
        """Verifica la firma del webhook de GitHub"""
        if not self.webhook_secret:
            logger.warning("GITHUB_WEBHOOK_SECRET no configurado - aceptando sin verificar")
            return True

        if not signature:
            return False

        try:
            # GitHub envía: sha256=xxxxx
            if signature.startswith('sha256='):
                expected = hmac.new(
                    self.webhook_secret.encode(),
                    payload,
                    hashlib.sha256
                ).hexdigest()
                return hmac.compare_digest(f"sha256={expected}", signature)
            elif signature.startswith('sha1='):
                expected = hmac.new(
                    self.webhook_secret.encode(),
                    payload,
                    hashlib.sha1
                ).hexdigest()
                return hmac.compare_digest(f"sha1={expected}", signature)
        except Exception as e:
            logger.error(f"Error verificando firma: {e}")

        return False

    def sync_known_agents(self, agents: Dict):
        """Sincroniza la lista de agentes conocidos desde repo_tracker"""
        self.known_agents = agents
        self._save_json(self.known_agents_file, agents)

    def is_known_user(self, username: str) -> bool:
        """Verifica si un usuario de GitHub está asociado a un agente conocido"""
        for agent_key, agent_data in self.known_agents.items():
            if agent_data.get("github_user") == username:
                return True
        return False

    def record_dlp_git_event(self, github_user: str, repo_name: str, hostname: str, ip: str,
                              operation: str = "push", branch: str = ""):
        """Registra un evento Git reportado por un agente DLP (push, clone, pull, fetch)"""
        event = {
            "timestamp": datetime.now().isoformat(),
            "github_user": github_user,
            "repo_name": repo_name,
            "hostname": hostname,
            "ip": ip,
            "operation": operation,
            "branch": branch
        }
        self.dlp_git_events.append(event)

        # Mantener solo últimos 1000 eventos (para correlación)
        if len(self.dlp_git_events) > 1000:
            self.dlp_git_events = self.dlp_git_events[-1000:]

        self._save_json(self.dlp_git_events_file, self.dlp_git_events)
        logger.info(f"📝 {operation.upper()} DLP registrado: {github_user} -> {repo_name} desde {hostname}")

    def has_matching_dlp_event(self, github_user: str, repo_name: str, operation: str = None) -> Dict:
        """
        Verifica si hay un evento Git del agente DLP que coincida.
        Retorna el evento del agente si existe, None si no.
        """
        now = datetime.now()

        for event in reversed(self.dlp_git_events):
            # Verificar usuario
            if event.get("github_user") != github_user:
                continue

            # Verificar operación si se especifica
            if operation and event.get("operation") != operation:
                continue

            # Verificar si el repo coincide (puede ser parcial)
            event_repo = event.get("repo_name", "")
            if repo_name and event_repo:
                # Comparar nombres de repo (ignorar organización)
                webhook_repo_name = repo_name.split("/")[-1] if "/" in repo_name else repo_name
                dlp_repo_name = event_repo.split("/")[-1] if "/" in event_repo else event_repo
                if webhook_repo_name.lower() != dlp_repo_name.lower():
                    continue

            # Verificar ventana de tiempo
            try:
                event_time = datetime.fromisoformat(event["timestamp"])
                time_diff = (now - event_time).total_seconds()
                if time_diff <= self.correlation_window_seconds:
                    return event
            except:
                continue

        return None

    def get_dlp_git_events(self, limit: int = 100, operation: str = None) -> List[Dict]:
        """Obtiene eventos Git reportados por agentes DLP"""
        events = self.dlp_git_events
        if operation:
            events = [e for e in events if e.get("operation") == operation]
        return sorted(events, key=lambda x: x.get("timestamp", ""), reverse=True)[:limit]

    def get_user_registered_machines(self, github_user: str) -> List[Dict]:
        """Obtiene las máquinas registradas para un usuario de GitHub"""
        machines = []
        for agent_key, agent_data in self.known_agents.items():
            if agent_data.get("github_user") == github_user:
                machines.append({
                    "hostname": agent_data.get("hostname"),
                    "ip": agent_data.get("ip"),
                    "last_seen": agent_data.get("last_seen")
                })
        return machines

    def get_known_github_users(self) -> List[str]:
        """Obtiene lista de usuarios de GitHub asociados a agentes DLP"""
        users = set()
        for agent_key, agent_data in self.known_agents.items():
            if agent_data.get("github_user"):
                users.add(agent_data["github_user"])
        return list(users)

    def process_webhook(self, event_type: str, payload: Dict, source_ip: str = None) -> Dict:
        """Procesa un evento de webhook de GitHub"""
        result = {
            "processed": True,
            "event_type": event_type,
            "is_authorized": True,
            "details": {}
        }

        try:
            if event_type == "push":
                result = self._process_push_event(payload, source_ip)
            elif event_type == "create":
                result = self._process_create_event(payload, source_ip)
            elif event_type == "member":
                result = self._process_member_event(payload, source_ip)
            elif event_type == "repository":
                result = self._process_repository_event(payload, source_ip)
            elif event_type == "ping":
                result = {"processed": True, "event_type": "ping", "message": "Webhook configurado correctamente"}
            else:
                result = {"processed": True, "event_type": event_type, "message": f"Evento {event_type} recibido"}

            # Guardar evento
            event_record = {
                "timestamp": datetime.now().isoformat(),
                "event_type": event_type,
                "source_ip": source_ip,
                "result": result
            }
            self.webhook_events.append(event_record)

            # Mantener solo últimos 500 eventos
            if len(self.webhook_events) > 500:
                self.webhook_events = self.webhook_events[-500:]

            self._save_json(self.webhook_events_file, self.webhook_events)

        except Exception as e:
            logger.error(f"Error procesando webhook {event_type}: {e}")
            result = {"processed": False, "error": str(e)}

        return result

    def _process_push_event(self, payload: Dict, source_ip: str) -> Dict:
        """Procesa evento de push"""
        pusher = payload.get("pusher", {}).get("name", "unknown")
        pusher_email = payload.get("pusher", {}).get("email", "")
        repo_name = payload.get("repository", {}).get("full_name", "unknown")
        repo_url = payload.get("repository", {}).get("html_url", "")
        ref = payload.get("ref", "")
        commits = payload.get("commits", [])

        # Verificar si el usuario está asociado a un agente DLP
        is_known_user = self.is_known_user(pusher)

        # Verificar si hay un evento DLP que coincida (push desde máquina con agente)
        matching_dlp_event = self.has_matching_dlp_event(pusher, repo_name, "push")

        # Determinar si está autorizado:
        # - Usuario conocido Y tiene evento DLP reciente = autorizado
        # - Usuario conocido PERO sin evento DLP = push desde máquina sin agente
        # - Usuario desconocido = no autorizado
        is_authorized = is_known_user and matching_dlp_event is not None

        # Determinar el tipo de alerta
        if not is_known_user:
            alert_type = "user_not_registered"
            alert_message = "Push desde usuario no registrado en ningún agente DLP"
        elif not matching_dlp_event:
            alert_type = "no_agent_detected"
            alert_message = "Push desde equipo SIN agente DLP (usuario registrado pero sin correlación)"
            registered_machines = self.get_user_registered_machines(pusher)
            if registered_machines:
                machines_str = ", ".join([m["hostname"] for m in registered_machines])
                alert_message += f". Máquinas registradas: {machines_str}"
        else:
            alert_type = None
            alert_message = None

        event_data = {
            "processed": True,
            "event_type": "push",
            "is_authorized": is_authorized,
            "alert_type": alert_type,
            "details": {
                "pusher": pusher,
                "pusher_email": pusher_email,
                "repo_name": repo_name,
                "repo_url": repo_url,
                "ref": ref,
                "commits_count": len(commits),
                "source_ip": source_ip,
                "timestamp": datetime.now().isoformat(),
                "matching_dlp_event": matching_dlp_event
            }
        }

        # Si no está autorizado, registrar como acceso no autorizado
        if not is_authorized:
            unauthorized_event = {
                "timestamp": datetime.now().isoformat(),
                "event_type": "push",
                "alert_type": alert_type,
                "username": pusher,
                "email": pusher_email,
                "repo_name": repo_name,
                "repo_url": repo_url,
                "ref": ref,
                "commits_count": len(commits),
                "source_ip": source_ip,
                "source": "github_webhook",
                "message": alert_message,
                "is_known_user": is_known_user
            }
            self.unauthorized_pushes.append(unauthorized_event)

            # Mantener solo últimos 200 eventos
            if len(self.unauthorized_pushes) > 200:
                self.unauthorized_pushes = self.unauthorized_pushes[-200:]

            self._save_json(self.unauthorized_pushes_file, self.unauthorized_pushes)

            if alert_type == "no_agent_detected":
                logger.warning(f"🚨 Push SIN AGENTE: {pusher} -> {repo_name} (usuario conocido, máquina desconocida)")
            else:
                logger.warning(f"🚨 Push no autorizado: {pusher} -> {repo_name}")

        return event_data

    def _process_create_event(self, payload: Dict, source_ip: str) -> Dict:
        """Procesa evento de creación (branch, tag)"""
        sender = payload.get("sender", {}).get("login", "unknown")
        repo_name = payload.get("repository", {}).get("full_name", "unknown")
        ref_type = payload.get("ref_type", "unknown")
        ref = payload.get("ref", "")

        return {
            "processed": True,
            "event_type": "create",
            "is_authorized": self.is_known_user(sender),
            "details": {
                "sender": sender,
                "repo_name": repo_name,
                "ref_type": ref_type,
                "ref": ref,
                "source_ip": source_ip
            }
        }

    def _process_member_event(self, payload: Dict, source_ip: str) -> Dict:
        """Procesa evento de cambio de miembros"""
        action = payload.get("action", "unknown")
        member = payload.get("member", {}).get("login", "unknown")
        repo_name = payload.get("repository", {}).get("full_name", "unknown")
        sender = payload.get("sender", {}).get("login", "unknown")

        logger.info(f"👥 Cambio de miembro: {action} {member} en {repo_name} por {sender}")

        return {
            "processed": True,
            "event_type": "member",
            "details": {
                "action": action,
                "member": member,
                "repo_name": repo_name,
                "sender": sender,
                "source_ip": source_ip
            }
        }

    def _process_repository_event(self, payload: Dict, source_ip: str) -> Dict:
        """Procesa evento de repositorio (creado, eliminado, etc)"""
        action = payload.get("action", "unknown")
        repo_name = payload.get("repository", {}).get("full_name", "unknown")
        sender = payload.get("sender", {}).get("login", "unknown")

        logger.info(f"📦 Evento de repositorio: {action} {repo_name} por {sender}")

        return {
            "processed": True,
            "event_type": "repository",
            "details": {
                "action": action,
                "repo_name": repo_name,
                "sender": sender,
                "source_ip": source_ip
            }
        }

    def get_unauthorized_pushes(self) -> List[Dict]:
        """Obtiene lista de pushes no autorizados"""
        return sorted(self.unauthorized_pushes, key=lambda x: x.get("timestamp", ""), reverse=True)

    def get_webhook_events(self, limit: int = 100) -> List[Dict]:
        """Obtiene últimos eventos de webhook"""
        return sorted(self.webhook_events, key=lambda x: x.get("timestamp", ""), reverse=True)[:limit]

    def get_stats(self) -> Dict:
        """Obtiene estadísticas de webhooks"""
        return {
            "total_events": len(self.webhook_events),
            "unauthorized_pushes": len(self.unauthorized_pushes),
            "known_github_users": len(self.get_known_github_users()),
            "webhook_secret_configured": bool(self.webhook_secret)
        }

    def register_github_user(self, agent_hostname: str, agent_ip: str, github_user: str):
        """Registra un usuario de GitHub asociado a un agente DLP"""
        key = f"{agent_hostname}_{agent_ip}"
        if key not in self.known_agents:
            self.known_agents[key] = {
                "hostname": agent_hostname,
                "ip": agent_ip,
                "first_seen": datetime.now().isoformat()
            }

        self.known_agents[key]["github_user"] = github_user
        self.known_agents[key]["last_seen"] = datetime.now().isoformat()

        self._save_json(self.known_agents_file, self.known_agents)
        logger.info(f"✓ Usuario GitHub registrado: {github_user} -> {agent_hostname}")


# Instancia global
webhook_handler = GitHubWebhookHandler()
