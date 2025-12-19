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
        # Buscar en eventos previos de agentes
        for agent_key, agent_data in self.known_agents.items():
            if agent_data.get("github_user") == username:
                return True
        return False

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
        is_known = self.is_known_user(pusher)

        event_data = {
            "processed": True,
            "event_type": "push",
            "is_authorized": is_known,
            "details": {
                "pusher": pusher,
                "pusher_email": pusher_email,
                "repo_name": repo_name,
                "repo_url": repo_url,
                "ref": ref,
                "commits_count": len(commits),
                "source_ip": source_ip,
                "timestamp": datetime.now().isoformat()
            }
        }

        # Si no es conocido, registrar como acceso no autorizado
        if not is_known:
            unauthorized_event = {
                "timestamp": datetime.now().isoformat(),
                "event_type": "push",
                "username": pusher,
                "email": pusher_email,
                "repo_name": repo_name,
                "repo_url": repo_url,
                "ref": ref,
                "commits_count": len(commits),
                "source_ip": source_ip,
                "source": "github_webhook",
                "message": f"Push desde usuario no registrado en agente DLP"
            }
            self.unauthorized_pushes.append(unauthorized_event)

            # Mantener solo últimos 200 eventos
            if len(self.unauthorized_pushes) > 200:
                self.unauthorized_pushes = self.unauthorized_pushes[-200:]

            self._save_json(self.unauthorized_pushes_file, self.unauthorized_pushes)

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
