#!/usr/bin/env python3
"""
GitHub API Integration for DLP Console
Cibershield R.L. 2025

Permite obtener información de repositorios, permisos y colaboradores.
"""

import os
import json
import requests
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path


class GitHubIntegration:
    """Integración con la API de GitHub"""

    def __init__(self, token: Optional[str] = None):
        """
        Inicializa la integración con GitHub.

        Args:
            token: Personal Access Token de GitHub (o se lee de GITHUB_TOKEN env)
        """
        self.token = token or os.getenv('GITHUB_TOKEN')
        self.base_url = "https://api.github.com"
        self.headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "DLP-Console-Cibershield"
        }
        if self.token:
            self.headers["Authorization"] = f"token {self.token}"

        # Cache para reducir llamadas a la API
        self._cache = {}
        self._cache_ttl = 600  # 10 minutos para datos generales
        self._org_cache_ttl = 1800  # 30 minutos para organizaciones (cambian poco)

    def is_configured(self) -> bool:
        """Verifica si hay un token configurado"""
        return bool(self.token)

    def _make_request(self, endpoint: str, method: str = "GET", json_data: Dict = None) -> Optional[Dict]:
        """Realiza una petición a la API de GitHub"""
        try:
            url = f"{self.base_url}{endpoint}"
            response = requests.request(method, url, headers=self.headers, json=json_data, timeout=10)

            if response.status_code in [200, 201]:
                if response.text:
                    return response.json()
                return {"success": True}
            elif response.status_code == 204:
                return {"success": True, "message": "Operación exitosa"}
            elif response.status_code == 404:
                return {"error": "No encontrado"}
            elif response.status_code == 403:
                return {"error": "Sin permisos o rate limit excedido"}
            elif response.status_code == 422:
                return {"error": "Datos inválidos"}
            else:
                return {"error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def get_repo_info(self, owner: str, repo: str) -> Optional[Dict]:
        """
        Obtiene información de un repositorio.

        Returns:
            Dict con información del repo o None si no existe
        """
        cache_key = f"repo:{owner}/{repo}"
        if cache_key in self._cache:
            cached = self._cache[cache_key]
            if (datetime.now() - cached['time']).seconds < self._cache_ttl:
                return cached['data']

        data = self._make_request(f"/repos/{owner}/{repo}")
        if data and "error" not in data:
            self._cache[cache_key] = {'data': data, 'time': datetime.now()}
        return data

    def get_repo_collaborators(self, owner: str, repo: str) -> List[Dict]:
        """
        Obtiene la lista de colaboradores de un repositorio.

        Returns:
            Lista de colaboradores con sus permisos
        """
        data = self._make_request(f"/repos/{owner}/{repo}/collaborators")
        if isinstance(data, list):
            collaborators = []
            for collab in data:
                collaborators.append({
                    "username": collab.get("login"),
                    "avatar": collab.get("avatar_url"),
                    "permissions": collab.get("permissions", {}),
                    "role": self._get_role_from_permissions(collab.get("permissions", {}))
                })
            return collaborators
        return []

    def get_repo_permissions(self, owner: str, repo: str, username: str) -> Dict:
        """
        Obtiene los permisos de un usuario específico en un repositorio.
        """
        data = self._make_request(f"/repos/{owner}/{repo}/collaborators/{username}/permission")
        if data and "error" not in data:
            return {
                "permission": data.get("permission"),
                "role_name": data.get("role_name"),
                "user": data.get("user", {}).get("login")
            }
        return {"permission": "none", "role_name": "Sin acceso"}

    def _get_role_from_permissions(self, permissions: Dict) -> str:
        """Determina el rol basado en los permisos"""
        if permissions.get("admin"):
            return "Admin"
        elif permissions.get("maintain"):
            return "Maintainer"
        elif permissions.get("push"):
            return "Write"
        elif permissions.get("triage"):
            return "Triage"
        elif permissions.get("pull"):
            return "Read"
        return "None"

    def get_repo_traffic(self, owner: str, repo: str) -> Dict:
        """
        Obtiene estadísticas de tráfico del repositorio.
        Requiere permisos de push en el repo.
        """
        clones = self._make_request(f"/repos/{owner}/{repo}/traffic/clones")
        views = self._make_request(f"/repos/{owner}/{repo}/traffic/views")
        referrers = self._make_request(f"/repos/{owner}/{repo}/traffic/popular/referrers")
        paths = self._make_request(f"/repos/{owner}/{repo}/traffic/popular/paths")

        return {
            "clones": clones if clones and "error" not in clones else {"count": 0, "uniques": 0, "clones": []},
            "views": views if views and "error" not in views else {"count": 0, "uniques": 0, "views": []},
            "referrers": referrers if referrers and "error" not in referrers else [],
            "paths": paths if paths and "error" not in paths else []
        }

    def get_org_traffic_summary(self, org: str, max_repos: int = 30) -> Dict:
        """
        Obtiene estadísticas de tráfico de los repositorios más activos de una organización.
        Requiere permisos de admin o push en los repos.

        Args:
            org: Nombre de la organización
            max_repos: Máximo de repos a consultar (default 30, los más recientes)

        Returns:
            Dict con resumen de tráfico por repositorio
        """
        # Verificar caché (30 minutos)
        cache_key = f"org_traffic:{org}"
        if cache_key in self._cache:
            cached = self._cache[cache_key]
            if (datetime.now() - cached['time']).seconds < 1800:  # 30 minutos
                return cached['data']

        all_repos = self.get_org_repos(org)

        # Ordenar por actividad reciente (pushed_at) y tomar solo los más activos
        sorted_repos = sorted(all_repos, key=lambda x: x.get("pushed_at") or "", reverse=True)
        repos = sorted_repos[:max_repos]

        traffic_data = {
            "organization": org,
            "timestamp": datetime.now().isoformat(),
            "total_repos": len(all_repos),
            "repos_checked": len(repos),
            "total_clones": 0,
            "total_unique_cloners": 0,
            "total_views": 0,
            "total_unique_visitors": 0,
            "repos_with_traffic": [],
            "daily_clones": {},
            "top_cloned_repos": [],
            "errors": []
        }

        for repo in repos:
            repo_name = repo.get("name")
            full_name = repo.get("full_name", f"{org}/{repo_name}")

            try:
                traffic = self.get_repo_traffic(org, repo_name)

                clones_data = traffic.get("clones", {})
                views_data = traffic.get("views", {})

                clone_count = clones_data.get("count", 0)
                unique_cloners = clones_data.get("uniques", 0)
                view_count = views_data.get("count", 0)
                unique_visitors = views_data.get("uniques", 0)

                # Solo incluir repos con actividad
                if clone_count > 0 or view_count > 0:
                    repo_traffic = {
                        "name": repo_name,
                        "full_name": full_name,
                        "url": repo.get("url"),
                        "private": repo.get("private"),
                        "clones": clone_count,
                        "unique_cloners": unique_cloners,
                        "views": view_count,
                        "unique_visitors": unique_visitors,
                        "daily_clones": clones_data.get("clones", []),
                        "daily_views": views_data.get("views", []),
                        "referrers": traffic.get("referrers", []),
                        "popular_paths": traffic.get("paths", [])
                    }
                    traffic_data["repos_with_traffic"].append(repo_traffic)

                    # Agregar clones diarios al total
                    for daily in clones_data.get("clones", []):
                        date = daily.get("timestamp", "")[:10]
                        if date not in traffic_data["daily_clones"]:
                            traffic_data["daily_clones"][date] = {"count": 0, "uniques": 0}
                        traffic_data["daily_clones"][date]["count"] += daily.get("count", 0)
                        traffic_data["daily_clones"][date]["uniques"] += daily.get("uniques", 0)

                traffic_data["total_clones"] += clone_count
                traffic_data["total_unique_cloners"] += unique_cloners
                traffic_data["total_views"] += view_count
                traffic_data["total_unique_visitors"] += unique_visitors

            except Exception as e:
                traffic_data["errors"].append({"repo": repo_name, "error": str(e)})

        # Ordenar repos por clones (top cloned)
        traffic_data["repos_with_traffic"].sort(key=lambda x: x.get("clones", 0), reverse=True)
        traffic_data["top_cloned_repos"] = traffic_data["repos_with_traffic"][:10]

        # Convertir daily_clones a lista ordenada
        traffic_data["daily_clones_list"] = [
            {"date": date, **data}
            for date, data in sorted(traffic_data["daily_clones"].items())
        ]

        # Guardar en caché
        self._cache[cache_key] = {'data': traffic_data, 'time': datetime.now()}

        return traffic_data

    def add_collaborator(self, owner: str, repo: str, username: str, permission: str = "push") -> Dict:
        """
        Agrega un colaborador a un repositorio.

        Args:
            owner: Dueño del repo (usuario u organización)
            repo: Nombre del repositorio
            username: Usuario a agregar
            permission: pull (read), push (write), admin, maintain, triage

        Returns:
            Dict con resultado de la operación
        """
        valid_permissions = ["pull", "push", "admin", "maintain", "triage"]
        if permission not in valid_permissions:
            return {"error": f"Permiso inválido. Usar: {', '.join(valid_permissions)}"}

        result = self._make_request(
            f"/repos/{owner}/{repo}/collaborators/{username}",
            method="PUT",
            json_data={"permission": permission}
        )

        # Limpiar caché de colaboradores
        cache_key = f"repo:{owner}/{repo}"
        if cache_key in self._cache:
            del self._cache[cache_key]

        return result if result else {"error": "Error al agregar colaborador"}

    def remove_collaborator(self, owner: str, repo: str, username: str) -> Dict:
        """
        Elimina un colaborador de un repositorio.
        """
        result = self._make_request(
            f"/repos/{owner}/{repo}/collaborators/{username}",
            method="DELETE"
        )

        # Limpiar caché
        cache_key = f"repo:{owner}/{repo}"
        if cache_key in self._cache:
            del self._cache[cache_key]

        return result if result else {"error": "Error al eliminar colaborador"}

    def update_collaborator_permission(self, owner: str, repo: str, username: str, permission: str) -> Dict:
        """
        Actualiza el permiso de un colaborador (es lo mismo que agregar con nuevo permiso).
        """
        return self.add_collaborator(owner, repo, username, permission)

    def get_org_repos(self, org: str) -> List[Dict]:
        """
        Obtiene todos los repositorios de una organización.
        Usa caché de 30 minutos.
        """
        cache_key = f"org_repos:{org}"
        if cache_key in self._cache:
            cached = self._cache[cache_key]
            if (datetime.now() - cached['time']).seconds < self._org_cache_ttl:
                return cached['data']

        repos = []
        page = 1
        while True:
            data = self._make_request(f"/orgs/{org}/repos?per_page=100&page={page}")
            if not data or isinstance(data, dict) and "error" in data:
                break
            if not data:
                break
            for repo in data:
                repos.append({
                    "name": repo.get("name"),
                    "full_name": repo.get("full_name"),
                    "private": repo.get("private"),
                    "url": repo.get("html_url"),
                    "description": repo.get("description"),
                    "created_at": repo.get("created_at"),
                    "updated_at": repo.get("updated_at"),
                    "pushed_at": repo.get("pushed_at"),
                    "default_branch": repo.get("default_branch"),
                    "visibility": repo.get("visibility"),
                    "archived": repo.get("archived"),
                })
            if len(data) < 100:
                break
            page += 1

        # Guardar en caché
        self._cache[cache_key] = {'data': repos, 'time': datetime.now()}
        return repos

    def get_org_members(self, org: str) -> List[Dict]:
        """
        Obtiene los miembros de una organización.
        Usa caché de 30 minutos.
        """
        cache_key = f"org_members:{org}"
        if cache_key in self._cache:
            cached = self._cache[cache_key]
            if (datetime.now() - cached['time']).seconds < self._org_cache_ttl:
                return cached['data']

        data = self._make_request(f"/orgs/{org}/members")
        members = []
        if isinstance(data, list):
            members = [{
                "username": m.get("login"),
                "avatar": m.get("avatar_url"),
                "role": "member"
            } for m in data]

        self._cache[cache_key] = {'data': members, 'time': datetime.now()}
        return members

    def get_org_info(self, org: str) -> Optional[Dict]:
        """
        Obtiene información de la organización.
        Usa caché de 30 minutos.
        """
        cache_key = f"org_info:{org}"
        if cache_key in self._cache:
            cached = self._cache[cache_key]
            if (datetime.now() - cached['time']).seconds < self._org_cache_ttl:
                return cached['data']

        data = self._make_request(f"/orgs/{org}")
        if data and "error" not in data:
            info = {
                "name": data.get("name"),
                "login": data.get("login"),
                "description": data.get("description"),
                "public_repos": data.get("public_repos"),
                "total_private_repos": data.get("total_private_repos"),
                "plan": data.get("plan", {}).get("name"),
                "members_count": data.get("members_count", 0),
                "avatar": data.get("avatar_url"),
            }
            self._cache[cache_key] = {'data': info, 'time': datetime.now()}
            return info
        return None


class RepositoryTracker:
    """Rastrea actividad de repositorios desde los eventos DLP"""

    def __init__(self, data_dir: str = None):
        # Usar /app/data si existe (Docker), sino usar directorio local
        if data_dir:
            self.data_dir = Path(data_dir)
        elif Path("/app/data").exists() or Path("/app").exists():
            self.data_dir = Path("/app/data")
        else:
            # Directorio local relativo al script
            self.data_dir = Path(__file__).parent / "data"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.repos_file = self.data_dir / "repositories.json"
        self.agents_file = self.data_dir / "known_agents.json"

        self.repositories = self._load_json(self.repos_file, {})
        self.known_agents = self._load_json(self.agents_file, {})

    def _load_json(self, path: Path, default: Dict) -> Dict:
        """Carga un archivo JSON o retorna el default"""
        try:
            if path.exists():
                return json.loads(path.read_text())
        except:
            pass
        return default

    def _save_json(self, path: Path, data: Dict):
        """Guarda datos en archivo JSON"""
        try:
            path.write_text(json.dumps(data, indent=2, default=str))
        except Exception as e:
            print(f"Error guardando {path}: {e}")

    def register_agent(self, hostname: str, ip: str):
        """Registra un agente conocido"""
        key = f"{hostname}_{ip}"
        if key not in self.known_agents:
            self.known_agents[key] = {
                "hostname": hostname,
                "ip": ip,
                "first_seen": datetime.now().isoformat(),
                "last_seen": datetime.now().isoformat()
            }
        else:
            self.known_agents[key]["last_seen"] = datetime.now().isoformat()

        self._save_json(self.agents_file, self.known_agents)

    def is_known_agent(self, hostname: str = None, ip: str = None) -> bool:
        """Verifica si un agente es conocido"""
        if hostname and ip:
            return f"{hostname}_{ip}" in self.known_agents
        if ip:
            return any(a.get("ip") == ip for a in self.known_agents.values())
        if hostname:
            return any(a.get("hostname") == hostname for a in self.known_agents.values())
        return False

    def track_event(self, event: Dict):
        """Registra un evento de actividad en un repositorio"""
        # Siempre registrar el agente, aunque no haya repo_name
        hostname = event.get("hostname")
        source_ip = event.get("source_ip")
        if hostname and source_ip:
            self.register_agent(hostname, source_ip)

        # Solo continuar con tracking de repo si hay repo_name
        repo_name = event.get("repo_name")
        if not repo_name:
            return

        # Inicializar repo si no existe
        if repo_name not in self.repositories:
            self.repositories[repo_name] = {
                "repo_name": repo_name,
                "repo_url": event.get("repo_url"),
                "first_seen": datetime.now().isoformat(),
                "total_clones": 0,
                "total_pushes": 0,
                "total_pulls": 0,
                "total_commits": 0,
                "clone_events": [],
                "activity": [],
                "users": {},
                "unauthorized_access": []
            }

        repo = self.repositories[repo_name]
        operation = event.get("git_operation") or event.get("event_type", "").replace("git_", "")

        # Contadores
        if operation == "clone" or event.get("event_type") == "new_repo_detected":
            repo["total_clones"] += 1
        elif operation == "push":
            repo["total_pushes"] += 1
        elif operation == "pull":
            repo["total_pulls"] += 1
        elif operation == "commit":
            repo["total_commits"] += 1

        # Registrar usuario
        username = event.get("username", "unknown")
        if username not in repo["users"]:
            repo["users"][username] = {
                "first_seen": datetime.now().isoformat(),
                "operations": 0
            }
        repo["users"][username]["operations"] += 1
        repo["users"][username]["last_seen"] = datetime.now().isoformat()

        # Registrar actividad
        activity_entry = {
            "timestamp": event.get("timestamp"),
            "operation": operation,
            "username": username,
            "hostname": hostname,
            "source_ip": source_ip,
            "branch": event.get("branch"),
            "is_from_agent": self.is_known_agent(hostname, source_ip)
        }
        repo["activity"].append(activity_entry)

        # Mantener solo últimas 100 actividades
        if len(repo["activity"]) > 100:
            repo["activity"] = repo["activity"][-100:]

        # Registrar clones específicamente
        if operation == "clone" or event.get("event_type") == "new_repo_detected":
            clone_entry = {
                "timestamp": event.get("timestamp"),
                "username": username,
                "hostname": hostname,
                "source_ip": source_ip,
                "repo_path": event.get("repo_path"),
                "is_from_agent": self.is_known_agent(hostname, source_ip)
            }
            repo["clone_events"].append(clone_entry)

            # Detectar acceso sin agente
            if not clone_entry["is_from_agent"]:
                repo["unauthorized_access"].append(clone_entry)

        self._save_json(self.repos_file, self.repositories)

    def get_repository_summary(self, repo_name: str) -> Optional[Dict]:
        """Obtiene resumen de un repositorio"""
        return self.repositories.get(repo_name)

    def get_all_repositories(self) -> Dict:
        """Obtiene todos los repositorios rastreados"""
        return self.repositories

    def get_known_agents(self) -> Dict:
        """Obtiene lista de agentes conocidos"""
        return self.known_agents

    def get_unauthorized_clones(self) -> List[Dict]:
        """Obtiene lista de clones desde equipos sin agente"""
        unauthorized = []
        for repo_name, repo in self.repositories.items():
            for clone in repo.get("unauthorized_access", []):
                clone["repo_name"] = repo_name
                unauthorized.append(clone)
        return sorted(unauthorized, key=lambda x: x.get("timestamp", ""), reverse=True)


# Instancia global
github_api = GitHubIntegration()
repo_tracker = RepositoryTracker()
