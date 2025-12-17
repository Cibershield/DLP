#!/usr/bin/env python3
"""
GitHub DLP Agent para Ubuntu - Versión Optimizada
Detecta descargas/clonaciones de repositorios GitHub fuera de IDEs autorizados
Con monitoreo de red y control de recursos

Compatible con: Ubuntu 20.04, 22.04, 24.04 (Desktop y Server)
"""

import os
import sys
import json
import time
import socket
import logging
import threading
import subprocess
import struct
import re
import platform
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Set, Tuple
from dataclasses import dataclass, asdict, field
from queue import Queue
from collections import deque

import psutil
import yaml

# ============================================================================
# CARGA DE CONFIGURACIÓN DESDE ARCHIVO
# ============================================================================

def load_config_from_yaml() -> Dict:
    """Carga configuración desde config.yaml si existe"""
    config_paths = [
        Path(__file__).parent.parent / "config.yaml",  # ../config.yaml
        Path(__file__).parent / "config.yaml",          # ./config.yaml
        Path("/etc/dlp-agent/config.yaml"),             # Instalación sistema
        Path.home() / ".dlp-agent" / "config.yaml",     # Config usuario
    ]

    for config_path in config_paths:
        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    yaml_config = yaml.safe_load(f)
                    if yaml_config:
                        return yaml_config, str(config_path)
            except Exception as e:
                print(f"[WARN] Error leyendo {config_path}: {e}")

    return None, None

# Cargar configuración YAML
_yaml_config, _config_file = load_config_from_yaml()

# ============================================================================
# DETECCIÓN DE SISTEMA OPERATIVO Y COMPATIBILIDAD
# ============================================================================

class SystemInfo:
    """Detecta información del sistema para compatibilidad"""

    def __init__(self):
        self.os_name = platform.system()
        self.os_release = platform.release()
        self.distribution = "unknown"
        self.version = "unknown"
        self.codename = "unknown"
        self.is_ubuntu = False
        self.is_desktop = False
        self.has_root = os.geteuid() == 0 if hasattr(os, 'geteuid') else False

        self._detect_distribution()
        self._detect_desktop()

    def _detect_distribution(self):
        """Detecta la distribución Linux"""
        if self.os_name != "Linux":
            return

        os_release_path = Path("/etc/os-release")
        if os_release_path.exists():
            try:
                content = os_release_path.read_text()
                for line in content.split('\n'):
                    if line.startswith('ID='):
                        self.distribution = line.split('=')[1].strip('"')
                    elif line.startswith('VERSION_ID='):
                        self.version = line.split('=')[1].strip('"')
                    elif line.startswith('VERSION_CODENAME='):
                        self.codename = line.split('=')[1].strip('"')

                self.is_ubuntu = self.distribution.lower() in ('ubuntu', 'linuxmint', 'pop')
            except Exception:
                pass

    def _detect_desktop(self):
        """Detecta si hay entorno de escritorio"""
        # Verificar variables de entorno comunes
        desktop_vars = ['DESKTOP_SESSION', 'XDG_CURRENT_DESKTOP', 'GNOME_DESKTOP_SESSION_ID']
        for var in desktop_vars:
            if os.environ.get(var):
                self.is_desktop = True
                return

        # Verificar display
        if os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY'):
            self.is_desktop = True

    def get_summary(self) -> Dict:
        """Retorna resumen del sistema"""
        return {
            "os": self.os_name,
            "distribution": self.distribution,
            "version": self.version,
            "codename": self.codename,
            "is_ubuntu": self.is_ubuntu,
            "is_desktop": self.is_desktop,
            "has_root": self.has_root
        }

# Información del sistema (singleton)
SYSTEM_INFO = SystemInfo()

# Intentar importar inotify para monitoreo de archivos
INOTIFY_AVAILABLE = False
INOTIFY_ERROR = None
try:
    import inotify.adapters
    import inotify.constants
    INOTIFY_AVAILABLE = True
except ImportError as e:
    INOTIFY_ERROR = str(e)
    # Solo mostrar advertencia si estamos en modo verbose o interactivo
    if sys.stdout.isatty():
        print(f"[INFO] inotify no disponible: {e}")

# ============================================================================
# CONFIGURACIÓN OPTIMIZADA PARA BAJO CONSUMO DE RECURSOS
# ============================================================================

# Valores por defecto
_DEFAULT_ALLOWED_PROCESSES = [
    "code", "code-insiders", "codium",
    "idea", "idea64", "pycharm", "pycharm64",
    "webstorm", "goland", "rider", "clion",
    "android-studio", "sublime_text", "atom",
    "eclipse", "netbeans",
]

# Obtener valores de config.yaml o usar defaults
def _get_console_config():
    """Obtiene la configuración de consola desde yaml o defaults"""
    if _yaml_config and 'console' in _yaml_config:
        return (
            _yaml_config['console'].get('host', 'localhost'),
            _yaml_config['console'].get('port', 5555)
        )
    return ('localhost', 5555)

_console_host, _console_port = _get_console_config()

CONFIG = {
    # IDEs y aplicaciones autorizadas (sus procesos padre)
    "allowed_processes": _yaml_config.get('allowed_processes', _DEFAULT_ALLOWED_PROCESSES) if _yaml_config else _DEFAULT_ALLOWED_PROCESSES,

    # Directorios a monitorear para carpetas .git
    "watch_directories": [
        str(Path.home()),
        "/tmp",
        "/var/tmp",
    ],

    # Directorios a excluir del monitoreo
    "exclude_directories": _yaml_config.get('exclude_directories', [
        ".cache", ".local/share/Trash", "snap", ".vscode",
        ".config/Code", "node_modules", ".npm", ".cargo",
    ]) if _yaml_config else [
        ".cache", ".local/share/Trash", "snap", ".vscode",
        ".config/Code", "node_modules", ".npm", ".cargo",
    ],

    # Servidor de consola - DESDE CONFIG.YAML
    "console_host": _console_host,
    "console_port": _console_port,
    
    # =========== CONFIGURACIÓN DE RENDIMIENTO ===========
    
    # Intervalos base (se ajustan dinámicamente según carga)
    "process_scan_interval": 2.0,      # Segundos entre escaneos de procesos
    "network_scan_interval": 5.0,      # Segundos entre escaneos de red
    "metrics_report_interval": 30.0,   # Segundos entre reportes de métricas
    
    # Límites de recursos del agente
    "max_cpu_percent": 5.0,            # Máximo % CPU que puede usar el agente
    "max_memory_mb": 100,              # Máxima memoria en MB
    "max_events_queue": 500,           # Máximo de eventos en cola
    
    # Throttling automático
    "system_cpu_threshold": 70.0,      # Si CPU del sistema > esto, reducir actividad
    "system_memory_threshold": 85.0,   # Si memoria del sistema > esto, reducir actividad
    "throttle_multiplier": 3.0,        # Multiplicar intervalos cuando hay throttle
    
    # Monitoreo de red
    "github_domains": [
        "github.com",
        "api.github.com",
        "raw.githubusercontent.com",
        "codeload.github.com",
        "gist.github.com",
        "objects.githubusercontent.com",
    ],
    "github_ips_cache_ttl": 300,       # Segundos para cachear resolución DNS
    
    # Nivel de logging
    "log_level": "INFO",
}


@dataclass
class DLPEvent:
    """Representa un evento de seguridad detectado"""
    timestamp: str
    event_type: str  # "git_command", "network_connection", "new_repo_detected", "agent_metrics"
    username: str
    hostname: str
    process_name: str
    command_line: str
    parent_process: str
    working_directory: str
    target_url: Optional[str] = None
    is_allowed: bool = False
    reason: str = ""
    # Campos adicionales para eventos de red
    remote_ip: Optional[str] = None
    remote_port: Optional[int] = None
    bytes_sent: Optional[int] = None
    bytes_recv: Optional[int] = None
    # Métricas del agente
    agent_cpu: Optional[float] = None
    agent_memory_mb: Optional[float] = None
    system_cpu: Optional[float] = None
    system_memory: Optional[float] = None
    
    def to_dict(self) -> Dict:
        # Filtrar campos None para reducir tamaño
        return {k: v for k, v in asdict(self).items() if v is not None}
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)


@dataclass
class AgentMetrics:
    """Métricas de rendimiento del agente"""
    timestamp: str
    cpu_percent: float
    memory_mb: float
    memory_percent: float
    threads_count: int
    events_queued: int
    events_sent: int
    events_failed: int
    system_cpu: float
    system_memory: float
    is_throttled: bool
    scan_intervals: Dict[str, float] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return asdict(self)


class ResourceManager:
    """Gestiona recursos y throttling del agente"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger("ResourceManager")
        self._process = psutil.Process()
        self._is_throttled = False
        self._throttle_reason = ""
        
        # Contadores
        self.events_sent = 0
        self.events_failed = 0
        
        # Intervalos actuales (se ajustan dinámicamente)
        self.current_intervals = {
            "process": config["process_scan_interval"],
            "network": config["network_scan_interval"],
        }
    
    def check_and_throttle(self) -> Tuple[bool, str]:
        """Verifica recursos del sistema y ajusta throttling"""
        try:
            # CPU del sistema
            system_cpu = psutil.cpu_percent(interval=0.1)
            
            # Memoria del sistema
            system_mem = psutil.virtual_memory().percent
            
            # Recursos del agente
            agent_cpu = self._process.cpu_percent(interval=0.1)
            agent_mem = self._process.memory_info().rss / (1024 * 1024)  # MB
            
            should_throttle = False
            reason = ""
            
            # Verificar límites del sistema
            if system_cpu > self.config["system_cpu_threshold"]:
                should_throttle = True
                reason = f"CPU sistema alta: {system_cpu:.1f}%"
            elif system_mem > self.config["system_memory_threshold"]:
                should_throttle = True
                reason = f"Memoria sistema alta: {system_mem:.1f}%"
            
            # Verificar límites del agente
            elif agent_cpu > self.config["max_cpu_percent"]:
                should_throttle = True
                reason = f"CPU agente alta: {agent_cpu:.1f}%"
            elif agent_mem > self.config["max_memory_mb"]:
                should_throttle = True
                reason = f"Memoria agente alta: {agent_mem:.1f}MB"
            
            # Aplicar/quitar throttle
            if should_throttle and not self._is_throttled:
                self._apply_throttle(reason)
            elif not should_throttle and self._is_throttled:
                self._remove_throttle()
            
            return self._is_throttled, self._throttle_reason
            
        except Exception as e:
            self.logger.error(f"Error verificando recursos: {e}")
            return False, ""
    
    def _apply_throttle(self, reason: str):
        """Aplica throttling aumentando intervalos"""
        self._is_throttled = True
        self._throttle_reason = reason
        multiplier = self.config["throttle_multiplier"]
        
        self.current_intervals["process"] = self.config["process_scan_interval"] * multiplier
        self.current_intervals["network"] = self.config["network_scan_interval"] * multiplier
        
        self.logger.warning(f"⚡ THROTTLE ACTIVADO: {reason}")
        self.logger.info(f"   Intervalos aumentados x{multiplier}")
    
    def _remove_throttle(self):
        """Quita throttling restaurando intervalos"""
        self._is_throttled = False
        self._throttle_reason = ""
        
        self.current_intervals["process"] = self.config["process_scan_interval"]
        self.current_intervals["network"] = self.config["network_scan_interval"]
        
        self.logger.info("⚡ THROTTLE DESACTIVADO: Recursos normalizados")
    
    def get_metrics(self) -> AgentMetrics:
        """Obtiene métricas actuales del agente"""
        try:
            return AgentMetrics(
                timestamp=datetime.now().isoformat(),
                cpu_percent=self._process.cpu_percent(interval=0.1),
                memory_mb=self._process.memory_info().rss / (1024 * 1024),
                memory_percent=self._process.memory_percent(),
                threads_count=self._process.num_threads(),
                events_queued=0,  # Se actualiza externamente
                events_sent=self.events_sent,
                events_failed=self.events_failed,
                system_cpu=psutil.cpu_percent(interval=0.1),
                system_memory=psutil.virtual_memory().percent,
                is_throttled=self._is_throttled,
                scan_intervals=self.current_intervals.copy()
            )
        except Exception as e:
            self.logger.error(f"Error obteniendo métricas: {e}")
            return None
    
    def get_interval(self, monitor_type: str) -> float:
        """Obtiene el intervalo actual para un tipo de monitor"""
        return self.current_intervals.get(monitor_type, 2.0)
    
    @property
    def is_throttled(self) -> bool:
        return self._is_throttled


class EventReporter:
    """Envía eventos a la consola central - Versión optimizada"""
    
    def __init__(self, host: str, port: int, resource_manager: ResourceManager):
        self.host = host
        self.port = port
        self.resource_manager = resource_manager
        self.event_queue: Queue = Queue(maxsize=CONFIG["max_events_queue"])
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self.logger = logging.getLogger("EventReporter")
        
        # También guardar eventos localmente
        self.local_log_path = Path.home() / ".dlp-agent" / "events.jsonl"
        self.local_log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Buffer para envío en lotes
        self._send_buffer: List[DLPEvent] = []
        self._buffer_size = 10
        self._last_flush = time.time()
        self._flush_interval = 5.0  # Segundos
    
    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._sender_loop, daemon=True)
        self._thread.start()
        self.logger.info("EventReporter iniciado")
    
    def stop(self):
        self.running = False
        self._flush_buffer()  # Enviar eventos pendientes
        if self._thread:
            self._thread.join(timeout=5)
    
    def report(self, event: DLPEvent):
        """Encola un evento para enviar"""
        try:
            self.event_queue.put_nowait(event)
        except:
            # Cola llena, descartar evento más antiguo
            try:
                self.event_queue.get_nowait()
                self.event_queue.put_nowait(event)
            except:
                pass
        
        # Guardar localmente siempre (async)
        self._save_local(event)
    
    def _save_local(self, event: DLPEvent):
        """Guarda evento localmente de forma no bloqueante"""
        try:
            with open(self.local_log_path, "a") as f:
                f.write(event.to_json() + "\n")
        except Exception as e:
            self.logger.debug(f"Error guardando local: {e}")
    
    def _sender_loop(self):
        while self.running:
            try:
                # Obtener evento con timeout
                try:
                    event = self.event_queue.get(timeout=1)
                    self._send_buffer.append(event)
                except:
                    pass
                
                # Flush si buffer lleno o timeout
                if (len(self._send_buffer) >= self._buffer_size or 
                    (self._send_buffer and time.time() - self._last_flush > self._flush_interval)):
                    self._flush_buffer()
                    
            except Exception as e:
                self.logger.error(f"Error en sender loop: {e}")
                time.sleep(1)
    
    def _flush_buffer(self):
        """Envía todos los eventos del buffer"""
        if not self._send_buffer:
            return
        
        events_to_send = self._send_buffer.copy()
        self._send_buffer.clear()
        self._last_flush = time.time()
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                sock.connect((self.host, self.port))
                
                # Enviar todos los eventos en una conexión
                data = "\n".join(e.to_json() for e in events_to_send) + "\n"
                sock.sendall(data.encode())
                
                self.resource_manager.events_sent += len(events_to_send)
                self.logger.debug(f"Enviados {len(events_to_send)} eventos")
                
        except ConnectionRefusedError:
            self.logger.debug("Consola no disponible, eventos guardados localmente")
            self.resource_manager.events_failed += len(events_to_send)
        except Exception as e:
            self.logger.error(f"Error enviando eventos: {e}")
            self.resource_manager.events_failed += len(events_to_send)
    
    @property
    def queue_size(self) -> int:
        return self.event_queue.qsize()


class ProcessMonitor:
    """Monitorea procesos del sistema buscando comandos git - Optimizado"""
    
    def __init__(self, config: Dict, reporter: EventReporter, resource_manager: ResourceManager):
        self.config = config
        self.reporter = reporter
        self.resource_manager = resource_manager
        self.logger = logging.getLogger("ProcessMonitor")
        self.seen_pids: Set[int] = set()
        self.hostname = socket.gethostname()
        self.running = False
        self._thread: Optional[threading.Thread] = None
        
        # Cache de procesos padre para evitar lookups repetidos
        self._parent_cache: Dict[int, Tuple[str, bool]] = {}
        self._cache_ttl = 60  # Segundos
        self._last_cache_clear = time.time()
    
    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        self.logger.info("ProcessMonitor iniciado")
    
    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)
    
    def _monitor_loop(self):
        while self.running:
            try:
                self._scan_processes()
                
                # Usar intervalo dinámico
                interval = self.resource_manager.get_interval("process")
                time.sleep(interval)
                
            except Exception as e:
                self.logger.error(f"Error en scan: {e}")
                time.sleep(5)
    
    def _scan_processes(self):
        """Escanea procesos activos buscando comandos git - Optimizado"""
        current_pids = set()
        
        # Limpiar cache periódicamente
        if time.time() - self._last_cache_clear > self._cache_ttl:
            self._parent_cache.clear()
            self._last_cache_clear = time.time()
        
        # Usar process_iter con attrs específicos (más eficiente)
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username', 'cwd', 'ppid']):
            try:
                pinfo = proc.info
                pid = pinfo['pid']
                current_pids.add(pid)
                
                # Saltar si ya procesamos este PID
                if pid in self.seen_pids:
                    continue
                
                cmdline = pinfo.get('cmdline') or []
                if not cmdline:
                    continue
                
                name = pinfo.get('name', '')
                
                # Filtro rápido: solo procesar si es git, gh, curl o wget
                if name not in ('git', 'gh', 'curl', 'wget'):
                    continue
                
                cmd_str = ' '.join(cmdline)
                
                # Verificar si es un comando de git relacionado con GitHub
                if self._is_github_git_command(cmd_str, name):
                    self.seen_pids.add(pid)
                    
                    # Verificar proceso padre (con cache)
                    ppid = pinfo.get('ppid')
                    parent_name, is_allowed = self._get_parent_info_cached(ppid)
                    
                    # Extraer URL si está presente
                    target_url = self._extract_github_url(cmd_str)
                    
                    event = DLPEvent(
                        timestamp=datetime.now().isoformat(),
                        event_type="git_command",
                        username=pinfo.get('username', 'unknown'),
                        hostname=self.hostname,
                        process_name=name,
                        command_line=cmd_str[:500],  # Limitar longitud
                        parent_process=parent_name,
                        working_directory=pinfo.get('cwd', 'unknown') or 'unknown',
                        target_url=target_url,
                        is_allowed=is_allowed,
                        reason="IDE autorizado" if is_allowed else "Ejecutado fuera de IDE autorizado"
                    )
                    
                    # Log según estado
                    if not is_allowed:
                        self.logger.warning(
                            f"🚨 ALERTA: {event.username} ejecutó '{cmd_str[:50]}...' "
                            f"desde {parent_name}"
                        )
                    else:
                        self.logger.info(
                            f"✓ Permitido: {event.username} ejecutó git desde {parent_name}"
                        )
                    
                    self.reporter.report(event)
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Limpiar PIDs que ya no existen (mantener set pequeño)
        if len(self.seen_pids) > 1000:
            self.seen_pids &= current_pids
    
    def _get_parent_info_cached(self, ppid: Optional[int]) -> Tuple[str, bool]:
        """Obtiene info del proceso padre con cache"""
        if not ppid:
            return ("unknown", False)
        
        if ppid in self._parent_cache:
            return self._parent_cache[ppid]
        
        parent_name = self._get_parent_process_name(ppid)
        is_allowed = self._is_allowed_parent(ppid)
        
        self._parent_cache[ppid] = (parent_name, is_allowed)
        return (parent_name, is_allowed)
    
    def _is_github_git_command(self, cmd: str, name: str) -> bool:
        """Verifica si es un comando git relacionado con GitHub"""
        cmd_lower = cmd.lower()
        
        # Comandos git clone/pull/fetch
        if name == 'git':
            if any(x in cmd_lower for x in ['clone', 'pull', 'fetch']):
                # Verificar si involucra GitHub o es clone genérico
                if 'github.com' in cmd_lower or 'clone' in cmd_lower:
                    return True
        
        # GitHub CLI
        elif name == 'gh':
            if any(x in cmd_lower for x in ['clone', 'fork', 'repo']):
                return True
        
        # Descargas directas
        elif name in ('curl', 'wget'):
            if 'github.com' in cmd_lower:
                if any(x in cmd_lower for x in ['archive', '.zip', '.tar', 'raw.']):
                    return True
        
        return False
    
    def _get_parent_process_name(self, ppid: Optional[int]) -> str:
        """Obtiene el nombre del proceso padre"""
        if not ppid:
            return "unknown"
        try:
            parent = psutil.Process(ppid)
            return parent.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return "unknown"
    
    def _is_allowed_parent(self, ppid: Optional[int]) -> bool:
        """Verifica si el proceso padre es un IDE autorizado"""
        if not ppid:
            return False
        
        allowed_lower = [p.lower() for p in self.config["allowed_processes"]]
        
        try:
            # Recorrer la jerarquía de procesos hacia arriba
            current_pid = ppid
            max_depth = 10
            
            for _ in range(max_depth):
                if current_pid is None or current_pid <= 1:
                    break
                
                proc = psutil.Process(current_pid)
                proc_name = proc.name().lower()
                
                # Verificar si algún ancestro es un IDE autorizado
                for allowed in allowed_lower:
                    if allowed in proc_name:
                        return True
                
                current_pid = proc.ppid()
                
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        
        return False
    
    def _extract_github_url(self, cmd: str) -> Optional[str]:
        """Extrae la URL de GitHub del comando"""
        patterns = [
            r'(https?://github\.com/[^\s]+)',
            r'(git@github\.com:[^\s]+)',
            r'(github\.com/[^\s]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, cmd, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None


class FileSystemMonitor:
    """Monitorea la creación de carpetas .git usando inotify - Optimizado"""
    
    def __init__(self, config: Dict, reporter: EventReporter, resource_manager: ResourceManager):
        self.config = config
        self.reporter = reporter
        self.resource_manager = resource_manager
        self.logger = logging.getLogger("FileSystemMonitor")
        self.hostname = socket.gethostname()
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self.notifier = None
    
    def start(self):
        if not INOTIFY_AVAILABLE:
            self.logger.warning("inotify no disponible, FileSystemMonitor deshabilitado")
            return
        
        self.running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        self.logger.info("FileSystemMonitor iniciado")
    
    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)
    
    def _should_exclude(self, path: str) -> bool:
        """Verifica si un path debe ser excluido"""
        for exclude in self.config["exclude_directories"]:
            if exclude in path:
                return True
        return False
    
    def _monitor_loop(self):
        """Loop principal de monitoreo con inotify"""
        try:
            self.notifier = inotify.adapters.InotifyTrees(
                self.config["watch_directories"],
                mask=inotify.constants.IN_CREATE | inotify.constants.IN_ISDIR
            )
            
            for event in self.notifier.event_gen(yield_nones=False):
                if not self.running:
                    break
                
                (_, type_names, path, filename) = event
                
                # Solo nos interesan directorios .git creados
                if 'IN_ISDIR' in type_names and filename == '.git':
                    full_path = os.path.join(path, filename)
                    
                    if self._should_exclude(full_path):
                        continue
                    
                    self.logger.warning(f"🚨 Nuevo repositorio detectado: {path}")
                    
                    # Determinar quién lo creó
                    username = self._get_directory_owner(full_path)
                    
                    event = DLPEvent(
                        timestamp=datetime.now().isoformat(),
                        event_type="new_repo_detected",
                        username=username,
                        hostname=self.hostname,
                        process_name="filesystem",
                        command_line="",
                        parent_process="",
                        working_directory=path,
                        target_url=None,
                        is_allowed=False,
                        reason=f"Nueva carpeta .git creada en {path}"
                    )
                    
                    self.reporter.report(event)
                    
        except Exception as e:
            self.logger.error(f"Error en FileSystemMonitor: {e}")
    
    def _get_directory_owner(self, path: str) -> str:
        """Obtiene el dueño de un directorio"""
        try:
            import pwd
            stat_info = os.stat(path)
            return pwd.getpwuid(stat_info.st_uid).pw_name
        except Exception:
            return "unknown"


class NetworkMonitor:
    """Monitorea conexiones de red a GitHub - Lectura eficiente de /proc/net"""
    
    def __init__(self, config: Dict, reporter: EventReporter, resource_manager: ResourceManager):
        self.config = config
        self.reporter = reporter
        self.resource_manager = resource_manager
        self.logger = logging.getLogger("NetworkMonitor")
        self.hostname = socket.gethostname()
        self.running = False
        self._thread: Optional[threading.Thread] = None
        
        # Cache de IPs de GitHub
        self._github_ips: Set[str] = set()
        self._last_dns_refresh = 0
        
        # Conexiones ya reportadas (para evitar duplicados)
        self._seen_connections: Set[str] = set()
        self._seen_connections_ttl = 300  # 5 minutos
        self._last_cleanup = time.time()
        
        # Estadísticas de red por proceso
        self._process_network_stats: Dict[int, Dict] = {}
    
    def start(self):
        self.running = True
        self._refresh_github_ips()
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        self.logger.info(f"NetworkMonitor iniciado - Monitoreando {len(self._github_ips)} IPs de GitHub")
    
    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)
    
    def _refresh_github_ips(self):
        """Resuelve y cachea IPs de dominios de GitHub"""
        now = time.time()
        if now - self._last_dns_refresh < self.config["github_ips_cache_ttl"]:
            return
        
        self._last_dns_refresh = now
        new_ips = set()
        
        for domain in self.config["github_domains"]:
            try:
                # Resolver A records
                ips = socket.getaddrinfo(domain, 443, socket.AF_INET, socket.SOCK_STREAM)
                for ip_info in ips:
                    new_ips.add(ip_info[4][0])
                
                # También IPv6
                try:
                    ips_v6 = socket.getaddrinfo(domain, 443, socket.AF_INET6, socket.SOCK_STREAM)
                    for ip_info in ips_v6:
                        new_ips.add(ip_info[4][0])
                except:
                    pass
                    
            except socket.gaierror:
                self.logger.debug(f"No se pudo resolver {domain}")
        
        if new_ips:
            self._github_ips = new_ips
            self.logger.debug(f"Actualizadas {len(self._github_ips)} IPs de GitHub")
    
    def _monitor_loop(self):
        while self.running:
            try:
                self._scan_connections()
                
                # Limpiar conexiones vistas periódicamente
                if time.time() - self._last_cleanup > self._seen_connections_ttl:
                    self._seen_connections.clear()
                    self._last_cleanup = time.time()
                
                # Refrescar IPs de GitHub periódicamente
                self._refresh_github_ips()
                
                # Usar intervalo dinámico
                interval = self.resource_manager.get_interval("network")
                time.sleep(interval)
                
            except Exception as e:
                self.logger.error(f"Error en network scan: {e}")
                time.sleep(10)
    
    def _scan_connections(self):
        """Escanea conexiones activas a IPs de GitHub"""
        if not self._github_ips:
            return
        
        try:
            # Usar psutil para conexiones (más eficiente que leer /proc directamente)
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                # Solo conexiones establecidas
                if conn.status != 'ESTABLISHED':
                    continue
                
                # Verificar si es a una IP de GitHub
                if not conn.raddr:
                    continue
                
                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port
                
                if remote_ip not in self._github_ips:
                    continue
                
                # Crear identificador único para esta conexión
                conn_id = f"{conn.pid}:{remote_ip}:{remote_port}"
                
                if conn_id in self._seen_connections:
                    continue
                
                self._seen_connections.add(conn_id)
                
                # Obtener información del proceso
                proc_info = self._get_process_info(conn.pid)
                
                if not proc_info:
                    continue
                
                # Verificar si es desde un IDE permitido
                is_allowed = self._is_allowed_process(conn.pid)
                
                event = DLPEvent(
                    timestamp=datetime.now().isoformat(),
                    event_type="network_connection",
                    username=proc_info.get('username', 'unknown'),
                    hostname=self.hostname,
                    process_name=proc_info.get('name', 'unknown'),
                    command_line=proc_info.get('cmdline', '')[:300],
                    parent_process=proc_info.get('parent', 'unknown'),
                    working_directory=proc_info.get('cwd', 'unknown'),
                    target_url=f"https://{remote_ip}",
                    remote_ip=remote_ip,
                    remote_port=remote_port,
                    is_allowed=is_allowed,
                    reason="IDE autorizado" if is_allowed else "Conexión a GitHub fuera de IDE"
                )
                
                # Log
                if not is_allowed:
                    self.logger.warning(
                        f"🌐 Conexión GitHub: {proc_info.get('name')} -> {remote_ip}:{remote_port} "
                        f"(usuario: {proc_info.get('username')})"
                    )
                
                self.reporter.report(event)
                
        except psutil.AccessDenied:
            self.logger.debug("Acceso denegado para algunas conexiones (ejecutar como root para ver todas)")
        except Exception as e:
            self.logger.error(f"Error escaneando conexiones: {e}")
    
    def _get_process_info(self, pid: int) -> Optional[Dict]:
        """Obtiene información de un proceso por PID"""
        if not pid:
            return None
        
        try:
            proc = psutil.Process(pid)
            parent = proc.parent()
            
            return {
                'name': proc.name(),
                'username': proc.username(),
                'cmdline': ' '.join(proc.cmdline()),
                'cwd': proc.cwd() if proc.cwd() else 'unknown',
                'parent': parent.name() if parent else 'unknown',
                'ppid': proc.ppid()
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None
    
    def _is_allowed_process(self, pid: int) -> bool:
        """Verifica si el proceso o sus ancestros son IDEs permitidos"""
        if not pid:
            return False
        
        allowed_lower = [p.lower() for p in self.config["allowed_processes"]]
        
        try:
            current_pid = pid
            max_depth = 10
            
            for _ in range(max_depth):
                if current_pid is None or current_pid <= 1:
                    break
                
                proc = psutil.Process(current_pid)
                proc_name = proc.name().lower()
                
                for allowed in allowed_lower:
                    if allowed in proc_name:
                        return True
                
                current_pid = proc.ppid()
                
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        
        return False


class MetricsReporter:
    """Reporta métricas del agente periódicamente"""
    
    def __init__(self, config: Dict, reporter: EventReporter, resource_manager: ResourceManager):
        self.config = config
        self.reporter = reporter
        self.resource_manager = resource_manager
        self.logger = logging.getLogger("MetricsReporter")
        self.hostname = socket.gethostname()
        self.running = False
        self._thread: Optional[threading.Thread] = None
    
    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._report_loop, daemon=True)
        self._thread.start()
        self.logger.info("MetricsReporter iniciado")
    
    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)
    
    def _report_loop(self):
        while self.running:
            try:
                # Verificar throttling
                self.resource_manager.check_and_throttle()
                
                # Obtener métricas
                metrics = self.resource_manager.get_metrics()
                
                if metrics:
                    metrics.events_queued = self.reporter.queue_size
                    
                    # Crear evento de métricas
                    event = DLPEvent(
                        timestamp=metrics.timestamp,
                        event_type="agent_metrics",
                        username=os.getenv('USER', 'agent'),
                        hostname=self.hostname,
                        process_name="dlp-agent",
                        command_line="",
                        parent_process="",
                        working_directory="",
                        agent_cpu=metrics.cpu_percent,
                        agent_memory_mb=metrics.memory_mb,
                        system_cpu=metrics.system_cpu,
                        system_memory=metrics.system_memory,
                        is_allowed=True,
                        reason=f"throttled={metrics.is_throttled}"
                    )
                    
                    self.reporter.report(event)
                    
                    # Log si hay throttling
                    if metrics.is_throttled:
                        self.logger.info(
                            f"📊 Métricas: CPU={metrics.cpu_percent:.1f}% "
                            f"RAM={metrics.memory_mb:.1f}MB "
                            f"[THROTTLED]"
                        )
                
                time.sleep(self.config["metrics_report_interval"])
                
            except Exception as e:
                self.logger.error(f"Error reportando métricas: {e}")
                time.sleep(30)


class DLPAgent:
    """Agente principal que coordina todos los monitores - Versión con Kernel Monitoring"""

    def __init__(self, config: Dict = None):
        self.config = config or CONFIG
        self.setup_logging()

        # Resource Manager primero (otros componentes lo necesitan)
        self.resource_manager = ResourceManager(self.config)

        self.reporter = EventReporter(
            self.config["console_host"],
            self.config["console_port"],
            self.resource_manager
        )

        # Monitores userspace (siempre disponibles)
        self.process_monitor = ProcessMonitor(self.config, self.reporter, self.resource_manager)
        self.filesystem_monitor = FileSystemMonitor(self.config, self.reporter, self.resource_manager)
        self.network_monitor = NetworkMonitor(self.config, self.reporter, self.resource_manager)
        self.metrics_reporter = MetricsReporter(self.config, self.reporter, self.resource_manager)

        # Monitor de kernel (requiere root para funcionalidad completa)
        self.kernel_monitor = None
        self._init_kernel_monitor()

        self.logger = logging.getLogger("DLPAgent")

    def _init_kernel_monitor(self):
        """Inicializa el monitor de kernel si está disponible"""
        try:
            from kernel_monitor import KernelMonitorManager, KernelEvent

            def kernel_event_handler(event: KernelEvent):
                """Convierte eventos de kernel a eventos DLP"""
                dlp_event = DLPEvent(
                    timestamp=event.timestamp,
                    event_type=f"kernel_{event.event_type}",
                    username=self._get_username_from_uid(event.uid),
                    hostname=socket.gethostname(),
                    process_name=event.comm,
                    command_line=event.args,
                    parent_process=str(event.ppid),
                    working_directory="",
                    target_url=None,
                    is_allowed=False,
                    reason=f"Detectado via {event.source}",
                    remote_ip=event.remote_ip,
                    remote_port=event.remote_port
                )
                self.reporter.report(dlp_event)

            self.kernel_monitor = KernelMonitorManager(kernel_event_handler)

        except ImportError:
            pass  # kernel_monitor no disponible
        except Exception as e:
            logging.getLogger("DLPAgent").debug(f"Error inicializando kernel monitor: {e}")

    def _get_username_from_uid(self, uid: int) -> str:
        """Convierte UID a nombre de usuario"""
        try:
            import pwd
            return pwd.getpwuid(uid).pw_name
        except:
            return str(uid)
    
    def setup_logging(self):
        """Configura el sistema de logging"""
        log_dir = Path.home() / ".dlp-agent"
        log_dir.mkdir(parents=True, exist_ok=True)
        
        logging.basicConfig(
            level=getattr(logging, self.config["log_level"]),
            format='%(asctime)s [%(name)s] %(levelname)s: %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler(log_dir / "agent.log")
            ]
        )
    
    def start(self):
        """Inicia todos los monitores"""
        self.logger.info("=" * 60)
        self.logger.info("DLP Agent v0.8 - Cibershield R.L.")
        self.logger.info("=" * 60)

        # Mostrar información del sistema
        sys_info = SYSTEM_INFO.get_summary()
        self.logger.info(f"Sistema: {sys_info['distribution']} {sys_info['version']}")
        self.logger.info(f"Hostname: {socket.gethostname()}")
        self.logger.info(f"Privilegios: {'root' if sys_info['has_root'] else 'usuario'}")
        self.logger.info("-" * 60)

        self.reporter.start()
        self.process_monitor.start()
        self.filesystem_monitor.start()
        self.network_monitor.start()
        self.metrics_reporter.start()

        # Iniciar monitor de kernel si está disponible
        kernel_status = None
        if self.kernel_monitor:
            if self.kernel_monitor.start():
                kernel_status = self.kernel_monitor.get_status()

        # Contar monitores activos
        active_monitors = ["ProcessMonitor", "NetworkMonitor", "MetricsReporter"]
        if INOTIFY_AVAILABLE:
            active_monitors.append("FileSystemMonitor")
        if kernel_status:
            if kernel_status.get('netlink_available'):
                active_monitors.append("Netlink")
            if kernel_status.get('ebpf_available'):
                active_monitors.append("eBPF")

        self.logger.info(f"Monitores activos: {len(active_monitors)}")
        self.logger.info("Agente iniciado correctamente")
    
    def stop(self):
        """Detiene todos los monitores"""
        self.logger.info("Deteniendo agente...")

        # Detener monitor de kernel primero
        if self.kernel_monitor:
            self.kernel_monitor.stop()
        self.process_monitor.stop()
        self.filesystem_monitor.stop()
        self.network_monitor.stop()
        self.metrics_reporter.stop()
        self.reporter.stop()
        self.logger.info("Agente detenido")
    
    def run(self):
        """Ejecuta el agente hasta recibir señal de parada"""
        self.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()


def main():
    """Punto de entrada principal"""
    agent = DLPAgent()
    agent.run()


if __name__ == "__main__":
    main()
