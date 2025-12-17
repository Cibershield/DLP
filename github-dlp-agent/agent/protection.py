#!/usr/bin/env python3
"""
Módulo de Protección y Persistencia para DLP Agent
Proporciona:
- Autenticación por clave para operaciones administrativas
- Watchdog para auto-recuperación
- Protección contra manipulación
- Alertas de seguridad

USO EMPRESARIAL: Este módulo está diseñado para entornos corporativos donde
el agente DLP debe estar protegido contra manipulación por usuarios finales.
La clave de administrador debe ser custodiada por el departamento de TI.
"""

import os
import sys
import json
import hashlib
import hmac
import time
import signal
import threading
import subprocess
import logging
from pathlib import Path
from typing import Optional, Dict, Callable
from dataclasses import dataclass, asdict
from datetime import datetime
import socket

# ============================================================================
# CONFIGURACIÓN
# ============================================================================

PROTECTION_CONFIG = {
    # Archivo de configuración de protección
    "config_file": "/etc/dlp-agent/protection.conf",
    "config_file_user": "~/.dlp-agent/protection.conf",

    # Intervalo del watchdog (segundos)
    "watchdog_interval": 30,

    # Máximo de intentos de autenticación fallidos
    "max_auth_failures": 3,

    # Bloqueo temporal tras fallos (segundos)
    "lockout_duration": 300,

    # Archivo de estado del watchdog
    "watchdog_state_file": "/var/run/dlp-agent-watchdog.state",
}


@dataclass
class SecurityAlert:
    """Alerta de seguridad"""
    timestamp: str
    alert_type: str  # "auth_failure", "tamper_attempt", "service_stopped", "config_modified"
    severity: str  # "low", "medium", "high", "critical"
    source_ip: Optional[str]
    username: str
    hostname: str
    details: str

    def to_dict(self) -> Dict:
        return asdict(self)


# ============================================================================
# ADMINISTRADOR DE CLAVES
# ============================================================================

class KeyManager:
    """Gestiona la clave de administrador para operaciones protegidas"""

    SALT_LENGTH = 32
    KEY_ITERATIONS = 100000

    def __init__(self, config_path: Optional[str] = None):
        self.logger = logging.getLogger("KeyManager")
        self.config_path = self._get_config_path(config_path)
        self._key_hash: Optional[bytes] = None
        self._salt: Optional[bytes] = None
        self._load_key()

        # Control de intentos fallidos
        self._failed_attempts = 0
        self._lockout_until = 0

    def _get_config_path(self, custom_path: Optional[str]) -> Path:
        """Determina la ruta del archivo de configuración"""
        if custom_path:
            return Path(custom_path)

        # Preferir configuración del sistema si existe
        system_config = Path(PROTECTION_CONFIG["config_file"])
        if system_config.exists():
            return system_config

        # Usar configuración de usuario
        user_config = Path(PROTECTION_CONFIG["config_file_user"]).expanduser()
        user_config.parent.mkdir(parents=True, exist_ok=True)
        return user_config

    def _load_key(self):
        """Carga la clave hasheada desde el archivo de configuración"""
        if not self.config_path.exists():
            self.logger.warning("No hay clave de administrador configurada")
            return

        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)
                self._key_hash = bytes.fromhex(config.get('key_hash', ''))
                self._salt = bytes.fromhex(config.get('salt', ''))
        except Exception as e:
            self.logger.error(f"Error cargando configuración de protección: {e}")

    def is_configured(self) -> bool:
        """Verifica si hay una clave configurada"""
        return self._key_hash is not None and len(self._key_hash) > 0

    def set_admin_key(self, new_key: str, current_key: Optional[str] = None) -> bool:
        """
        Establece o cambia la clave de administrador.
        Si ya existe una clave, se requiere la actual para cambiarla.
        """
        # Si ya hay clave, verificar la actual
        if self.is_configured():
            if not current_key or not self.verify_key(current_key):
                self.logger.warning("Intento de cambiar clave sin autenticación válida")
                return False

        # Generar salt y hash
        self._salt = os.urandom(self.SALT_LENGTH)
        self._key_hash = self._hash_key(new_key, self._salt)

        # Guardar configuración
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)

            config = {
                'key_hash': self._key_hash.hex(),
                'salt': self._salt.hex(),
                'created_at': datetime.now().isoformat(),
                'created_by': os.getenv('USER', 'unknown')
            }

            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=2)

            # Proteger el archivo
            os.chmod(self.config_path, 0o600)

            self.logger.info("Clave de administrador configurada exitosamente")
            return True

        except Exception as e:
            self.logger.error(f"Error guardando clave: {e}")
            return False

    def verify_key(self, key: str) -> bool:
        """Verifica si la clave proporcionada es correcta"""
        # Verificar lockout
        if time.time() < self._lockout_until:
            remaining = int(self._lockout_until - time.time())
            self.logger.warning(f"Sistema bloqueado. Reintentar en {remaining} segundos")
            return False

        if not self.is_configured():
            self.logger.warning("No hay clave configurada, acceso denegado")
            return False

        # Verificar clave
        test_hash = self._hash_key(key, self._salt)

        if hmac.compare_digest(test_hash, self._key_hash):
            self._failed_attempts = 0
            return True
        else:
            self._failed_attempts += 1
            self.logger.warning(f"Clave incorrecta (intento {self._failed_attempts}/{PROTECTION_CONFIG['max_auth_failures']})")

            if self._failed_attempts >= PROTECTION_CONFIG['max_auth_failures']:
                self._lockout_until = time.time() + PROTECTION_CONFIG['lockout_duration']
                self.logger.critical(f"Demasiados intentos fallidos. Bloqueado por {PROTECTION_CONFIG['lockout_duration']} segundos")

            return False

    def _hash_key(self, key: str, salt: bytes) -> bytes:
        """Genera hash de la clave usando PBKDF2"""
        return hashlib.pbkdf2_hmac(
            'sha256',
            key.encode('utf-8'),
            salt,
            self.KEY_ITERATIONS
        )


# ============================================================================
# WATCHDOG - Auto-recuperación del servicio
# ============================================================================

class ServiceWatchdog:
    """
    Watchdog que monitorea el agente principal y lo reinicia si se detiene.
    Diseñado para ejecutarse como servicio systemd separado.
    """

    def __init__(self, key_manager: KeyManager, alert_callback: Optional[Callable] = None):
        self.logger = logging.getLogger("ServiceWatchdog")
        self.key_manager = key_manager
        self.alert_callback = alert_callback
        self.running = False
        self._thread: Optional[threading.Thread] = None

        # Procesos a monitorear
        self.watched_processes = [
            {"name": "dlp-agent", "command": "dlp_agent.py", "restart_cmd": "systemctl restart dlp-agent"},
        ]

        # Estado
        self._last_check = 0
        self._restart_count = 0
        self._max_restarts = 5
        self._restart_window = 3600  # 1 hora

    def start(self):
        """Inicia el watchdog"""
        self.running = True
        self._thread = threading.Thread(target=self._watchdog_loop, daemon=True)
        self._thread.start()
        self.logger.info("Watchdog iniciado")

    def stop(self, admin_key: Optional[str] = None) -> bool:
        """
        Detiene el watchdog. Requiere clave de administrador.
        """
        if self.key_manager.is_configured():
            if not admin_key or not self.key_manager.verify_key(admin_key):
                self.logger.warning("Intento de detener watchdog sin autorización")
                self._send_alert("tamper_attempt", "high",
                    "Intento de detener watchdog sin clave de administrador")
                return False

        self.running = False
        if self._thread:
            self._thread.join(timeout=5)
        self.logger.info("Watchdog detenido (autorizado)")
        return True

    def _watchdog_loop(self):
        """Loop principal del watchdog"""
        while self.running:
            try:
                self._check_processes()
                time.sleep(PROTECTION_CONFIG["watchdog_interval"])
            except Exception as e:
                self.logger.error(f"Error en watchdog: {e}")
                time.sleep(10)

    def _check_processes(self):
        """Verifica que los procesos monitoreados estén corriendo"""
        import psutil

        for proc_config in self.watched_processes:
            proc_name = proc_config["name"]
            proc_cmd = proc_config["command"]
            restart_cmd = proc_config["restart_cmd"]

            # Buscar proceso
            found = False
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    cmdline = ' '.join(proc.info.get('cmdline', []))
                    if proc_cmd in cmdline:
                        found = True
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            if not found:
                self.logger.warning(f"Proceso {proc_name} no encontrado, reiniciando...")
                self._send_alert("service_stopped", "high",
                    f"Proceso {proc_name} detenido, intentando reinicio automático")
                self._restart_process(restart_cmd)

    def _restart_process(self, restart_cmd: str):
        """Reinicia un proceso"""
        # Verificar límite de reinicios
        current_time = time.time()
        if current_time - self._last_check > self._restart_window:
            self._restart_count = 0

        if self._restart_count >= self._max_restarts:
            self.logger.critical("Demasiados reinicios, requiere intervención manual")
            self._send_alert("service_stopped", "critical",
                "Excedido límite de reinicios automáticos")
            return

        try:
            subprocess.run(restart_cmd.split(), check=True, capture_output=True)
            self._restart_count += 1
            self._last_check = current_time
            self.logger.info(f"Proceso reiniciado (intento {self._restart_count}/{self._max_restarts})")
        except Exception as e:
            self.logger.error(f"Error reiniciando proceso: {e}")

    def _send_alert(self, alert_type: str, severity: str, details: str):
        """Envía alerta de seguridad"""
        alert = SecurityAlert(
            timestamp=datetime.now().isoformat(),
            alert_type=alert_type,
            severity=severity,
            source_ip=None,
            username=os.getenv('USER', 'unknown'),
            hostname=socket.gethostname(),
            details=details
        )

        if self.alert_callback:
            self.alert_callback(alert)

        # Log según severidad
        if severity == "critical":
            self.logger.critical(f"ALERTA: {details}")
        elif severity == "high":
            self.logger.warning(f"ALERTA: {details}")
        else:
            self.logger.info(f"ALERTA: {details}")


# ============================================================================
# PROTECTOR DE ARCHIVOS - Detecta modificaciones
# ============================================================================

class FileProtector:
    """Monitorea archivos críticos y detecta modificaciones no autorizadas"""

    def __init__(self, alert_callback: Optional[Callable] = None):
        self.logger = logging.getLogger("FileProtector")
        self.alert_callback = alert_callback
        self._file_hashes: Dict[str, str] = {}
        self.running = False
        self._thread: Optional[threading.Thread] = None

        # Archivos a proteger
        self.protected_files = []

    def add_protected_file(self, file_path: str):
        """Agrega un archivo a la lista de protección"""
        path = Path(file_path)
        if path.exists():
            self.protected_files.append(str(path))
            self._file_hashes[str(path)] = self._hash_file(path)

    def start(self):
        """Inicia el monitoreo de archivos"""
        self.running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        self.logger.info(f"FileProtector iniciado, monitoreando {len(self.protected_files)} archivos")

    def stop(self):
        """Detiene el monitoreo"""
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)

    def _monitor_loop(self):
        """Loop de monitoreo"""
        while self.running:
            try:
                self._check_files()
                time.sleep(60)  # Verificar cada minuto
            except Exception as e:
                self.logger.error(f"Error en FileProtector: {e}")
                time.sleep(30)

    def _check_files(self):
        """Verifica integridad de archivos protegidos"""
        for file_path in self.protected_files:
            path = Path(file_path)

            if not path.exists():
                self._send_alert(file_path, "deleted")
                continue

            current_hash = self._hash_file(path)
            stored_hash = self._file_hashes.get(file_path)

            if stored_hash and current_hash != stored_hash:
                self._send_alert(file_path, "modified")
                self._file_hashes[file_path] = current_hash

    def _hash_file(self, path: Path) -> str:
        """Calcula hash SHA256 de un archivo"""
        try:
            sha256 = hashlib.sha256()
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception:
            return ""

    def _send_alert(self, file_path: str, change_type: str):
        """Envía alerta de modificación"""
        alert = SecurityAlert(
            timestamp=datetime.now().isoformat(),
            alert_type="config_modified",
            severity="high",
            source_ip=None,
            username=os.getenv('USER', 'unknown'),
            hostname=socket.gethostname(),
            details=f"Archivo {change_type}: {file_path}"
        )

        if self.alert_callback:
            self.alert_callback(alert)

        self.logger.warning(f"Archivo {change_type}: {file_path}")


# ============================================================================
# GESTOR DE PROTECCIÓN PRINCIPAL
# ============================================================================

class ProtectionManager:
    """
    Gestor principal de protección que coordina todos los componentes.
    """

    def __init__(self, alert_callback: Optional[Callable] = None):
        self.logger = logging.getLogger("ProtectionManager")
        self.alert_callback = alert_callback

        # Componentes
        self.key_manager = KeyManager()
        self.watchdog = ServiceWatchdog(self.key_manager, alert_callback)
        self.file_protector = FileProtector(alert_callback)

        # Estado
        self._is_protected = False

    def initialize(self, admin_key: Optional[str] = None) -> bool:
        """
        Inicializa el sistema de protección.
        Si no hay clave configurada y se proporciona una, la establece.
        """
        if not self.key_manager.is_configured():
            if admin_key:
                if self.key_manager.set_admin_key(admin_key):
                    self.logger.info("Sistema de protección inicializado con nueva clave")
                else:
                    return False
            else:
                self.logger.warning("Sistema de protección sin clave configurada")
                return True  # Continuar sin protección

        self._is_protected = True
        return True

    def enable_protection(self):
        """Habilita todos los componentes de protección"""
        self.watchdog.start()
        self.file_protector.start()
        self.logger.info("Protección habilitada")

    def disable_protection(self, admin_key: str) -> bool:
        """Deshabilita la protección (requiere clave)"""
        if not self.key_manager.verify_key(admin_key):
            self.logger.warning("Clave incorrecta para deshabilitar protección")
            return False

        self.watchdog.stop(admin_key)
        self.file_protector.stop()
        self.logger.info("Protección deshabilitada (autorizado)")
        return True

    def uninstall(self, admin_key: str) -> bool:
        """
        Desinstala el agente (requiere clave de administrador).
        Retorna comandos para completar desinstalación manual.
        """
        if not self.key_manager.verify_key(admin_key):
            self.logger.warning("Clave incorrecta para desinstalar")
            self._send_alert("tamper_attempt", "critical",
                "Intento de desinstalación con clave incorrecta")
            return False

        # Deshabilitar protección
        self.disable_protection(admin_key)

        self.logger.info("Desinstalación autorizada")
        print("\n" + "=" * 60)
        print("DESINSTALACIÓN AUTORIZADA")
        print("=" * 60)
        print("\nEjecutar los siguientes comandos para completar:")
        print("""
# Detener servicios
sudo systemctl stop dlp-agent dlp-console dlp-watchdog

# Deshabilitar servicios
sudo systemctl disable dlp-agent dlp-console dlp-watchdog

# Eliminar archivos de servicio
sudo rm /etc/systemd/system/dlp-*.service
sudo systemctl daemon-reload

# Eliminar archivos del agente
sudo rm -rf /opt/dlp-agent  # o el directorio de instalación
rm -rf ~/.dlp-agent

# Eliminar configuración de protección
sudo rm -rf /etc/dlp-agent
""")
        print("=" * 60)

        return True

    def _send_alert(self, alert_type: str, severity: str, details: str):
        """Envía alerta de seguridad"""
        alert = SecurityAlert(
            timestamp=datetime.now().isoformat(),
            alert_type=alert_type,
            severity=severity,
            source_ip=None,
            username=os.getenv('USER', 'unknown'),
            hostname=socket.gethostname(),
            details=details
        )

        if self.alert_callback:
            self.alert_callback(alert)

    @property
    def is_protected(self) -> bool:
        return self._is_protected and self.key_manager.is_configured()


# ============================================================================
# CLI PARA ADMINISTRACIÓN
# ============================================================================

def admin_cli():
    """CLI para administración del sistema de protección"""
    import argparse
    import getpass

    parser = argparse.ArgumentParser(description="DLP Agent Protection Manager")
    parser.add_argument('command', choices=['setup', 'verify', 'uninstall', 'status'],
                       help='Comando a ejecutar')
    parser.add_argument('--key', help='Clave de administrador (se pedirá si no se proporciona)')

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    manager = ProtectionManager()

    if args.command == 'setup':
        print("Configurando clave de administrador para DLP Agent")
        print("IMPORTANTE: Guarde esta clave en un lugar seguro.")
        print("           Se requiere para desinstalar el agente.\n")

        new_key = getpass.getpass("Nueva clave de administrador: ")
        confirm_key = getpass.getpass("Confirmar clave: ")

        if new_key != confirm_key:
            print("ERROR: Las claves no coinciden")
            sys.exit(1)

        if len(new_key) < 8:
            print("ERROR: La clave debe tener al menos 8 caracteres")
            sys.exit(1)

        if manager.key_manager.set_admin_key(new_key):
            print("\n[OK] Clave configurada exitosamente")
            print(f"    Archivo: {manager.key_manager.config_path}")
        else:
            print("\n[ERROR] No se pudo configurar la clave")
            sys.exit(1)

    elif args.command == 'verify':
        key = args.key or getpass.getpass("Clave de administrador: ")

        if manager.key_manager.verify_key(key):
            print("[OK] Clave válida")
        else:
            print("[ERROR] Clave inválida")
            sys.exit(1)

    elif args.command == 'uninstall':
        key = args.key or getpass.getpass("Clave de administrador para desinstalar: ")

        if manager.uninstall(key):
            print("\n[OK] Desinstalación autorizada")
        else:
            print("\n[ERROR] Clave incorrecta - desinstalación denegada")
            sys.exit(1)

    elif args.command == 'status':
        print("Estado del sistema de protección:")
        print(f"  Clave configurada: {'Sí' if manager.key_manager.is_configured() else 'No'}")
        print(f"  Archivo config: {manager.key_manager.config_path}")
        print(f"  Protección activa: {'Sí' if manager.is_protected else 'No'}")


if __name__ == "__main__":
    admin_cli()
