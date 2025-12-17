#!/usr/bin/env python3
"""
DLP Agent Watchdog Service
Servicio independiente que monitorea el agente DLP y lo reinicia si se detiene.
Diseñado para ejecutarse como servicio systemd separado.

Este servicio:
- Monitorea que dlp-agent esté corriendo
- Lo reinicia automáticamente si se detiene
- Envía alertas si detecta manipulación
- Solo puede ser detenido con la clave de administrador
"""

import os
import sys
import time
import signal
import socket
import logging
import subprocess
import json
from pathlib import Path
from datetime import datetime
from typing import Optional

# Agregar directorio del agente al path
SCRIPT_DIR = Path(__file__).parent
sys.path.insert(0, str(SCRIPT_DIR))

try:
    import psutil
except ImportError:
    print("ERROR: psutil no instalado. Ejecutar: pip install psutil")
    sys.exit(1)

# ============================================================================
# CONFIGURACIÓN
# ============================================================================

WATCHDOG_CONFIG = {
    # Intervalo de verificación (segundos)
    "check_interval": 30,

    # Proceso principal a monitorear
    "main_process": {
        "name": "dlp-agent",
        "search_pattern": "dlp_agent.py",
        "restart_command": "systemctl restart dlp-agent",
    },

    # Límites de reinicio
    "max_restarts_per_hour": 5,
    "restart_cooldown": 60,  # Segundos entre reinicios

    # Archivos de estado
    "state_file": "/var/run/dlp-watchdog.state",
    "pid_file": "/var/run/dlp-watchdog.pid",

    # Consola para reportar alertas
    "console_host": "localhost",
    "console_port": 5555,
}


class WatchdogService:
    """Servicio watchdog principal"""

    def __init__(self):
        self.logger = self._setup_logging()
        self.running = False
        self.hostname = socket.gethostname()

        # Estado
        self.restart_count = 0
        self.restart_times = []
        self.last_restart = 0

        # Signal handlers
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

        self.logger.info("Watchdog inicializado")

    def _setup_logging(self) -> logging.Logger:
        """Configura logging"""
        log_dir = Path.home() / ".dlp-agent"
        log_dir.mkdir(parents=True, exist_ok=True)

        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [Watchdog] %(levelname)s: %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler(log_dir / "watchdog.log")
            ]
        )
        return logging.getLogger("Watchdog")

    def _handle_signal(self, signum, frame):
        """Maneja señales de terminación"""
        self.logger.info(f"Señal {signum} recibida")

        # Verificar si hay clave de administrador configurada
        try:
            from protection import KeyManager
            key_manager = KeyManager()

            if key_manager.is_configured():
                self.logger.warning("Intento de detener watchdog - requiere autorización")
                self._send_alert("tamper_attempt", "high",
                    f"Intento de detener watchdog via señal {signum}")
                # NO detenerse - ignorar la señal
                return
        except ImportError:
            pass

        # Si no hay protección, permitir detención
        self.running = False

    def start(self):
        """Inicia el watchdog"""
        self.running = True
        self._write_pid_file()

        self.logger.info("=" * 50)
        self.logger.info("DLP Watchdog Service iniciando...")
        self.logger.info(f"Monitoreando: {WATCHDOG_CONFIG['main_process']['name']}")
        self.logger.info(f"Intervalo: {WATCHDOG_CONFIG['check_interval']}s")
        self.logger.info("=" * 50)

        try:
            self._run_loop()
        finally:
            self._cleanup()

    def _run_loop(self):
        """Loop principal"""
        while self.running:
            try:
                self._check_agent()
                self._cleanup_restart_history()
                time.sleep(WATCHDOG_CONFIG["check_interval"])
            except Exception as e:
                self.logger.error(f"Error en loop: {e}")
                time.sleep(10)

    def _check_agent(self):
        """Verifica si el agente está corriendo"""
        config = WATCHDOG_CONFIG["main_process"]
        search_pattern = config["search_pattern"]

        # Buscar proceso
        agent_running = False
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmdline = ' '.join(proc.info.get('cmdline', []))
                if search_pattern in cmdline:
                    agent_running = True
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if not agent_running:
            self.logger.warning(f"Agente no detectado!")
            self._handle_agent_down()

    def _handle_agent_down(self):
        """Maneja la situación cuando el agente no está corriendo"""
        current_time = time.time()

        # Verificar cooldown
        if current_time - self.last_restart < WATCHDOG_CONFIG["restart_cooldown"]:
            self.logger.info("En cooldown, esperando...")
            return

        # Verificar límite de reinicios por hora
        hour_ago = current_time - 3600
        recent_restarts = [t for t in self.restart_times if t > hour_ago]

        if len(recent_restarts) >= WATCHDOG_CONFIG["max_restarts_per_hour"]:
            self.logger.critical("Excedido límite de reinicios por hora!")
            self._send_alert("service_stopped", "critical",
                "Agente DLP detenido - excedido límite de reinicios automáticos")
            return

        # Intentar reinicio
        self._restart_agent()

    def _restart_agent(self):
        """Reinicia el agente"""
        config = WATCHDOG_CONFIG["main_process"]
        restart_cmd = config["restart_command"]

        self.logger.info(f"Reiniciando agente: {restart_cmd}")

        try:
            result = subprocess.run(
                restart_cmd.split(),
                capture_output=True,
                timeout=30,
                text=True
            )

            if result.returncode == 0:
                self.logger.info("Agente reiniciado exitosamente")
                self.restart_count += 1
                self.restart_times.append(time.time())
                self.last_restart = time.time()

                self._send_alert("service_restarted", "medium",
                    f"Agente DLP reiniciado automáticamente (reinicio #{self.restart_count})")
            else:
                self.logger.error(f"Error reiniciando: {result.stderr}")
                self._send_alert("restart_failed", "high",
                    f"Fallo al reiniciar agente: {result.stderr[:200]}")

        except subprocess.TimeoutExpired:
            self.logger.error("Timeout reiniciando agente")
        except Exception as e:
            self.logger.error(f"Error: {e}")

    def _cleanup_restart_history(self):
        """Limpia historial de reinicios antiguo"""
        hour_ago = time.time() - 3600
        self.restart_times = [t for t in self.restart_times if t > hour_ago]

    def _send_alert(self, alert_type: str, severity: str, details: str):
        """Envía alerta a la consola"""
        try:
            alert = {
                "timestamp": datetime.now().isoformat(),
                "event_type": f"watchdog_{alert_type}",
                "username": "watchdog",
                "hostname": self.hostname,
                "process_name": "dlp-watchdog",
                "command_line": "",
                "parent_process": "",
                "working_directory": "",
                "is_allowed": True,
                "reason": details,
            }

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                sock.connect((
                    WATCHDOG_CONFIG["console_host"],
                    WATCHDOG_CONFIG["console_port"]
                ))
                sock.sendall((json.dumps(alert) + "\n").encode())

        except Exception as e:
            self.logger.debug(f"No se pudo enviar alerta: {e}")

    def _write_pid_file(self):
        """Escribe archivo PID"""
        try:
            pid_file = Path(WATCHDOG_CONFIG["pid_file"])
            pid_file.parent.mkdir(parents=True, exist_ok=True)
            pid_file.write_text(str(os.getpid()))
        except Exception as e:
            self.logger.warning(f"No se pudo escribir PID file: {e}")

    def _cleanup(self):
        """Limpieza al terminar"""
        try:
            pid_file = Path(WATCHDOG_CONFIG["pid_file"])
            if pid_file.exists():
                pid_file.unlink()
        except:
            pass
        self.logger.info("Watchdog detenido")


def main():
    """Punto de entrada"""
    # Verificar root
    if os.geteuid() != 0:
        print("ADVERTENCIA: Watchdog debería ejecutarse como root para reiniciar servicios")

    watchdog = WatchdogService()
    watchdog.start()


if __name__ == "__main__":
    main()
