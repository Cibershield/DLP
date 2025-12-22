#!/usr/bin/env python3
"""
Access Scheduler Module for DLP Console
Cibershield R.L. 2025

Gestiona la revocación automática de accesos temporales expirados.
"""

import logging
from datetime import datetime
from typing import Optional

logger = logging.getLogger("AccessScheduler")


class AccessScheduler:
    """
    Scheduler para revocar automáticamente accesos temporales expirados.
    Usa APScheduler para ejecutar tareas en background.
    """

    def __init__(self, database, github_api):
        """
        Inicializa el scheduler.

        Args:
            database: Instancia de DLPDatabase
            github_api: Instancia de GitHubIntegration
        """
        self.db = database
        self.github = github_api
        self.scheduler = None
        self.is_running = False

    def start(self, check_interval_minutes: int = 1):
        """
        Inicia el scheduler.

        Args:
            check_interval_minutes: Intervalo de verificación en minutos (default: 1)
        """
        try:
            from apscheduler.schedulers.background import BackgroundScheduler
            from apscheduler.triggers.interval import IntervalTrigger

            self.scheduler = BackgroundScheduler(daemon=True)

            # Job principal: revisar accesos expirados
            self.scheduler.add_job(
                self.revoke_expired_access,
                IntervalTrigger(minutes=check_interval_minutes),
                id='revoke_expired_access',
                name='Revocar accesos expirados',
                replace_existing=True
            )

            # Job secundario: alertas de accesos que expiran pronto (cada hora)
            self.scheduler.add_job(
                self.check_expiring_soon,
                IntervalTrigger(hours=1),
                id='check_expiring_soon',
                name='Verificar accesos por expirar',
                replace_existing=True
            )

            self.scheduler.start()
            self.is_running = True
            logger.info(f"✓ AccessScheduler iniciado (intervalo: {check_interval_minutes} min)")

        except ImportError:
            logger.warning("APScheduler no instalado. Scheduler deshabilitado.")
            logger.info("Instalar con: pip install apscheduler")
            self.is_running = False

        except Exception as e:
            logger.error(f"Error iniciando scheduler: {e}")
            self.is_running = False

    def stop(self):
        """Detiene el scheduler"""
        if self.scheduler and self.is_running:
            self.scheduler.shutdown(wait=False)
            self.is_running = False
            logger.info("✓ AccessScheduler detenido")

    def revoke_expired_access(self):
        """
        Revoca todos los accesos temporales que ya expiraron.
        Esta función se ejecuta periódicamente por el scheduler.
        """
        try:
            expired_grants = self.db.get_expired_access_grants()

            if not expired_grants:
                return

            logger.info(f"Procesando {len(expired_grants)} accesos expirados...")

            for grant in expired_grants:
                try:
                    # Revocar acceso en GitHub
                    result = self.github.remove_collaborator(
                        grant['organization'],
                        grant['repo_name'],
                        grant['github_user']
                    )

                    if result and result.get('success'):
                        # Marcar como expirado en la base de datos
                        self.db.mark_grant_expired(
                            grant['id'],
                            "Expiración automática - acceso revocado en GitHub"
                        )
                        logger.info(
                            f"✓ Acceso revocado: {grant['github_user']} -> "
                            f"{grant['organization']}/{grant['repo_name']}"
                        )
                    else:
                        error_msg = result.get('error', 'Error desconocido') if result else 'Sin respuesta'
                        # Marcar como expirado de todas formas (para no reintentar infinitamente)
                        self.db.mark_grant_expired(
                            grant['id'],
                            f"Expiración automática - error al revocar: {error_msg}"
                        )
                        logger.warning(
                            f"⚠ Error revocando acceso de {grant['github_user']}: {error_msg}"
                        )

                except Exception as e:
                    logger.error(f"Error procesando grant {grant['id']}: {e}")
                    # Marcar como expirado para no reintentar
                    self.db.mark_grant_expired(
                        grant['id'],
                        f"Expiración automática - excepción: {str(e)}"
                    )

        except Exception as e:
            logger.error(f"Error en revoke_expired_access: {e}")

    def check_expiring_soon(self, hours: int = 24):
        """
        Verifica accesos que expiran pronto y registra alertas.
        Esta función se ejecuta cada hora.
        """
        try:
            expiring = self.db.get_grants_expiring_soon(hours)

            if expiring:
                logger.info(f"⏰ {len(expiring)} accesos expiran en las próximas {hours} horas")
                for grant in expiring:
                    logger.debug(
                        f"  - {grant['github_user']} -> {grant['organization']}/{grant['repo_name']} "
                        f"(expira: {grant['expires_at']})"
                    )

        except Exception as e:
            logger.error(f"Error en check_expiring_soon: {e}")

    def run_manual_check(self) -> dict:
        """
        Ejecuta una verificación manual de accesos expirados.
        Útil para testing o ejecución on-demand.

        Returns:
            Dict con estadísticas de la ejecución
        """
        stats = {
            'checked': 0,
            'revoked': 0,
            'errors': 0,
            'timestamp': datetime.now().isoformat()
        }

        try:
            expired_grants = self.db.get_expired_access_grants()
            stats['checked'] = len(expired_grants)

            for grant in expired_grants:
                try:
                    result = self.github.remove_collaborator(
                        grant['organization'],
                        grant['repo_name'],
                        grant['github_user']
                    )

                    if result and result.get('success'):
                        self.db.mark_grant_expired(grant['id'])
                        stats['revoked'] += 1
                    else:
                        self.db.mark_grant_expired(
                            grant['id'],
                            f"Error: {result.get('error', 'unknown')}" if result else "Sin respuesta"
                        )
                        stats['errors'] += 1

                except Exception as e:
                    self.db.mark_grant_expired(grant['id'], f"Excepción: {str(e)}")
                    stats['errors'] += 1

        except Exception as e:
            logger.error(f"Error en run_manual_check: {e}")
            stats['error_message'] = str(e)

        return stats

    def get_status(self) -> dict:
        """Obtiene el estado del scheduler"""
        return {
            'is_running': self.is_running,
            'scheduler_active': self.scheduler.running if self.scheduler else False,
            'jobs': [
                {
                    'id': job.id,
                    'name': job.name,
                    'next_run': str(job.next_run_time) if job.next_run_time else None
                }
                for job in (self.scheduler.get_jobs() if self.scheduler else [])
            ]
        }


# Instancia global (se inicializa en dlp_console.py)
access_scheduler: Optional[AccessScheduler] = None


def init_scheduler(database, github_api, check_interval: int = 1) -> AccessScheduler:
    """
    Inicializa y arranca el scheduler global.

    Args:
        database: Instancia de DLPDatabase
        github_api: Instancia de GitHubIntegration
        check_interval: Intervalo de verificación en minutos

    Returns:
        Instancia del AccessScheduler
    """
    global access_scheduler
    access_scheduler = AccessScheduler(database, github_api)
    access_scheduler.start(check_interval)
    return access_scheduler


def get_scheduler() -> Optional[AccessScheduler]:
    """Obtiene la instancia global del scheduler"""
    return access_scheduler
