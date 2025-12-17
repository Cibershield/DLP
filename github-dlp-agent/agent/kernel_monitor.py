#!/usr/bin/env python3
"""
Kernel-Level Monitoring Module para GitHub DLP Agent
Proporciona monitoreo profundo a nivel de kernel usando múltiples técnicas:

1. eBPF (extended BPF) - Monitoreo de syscalls execve, connect, etc.
2. Netlink Process Connector - Eventos de fork/exec/exit del kernel
3. Audit Subsystem - Fallback usando auditd

Requiere: Ubuntu 20.04+ con kernel 5.4+
Privilegios: ROOT requerido para monitoreo completo
"""

import os
import sys
import struct
import socket
import logging
import threading
import time
import ctypes
import subprocess
import re
from typing import Optional, Dict, List, Callable, Set, Tuple
from dataclasses import dataclass
from datetime import datetime
from queue import Queue
from pathlib import Path
from abc import ABC, abstractmethod

# ============================================================================
# CONFIGURACIÓN
# ============================================================================

KERNEL_CONFIG = {
    # Procesos a monitorear específicamente
    "monitored_binaries": [
        "git", "gh", "curl", "wget", "ssh", "scp", "rsync",
        "docker", "podman", "snap"
    ],

    # Patrones de argumentos sospechosos
    "suspicious_patterns": [
        r"github\.com",
        r"gitlab\.com",
        r"bitbucket\.org",
        r"\.git",
        r"clone",
        r"pull",
        r"fetch",
    ],

    # Puertos de red a monitorear
    "monitored_ports": [22, 80, 443, 9418],  # SSH, HTTP, HTTPS, Git

    # IPs de GitHub (se actualizan dinámicamente)
    "github_ip_ranges": [],

    # Intervalo de verificación de salud
    "health_check_interval": 30,
}


@dataclass
class KernelEvent:
    """Evento capturado a nivel de kernel"""
    timestamp: str
    event_type: str  # "execve", "connect", "fork", "exit", "file_open"
    pid: int
    ppid: int
    uid: int
    gid: int
    comm: str  # Nombre del proceso (max 16 chars)
    filename: str  # Binario ejecutado o archivo accedido
    args: str  # Argumentos de línea de comandos
    return_value: int = 0
    # Para eventos de red
    remote_ip: Optional[str] = None
    remote_port: Optional[int] = None
    local_port: Optional[int] = None
    # Metadata
    source: str = "unknown"  # "ebpf", "netlink", "audit"

    def to_dict(self) -> Dict:
        return {k: v for k, v in self.__dict__.items() if v is not None}


# ============================================================================
# ABSTRACT BASE CLASS PARA MONITORES DE KERNEL
# ============================================================================

class KernelMonitorBase(ABC):
    """Clase base abstracta para monitores de kernel"""

    def __init__(self, event_callback: Callable[[KernelEvent], None]):
        self.event_callback = event_callback
        self.logger = logging.getLogger(self.__class__.__name__)
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self._available = False
        self._check_availability()

    @abstractmethod
    def _check_availability(self) -> bool:
        """Verifica si este monitor está disponible en el sistema"""
        pass

    @abstractmethod
    def _monitor_loop(self):
        """Loop principal de monitoreo"""
        pass

    @property
    def is_available(self) -> bool:
        return self._available

    def start(self):
        if not self._available:
            self.logger.warning(f"{self.__class__.__name__} no disponible")
            return False

        self.running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        self.logger.info(f"{self.__class__.__name__} iniciado")
        return True

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)


# ============================================================================
# eBPF MONITOR - Monitoreo de syscalls usando BCC
# ============================================================================

class EBPFMonitor(KernelMonitorBase):
    """
    Monitor basado en eBPF para capturar syscalls a nivel de kernel.
    Requiere: python3-bcc, linux-headers-$(uname -r), privilegios root
    """

    # Programa eBPF para monitorear execve
    EXECVE_BPF_PROGRAM = """
    #include <uapi/linux/ptrace.h>
    #include <linux/sched.h>
    #include <linux/fs.h>

    #define ARGSIZE 256
    #define MAXARG 20

    struct exec_event_t {
        u32 pid;
        u32 ppid;
        u32 uid;
        u32 gid;
        char comm[TASK_COMM_LEN];
        char filename[ARGSIZE];
        char args[ARGSIZE];
        int retval;
    };

    BPF_PERF_OUTPUT(exec_events);
    BPF_HASH(tasks, u32, struct exec_event_t);

    int syscall__execve(struct pt_regs *ctx,
        const char __user *filename,
        const char __user *const __user *__argv,
        const char __user *const __user *__envp)
    {
        struct exec_event_t event = {};
        u32 pid = bpf_get_current_pid_tgid() >> 32;

        event.pid = pid;
        event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        event.gid = bpf_get_current_uid_gid() >> 32;

        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        event.ppid = task->real_parent->tgid;

        bpf_get_current_comm(&event.comm, sizeof(event.comm));
        bpf_probe_read_user_str(&event.filename, sizeof(event.filename), filename);

        // Leer primer argumento
        const char *argp;
        bpf_probe_read_user(&argp, sizeof(argp), &__argv[0]);
        if (argp) {
            bpf_probe_read_user_str(&event.args, sizeof(event.args), argp);
        }

        tasks.update(&pid, &event);
        return 0;
    }

    int do_ret_sys_execve(struct pt_regs *ctx)
    {
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        struct exec_event_t *event = tasks.lookup(&pid);

        if (event == 0) {
            return 0;
        }

        event->retval = PT_REGS_RC(ctx);
        exec_events.perf_submit(ctx, event, sizeof(*event));
        tasks.delete(&pid);
        return 0;
    }
    """

    # Programa eBPF para monitorear connect()
    CONNECT_BPF_PROGRAM = """
    #include <uapi/linux/ptrace.h>
    #include <net/sock.h>
    #include <bcc/proto.h>

    struct connect_event_t {
        u32 pid;
        u32 uid;
        char comm[TASK_COMM_LEN];
        u32 daddr;
        u16 dport;
        u16 family;
    };

    BPF_PERF_OUTPUT(connect_events);

    int trace_connect_entry(struct pt_regs *ctx, struct sock *sk)
    {
        u16 family = sk->__sk_common.skc_family;
        if (family != AF_INET && family != AF_INET6) {
            return 0;
        }

        struct connect_event_t event = {};
        event.pid = bpf_get_current_pid_tgid() >> 32;
        event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        event.family = family;

        bpf_get_current_comm(&event.comm, sizeof(event.comm));

        if (family == AF_INET) {
            event.daddr = sk->__sk_common.skc_daddr;
            event.dport = sk->__sk_common.skc_dport;
        }

        connect_events.perf_submit(ctx, &event, sizeof(event));
        return 0;
    }
    """

    def __init__(self, event_callback: Callable[[KernelEvent], None]):
        self.bpf = None
        self.bcc_available = False
        super().__init__(event_callback)

    def _check_availability(self) -> bool:
        """Verifica si BCC está disponible"""
        # Verificar privilegios root
        if os.geteuid() != 0:
            self.logger.debug("eBPF requiere privilegios root")
            self._available = False
            return False

        # Verificar si BCC está instalado
        try:
            from bcc import BPF
            self.bcc_available = True
            self._available = True
            self.logger.info("BCC/eBPF disponible")
            return True
        except ImportError:
            self.logger.debug("python3-bcc no instalado")
            self._available = False
            return False
        except Exception as e:
            self.logger.debug(f"Error verificando BCC: {e}")
            self._available = False
            return False

    def _monitor_loop(self):
        """Loop principal de monitoreo eBPF"""
        if not self.bcc_available:
            return

        try:
            from bcc import BPF

            # Cargar programa eBPF para execve
            self.logger.info("Cargando programa eBPF para execve...")
            self.bpf = BPF(text=self.EXECVE_BPF_PROGRAM)

            # Attach a syscall
            execve_fnname = self.bpf.get_syscall_fnname("execve")
            self.bpf.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")
            self.bpf.attach_kretprobe(event=execve_fnname, fn_name="do_ret_sys_execve")

            # Callback para eventos
            def handle_exec_event(cpu, data, size):
                event = self.bpf["exec_events"].event(data)
                self._process_exec_event(event)

            self.bpf["exec_events"].open_perf_buffer(handle_exec_event)

            self.logger.info("eBPF Monitor activo - capturando syscalls")

            while self.running:
                try:
                    self.bpf.perf_buffer_poll(timeout=1000)
                except KeyboardInterrupt:
                    break

        except Exception as e:
            self.logger.error(f"Error en eBPF monitor: {e}")
        finally:
            if self.bpf:
                self.bpf.cleanup()

    def _process_exec_event(self, event):
        """Procesa evento de execve capturado"""
        try:
            filename = event.filename.decode('utf-8', errors='replace')
            comm = event.comm.decode('utf-8', errors='replace')
            args = event.args.decode('utf-8', errors='replace')

            # Filtrar solo binarios de interés
            basename = os.path.basename(filename)
            if basename not in KERNEL_CONFIG["monitored_binaries"]:
                # Verificar patrones sospechosos en argumentos
                is_suspicious = any(
                    re.search(pattern, args, re.IGNORECASE)
                    for pattern in KERNEL_CONFIG["suspicious_patterns"]
                )
                if not is_suspicious:
                    return

            kernel_event = KernelEvent(
                timestamp=datetime.now().isoformat(),
                event_type="execve",
                pid=event.pid,
                ppid=event.ppid,
                uid=event.uid,
                gid=event.gid,
                comm=comm,
                filename=filename,
                args=args,
                return_value=event.retval,
                source="ebpf"
            )

            self.event_callback(kernel_event)

        except Exception as e:
            self.logger.error(f"Error procesando evento execve: {e}")


# ============================================================================
# NETLINK PROCESS CONNECTOR - Eventos de procesos del kernel
# ============================================================================

class NetlinkProcessMonitor(KernelMonitorBase):
    """
    Monitor usando Netlink Process Connector para eventos fork/exec/exit.
    Más ligero que eBPF, disponible en todos los kernels Linux modernos.
    Requiere: CAP_NET_ADMIN o root
    """

    # Constantes de Netlink
    NETLINK_CONNECTOR = 11
    CN_IDX_PROC = 1
    CN_VAL_PROC = 1

    # Tipos de eventos
    PROC_EVENT_NONE = 0x00000000
    PROC_EVENT_FORK = 0x00000001
    PROC_EVENT_EXEC = 0x00000002
    PROC_EVENT_UID = 0x00000004
    PROC_EVENT_GID = 0x00000040
    PROC_EVENT_SID = 0x00000080
    PROC_EVENT_PTRACE = 0x00000100
    PROC_EVENT_COMM = 0x00000200
    PROC_EVENT_EXIT = 0x80000000

    def __init__(self, event_callback: Callable[[KernelEvent], None]):
        self.socket = None
        super().__init__(event_callback)

    def _check_availability(self) -> bool:
        """Verifica si Netlink Process Connector está disponible"""
        if os.geteuid() != 0:
            self.logger.debug("Netlink Process Connector requiere root")
            self._available = False
            return False

        # Verificar si el módulo está cargado
        try:
            with open('/proc/net/connector', 'r') as f:
                self._available = True
                return True
        except FileNotFoundError:
            # Intentar cargar el módulo
            try:
                subprocess.run(['modprobe', 'cn'], check=True, capture_output=True)
                self._available = True
                return True
            except:
                pass

        self._available = False
        return False

    def _monitor_loop(self):
        """Loop principal de monitoreo Netlink"""
        try:
            # Crear socket Netlink
            self.socket = socket.socket(
                socket.AF_NETLINK,
                socket.SOCK_DGRAM,
                self.NETLINK_CONNECTOR
            )
            self.socket.bind((os.getpid(), self.CN_IDX_PROC))

            # Suscribirse a eventos de procesos
            self._subscribe_proc_events()

            self.logger.info("Netlink Process Monitor activo")

            while self.running:
                try:
                    self.socket.settimeout(1.0)
                    data = self.socket.recv(4096)
                    self._process_netlink_message(data)
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        self.logger.error(f"Error recibiendo: {e}")

        except Exception as e:
            self.logger.error(f"Error en Netlink monitor: {e}")
        finally:
            if self.socket:
                self.socket.close()

    def _subscribe_proc_events(self):
        """Suscribe a eventos de procesos"""
        # Estructura del mensaje de suscripción
        # nlmsghdr + cn_msg + enum proc_cn_mcast_op

        NLMSG_DONE = 0x3

        # nlmsghdr
        nlmsg_len = 36  # Total length
        nlmsg_type = NLMSG_DONE
        nlmsg_flags = 0
        nlmsg_seq = 0
        nlmsg_pid = os.getpid()

        nlmsghdr = struct.pack('=IHHII', nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid)

        # cn_msg
        cn_idx = self.CN_IDX_PROC
        cn_val = self.CN_VAL_PROC
        cn_seq = 0
        cn_ack = 0
        cn_len = 4  # sizeof(enum proc_cn_mcast_op)
        cn_flags = 0

        cn_msg = struct.pack('=IIIIHH', cn_idx, cn_val, cn_seq, cn_ack, cn_len, cn_flags)

        # PROC_CN_MCAST_LISTEN = 1
        op = struct.pack('=I', 1)

        msg = nlmsghdr + cn_msg + op
        self.socket.send(msg)

    def _process_netlink_message(self, data):
        """Procesa mensaje Netlink recibido"""
        if len(data) < 36:
            return

        # Parse nlmsghdr (16 bytes)
        nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid = struct.unpack('=IHHII', data[:16])

        # Parse cn_msg (20 bytes)
        offset = 16
        cn_idx, cn_val, cn_seq, cn_ack, cn_len, cn_flags = struct.unpack(
            '=IIIIHH', data[offset:offset+20]
        )

        if cn_idx != self.CN_IDX_PROC or cn_val != self.CN_VAL_PROC:
            return

        # Parse proc_event
        offset = 36
        if offset + 4 > len(data):
            return

        what = struct.unpack('=I', data[offset:offset+4])[0]

        if what == self.PROC_EVENT_EXEC:
            self._handle_exec_event(data[offset:])
        elif what == self.PROC_EVENT_FORK:
            self._handle_fork_event(data[offset:])
        elif what == self.PROC_EVENT_EXIT:
            self._handle_exit_event(data[offset:])

    def _handle_exec_event(self, data):
        """Maneja evento EXEC"""
        try:
            # proc_event structure para exec
            # what (4) + cpu (4) + timestamp (8) + process_pid (4) + process_tgid (4)
            if len(data) < 24:
                return

            what, cpu, ts_ns_lo, ts_ns_hi, process_pid, process_tgid = struct.unpack(
                '=IIIIII', data[:24]
            )

            # Obtener información del proceso desde /proc
            proc_info = self._get_proc_info(process_pid)
            if not proc_info:
                return

            # Filtrar procesos de interés
            if proc_info['comm'] not in KERNEL_CONFIG["monitored_binaries"]:
                # Verificar si los argumentos son sospechosos
                is_suspicious = any(
                    re.search(pattern, proc_info['cmdline'], re.IGNORECASE)
                    for pattern in KERNEL_CONFIG["suspicious_patterns"]
                )
                if not is_suspicious:
                    return

            kernel_event = KernelEvent(
                timestamp=datetime.now().isoformat(),
                event_type="execve",
                pid=process_pid,
                ppid=proc_info['ppid'],
                uid=proc_info['uid'],
                gid=proc_info['gid'],
                comm=proc_info['comm'],
                filename=proc_info['exe'],
                args=proc_info['cmdline'],
                source="netlink"
            )

            self.event_callback(kernel_event)

        except Exception as e:
            self.logger.debug(f"Error procesando exec event: {e}")

    def _handle_fork_event(self, data):
        """Maneja evento FORK (para tracking de procesos hijos)"""
        # Por ahora solo logueamos, no generamos eventos
        pass

    def _handle_exit_event(self, data):
        """Maneja evento EXIT"""
        pass

    def _get_proc_info(self, pid: int) -> Optional[Dict]:
        """Obtiene información de un proceso desde /proc"""
        try:
            proc_path = Path(f'/proc/{pid}')
            if not proc_path.exists():
                return None

            # Leer comm
            comm = (proc_path / 'comm').read_text().strip()

            # Leer cmdline
            cmdline_raw = (proc_path / 'cmdline').read_bytes()
            cmdline = cmdline_raw.replace(b'\x00', b' ').decode('utf-8', errors='replace').strip()

            # Leer exe
            try:
                exe = os.readlink(proc_path / 'exe')
            except:
                exe = comm

            # Leer status para uid/gid/ppid
            status = (proc_path / 'status').read_text()
            uid = gid = ppid = 0

            for line in status.split('\n'):
                if line.startswith('Uid:'):
                    uid = int(line.split()[1])
                elif line.startswith('Gid:'):
                    gid = int(line.split()[1])
                elif line.startswith('PPid:'):
                    ppid = int(line.split()[1])

            return {
                'comm': comm,
                'cmdline': cmdline,
                'exe': exe,
                'uid': uid,
                'gid': gid,
                'ppid': ppid
            }

        except Exception:
            return None


# ============================================================================
# AUDIT SUBSYSTEM MONITOR - Fallback usando auditd
# ============================================================================

class AuditMonitor(KernelMonitorBase):
    """
    Monitor usando el subsistema de auditoría de Linux (auditd).
    Funciona como fallback cuando eBPF y Netlink no están disponibles.
    Requiere: auditd instalado y ejecutándose
    """

    def __init__(self, event_callback: Callable[[KernelEvent], None]):
        self.audit_rules_added = False
        super().__init__(event_callback)

    def _check_availability(self) -> bool:
        """Verifica si auditd está disponible"""
        if os.geteuid() != 0:
            self._available = False
            return False

        # Verificar si auditctl está disponible
        try:
            result = subprocess.run(
                ['auditctl', '-s'],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                self._available = True
                return True
        except:
            pass

        self._available = False
        return False

    def _setup_audit_rules(self):
        """Configura reglas de auditoría para DLP"""
        rules = [
            # Monitorear ejecución de git
            '-a always,exit -F arch=b64 -S execve -F path=/usr/bin/git -k dlp_git',
            '-a always,exit -F arch=b64 -S execve -F path=/usr/bin/gh -k dlp_github',
            # Monitorear curl/wget a GitHub
            '-a always,exit -F arch=b64 -S execve -F path=/usr/bin/curl -k dlp_download',
            '-a always,exit -F arch=b64 -S execve -F path=/usr/bin/wget -k dlp_download',
            # Monitorear conexiones de red
            '-a always,exit -F arch=b64 -S connect -k dlp_network',
        ]

        for rule in rules:
            try:
                subprocess.run(
                    ['auditctl'] + rule.split(),
                    capture_output=True,
                    timeout=5
                )
            except Exception as e:
                self.logger.warning(f"Error añadiendo regla audit: {e}")

        self.audit_rules_added = True

    def _cleanup_audit_rules(self):
        """Limpia las reglas de auditoría añadidas"""
        if not self.audit_rules_added:
            return

        try:
            # Eliminar reglas por key
            for key in ['dlp_git', 'dlp_github', 'dlp_download', 'dlp_network']:
                subprocess.run(
                    ['auditctl', '-D', '-k', key],
                    capture_output=True,
                    timeout=5
                )
        except:
            pass

    def _monitor_loop(self):
        """Loop principal leyendo ausearch"""
        try:
            self._setup_audit_rules()
            self.logger.info("Audit Monitor activo")

            # Usar ausearch para leer eventos
            last_event_id = 0

            while self.running:
                try:
                    # Buscar eventos recientes
                    result = subprocess.run(
                        ['ausearch', '-k', 'dlp_git,dlp_github,dlp_download',
                         '--format', 'text', '-ts', 'recent'],
                        capture_output=True,
                        timeout=5,
                        text=True
                    )

                    if result.returncode == 0 and result.stdout:
                        self._parse_audit_output(result.stdout)

                    time.sleep(2)

                except subprocess.TimeoutExpired:
                    continue
                except Exception as e:
                    if self.running:
                        self.logger.debug(f"Error en ausearch: {e}")
                    time.sleep(5)

        except Exception as e:
            self.logger.error(f"Error en Audit monitor: {e}")
        finally:
            self._cleanup_audit_rules()

    def _parse_audit_output(self, output: str):
        """Parsea salida de ausearch"""
        # Simplificado - en producción usar librería de parsing de audit
        for line in output.split('\n'):
            if 'EXECVE' in line or 'SYSCALL' in line:
                # Extraer información básica
                pid_match = re.search(r'pid=(\d+)', line)
                ppid_match = re.search(r'ppid=(\d+)', line)
                uid_match = re.search(r'uid=(\d+)', line)
                comm_match = re.search(r'comm="([^"]+)"', line)
                exe_match = re.search(r'exe="([^"]+)"', line)

                if pid_match and comm_match:
                    kernel_event = KernelEvent(
                        timestamp=datetime.now().isoformat(),
                        event_type="execve",
                        pid=int(pid_match.group(1)),
                        ppid=int(ppid_match.group(1)) if ppid_match else 0,
                        uid=int(uid_match.group(1)) if uid_match else 0,
                        gid=0,
                        comm=comm_match.group(1),
                        filename=exe_match.group(1) if exe_match else "",
                        args="",
                        source="audit"
                    )

                    self.event_callback(kernel_event)

    def stop(self):
        super().stop()
        self._cleanup_audit_rules()


# ============================================================================
# NETWORK KERNEL MONITOR - Monitoreo de red a nivel de kernel
# ============================================================================

class NetworkKernelMonitor(KernelMonitorBase):
    """
    Monitor de conexiones de red usando Netlink SOCK_DIAG.
    Más eficiente que polling /proc/net/tcp.
    """

    NETLINK_SOCK_DIAG = 4
    SOCK_DIAG_BY_FAMILY = 20

    def __init__(self, event_callback: Callable[[KernelEvent], None], github_ips: Set[str] = None):
        self.github_ips = github_ips or set()
        self.seen_connections: Set[str] = set()
        super().__init__(event_callback)

    def _check_availability(self) -> bool:
        """Siempre disponible en Linux moderno"""
        self._available = os.geteuid() == 0
        return self._available

    def update_github_ips(self, ips: Set[str]):
        """Actualiza el set de IPs de GitHub a monitorear"""
        self.github_ips = ips

    def _monitor_loop(self):
        """Loop de monitoreo de conexiones"""
        try:
            # Usar pyroute2 si está disponible, sino netlink directo
            try:
                from pyroute2 import DiagSocket
                self._monitor_with_pyroute2()
            except ImportError:
                self._monitor_with_psutil()

        except Exception as e:
            self.logger.error(f"Error en Network Kernel Monitor: {e}")

    def _monitor_with_pyroute2(self):
        """Monitoreo usando pyroute2 DiagSocket"""
        from pyroute2 import DiagSocket

        self.logger.info("Network Kernel Monitor activo (pyroute2)")

        while self.running:
            try:
                with DiagSocket() as ds:
                    # Obtener conexiones TCP establecidas
                    connections = ds.get_sock_stats(family=socket.AF_INET, states=(1,))  # ESTABLISHED

                    for conn in connections:
                        self._check_connection(conn)

                time.sleep(3)

            except Exception as e:
                self.logger.debug(f"Error en pyroute2: {e}")
                time.sleep(5)

    def _monitor_with_psutil(self):
        """Fallback usando psutil"""
        import psutil

        self.logger.info("Network Kernel Monitor activo (psutil fallback)")

        while self.running:
            try:
                connections = psutil.net_connections(kind='inet')

                for conn in connections:
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        remote_ip = conn.raddr.ip
                        remote_port = conn.raddr.port

                        # Verificar si es conexión a GitHub
                        if remote_ip in self.github_ips or remote_port in [443, 22, 9418]:
                            conn_id = f"{conn.pid}:{remote_ip}:{remote_port}"

                            if conn_id not in self.seen_connections:
                                self.seen_connections.add(conn_id)
                                self._report_connection(conn.pid, remote_ip, remote_port)

                # Limpiar conexiones viejas
                if len(self.seen_connections) > 10000:
                    self.seen_connections.clear()

                time.sleep(3)

            except Exception as e:
                self.logger.debug(f"Error en psutil: {e}")
                time.sleep(5)

    def _check_connection(self, conn):
        """Verifica una conexión del DiagSocket"""
        # Implementación simplificada
        pass

    def _report_connection(self, pid: int, remote_ip: str, remote_port: int):
        """Reporta una conexión detectada"""
        try:
            proc_path = Path(f'/proc/{pid}')
            if not proc_path.exists():
                return

            comm = (proc_path / 'comm').read_text().strip()
            cmdline = (proc_path / 'cmdline').read_bytes().replace(b'\x00', b' ').decode('utf-8', errors='replace')

            # Obtener uid
            status = (proc_path / 'status').read_text()
            uid = ppid = 0
            for line in status.split('\n'):
                if line.startswith('Uid:'):
                    uid = int(line.split()[1])
                elif line.startswith('PPid:'):
                    ppid = int(line.split()[1])

            kernel_event = KernelEvent(
                timestamp=datetime.now().isoformat(),
                event_type="connect",
                pid=pid,
                ppid=ppid,
                uid=uid,
                gid=0,
                comm=comm,
                filename="",
                args=cmdline,
                remote_ip=remote_ip,
                remote_port=remote_port,
                source="netlink"
            )

            self.event_callback(kernel_event)

        except Exception as e:
            self.logger.debug(f"Error reportando conexión: {e}")


# ============================================================================
# COMPOSITE KERNEL MONITOR - Combina todos los monitores
# ============================================================================

class KernelMonitorManager:
    """
    Gestor que combina múltiples monitores de kernel.
    Selecciona automáticamente el mejor disponible.
    """

    def __init__(self, event_callback: Callable[[KernelEvent], None]):
        self.event_callback = event_callback
        self.logger = logging.getLogger("KernelMonitorManager")
        self.monitors: List[KernelMonitorBase] = []
        self.running = False

        self._initialize_monitors()

    def _initialize_monitors(self):
        """Inicializa los monitores disponibles en orden de preferencia"""
        # 1. Intentar eBPF (más potente)
        ebpf = EBPFMonitor(self.event_callback)
        if ebpf.is_available:
            self.monitors.append(ebpf)
            self.logger.info("eBPF Monitor disponible")

        # 2. Intentar Netlink Process Connector
        netlink = NetlinkProcessMonitor(self.event_callback)
        if netlink.is_available and not any(isinstance(m, EBPFMonitor) for m in self.monitors):
            self.monitors.append(netlink)
            self.logger.info("Netlink Process Monitor disponible")

        # 3. Intentar Audit como fallback
        audit = AuditMonitor(self.event_callback)
        if audit.is_available and not self.monitors:
            self.monitors.append(audit)
            self.logger.info("Audit Monitor disponible (fallback)")

        # 4. Monitor de red siempre
        network = NetworkKernelMonitor(self.event_callback)
        if network.is_available:
            self.monitors.append(network)
            self.logger.info("Network Kernel Monitor disponible")

        if not self.monitors:
            self.logger.warning("No hay monitores de kernel disponibles - ejecutar como root")

    def start(self):
        """Inicia todos los monitores disponibles"""
        self.running = True

        for monitor in self.monitors:
            try:
                monitor.start()
            except Exception as e:
                self.logger.error(f"Error iniciando {monitor.__class__.__name__}: {e}")

        if self.monitors:
            self.logger.info(f"Kernel Monitor Manager activo con {len(self.monitors)} monitor(es)")

        return len(self.monitors) > 0

    def stop(self):
        """Detiene todos los monitores"""
        self.running = False

        for monitor in self.monitors:
            try:
                monitor.stop()
            except Exception as e:
                self.logger.error(f"Error deteniendo {monitor.__class__.__name__}: {e}")

    def get_status(self) -> Dict:
        """Retorna estado de los monitores"""
        return {
            "active_monitors": [m.__class__.__name__ for m in self.monitors if m.is_available],
            "ebpf_available": any(isinstance(m, EBPFMonitor) and m.is_available for m in self.monitors),
            "netlink_available": any(isinstance(m, NetlinkProcessMonitor) and m.is_available for m in self.monitors),
            "audit_available": any(isinstance(m, AuditMonitor) and m.is_available for m in self.monitors),
            "network_available": any(isinstance(m, NetworkKernelMonitor) and m.is_available for m in self.monitors),
        }

    def update_github_ips(self, ips: Set[str]):
        """Actualiza IPs de GitHub en el monitor de red"""
        for monitor in self.monitors:
            if isinstance(monitor, NetworkKernelMonitor):
                monitor.update_github_ips(ips)


# ============================================================================
# FUNCIÓN DE UTILIDAD PARA VERIFICAR CAPACIDADES
# ============================================================================

def check_kernel_capabilities() -> Dict:
    """
    Verifica las capacidades de monitoreo de kernel disponibles.
    Útil para diagnóstico.
    """
    caps = {
        "is_root": os.geteuid() == 0,
        "ebpf_available": False,
        "netlink_available": False,
        "audit_available": False,
        "kernel_version": "",
        "recommendations": []
    }

    # Obtener versión del kernel
    try:
        caps["kernel_version"] = os.uname().release
    except:
        pass

    # Verificar eBPF/BCC
    try:
        from bcc import BPF
        caps["ebpf_available"] = True
    except ImportError:
        caps["recommendations"].append(
            "Instalar python3-bcc para monitoreo eBPF: sudo apt install python3-bcc bpfcc-tools linux-headers-$(uname -r)"
        )

    # Verificar Netlink
    if os.path.exists('/proc/net/connector'):
        caps["netlink_available"] = True
    else:
        caps["recommendations"].append(
            "Cargar módulo cn para Netlink: sudo modprobe cn"
        )

    # Verificar Audit
    try:
        result = subprocess.run(['auditctl', '-s'], capture_output=True, timeout=5)
        caps["audit_available"] = result.returncode == 0
    except:
        caps["recommendations"].append(
            "Instalar auditd: sudo apt install auditd"
        )

    if not caps["is_root"]:
        caps["recommendations"].insert(0, "Ejecutar como root para monitoreo completo de kernel")

    return caps


if __name__ == "__main__":
    # Test de capacidades
    import json

    logging.basicConfig(level=logging.DEBUG)

    print("Verificando capacidades de monitoreo de kernel...\n")
    caps = check_kernel_capabilities()
    print(json.dumps(caps, indent=2))

    if caps["is_root"]:
        print("\nIniciando test de monitoreo...")

        def event_handler(event: KernelEvent):
            print(f"[{event.source}] {event.event_type}: {event.comm} (PID: {event.pid})")
            if event.args:
                print(f"  Args: {event.args[:100]}")

        manager = KernelMonitorManager(event_handler)
        print(f"\nEstado: {manager.get_status()}")

        manager.start()

        try:
            print("\nMonitoreando... (Ctrl+C para detener)")
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass

        manager.stop()
        print("\nMonitoreo detenido")
    else:
        print("\n⚠️  Ejecutar como root para test completo")
