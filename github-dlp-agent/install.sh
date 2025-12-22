#!/bin/bash
#
# Instalador del GitHub DLP Agent para Ubuntu y Debian
# Compatible con:
#   - Ubuntu 20.04, 22.04, 24.04 (Desktop y Server)
#   - Debian 11 (Bullseye), Debian 12 (Bookworm)
#   - Derivadas de Ubuntu/Debian (Linux Mint, Pop!_OS, etc.)
#

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Variables globales
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PATH="$SCRIPT_DIR/venv"
MIN_PYTHON_VERSION="3.8"
INSTALL_TYPE="user"
INSTALL_COMPONENT="agent"  # agent, console, or both
DISTRO=""                  # ubuntu, debian
DISTRO_VERSION=""
DISTRO_CODENAME=""
DEBIAN_VERSION=""          # Para verificación de paquetes específicos de Debian
IS_DESKTOP=false
ARCH=""                    # x86_64, aarch64

# Funciones de utilidad
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Banner
show_banner() {
    echo -e "${CYAN}"
    echo "======================================================================"
    echo "              DLP Solution - Instalador v0.9"
    echo "            Desarrollado por Cibershield R.L. 2025"
    echo "======================================================================"
    echo -e "${NC}"
}

# Seleccionar componente a instalar
select_component() {
    echo ""
    echo -e "${YELLOW}¿Qué componente desea instalar?${NC}"
    echo ""
    echo "  1) Agente DLP     - Monitorea equipos de usuarios (instalar en endpoints)"
    echo "  2) Consola DLP    - Dashboard centralizado (instalar en servidor)"
    echo "  3) Ambos          - Agente + Consola en el mismo equipo"
    echo ""
    read -p "Seleccione [1/2/3]: " choice

    case $choice in
        1)
            INSTALL_COMPONENT="agent"
            log_info "Instalando: Agente DLP"
            ;;
        2)
            INSTALL_COMPONENT="console"
            log_info "Instalando: Consola DLP"
            ;;
        3)
            INSTALL_COMPONENT="both"
            log_info "Instalando: Agente + Consola"
            ;;
        *)
            log_error "Opción inválida"
            exit 1
            ;;
    esac
    echo ""
}

# Detectar arquitectura del sistema
detect_architecture() {
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64)
            ARCH="x86_64"
            log_success "Arquitectura: x86_64 (64-bit)"
            ;;
        aarch64|arm64)
            ARCH="aarch64"
            log_success "Arquitectura: ARM64"
            ;;
        armv7l|armhf)
            ARCH="armv7l"
            log_warning "Arquitectura: ARM32 - soporte limitado"
            ;;
        *)
            log_warning "Arquitectura: $ARCH - puede tener compatibilidad limitada"
            ;;
    esac
}

# Detectar distribución y versión
detect_distribution() {
    log_info "Detectando distribución..."

    if [ ! -f /etc/os-release ]; then
        log_error "No se puede detectar la distribución. /etc/os-release no existe."
        exit 1
    fi

    source /etc/os-release

    # Detectar distribución base
    case "$ID" in
        ubuntu)
            DISTRO="ubuntu"
            DISTRO_VERSION="$VERSION_ID"
            DISTRO_CODENAME="$VERSION_CODENAME"
            ;;
        debian)
            DISTRO="debian"
            DISTRO_VERSION="$VERSION_ID"
            DISTRO_CODENAME="$VERSION_CODENAME"
            DEBIAN_VERSION="$VERSION_ID"
            ;;
        linuxmint|pop|elementary|zorin)
            # Derivadas de Ubuntu
            DISTRO="ubuntu"
            DISTRO_VERSION="$VERSION_ID"
            DISTRO_CODENAME="$VERSION_CODENAME"
            log_info "Derivada de Ubuntu detectada: $ID"
            ;;
        raspbian)
            # Raspberry Pi OS (basada en Debian)
            DISTRO="debian"
            DISTRO_VERSION="$VERSION_ID"
            DISTRO_CODENAME="$VERSION_CODENAME"
            DEBIAN_VERSION="$VERSION_ID"
            log_info "Raspberry Pi OS detectado (basada en Debian)"
            ;;
        *)
            # Verificar ID_LIKE para otras derivadas
            if [[ "$ID_LIKE" == *"ubuntu"* ]]; then
                DISTRO="ubuntu"
                DISTRO_VERSION="$VERSION_ID"
                DISTRO_CODENAME="$VERSION_CODENAME"
                log_info "Derivada de Ubuntu detectada: $ID"
            elif [[ "$ID_LIKE" == *"debian"* ]]; then
                DISTRO="debian"
                DISTRO_VERSION="$VERSION_ID"
                DISTRO_CODENAME="$VERSION_CODENAME"
                # Intentar detectar versión de Debian base
                if [ -f /etc/debian_version ]; then
                    DEBIAN_VERSION=$(cat /etc/debian_version | cut -d'.' -f1)
                fi
                log_info "Derivada de Debian detectada: $ID"
            else
                log_error "Distribución no soportada: $ID"
                log_info "Este instalador es compatible con Ubuntu y Debian (y derivadas)"
                exit 1
            fi
            ;;
    esac

    log_success "Distribución: $PRETTY_NAME"
    log_info "Base: $DISTRO $DISTRO_VERSION ($DISTRO_CODENAME)"

    # Verificar versión mínima según distribución
    case "$DISTRO" in
        ubuntu)
            major_version=$(echo "$DISTRO_VERSION" | cut -d'.' -f1)
            if [ "$major_version" -lt 20 ]; then
                log_error "Se requiere Ubuntu 20.04 o superior. Detectado: $DISTRO_VERSION"
                exit 1
            fi
            ;;
        debian)
            # Debian 11+ requerido
            if [ -n "$DEBIAN_VERSION" ] && [ "$DEBIAN_VERSION" -lt 11 ]; then
                log_error "Se requiere Debian 11 (Bullseye) o superior. Detectado: $DEBIAN_VERSION"
                exit 1
            fi
            ;;
    esac

    # Detectar arquitectura
    detect_architecture

    # Detectar si es Desktop o Server
    if dpkg -l 2>/dev/null | grep -qE "ubuntu-desktop|gnome-shell|kde-plasma-desktop|xfce4|mate-desktop|cinnamon|lxde|lxqt"; then
        IS_DESKTOP=true
        log_info "Modo: Desktop (GUI detectado)"
    else
        IS_DESKTOP=false
        log_info "Modo: Server (sin GUI)"
    fi
}

# Verificar versión de Python
check_python_version() {
    log_info "Verificando Python..."

    # Buscar Python 3
    PYTHON_CMD=""
    for cmd in python3.12 python3.11 python3.10 python3.9 python3.8 python3; do
        if command -v $cmd &> /dev/null; then
            PYTHON_CMD=$cmd
            break
        fi
    done

    if [ -z "$PYTHON_CMD" ]; then
        log_error "Python 3 no encontrado."
        log_info "Instalar con: sudo apt install python3 python3-pip python3-venv"
        exit 1
    fi

    # Verificar versión mínima
    PYTHON_VERSION=$($PYTHON_CMD -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')

    if [ "$(printf '%s\n' "$MIN_PYTHON_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$MIN_PYTHON_VERSION" ]; then
        log_error "Se requiere Python $MIN_PYTHON_VERSION+. Instalado: $PYTHON_VERSION"
        exit 1
    fi

    log_success "Python $PYTHON_VERSION encontrado ($PYTHON_CMD)"

    # Verificar venv
    if ! $PYTHON_CMD -c "import venv" 2>/dev/null; then
        log_warning "python3-venv no instalado."
        if [ "$EUID" -eq 0 ]; then
            log_info "Instalando python3-venv..."
            apt install -y python3-venv
        else
            log_error "Instalar con: sudo apt install python3-venv"
            exit 1
        fi
    fi
}

# Verificar dependencias del sistema
check_system_dependencies() {
    log_info "Verificando dependencias del sistema..."

    MISSING_DEPS=()

    # Verificar pip
    if ! $PYTHON_CMD -m pip --version &> /dev/null; then
        MISSING_DEPS+=("python3-pip")
    fi

    # Verificar git (útil para actualizaciones)
    if ! command -v git &> /dev/null; then
        MISSING_DEPS+=("git")
    fi

    if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
        if [ "$EUID" -eq 0 ]; then
            log_info "Instalando dependencias: ${MISSING_DEPS[*]}"
            apt update
            apt install -y "${MISSING_DEPS[@]}"
        else
            log_error "Dependencias faltantes: ${MISSING_DEPS[*]}"
            log_info "Instalar con: sudo apt install ${MISSING_DEPS[*]}"
            exit 1
        fi
    fi

    log_success "Dependencias del sistema verificadas"
}

# Determinar nombre del paquete BCC según distribución
get_bcc_package_name() {
    case "$DISTRO" in
        ubuntu)
            echo "python3-bcc"
            ;;
        debian)
            if [ -n "$DEBIAN_VERSION" ]; then
                if [ "$DEBIAN_VERSION" -ge 12 ]; then
                    # Debian 12 (Bookworm) y superior
                    echo "python3-bpfcc"
                else
                    # Debian 11 (Bullseye)
                    echo "bpfcc-python3"
                fi
            else
                # Fallback para derivadas de Debian
                echo "python3-bpfcc"
            fi
            ;;
        *)
            echo "python3-bcc"
            ;;
    esac
}

# Verificar si BCC está instalado (cualquier variante del nombre)
is_bcc_installed() {
    dpkg -l 2>/dev/null | grep -qE "python3-bcc|python3-bpfcc|bpfcc-python3"
}

# Instalar dependencias para monitoreo a nivel de kernel
install_kernel_monitoring_deps() {
    log_info "Configurando monitoreo a nivel de kernel..."

    if [ "$EUID" -ne 0 ]; then
        log_warning "Monitoreo de kernel requiere instalacion como root"
        log_info "El agente funcionara con monitoreo basico (userspace)"
        log_info "Para monitoreo completo, reinstalar con: sudo ./install.sh"
        return
    fi

    # Obtener versión del kernel
    KERNEL_VERSION=$(uname -r)
    log_info "Kernel detectado: $KERNEL_VERSION"

    # Lista de paquetes para monitoreo de kernel
    KERNEL_DEPS=()

    # eBPF/BCC - Monitoreo de syscalls (nombre varía según distro)
    if ! is_bcc_installed; then
        BCC_PACKAGE=$(get_bcc_package_name)
        log_info "Paquete BCC para $DISTRO: $BCC_PACKAGE"
        KERNEL_DEPS+=("$BCC_PACKAGE")
        KERNEL_DEPS+=("bpfcc-tools")
    fi

    # Linux headers para compilacion de programas eBPF
    if ! dpkg -l 2>/dev/null | grep -q "linux-headers-$KERNEL_VERSION"; then
        KERNEL_DEPS+=("linux-headers-$KERNEL_VERSION")
    fi

    # Auditd - Sistema de auditoria del kernel (fallback)
    if ! command -v auditctl &> /dev/null; then
        KERNEL_DEPS+=("auditd")
        # audispd-plugins puede no existir en todas las versiones
        if apt-cache show audispd-plugins &>/dev/null; then
            KERNEL_DEPS+=("audispd-plugins")
        fi
    fi

    # Instalar dependencias
    if [ ${#KERNEL_DEPS[@]} -gt 0 ]; then
        log_info "Instalando dependencias de kernel: ${KERNEL_DEPS[*]}"
        apt update
        apt install -y "${KERNEL_DEPS[@]}" || {
            log_warning "Algunas dependencias de kernel no pudieron instalarse"
            log_info "El agente usara metodos alternativos de monitoreo"
        }
    fi

    # Cargar modulo cn para Netlink Process Connector
    if [ ! -f /proc/net/connector ]; then
        log_info "Cargando modulo Netlink Connector..."
        modprobe cn || log_warning "No se pudo cargar modulo cn"

        # Agregar a modules para carga automatica
        if ! grep -q "^cn$" /etc/modules 2>/dev/null; then
            echo "cn" >> /etc/modules
        fi
    fi

    # Verificar que eBPF esta disponible
    if [ -d /sys/kernel/debug/tracing ]; then
        log_success "eBPF/tracing disponible"
    else
        log_warning "eBPF tracing no disponible - montar debugfs"
        mount -t debugfs none /sys/kernel/debug 2>/dev/null || true
    fi

    # Configurar auditd si esta instalado
    if command -v auditctl &> /dev/null; then
        # Habilitar servicio
        systemctl enable auditd 2>/dev/null || true
        systemctl start auditd 2>/dev/null || true
        log_success "auditd configurado como fallback"
    fi

    # Verificar capacidades instaladas
    echo ""
    log_info "Capacidades de monitoreo de kernel:"

    if is_bcc_installed; then
        log_success "  eBPF/BCC: Disponible (monitoreo de syscalls)"
    else
        log_warning "  eBPF/BCC: No disponible"
    fi

    if [ -f /proc/net/connector ]; then
        log_success "  Netlink Connector: Disponible (eventos de procesos)"
    else
        log_warning "  Netlink Connector: No disponible"
    fi

    if command -v auditctl &> /dev/null; then
        log_success "  Audit Subsystem: Disponible (fallback)"
    else
        log_warning "  Audit Subsystem: No disponible"
    fi

    echo ""
}

# Verificar compatibilidad del kernel con inotify
check_inotify_support() {
    log_info "Verificando soporte de inotify..."

    if [ ! -f /proc/sys/fs/inotify/max_user_watches ]; then
        log_warning "inotify no disponible en este kernel"
        log_info "El monitoreo de sistema de archivos estará deshabilitado"
        return
    fi

    MAX_WATCHES=$(cat /proc/sys/fs/inotify/max_user_watches)

    if [ "$MAX_WATCHES" -lt 65536 ]; then
        log_warning "inotify max_user_watches bajo ($MAX_WATCHES)"
        if [ "$EUID" -eq 0 ]; then
            log_info "Aumentando límite de inotify watches..."
            echo "fs.inotify.max_user_watches=524288" >> /etc/sysctl.conf
            sysctl -p
        else
            log_info "Para mejor rendimiento, ejecutar como root:"
            log_info "  echo 'fs.inotify.max_user_watches=524288' | sudo tee -a /etc/sysctl.conf"
            log_info "  sudo sysctl -p"
        fi
    fi

    log_success "inotify disponible (max_watches: $MAX_WATCHES)"
}

# Crear entorno virtual
create_virtualenv() {
    log_info "Creando entorno virtual..."

    if [ -d "$VENV_PATH" ]; then
        log_warning "Entorno virtual existente detectado"
        read -p "¿Recrear entorno virtual? [y/N]: " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -rf "$VENV_PATH"
        else
            log_info "Usando entorno virtual existente"
            return
        fi
    fi

    $PYTHON_CMD -m venv "$VENV_PATH"
    log_success "Entorno virtual creado en $VENV_PATH"
}

# Instalar dependencias Python
install_python_deps() {
    log_info "Instalando dependencias Python..."

    source "$VENV_PATH/bin/activate"

    # Actualizar pip
    pip install --upgrade pip wheel setuptools > /dev/null 2>&1

    # Instalar dependencias
    if [ -f "$SCRIPT_DIR/requirements.txt" ]; then
        pip install -r "$SCRIPT_DIR/requirements.txt"
        log_success "Dependencias Python instaladas"
    else
        log_error "requirements.txt no encontrado"
        exit 1
    fi

    deactivate
}

# Crear directorios de datos
create_data_directories() {
    log_info "Creando directorios de datos..."

    mkdir -p ~/.dlp-agent/logs
    chmod 700 ~/.dlp-agent

    log_success "Directorios creados en ~/.dlp-agent"
}

# Crear scripts de inicio
create_startup_scripts() {
    log_info "Creando scripts de inicio..."

    # Determinar rutas de los scripts Python
    AGENT_SCRIPT="$SCRIPT_DIR/agent/dlp_agent.py"
    CONSOLE_SCRIPT="$SCRIPT_DIR/console/dlp_console.py"

    # Si no existen en subdirectorios, usar los del directorio padre
    if [ ! -f "$AGENT_SCRIPT" ]; then
        AGENT_SCRIPT="$(dirname "$SCRIPT_DIR")/dlp_agent.py"
    fi
    if [ ! -f "$CONSOLE_SCRIPT" ]; then
        CONSOLE_SCRIPT="$(dirname "$SCRIPT_DIR")/dlp_console.py"
    fi

    # Script para iniciar el agente
    cat > "$SCRIPT_DIR/start-agent.sh" << EOF
#!/bin/bash
# DLP Agent Launcher
SCRIPT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
source "\$SCRIPT_DIR/venv/bin/activate"

# Verificar que el script existe
if [ -f "$AGENT_SCRIPT" ]; then
    exec python3 "$AGENT_SCRIPT" "\$@"
elif [ -f "\$SCRIPT_DIR/agent/dlp_agent.py" ]; then
    exec python3 "\$SCRIPT_DIR/agent/dlp_agent.py" "\$@"
else
    echo "Error: dlp_agent.py no encontrado"
    exit 1
fi
EOF
    chmod +x "$SCRIPT_DIR/start-agent.sh"

    # Script para iniciar la consola
    cat > "$SCRIPT_DIR/start-console.sh" << EOF
#!/bin/bash
# DLP Console Launcher
SCRIPT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
source "\$SCRIPT_DIR/venv/bin/activate"

# Verificar que el script existe
if [ -f "$CONSOLE_SCRIPT" ]; then
    exec python3 "$CONSOLE_SCRIPT" "\$@"
elif [ -f "\$SCRIPT_DIR/console/dlp_console.py" ]; then
    exec python3 "\$SCRIPT_DIR/console/dlp_console.py" "\$@"
else
    echo "Error: dlp_console.py no encontrado"
    exit 1
fi
EOF
    chmod +x "$SCRIPT_DIR/start-console.sh"

    log_success "Scripts de inicio creados"
}

# Crear servicios systemd
create_systemd_services() {
    if [ "$EUID" -ne 0 ]; then
        log_info "Ejecutar como root para crear servicios systemd"
        return
    fi

    log_info "Creando servicios systemd..."

    # Obtener usuario que ejecutó sudo
    SUDO_USER_NAME="${SUDO_USER:-root}"

    # Crear directorio de configuracion del sistema
    mkdir -p /etc/dlp-agent
    chmod 700 /etc/dlp-agent

    # =========================================================================
    # SERVICIO DEL AGENTE (solo si se instala agente)
    # =========================================================================
    if [[ "$INSTALL_COMPONENT" == "agent" || "$INSTALL_COMPONENT" == "both" ]]; then
        cat > /etc/systemd/system/dlp-agent.service << EOF
[Unit]
Description=DLP Agent - Cibershield
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$SCRIPT_DIR
ExecStart=$SCRIPT_DIR/start-agent.sh
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

        # SERVICIO WATCHDOG (solo para agente)
        cat > /etc/systemd/system/dlp-watchdog.service << EOF
[Unit]
Description=DLP Agent Watchdog - Cibershield
After=network-online.target
Wants=dlp-agent.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$SCRIPT_DIR
ExecStart=$SCRIPT_DIR/venv/bin/python3 $SCRIPT_DIR/agent/watchdog.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
        log_success "Servicio dlp-agent.service creado"
        log_success "Servicio dlp-watchdog.service creado"
    fi

    # =========================================================================
    # SERVICIO DE LA CONSOLA (solo si se instala consola)
    # =========================================================================
    if [[ "$INSTALL_COMPONENT" == "console" || "$INSTALL_COMPONENT" == "both" ]]; then
        cat > /etc/systemd/system/dlp-console.service << EOF
[Unit]
Description=DLP Console - Cibershield
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SUDO_USER_NAME
Group=$SUDO_USER_NAME
WorkingDirectory=$SCRIPT_DIR
ExecStart=$SCRIPT_DIR/start-console.sh
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
        log_success "Servicio dlp-console.service creado"
    fi

    # =========================================================================
    # Script de desinstalacion protegido
    # =========================================================================
    cat > "$SCRIPT_DIR/uninstall.sh" << 'UNINSTALL_EOF'
#!/bin/bash
# Desinstalador del DLP Agent
# Requiere clave de administrador

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "======================================"
echo "  DLP Agent - Desinstalacion"
echo "======================================"
echo ""
echo "ADVERTENCIA: Se requiere la clave de administrador"
echo "             configurada durante la instalacion."
echo ""

# Verificar clave usando el modulo de proteccion
source "$SCRIPT_DIR/venv/bin/activate"
python3 "$SCRIPT_DIR/agent/protection.py" uninstall

if [ $? -ne 0 ]; then
    echo ""
    echo "ERROR: Desinstalacion cancelada - clave incorrecta"
    exit 1
fi

deactivate
echo ""
echo "Desinstalacion completada."
UNINSTALL_EOF
    chmod +x "$SCRIPT_DIR/uninstall.sh"

    systemctl daemon-reload

    log_success "Servicios systemd creados:"
    log_info "  - dlp-agent.service (monitoreo kernel, root)"
    log_info "  - dlp-console.service (dashboard web)"
    log_info "  - dlp-watchdog.service (persistencia)"
    echo ""
    echo -e "${YELLOW}Para habilitar e iniciar los servicios:${NC}"
    echo "  sudo systemctl enable dlp-agent dlp-console"
    echo "  sudo systemctl start dlp-agent dlp-console"
}

# Configurar clave de administrador para proteccion
configure_admin_key() {
    if [ "$EUID" -ne 0 ]; then
        log_info "Proteccion con clave requiere instalacion como root"
        return
    fi

    echo ""
    echo -e "${YELLOW}======================================================================"
    echo "             CONFIGURACION DE CLAVE DE ADMINISTRADOR"
    echo "======================================================================${NC}"
    echo ""
    echo "El agente DLP puede protegerse con una clave de administrador."
    echo "Esta clave sera REQUERIDA para:"
    echo "  - Desinstalar el agente"
    echo "  - Detener los servicios de forma permanente"
    echo "  - Modificar la configuracion de proteccion"
    echo ""
    echo -e "${RED}IMPORTANTE: Guarde esta clave en un lugar seguro.${NC}"
    echo -e "${RED}           Sin ella NO podra desinstalar el agente.${NC}"
    echo ""

    read -p "¿Desea configurar una clave de administrador? [S/n]: " -n 1 -r
    echo

    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        # Solicitar clave
        while true; do
            read -s -p "Ingrese clave de administrador (min 8 caracteres): " ADMIN_KEY
            echo

            if [ ${#ADMIN_KEY} -lt 8 ]; then
                log_error "La clave debe tener al menos 8 caracteres"
                continue
            fi

            read -s -p "Confirme la clave: " ADMIN_KEY_CONFIRM
            echo

            if [ "$ADMIN_KEY" != "$ADMIN_KEY_CONFIRM" ]; then
                log_error "Las claves no coinciden"
                continue
            fi

            break
        done

        # Configurar clave usando el modulo de proteccion
        source "$VENV_PATH/bin/activate"
        echo "$ADMIN_KEY" | python3 -c "
import sys
sys.path.insert(0, '$SCRIPT_DIR/agent')
from protection import KeyManager
km = KeyManager('/etc/dlp-agent/protection.conf')
key = sys.stdin.read().strip()
if km.set_admin_key(key):
    print('OK')
else:
    print('ERROR')
    sys.exit(1)
" 2>/dev/null

        if [ $? -eq 0 ]; then
            log_success "Clave de administrador configurada"
            echo ""
            echo -e "${GREEN}La clave ha sido guardada en: /etc/dlp-agent/protection.conf${NC}"
            echo -e "${YELLOW}GUARDE LA CLAVE EN UN LUGAR SEGURO${NC}"
        else
            log_warning "No se pudo configurar la clave de proteccion"
        fi
        deactivate
    else
        log_info "Proteccion con clave omitida"
        log_warning "El agente podra ser desinstalado sin autorizacion"
    fi
    echo ""
}

# Crear indicador de escritorio (solo en modo Desktop)
create_desktop_indicator() {
    if [ "$IS_DESKTOP" != true ]; then
        return
    fi

    log_info "Configurando integracion de escritorio..."

    # Crear archivo .desktop para autostart (opcional)
    AUTOSTART_DIR="$HOME/.config/autostart"
    mkdir -p "$AUTOSTART_DIR"

    cat > "$AUTOSTART_DIR/dlp-agent-indicator.desktop" << EOF
[Desktop Entry]
Type=Application
Name=DLP Agent Status
Comment=GitHub DLP Agent Status Indicator
Exec=$SCRIPT_DIR/start-agent.sh --background
Icon=security-high
Hidden=true
NoDisplay=true
X-GNOME-Autostart-enabled=false
EOF

    log_success "Integracion de escritorio configurada"
    log_info "Para habilitar autostart, editar: $AUTOSTART_DIR/dlp-agent-indicator.desktop"
}

# Verificar instalación
verify_installation() {
    log_info "Verificando instalación..."

    source "$VENV_PATH/bin/activate"

    # Verificar imports
    IMPORT_CHECK=$($PYTHON_CMD -c "
import sys
errors = []
try:
    import psutil
except ImportError:
    errors.append('psutil')
try:
    import flask
except ImportError:
    errors.append('flask')
try:
    import inotify
except ImportError:
    errors.append('inotify (opcional)')

if errors:
    print('MISSING:' + ','.join(errors))
else:
    print('OK')
" 2>&1)

    deactivate

    if [[ "$IMPORT_CHECK" == "OK" ]]; then
        log_success "Todas las dependencias verificadas"
        return 0
    else
        log_warning "Algunas dependencias no están disponibles: $IMPORT_CHECK"
        return 1
    fi
}

# Mostrar resumen final
show_summary() {
    echo ""
    echo -e "${GREEN}"
    echo "======================================================================"
    echo "              INSTALACION COMPLETADA EXITOSAMENTE"
    echo "         Desarrollado por Cibershield R.L. 2025 - v0.9"
    echo "======================================================================"
    echo -e "${NC}"
    echo ""
    echo -e "${CYAN}Sistema:${NC}"
    echo "  Distribución: $PRETTY_NAME"
    echo "  Base: $DISTRO $DISTRO_VERSION"
    echo "  Arquitectura: $ARCH"
    echo "  Componente instalado: $INSTALL_COMPONENT"
    echo ""

    # =========================================================================
    # RESUMEN PARA AGENTE
    # =========================================================================
    if [[ "$INSTALL_COMPONENT" == "agent" || "$INSTALL_COMPONENT" == "both" ]]; then
        echo -e "${CYAN}=== AGENTE DLP ===${NC}"
        echo ""
        if [ "$EUID" -eq 0 ]; then
            echo -e "${CYAN}Capacidades de monitoreo:${NC}"
            echo "  [+] Monitoreo de procesos (userspace)"
            echo "  [+] Monitoreo de sistema de archivos (inotify)"
            echo "  [+] Monitoreo de red (conexiones)"
            if is_bcc_installed; then
                echo "  [+] Monitoreo de kernel (eBPF/syscalls)"
            fi
            if [ -f /proc/net/connector ]; then
                echo "  [+] Eventos de procesos (Netlink)"
            fi
            echo ""

            if [ -f /etc/dlp-agent/protection.conf ]; then
                echo -e "${CYAN}Proteccion:${NC}"
                echo "  [+] Clave de administrador: CONFIGURADA"
                echo -e "  ${RED}IMPORTANTE: No olvide la clave de administrador${NC}"
                echo ""
            fi

            echo -e "${YELLOW}Servicios:${NC}"
            echo "  sudo systemctl enable --now dlp-agent dlp-watchdog"
            echo "  sudo systemctl status dlp-agent"
            echo ""

            echo -e "${YELLOW}Logs:${NC}"
            echo "  journalctl -u dlp-agent -f"
            echo "  ~/.dlp-agent/events.jsonl"
            echo ""

            echo -e "${CYAN}======================================================================"
            echo "              CONFIGURACION DE CONSOLA REMOTA"
            echo "======================================================================${NC}"
            echo ""
            echo "  Editar: $SCRIPT_DIR/config.yaml"
            echo ""
            echo "    console:"
            echo "      host: \"IP_DEL_SERVIDOR_CONSOLA\""
            echo "      port: 5555"
            echo ""
            echo "  Luego: sudo systemctl restart dlp-agent"
            echo ""
        else
            echo "  Iniciar: cd $SCRIPT_DIR && ./start-agent.sh"
            echo ""
        fi
    fi

    # =========================================================================
    # RESUMEN PARA CONSOLA
    # =========================================================================
    if [[ "$INSTALL_COMPONENT" == "console" || "$INSTALL_COMPONENT" == "both" ]]; then
        echo -e "${CYAN}=== CONSOLA DLP ===${NC}"
        echo ""
        echo -e "${YELLOW}Dashboard web:${NC}"
        echo "  http://$(hostname -I | awk '{print $1}'):8080"
        echo "  http://localhost:8080"
        echo ""
        echo -e "${YELLOW}Puerto TCP para agentes:${NC}"
        echo "  5555"
        echo ""

        if [ "$EUID" -eq 0 ]; then
            echo -e "${YELLOW}Servicio:${NC}"
            echo "  sudo systemctl enable --now dlp-console"
            echo "  sudo systemctl status dlp-console"
            echo ""
        else
            echo "  Iniciar: cd $SCRIPT_DIR && ./start-console.sh"
            echo ""
        fi

        echo -e "${CYAN}Los agentes deben configurar esta IP en su config.yaml${NC}"
        echo ""
    fi
}

# Main
main() {
    show_banner

    # Seleccionar qué instalar
    select_component

    # Verificar tipo de instalacion
    if [ "$EUID" -eq 0 ]; then
        INSTALL_TYPE="system"
        log_info "Ejecutando como root - instalacion a nivel de sistema"
    else
        INSTALL_TYPE="user"
        log_info "Ejecutando como usuario - instalacion local"
        log_warning "Para servicios systemd, ejecutar con: sudo ./install.sh"
    fi

    # Ejecutar pasos de instalacion
    detect_distribution
    check_python_version
    check_system_dependencies

    # Instalar dependencias de kernel (solo para agente y como root)
    if [[ "$INSTALL_COMPONENT" == "agent" || "$INSTALL_COMPONENT" == "both" ]]; then
        install_kernel_monitoring_deps
        check_inotify_support
    fi

    create_virtualenv
    install_python_deps
    create_data_directories
    create_startup_scripts

    if [ "$INSTALL_TYPE" = "system" ]; then
        create_systemd_services
        # Configurar clave de administrador (solo para agente)
        if [[ "$INSTALL_COMPONENT" == "agent" || "$INSTALL_COMPONENT" == "both" ]]; then
            configure_admin_key
        fi
    fi

    verify_installation
    show_summary
}

# Ejecutar
main "$@"
