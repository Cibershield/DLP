#!/bin/bash
#
# Script de Verificación de Compatibilidad - GitHub DLP Agent
# Verifica que el sistema cumple los requisitos antes de la instalación
#

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PATH="$SCRIPT_DIR/venv"
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_WARNINGS=0

# Funciones de utilidad
test_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((TESTS_PASSED++))
}

test_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((TESTS_FAILED++))
}

test_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    ((TESTS_WARNINGS++))
}

test_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Banner
echo ""
echo -e "${BLUE}======================================================================"
echo "           GitHub DLP Agent - Verificacion de Compatibilidad"
echo "======================================================================${NC}"
echo ""

# ============================================================================
# TEST 1: Sistema Operativo
# ============================================================================
echo -e "${BLUE}[TEST] Sistema Operativo${NC}"

if [ -f /etc/os-release ]; then
    source /etc/os-release
    test_info "Distribucion: $PRETTY_NAME"

    if [[ "$ID" == "ubuntu" ]]; then
        major_version=$(echo "$VERSION_ID" | cut -d'.' -f1)
        if [ "$major_version" -ge 20 ]; then
            test_pass "Ubuntu $VERSION_ID soportado"
        else
            test_fail "Ubuntu $VERSION_ID no soportado (minimo 20.04)"
        fi
    elif [[ "$ID_LIKE" == *"ubuntu"* ]] || [[ "$ID_LIKE" == *"debian"* ]]; then
        test_warn "Derivado de Ubuntu/Debian detectado - puede funcionar"
    else
        test_fail "Distribucion no soportada: $ID"
    fi
else
    test_fail "/etc/os-release no encontrado"
fi

# ============================================================================
# TEST 2: Python
# ============================================================================
echo ""
echo -e "${BLUE}[TEST] Python${NC}"

PYTHON_CMD=""
for cmd in python3.12 python3.11 python3.10 python3.9 python3.8 python3; do
    if command -v $cmd &> /dev/null; then
        PYTHON_CMD=$cmd
        break
    fi
done

if [ -z "$PYTHON_CMD" ]; then
    test_fail "Python 3 no encontrado"
else
    PYTHON_VERSION=$($PYTHON_CMD -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    test_info "Python encontrado: $PYTHON_CMD ($PYTHON_VERSION)"

    # Verificar versión mínima
    if [ "$(printf '%s\n' "3.8" "$PYTHON_VERSION" | sort -V | head -n1)" = "3.8" ]; then
        test_pass "Python $PYTHON_VERSION >= 3.8"
    else
        test_fail "Python $PYTHON_VERSION < 3.8 (minimo requerido)"
    fi

    # Verificar módulos estándar
    if $PYTHON_CMD -c "import venv" 2>/dev/null; then
        test_pass "python3-venv disponible"
    else
        test_fail "python3-venv no instalado"
    fi
fi

# ============================================================================
# TEST 3: Entorno Virtual (si existe)
# ============================================================================
echo ""
echo -e "${BLUE}[TEST] Entorno Virtual${NC}"

if [ -d "$VENV_PATH" ]; then
    test_pass "Entorno virtual existe en $VENV_PATH"

    if [ -f "$VENV_PATH/bin/activate" ]; then
        test_pass "Script de activacion existe"

        # Verificar dependencias
        source "$VENV_PATH/bin/activate"

        # psutil
        if python3 -c "import psutil" 2>/dev/null; then
            PSUTIL_VER=$(python3 -c "import psutil; print(psutil.__version__)")
            test_pass "psutil $PSUTIL_VER instalado"
        else
            test_fail "psutil no instalado"
        fi

        # flask
        if python3 -c "import flask" 2>/dev/null; then
            FLASK_VER=$(python3 -c "import flask; print(flask.__version__)")
            test_pass "flask $FLASK_VER instalado"
        else
            test_fail "flask no instalado"
        fi

        # inotify
        if python3 -c "import inotify" 2>/dev/null; then
            test_pass "inotify instalado"
        else
            test_warn "inotify no instalado (FileSystemMonitor deshabilitado)"
        fi

        # msal
        if python3 -c "import msal" 2>/dev/null; then
            test_pass "msal instalado (Azure AD auth)"
        else
            test_warn "msal no instalado (auth basica)"
        fi

        # requests
        if python3 -c "import requests" 2>/dev/null; then
            test_pass "requests instalado (GitHub API)"
        else
            test_warn "requests no instalado (GitHub API deshabilitada)"
        fi

        deactivate
    else
        test_fail "Script de activacion no encontrado"
    fi
else
    test_info "Entorno virtual no encontrado - ejecutar ./install.sh primero"
fi

# ============================================================================
# TEST 4: Kernel Features (inotify)
# ============================================================================
echo ""
echo -e "${BLUE}[TEST] Caracteristicas del Kernel${NC}"

if [ -f /proc/sys/fs/inotify/max_user_watches ]; then
    MAX_WATCHES=$(cat /proc/sys/fs/inotify/max_user_watches)
    test_info "inotify max_user_watches: $MAX_WATCHES"

    if [ "$MAX_WATCHES" -ge 65536 ]; then
        test_pass "inotify configurado correctamente"
    else
        test_warn "inotify max_user_watches bajo ($MAX_WATCHES < 65536)"
    fi
else
    test_warn "inotify no disponible en este kernel"
fi

# ============================================================================
# TEST 5: Permisos
# ============================================================================
echo ""
echo -e "${BLUE}[TEST] Permisos${NC}"

if [ "$EUID" -eq 0 ]; then
    test_info "Ejecutando como root"
    test_pass "NetworkMonitor tendra acceso completo"
else
    test_info "Ejecutando como usuario normal"
    test_warn "NetworkMonitor tendra acceso limitado (solo procesos del usuario)"
fi

# Verificar acceso a /proc
if [ -r /proc/1/cmdline ] 2>/dev/null; then
    test_pass "Acceso de lectura a /proc"
else
    test_warn "Acceso limitado a /proc"
fi

# ============================================================================
# TEST 6: Archivos del Agente
# ============================================================================
echo ""
echo -e "${BLUE}[TEST] Archivos del Agente${NC}"

# Verificar scripts de inicio
if [ -f "$SCRIPT_DIR/start-agent.sh" ] && [ -x "$SCRIPT_DIR/start-agent.sh" ]; then
    test_pass "start-agent.sh existe y es ejecutable"
elif [ -f "$SCRIPT_DIR/start-agent.sh" ]; then
    test_warn "start-agent.sh existe pero no es ejecutable"
else
    test_info "start-agent.sh no encontrado (se creara con install.sh)"
fi

if [ -f "$SCRIPT_DIR/start-console.sh" ] && [ -x "$SCRIPT_DIR/start-console.sh" ]; then
    test_pass "start-console.sh existe y es ejecutable"
elif [ -f "$SCRIPT_DIR/start-console.sh" ]; then
    test_warn "start-console.sh existe pero no es ejecutable"
else
    test_info "start-console.sh no encontrado (se creara con install.sh)"
fi

# Verificar scripts Python
AGENT_FOUND=false
for path in "$SCRIPT_DIR/agent/dlp_agent.py" "$(dirname "$SCRIPT_DIR")/dlp_agent.py"; do
    if [ -f "$path" ]; then
        test_pass "dlp_agent.py encontrado: $path"
        AGENT_FOUND=true
        break
    fi
done
if [ "$AGENT_FOUND" = false ]; then
    test_fail "dlp_agent.py no encontrado"
fi

CONSOLE_FOUND=false
for path in "$SCRIPT_DIR/console/dlp_console.py" "$(dirname "$SCRIPT_DIR")/dlp_console.py"; do
    if [ -f "$path" ]; then
        test_pass "dlp_console.py encontrado: $path"
        CONSOLE_FOUND=true
        break
    fi
done
if [ "$CONSOLE_FOUND" = false ]; then
    test_fail "dlp_console.py no encontrado"
fi

# ============================================================================
# TEST 7: Directorio de Datos
# ============================================================================
echo ""
echo -e "${BLUE}[TEST] Directorio de Datos${NC}"

DATA_DIR="$HOME/.dlp-agent"
if [ -d "$DATA_DIR" ]; then
    test_pass "Directorio de datos existe: $DATA_DIR"

    if [ -w "$DATA_DIR" ]; then
        test_pass "Directorio de datos es escribible"
    else
        test_fail "Directorio de datos no es escribible"
    fi
else
    test_info "Directorio de datos no existe (se creara al iniciar)"
fi

# ============================================================================
# TEST 8: Puertos
# ============================================================================
echo ""
echo -e "${BLUE}[TEST] Disponibilidad de Puertos${NC}"

# Puerto TCP 5555
if command -v ss &> /dev/null; then
    if ! ss -tuln 2>/dev/null | grep -q ":5555 "; then
        test_pass "Puerto 5555 disponible (TCP receiver)"
    else
        test_warn "Puerto 5555 en uso - puede haber conflicto"
    fi

    # Puerto HTTP 8080
    if ! ss -tuln 2>/dev/null | grep -q ":8080 "; then
        test_pass "Puerto 8080 disponible (Web dashboard)"
    else
        test_warn "Puerto 8080 en uso - puede haber conflicto"
    fi
else
    test_info "ss no disponible - omitiendo verificacion de puertos"
fi

# ============================================================================
# TEST 9: Servicios Systemd (si aplica)
# ============================================================================
echo ""
echo -e "${BLUE}[TEST] Servicios Systemd${NC}"

if [ -f /etc/systemd/system/dlp-agent.service ]; then
    test_pass "Servicio dlp-agent.service instalado"

    if systemctl is-enabled dlp-agent.service 2>/dev/null | grep -q "enabled"; then
        test_pass "Servicio dlp-agent habilitado"
    else
        test_info "Servicio dlp-agent no habilitado"
    fi
else
    test_info "Servicio systemd no instalado (instalacion de usuario)"
fi

# ============================================================================
# RESUMEN
# ============================================================================
echo ""
echo -e "${BLUE}======================================================================"
echo "                           RESUMEN"
echo "======================================================================${NC}"
echo ""
echo -e "  ${GREEN}Pasadas:${NC}     $TESTS_PASSED"
echo -e "  ${YELLOW}Advertencias:${NC} $TESTS_WARNINGS"
echo -e "  ${RED}Fallidas:${NC}    $TESTS_FAILED"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}El sistema es compatible con el agente DLP.${NC}"
    echo ""
    if [ ! -d "$VENV_PATH" ]; then
        echo "Siguiente paso: ./install.sh"
    else
        echo "Para iniciar:"
        echo "  1. Consola: ./start-console.sh"
        echo "  2. Agente:  ./start-agent.sh"
    fi
    echo ""
    exit 0
else
    echo -e "${RED}Hay $TESTS_FAILED problema(s) de compatibilidad. Revisar los errores arriba.${NC}"
    echo ""
    exit 1
fi
