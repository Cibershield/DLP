#!/bin/bash
# Deploy Script - Administración GitHub Console
# Cibershield R.L. 2025
#
# Este script configura DNS y despliega la consola automáticamente

set -e

echo "=============================================="
echo "  Administración GitHub - Deploy Script"
echo "  Cibershield R.L. 2025"
echo "=============================================="

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Verificar si se ejecuta como root para algunas operaciones
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${YELLOW}Nota: Algunas operaciones pueden requerir sudo${NC}"
    fi
}

# Configurar DNS del sistema si es necesario
configure_dns() {
    echo -e "${YELLOW}[1/5] Verificando configuración DNS...${NC}"

    # Verificar si podemos resolver Docker Hub
    if ! nslookup registry-1.docker.io > /dev/null 2>&1; then
        echo -e "${RED}DNS no resuelve Docker Hub. Configurando...${NC}"

        # Agregar DNS de Google si no están
        if ! grep -q "8.8.8.8" /etc/resolv.conf; then
            echo -e "${YELLOW}Agregando DNS de Google a /etc/resolv.conf${NC}"
            sudo cp /etc/resolv.conf /etc/resolv.conf.backup
            echo -e "nameserver 8.8.8.8\nnameserver 8.8.4.4" | sudo tee -a /etc/resolv.conf > /dev/null
        fi
    fi

    echo -e "${GREEN}DNS configurado correctamente${NC}"
}

# Configurar Docker DNS
configure_docker_dns() {
    echo -e "${YELLOW}[2/5] Configurando DNS de Docker...${NC}"

    DAEMON_JSON="/etc/docker/daemon.json"

    if [ ! -f "$DAEMON_JSON" ] || ! grep -q "8.8.8.8" "$DAEMON_JSON"; then
        echo -e "${YELLOW}Configurando DNS en Docker daemon...${NC}"
        sudo tee "$DAEMON_JSON" > /dev/null << 'EOF'
{
  "dns": ["8.8.8.8", "8.8.4.4"]
}
EOF
        echo -e "${YELLOW}Reiniciando Docker...${NC}"
        sudo systemctl restart docker
        sleep 2
    fi

    echo -e "${GREEN}Docker DNS configurado${NC}"
}

# Verificar conexión a Docker Hub
verify_docker_hub() {
    echo -e "${YELLOW}[3/5] Verificando conexión a Docker Hub...${NC}"

    if docker pull hello-world > /dev/null 2>&1; then
        echo -e "${GREEN}Conexión a Docker Hub OK${NC}"
        docker rmi hello-world > /dev/null 2>&1 || true
    else
        echo -e "${RED}Error: No se puede conectar a Docker Hub${NC}"
        echo "Verifique su conexión a internet y configuración DNS"
        exit 1
    fi
}

# Construir contenedor
build_container() {
    echo -e "${YELLOW}[4/5] Construyendo contenedor...${NC}"
    docker compose build --no-cache
    echo -e "${GREEN}Contenedor construido${NC}"
}

# Iniciar contenedor
start_container() {
    echo -e "${YELLOW}[5/5] Iniciando contenedor...${NC}"
    docker compose down 2>/dev/null || true
    docker compose up -d
    echo -e "${GREEN}Contenedor iniciado${NC}"
}

# Mostrar estado
show_status() {
    echo ""
    echo "=============================================="
    echo -e "${GREEN}Despliegue completado exitosamente${NC}"
    echo "=============================================="
    echo ""
    docker compose ps
    echo ""
    echo "Dashboard: http://$(hostname -I | awk '{print $1}'):8080"
    echo "TCP Receiver: puerto 5555"
    echo ""
}

# Main
main() {
    check_root
    configure_dns
    configure_docker_dns
    verify_docker_hub
    build_container
    start_container
    show_status
}

main "$@"
