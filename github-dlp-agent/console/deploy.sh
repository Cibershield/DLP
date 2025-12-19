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
        echo -e "${YELLOW}Nota: Ejecute con sudo para configurar DNS correctamente${NC}"
    fi
}

# Configurar DNS del sistema permanentemente
configure_dns() {
    echo -e "${YELLOW}[1/6] Configurando DNS del sistema...${NC}"

    # Desbloquear resolv.conf si está bloqueado
    sudo chattr -i /etc/resolv.conf 2>/dev/null || true

    # Configurar resolv.conf con DNS de Google primero
    sudo tee /etc/resolv.conf > /dev/null << 'EOF'
# Configurado por DLP Deploy Script
nameserver 8.8.8.8
nameserver 8.8.4.4
EOF

    # Bloquear para que NetworkManager no lo sobrescriba
    sudo chattr +i /etc/resolv.conf

    echo -e "${GREEN}DNS del sistema configurado (8.8.8.8, 8.8.4.4)${NC}"
}

# Configurar /etc/hosts para Docker Hub
configure_hosts() {
    echo -e "${YELLOW}[2/6] Configurando /etc/hosts para Docker Hub...${NC}"

    # Resolver IPs de Docker Hub usando DNS de Google
    REGISTRY_IP=$(nslookup registry-1.docker.io 8.8.8.8 2>/dev/null | grep "Address:" | tail -1 | awk '{print $2}')
    AUTH_IP=$(nslookup auth.docker.io 8.8.8.8 2>/dev/null | grep "Address:" | tail -1 | awk '{print $2}')
    PROD_IP=$(nslookup production.cloudflare.docker.com 8.8.8.8 2>/dev/null | grep "Address:" | tail -1 | awk '{print $2}')

    # Eliminar entradas anteriores de Docker Hub
    sudo sed -i '/registry-1.docker.io/d' /etc/hosts 2>/dev/null || true
    sudo sed -i '/auth.docker.io/d' /etc/hosts 2>/dev/null || true
    sudo sed -i '/production.cloudflare.docker.com/d' /etc/hosts 2>/dev/null || true
    sudo sed -i '/r2.cloudflarestorage.com/d' /etc/hosts 2>/dev/null || true

    # Agregar nuevas entradas
    if [ -n "$REGISTRY_IP" ]; then
        echo "$REGISTRY_IP registry-1.docker.io" | sudo tee -a /etc/hosts > /dev/null
    fi
    if [ -n "$AUTH_IP" ]; then
        echo "$AUTH_IP auth.docker.io" | sudo tee -a /etc/hosts > /dev/null
    fi
    if [ -n "$PROD_IP" ]; then
        echo "$PROD_IP production.cloudflare.docker.com" | sudo tee -a /etc/hosts > /dev/null
    fi

    echo -e "${GREEN}Hosts configurado para Docker Hub${NC}"
}

# Configurar Docker DNS
configure_docker_dns() {
    echo -e "${YELLOW}[3/6] Configurando DNS de Docker...${NC}"

    DAEMON_JSON="/etc/docker/daemon.json"

    # Siempre configurar daemon.json con DNS
    sudo tee "$DAEMON_JSON" > /dev/null << 'EOF'
{"dns":["8.8.8.8","8.8.4.4"]}
EOF

    # Reiniciar Docker
    echo -e "${YELLOW}Reiniciando Docker...${NC}"
    sudo systemctl daemon-reload
    sudo systemctl restart docker
    sleep 3

    echo -e "${GREEN}Docker DNS configurado${NC}"
}

# Verificar conexión a Docker Hub
verify_docker_hub() {
    echo -e "${YELLOW}[4/6] Verificando conexión a Docker Hub...${NC}"

    # Intentar hasta 3 veces
    for i in 1 2 3; do
        if docker pull hello-world > /dev/null 2>&1; then
            echo -e "${GREEN}Conexión a Docker Hub OK${NC}"
            docker rmi hello-world > /dev/null 2>&1 || true
            return 0
        fi
        echo -e "${YELLOW}Intento $i fallido, reintentando...${NC}"
        sleep 2
    done

    echo -e "${RED}Error: No se puede conectar a Docker Hub${NC}"
    echo "Verifique su conexión a internet"
    exit 1
}

# Construir contenedor
build_container() {
    echo -e "${YELLOW}[5/6] Construyendo contenedor...${NC}"
    docker compose build --no-cache
    echo -e "${GREEN}Contenedor construido${NC}"
}

# Iniciar contenedor
start_container() {
    echo -e "${YELLOW}[6/6] Iniciando contenedor...${NC}"
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
    echo "Webhook URL: http://$(hostname -I | awk '{print $1}'):8080/webhook/github"
    echo ""
}

# Main
main() {
    check_root
    configure_dns
    configure_hosts
    configure_docker_dns
    verify_docker_hub
    build_container
    start_container
    show_status
}

main "$@"
