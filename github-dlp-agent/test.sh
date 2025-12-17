#!/bin/bash
#
# Script de prueba para GitHub DLP Agent
# Ejecutar después de tener la consola y el agente corriendo
#

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║           GitHub DLP Agent - Pruebas                     ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Verificar que la consola está corriendo
echo -e "\n${YELLOW}[1/4] Verificando consola...${NC}"
if curl -s http://localhost:8080/api/stats > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Consola activa en http://localhost:8080${NC}"
else
    echo -e "${RED}✗ Consola no detectada. Iniciar con: ./start-console.sh${NC}"
    exit 1
fi

# Verificar que el agente está corriendo (buscar proceso)
echo -e "\n${YELLOW}[2/4] Verificando agente...${NC}"
if pgrep -f "dlp_agent.py" > /dev/null; then
    echo -e "${GREEN}✓ Agente activo${NC}"
else
    echo -e "${RED}✗ Agente no detectado. Iniciar con: ./start-agent.sh${NC}"
    exit 1
fi

# Crear directorio temporal para pruebas
TEST_DIR="/tmp/dlp-test-$$"
mkdir -p "$TEST_DIR"

echo -e "\n${YELLOW}[3/4] Ejecutando prueba de detección...${NC}"
echo -e "${BLUE}Ejecutando: git clone https://github.com/octocat/Hello-World.git${NC}"
echo ""

# Ejecutar git clone (esto debería ser detectado)
cd "$TEST_DIR"
git clone --depth 1 https://github.com/octocat/Hello-World.git 2>/dev/null

# Esperar a que el agente lo detecte
sleep 3

# Verificar si se detectó
echo -e "\n${YELLOW}[4/4] Verificando detección...${NC}"
STATS=$(curl -s http://localhost:8080/api/stats)
TOTAL=$(echo "$STATS" | grep -o '"total_events":[0-9]*' | cut -d: -f2)

if [ "$TOTAL" -gt 0 ]; then
    echo -e "${GREEN}✓ ¡Evento detectado! Total de eventos: $TOTAL${NC}"
    echo ""
    echo -e "${BLUE}Últimos eventos:${NC}"
    curl -s http://localhost:8080/api/events | python3 -c "
import sys, json
data = json.load(sys.stdin)
for event in data['events'][:3]:
    status = '✓ PERMITIDO' if event.get('is_allowed') else '🚨 ALERTA'
    print(f\"  {status}: {event.get('username')}@{event.get('hostname')}\")
    print(f\"    Comando: {event.get('command_line', 'N/A')[:60]}...\")
    print(f\"    Desde: {event.get('parent_process', 'N/A')}\")
    print()
"
else
    echo -e "${YELLOW}⚠ No se detectaron eventos aún. Puede haber un pequeño delay.${NC}"
    echo "Verificar manualmente en: http://localhost:8080"
fi

# Limpiar
rm -rf "$TEST_DIR"

echo -e "\n${GREEN}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║              Prueba completada                           ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║  Dashboard: http://localhost:8080                        ║"
echo "║  Logs:      ~/.dlp-agent/agent.log                       ║"
echo "║  Eventos:   ~/.dlp-agent/events.jsonl                    ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
