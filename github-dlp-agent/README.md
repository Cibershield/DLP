# 🛡️ GitHub DLP Agent

Agente de Prevención de Pérdida de Datos (DLP) para Ubuntu que detecta y reporta cuando usuarios descargan/clonan repositorios de GitHub **fuera de IDEs autorizados**.

## 🎯 Características

- **Monitoreo de Procesos**: Detecta comandos `git clone`, `git pull`, `git fetch`, `gh repo clone`, descargas via `curl`/`wget`
- **Monitoreo de Sistema de Archivos**: Detecta creación de carpetas `.git` usando inotify (eficiente, sin polling)
- **Filtrado Inteligente**: Permite operaciones desde IDEs autorizados (VS Code, JetBrains, etc.)
- **Consola Web**: Dashboard en tiempo real para visualizar eventos
- **Multi-agente**: Múltiples máquinas pueden reportar a una consola central
- **Persistencia Local**: Eventos guardados localmente incluso si la consola no está disponible

## 📋 Requisitos

- Ubuntu 20.04+ (o cualquier distribución con systemd)
- Python 3.8+
- Permisos de lectura en `/proc` (para monitoreo de procesos)

## 🚀 Instalación Rápida

```bash
# Clonar o copiar el proyecto
cd github-dlp-agent

# Ejecutar instalador
chmod +x install.sh
./install.sh

# O como root para instalación de sistema con servicios systemd
sudo ./install.sh
```

## 🖥️ Uso Manual

### 1. Iniciar la Consola

```bash
./start-console.sh
```

Esto inicia:
- Servidor TCP en puerto **5555** (recibe eventos de agentes)
- Dashboard web en **http://localhost:8080**

### 2. Iniciar el Agente

En otra terminal:

```bash
./start-agent.sh
```

El agente comenzará a monitorear y enviar eventos a la consola.

## 🧪 Probar que Funciona

Con ambos servicios corriendo:

```bash
# Esto DEBERÍA generar una alerta (ejecutado desde bash)
git clone https://github.com/octocat/Hello-World.git /tmp/test-dlp

# Esto NO debería generar alerta si se ejecuta desde VS Code
# (abrir terminal integrada de VS Code y ejecutar el mismo comando)
```

Verifica en el dashboard http://localhost:8080 que aparece el evento.

## ⚙️ Configuración

Editar `config.yaml` para personalizar:

```yaml
# Agregar IDEs permitidos
allowed_processes:
  - code
  - pycharm
  - mi-ide-custom

# Cambiar servidor de consola (para múltiples agentes)
console:
  host: "192.168.1.100"
  port: 5555

# Directorios a monitorear
watch_directories:
  - "~"
  - "/proyectos"
```

## 🏗️ Arquitectura

```
┌─────────────────────────────────────────────────────────────┐
│                      AGENTE (por máquina)                   │
├─────────────────────────────────────────────────────────────┤
│  ProcessMonitor          │  FileSystemMonitor               │
│  - Escanea /proc         │  - inotify en directorios        │
│  - Detecta git commands  │  - Detecta .git folders          │
│  - Verifica proceso      │                                  │
│    padre (IDE check)     │                                  │
├─────────────────────────────────────────────────────────────┤
│                     EventReporter                           │
│  - Encola eventos        │  - Guarda local (.jsonl)        │
│  - Envía via TCP         │                                  │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ TCP :5555
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     CONSOLA (servidor)                      │
├─────────────────────────────────────────────────────────────┤
│  TCP Receiver             │  Flask Web Server               │
│  - Acepta conexiones      │  - Dashboard HTML/JS            │
│  - Parsea JSON events     │  - API REST /api/events         │
│  - Almacena en memoria    │  - Auto-refresh 3s              │
└─────────────────────────────────────────────────────────────┘
```

## 📁 Estructura de Archivos

```
github-dlp-agent/
├── agent/
│   └── dlp_agent.py       # Agente principal
├── console/
│   └── dlp_console.py     # Consola web
├── config.yaml            # Configuración editable
├── requirements.txt       # Dependencias Python
├── install.sh            # Script de instalación
├── start-agent.sh        # Iniciar agente (generado)
├── start-console.sh      # Iniciar consola (generado)
└── README.md             # Esta documentación

~/.dlp-agent/              # Datos locales del agente
├── agent.log             # Log del agente
└── events.jsonl          # Eventos locales (backup)
```

## 🔧 Servicios Systemd

Si instalaste como root:

```bash
# Habilitar servicios
sudo systemctl enable dlp-agent dlp-console

# Iniciar
sudo systemctl start dlp-agent dlp-console

# Ver estado
sudo systemctl status dlp-agent
sudo systemctl status dlp-console

# Ver logs
sudo journalctl -u dlp-agent -f
sudo journalctl -u dlp-console -f
```

## 📊 API de la Consola

```bash
# Obtener eventos y estadísticas
curl http://localhost:8080/api/events

# Solo estadísticas
curl http://localhost:8080/api/stats
```

## 🔐 Consideraciones de Seguridad

1. **Permisos**: El agente necesita poder leer `/proc` para detectar procesos. Como usuario normal puede monitorear sus propios procesos; como root, todos.

2. **Red**: La comunicación agente-consola es via TCP sin cifrado. Para producción, considera:
   - Usar SSH tunneling
   - Implementar TLS
   - Usar VPN

3. **Evasión**: Un usuario técnico podría:
   - Renombrar `git` → detectado por análisis de cmdline
   - Usar git via container → parcialmente detectable
   - Descargar ZIP manualmente del navegador → detectable si monitoreas Downloads

## 🚧 Futuras Mejoras

- [ ] Soporte para archivo de configuración YAML
- [ ] Integración con Slack/Teams (webhooks)
- [ ] Modo "bloqueo" (requiere eBPF)
- [ ] Dashboard con histórico persistente (SQLite)
- [ ] Exportar reportes a PDF/Excel
- [ ] Monitor de tráfico de red (conexiones a github.com)
- [ ] Agente para Windows

## 📝 Licencia

MIT - Úsalo como quieras.

---

Desarrollado para Delfix-CR 🇨🇷
