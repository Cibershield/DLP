# Windows DLP Agent

Agente de Prevención de Pérdida de Datos (DLP) para Windows.
Monitorea operaciones de git, conexiones de red a GitHub, y cambios en el sistema de archivos.

## Requisitos

- Windows 10/11 (x64 o ARM64)
- Python 3.8+ (para desarrollo/build)
- Acceso de red a la consola DLP

## Instalación Rápida

### Opción 1: Ejecutable pre-compilado

1. Descargar `DLPAgent_x64.exe` o `DLPAgent_ARM64.exe` según tu arquitectura
2. Copiar `config.yaml` al mismo directorio
3. Editar `config.yaml` con la dirección de tu consola DLP
4. Ejecutar el agente

```powershell
# Verificar estado del sistema
.\DLPAgent_x64.exe --status

# Ejecutar en modo debug
.\DLPAgent_x64.exe --debug

# Ejecutar normalmente
.\DLPAgent_x64.exe
```

### Opción 2: Desde código fuente

```powershell
# Instalar dependencias
pip install -r requirements.txt

# Ejecutar directamente
python dlp_agent_windows.py
```

## Configuración

Editar `config.yaml`:

```yaml
console:
  host: "192.168.1.100"  # IP de la consola DLP
  port: 5000

monitoring:
  paths:
    - "%USERPROFILE%"
    - "C:\\Repos"
```

## Compilar Ejecutable

```powershell
cd installer

# Build automático (detecta arquitectura)
.\build.ps1

# Build específico
.\build.ps1 -Arch x64
.\build.ps1 -Arch arm64

# Limpiar y compilar
.\build.ps1 -Clean -Arch x64
```

## Monitoreo

El agente monitorea:

- **Procesos**: Ejecución de git.exe, gh.exe, y otros comandos
- **Red**: Conexiones a servidores de GitHub (IPs conocidas)
- **Archivos**: Creación de directorios .git y archivos sensibles

## Servicio Windows (Opcional)

Para instalar como servicio:

```powershell
# Requiere NSSM o sc.exe
sc create DLPAgent binPath= "C:\path\to\DLPAgent_x64.exe" start= auto
sc description DLPAgent "Cibershield DLP Agent"
sc start DLPAgent
```

## Arquitectura

```
windows_agent/
├── dlp_agent_windows.py    # Orquestador principal
├── config.yaml             # Configuración
├── monitors/
│   ├── process_monitor.py  # WMI/psutil
│   ├── file_monitor.py     # watchdog
│   ├── network_monitor.py  # psutil/ETW
│   └── git_detector.py     # Análisis de comandos git
├── utils/
│   ├── system_info.py      # Info del sistema
│   ├── config_loader.py    # Carga de YAML
│   └── event_reporter.py   # Envío de eventos
└── installer/
    ├── build.ps1           # Script de compilación
    ├── dlp_agent_x64.spec  # PyInstaller x64
    └── dlp_agent_arm64.spec # PyInstaller ARM64
```

## Solución de Problemas

### El agente no detecta procesos

- Verificar que el agente tenga permisos de administrador
- Comprobar que WMI esté funcionando: `wmic process list brief`

### No hay conexión con la consola

- Verificar `config.yaml` con la IP/puerto correctos
- Comprobar firewall permite conexiones salientes al puerto configurado
- Probar: `curl http://CONSOLA_IP:5000/api/status`

### Error al compilar

- Verificar versión de Python (3.8+)
- Reinstalar dependencias: `pip install -r requirements.txt --force-reinstall`
- Para ARM64: usar Python ARM64 nativo

## Licencia

Cibershield R.L. 2025
