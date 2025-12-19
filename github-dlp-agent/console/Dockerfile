# DLP Console - Cibershield R.L.
# Imagen Docker para la consola centralizada

FROM python:3.11-slim

LABEL maintainer="Cibershield R.L."
LABEL version="0.9"
LABEL description="DLP Console - Dashboard centralizado para monitoreo de agentes"

# Variables de entorno
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Directorio de trabajo
WORKDIR /app

# Instalar dependencias del sistema
RUN apt-get update && apt-get install -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Copiar requirements y instalar dependencias Python
COPY requirements-console.txt .
RUN pip install --no-cache-dir -r requirements-console.txt

# Copiar código de la consola
COPY dlp_console.py .
COPY github_integration.py .
COPY github_webhook.py .
COPY auth.py .

# Crear directorio para datos
RUN mkdir -p /app/data

# Exponer puertos
# 8080 - Dashboard web
# 5555 - TCP receiver para agentes
EXPOSE 8080 5555

# Usuario no-root para seguridad
RUN useradd -m -u 1000 dlpconsole
RUN chown -R dlpconsole:dlpconsole /app
USER dlpconsole

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import socket; s=socket.socket(); s.connect(('localhost', 8080)); s.close()" || exit 1

# Comando de inicio
CMD ["python", "dlp_console.py"]
