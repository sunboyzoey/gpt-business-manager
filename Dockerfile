FROM node:22-bookworm-slim AS frontend
WORKDIR /src/frontend
COPY frontend/package*.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.13-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    GBM_HOST=0.0.0.0 GBM_PORT=8011 GBM_RUNTIME_DIR=/app/data \
    DRISSION_BROWSER_PATH=/usr/bin/chromium
RUN apt-get update && apt-get install -y --no-install-recommends chromium ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt requirements.lock.txt ./
RUN pip install --no-cache-dir -r requirements.lock.txt
COPY . .
COPY --from=frontend /src/static ./static
RUN mkdir -p /app/data && useradd --system --uid 10001 --home /app gbm \
    && chown -R gbm:gbm /app/data
USER gbm
EXPOSE 8011
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8011/healthz', timeout=3)"
ENTRYPOINT ["sh", "scripts/container-entrypoint.sh"]
