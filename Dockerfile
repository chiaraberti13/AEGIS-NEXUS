FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN groupadd -r aegis && useradd -r -g aegis -d /nonexistent -s /usr/sbin/nologin aegis \
    && mkdir -p /data && chown aegis:aegis /data
WORKDIR /app
COPY pyproject.toml requirements.lock ./
COPY src ./src
COPY scripts ./scripts
# Reproducible build: install the hash-locked runtime dependencies first
# (every wheel verified against requirements.lock), then the project itself
# with --no-deps so nothing is resolved unpinned.
RUN pip install --no-cache-dir --require-hashes -r requirements.lock \
    && pip install --no-cache-dir --no-deps .
USER aegis
EXPOSE 8600
CMD ["gunicorn", "--bind", "0.0.0.0:8600", "--workers", "2", "--threads", "4", "--timeout", "30", "--graceful-timeout", "10", "--keep-alive", "2", "--limit-request-line", "2048", "--limit-request-fields", "50", "--limit-request-field_size", "4096", "--max-requests", "2000", "--max-requests-jitter", "200", "aegis_nexus.app:app"]
