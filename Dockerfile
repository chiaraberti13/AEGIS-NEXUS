FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN groupadd -r aegis && useradd -r -g aegis -d /nonexistent -s /usr/sbin/nologin aegis \
    && mkdir -p /data && chown aegis:aegis /data
WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
COPY scripts ./scripts
RUN pip install --no-cache-dir .
USER aegis
EXPOSE 8600
CMD ["gunicorn", "--bind", "0.0.0.0:8600", "--workers", "2", "--threads", "4", "--timeout", "30", "--graceful-timeout", "10", "--keep-alive", "2", "--limit-request-line", "2048", "--limit-request-fields", "50", "--limit-request-field_size", "4096", "--max-requests", "2000", "--max-requests-jitter", "200", "aegis_nexus.app:app"]
