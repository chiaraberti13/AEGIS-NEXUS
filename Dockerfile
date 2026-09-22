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
CMD ["gunicorn", "--bind", "0.0.0.0:8600", "--workers", "2", "--threads", "4", "--timeout", "30", "aegis_nexus.app:app"]
