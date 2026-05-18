FROM python:3.11-slim AS builder

WORKDIR /build
COPY pyproject.toml .
COPY src/ src/

RUN pip install --no-cache-dir --prefix=/install ".[all]"

# --- Runtime stage ---
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        tini curl && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 1001 sentinelforge && \
    useradd --uid 1001 --gid sentinelforge --shell /usr/sbin/nologin --create-home sentinelforge

WORKDIR /app

COPY --from=builder /install /usr/local
COPY --from=builder /build/src /app/src
COPY --from=builder /build/pyproject.toml /app/
COPY configs/ configs/

RUN mkdir -p /app/data /app/logs /var/lib/sentinelforge /var/log/sentinelforge && \
    chown -R sentinelforge:sentinelforge /var/lib/sentinelforge /var/log/sentinelforge /app

ENV PYTHONPATH=/app/src
ENV PYTHONUNBUFFERED=1

USER sentinelforge

EXPOSE 8000 8501

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

ENTRYPOINT ["tini", "--"]
CMD ["python", "-m", "sentinelforge.cli", "serve"]
