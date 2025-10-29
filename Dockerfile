# Stage 1: install deps
FROM python:3.12-slim AS builder
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# apt deps if needed (curl, build-essential etc)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/miniscanner

# copy only requirements first for cache
COPY requirements.txt /opt/miniscanner/requirements.txt
RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

# Stage 2: runtime image
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /opt/miniscanner

# copy installed packages from builder (not necessary because we pip install again),
# but to keep it simple, we install again with --no-cache-dir
COPY requirements.txt /opt/miniscanner/requirements.txt
RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

# copy project files
COPY . /opt/miniscanner

# default entrypoint: run as CLI (pass args into the container)
ENTRYPOINT ["python", "-m", "src.app"]
# Example default command: nothing (user passes args). You can set CMD to show help:
CMD ["--help"]
