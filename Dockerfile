# DjangoSentinel container image
# Two build targets share one base:
#   production  - small image that runs the `sentinel` command (default)
#   development - editable install + test tools, for working on DjangoSentinel itself
#
#   docker build -t django-sentinel .                         # production
#   docker build --target development -t django-sentinel:dev .

FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# git is needed for diff-based scanning (--diff / --staged / --base)
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/sentinel
COPY pyproject.toml README.md LICENSE ./
COPY djangosentinel ./djangosentinel


# ── production ───────────────────────────────────────────────────────────────
FROM base AS production

RUN pip install . \
    && useradd --create-home --uid 1000 sentinel

USER sentinel

# The project to scan is mounted at /src (see docker-compose.yml)
WORKDIR /src
# Git refuses to read repositories owned by another user unless told otherwise
RUN git config --global --add safe.directory /src

ENTRYPOINT ["sentinel"]
CMD ["scan", "."]


# ── development ──────────────────────────────────────────────────────────────
FROM base AS development

COPY tests ./tests
RUN pip install -e ".[dev]"

WORKDIR /opt/sentinel
CMD ["python", "-m", "pytest", "-q"]
