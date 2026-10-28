# syntax=docker/dockerfile:1
# Runner image for the stress-test corpus (see stress.py).
# Build context: the repository root, filtered by Dockerfile.dockerignore.
#
# The image carries licenseal's locked runtime dependencies, tethered (the
# `egress` group, which harness.py runs every scan under), and an editable
# install rooted at /src/src. At run time the working tree's src/ is mounted
# read-only over /src/src, so scans exercise the current code without a
# rebuild. Rebuild only when pyproject.toml or uv.lock changes.
FROM ghcr.io/astral-sh/uv:0.13.5-python3.14-trixie-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_LINK_MODE=copy \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GIT_LFS_SKIP_SMUDGE=1 \
    GIT_TERMINAL_PROMPT=0

WORKDIR /src
COPY pyproject.toml uv.lock PYPI.md LICENSE NOTICE ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --group egress --no-install-project
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --group egress

ENV PATH=/opt/venv/bin:$PATH

# Unprivileged user; /corpus is the named volume, /out the host output dir.
RUN useradd --create-home --uid 1000 scan \
    && mkdir /corpus /out /work \
    && chown scan:scan /corpus /out /work
USER scan
WORKDIR /work
ENTRYPOINT []
CMD ["licenseal", "--version"]
