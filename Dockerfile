FROM python:3.12-slim AS builder

WORKDIR /opt/sentinel
RUN python -m pip install --no-cache-dir uv==0.6.14

COPY pyproject.toml uv.lock README.md DISCLAIMER.md LICENSE ./
COPY src/ ./src/
RUN uv sync --locked --no-dev --no-editable

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/sentinel/.venv/bin:${PATH}"

RUN useradd --create-home --uid 10001 sentinel \
    && mkdir -p /data \
    && chown sentinel:sentinel /data

COPY --from=builder --chown=10001:10001 /opt/sentinel/.venv /opt/sentinel/.venv

WORKDIR /data
USER 10001:10001

ENTRYPOINT ["sentinel"]
CMD ["--help"]
