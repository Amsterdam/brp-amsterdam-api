FROM python:3.14-slim-trixie AS builder
MAINTAINER datapunt@amsterdam.nl

WORKDIR /app

COPY --from=ghcr.io/astral-sh/uv:0.13.7 /uv /uvx /bin/

RUN apt-get update && apt-get install --no-install-recommends -y \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml uv.lock ./

ENV CC=/usr/bin/gcc \
    UV_PROJECT_ENVIRONMENT=/app/.venv

RUN uv sync --frozen --no-install-project --all-groups

# Start runtime image,
FROM python:3.14-slim-trixie
RUN useradd -U -r brpamsterdamapi
RUN apt-get update && apt-get install --no-install-recommends -y \
    curl \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Copy python build artifacts from builder image
COPY --from=builder /app/.venv /app/.venv

COPY src/ /app/src/
COPY pyproject.toml uv.lock /app/

WORKDIR /app


COPY src/config/ca/* /usr/local/share/ca-certificates/

# Have some defaults so the container is easier to start
ENV VIRTUAL_ENV=/app/.venv \
    PATH="/app/.venv/bin:$PATH" \
    PYTHONPATH="/app/src" \
    DJANGO_SETTINGS_MODULE=brp_amsterdam_api.settings \
    DJANGO_DEBUG=false \
    UWSGI_HTTP_SOCKET=:8000 \
    UWSGI_MODULE=brp_amsterdam_api.wsgi \
    UWSGI_CALLABLE=application \
    UWSGI_MASTER=1 \
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt

RUN /app/.venv/bin/python src/manage.py collectstatic --noinput \
 && update-ca-certificates --verbose

EXPOSE 8000
USER brpamsterdamapi
CMD ["uwsgi"]
