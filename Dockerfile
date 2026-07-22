FROM node:22-bookworm-slim AS frontend-builder
WORKDIR /src/frontend

COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --fund=false

COPY frontend/ ./
RUN npm run build

FROM rust:1.94.1-bookworm AS backend-builder
WORKDIR /src

RUN apt-get update \
    && apt-get install -y --no-install-recommends libsqlite3-dev libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY backend/ backend/
COPY --from=frontend-builder /src/frontend/dist frontend/dist

# The frontend is already built in the preceding stage and embedded by build.rs.
ENV SSO_SKIP_FRONTEND_BUILD=1
RUN cargo build --release --locked --package sso-backend

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl libsqlite3-0 libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system signet \
    && useradd --system --gid signet --create-home --home-dir /app signet

WORKDIR /app
COPY --from=backend-builder /src/target/release/sso-backend /usr/local/bin/signet
COPY config/default.toml /app/config/default.toml

# The development configuration binds loopback only; a container must accept
# connections forwarded from its published port.
RUN sed -i 's/host = "127.0.0.1"/host = "0.0.0.0"/' /app/config/default.toml \
    && mkdir -p /app/data \
    && chown -R signet:signet /app

ENV SSO_CONFIG=/app/config/default.toml
EXPOSE 8080
VOLUME ["/app/data"]

USER signet
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl --fail --silent --show-error http://127.0.0.1:8080/api/health/live || exit 1

ENTRYPOINT ["/usr/local/bin/signet"]
