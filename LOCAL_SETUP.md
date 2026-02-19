# Fluxer — Local Test System Setup

Guide for setting up a complete local development environment with Docker Compose.

---

## Prerequisites

| Tool | Min. Version | Notes |
|------|-------------|-------|
| **Docker** | 24+ | Including Docker Compose v2 (`docker compose`) |
| **Node.js** | 24 LTS | Only needed for local scripts; containers bring their own runtime |
| **pnpm** | 10.x | Automatically activated in containers via Corepack |
| **just** | 1.x | Task runner, optional but recommended (`cargo install just` or `brew install just`) |
| **Rust** | nightly | Only for `fluxer_metrics` and Cassandra migration tool |
| **Erlang/OTP** | 28 | Only if building the gateway locally (outside Docker) |

**Recommended resources:** At least 8 GB of free RAM for all containers.

---

## 1. Clone the Repository

```bash
git clone <repository-url> FluxerCentralized
cd FluxerCentralized
```

---

## 2. Set Up the Environment File

```bash
cp dev/.env.example dev/.env
```

The `.env.example` already contains working defaults for local development. The following values may need to be adjusted:

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql://postgres:postgres@postgres:5432/fluxer` | PostgreSQL connection |
| `REDIS_URL` | `redis://redis:6379` | Valkey/Redis connection |
| `CASSANDRA_HOSTS` | `cassandra` | ScyllaDB host |
| `MEILISEARCH_API_KEY` | `masterKey` | Meilisearch master key |
| `AWS_S3_ENDPOINT` | `http://minio:9000` | Local MinIO S3 endpoint |
| `SSO_ENABLED` | `false` | Enable SSO (see section 7) |

> **Note:** All hostnames (`postgres`, `redis`, `cassandra`, etc.) refer to Docker service names within the shared `fluxer-shared` network.

---

## 3. Create the Docker Network

All services share an external Docker network:

```bash
docker network create fluxer-shared
```

Or via `just`:

```bash
just ensure-network
```

---

## 4. Start Services

### Option A: Using `just` (recommended)

```bash
# Initial setup (creates .env, network, LiveKit config)
just setup

# Start database services
just up postgres redis cassandra meilisearch minio minio-setup

# Run Cassandra migrations (requires pre-built migration tool)
just mig-up cassandra cassandra cassandra

# Start all application services
just up api worker media gateway caddy
```

### Option B: Directly with Docker Compose

```bash
# Database services
docker compose --env-file dev/.env -f dev/compose.yaml up -d \
  postgres redis cassandra meilisearch minio minio-setup

# Wait for Cassandra to become healthy (~90s)
docker compose --env-file dev/.env -f dev/compose.yaml ps

# Application services
docker compose --env-file dev/.env -f dev/compose.yaml up -d \
  api worker media gateway caddy
```

---

## 5. Service Overview

All services are accessible through the **Caddy reverse proxy** on port `8088`:

| Service | Internal Port | URL (via Caddy) | Technology |
|---------|--------------|-----------------|------------|
| **Caddy** (Reverse Proxy) | 8088 | `http://localhost:8088` | Caddy 2 |
| **API** | 8080 | `http://localhost:8088/api/` | Node.js / Hono |
| **Worker** | — | — (Background) | Node.js |
| **Gateway** (WebSocket) | 8080 | `ws://localhost:8088/gateway/` | Erlang/OTP |
| **Media Proxy** | 8080 | `http://localhost:8088/media/` | Node.js |
| **Admin Panel** | 8080 | `http://localhost:8088/admin/` | Gleam |
| **Marketing** | 8080 | `http://localhost:8088/marketing/` | Gleam |
| **SSO Server** | 8090 | `http://localhost:8088/sso/` | Node.js / Hono |
| **Metrics** | 8080 | `http://localhost:8088/metrics/` | Rust |
| **Docs** | 3000 | — | Next.js |

### Database Services (not exposed via Caddy)

| Service | Port | Credentials |
|---------|------|-------------|
| **PostgreSQL** | 5432 (internal) | `postgres` / `postgres` / DB: `fluxer` |
| **ScyllaDB** (Cassandra) | 9042 | `cassandra` / `cassandra` |
| **Valkey** (Redis) | 6379 (internal) | No password |
| **MinIO** (S3) | 9000/9001 (internal) | `minioadmin` / `minioadmin` |
| **MeiliSearch** | 7700 (internal) | Key: `masterKey` |
| **ClamAV** | 3310 (internal) | — |
| **ClickHouse** | 8123/9000 | `fluxer` / `fluxer_dev` (profile `clickhouse`) |

---

## 6. Cassandra Migrations

The migration tool must be compiled once:

```bash
# Build migration tool
cargo build --release --manifest-path scripts/cassandra-migrate/Cargo.toml

# Run migrations (against local Cassandra)
just mig-up

# Or directly via Docker:
docker compose --env-file dev/.env -f dev/compose.yaml up cassandra-migrate
```

Create a new migration:

```bash
just mig "add_some_table"
```

---

## 7. Enable SSO (Optional)

For cross-instance session management:

### 7.1 Generate JWT Keys

```bash
cd fluxer_sso
pnpm install
pnpm generate-keys
```

### 7.2 Add Keys to `dev/.env`

```dotenv
SSO_ENABLED=true
SSO_JWT_PRIVATE_KEY=<generated private key>
SSO_JWT_PUBLIC_KEY=<generated public key>
SSO_SERVICE_SECRET=dev-sso-secret-change-in-production
```

### 7.3 Start the SSO Server

```bash
just up sso
# or
docker compose --env-file dev/.env -f dev/compose.yaml up -d sso
```

---

## 8. Multi-Instance Test (SSO with 3 API Instances)

A dedicated Compose file exists for testing with multiple API instances:

```bash
docker compose --env-file dev/.env \
  -f dev/compose.yaml \
  -f dev/compose.local-test.yaml \
  up -d sso api-1 api-2 api-3 postgres redis cassandra meilisearch minio minio-setup caddy
```

This starts 3 API instances (`fluxer-1`, `fluxer-2`, `fluxer-3`) on ports 8080, 8081, 8082 — all connected via the SSO server for global session management.

---

## 9. Optional Services

### ClickHouse (Metrics Persistence)

```bash
docker compose --env-file dev/.env -f dev/compose.yaml --profile clickhouse up -d clickhouse metrics-clickhouse
```

### LiveKit (Voice/Video)

```bash
# Generate LiveKit config
just livekit-sync

# Start LiveKit
just up livekit
```

Ports: `7880` (HTTP), `7882/udp`, `7999/udp`

### ClamAV (Virus Scanner)

```bash
just up clamav
```

Enable in `dev/.env`:

```dotenv
CLAMAV_ENABLED=true
```

> **Note:** ClamAV requires ~5 minutes for the initial start (signature download).

### Docs (Documentation)

```bash
just up docs
```

---

## 10. Useful Commands

```bash
# Follow logs
just logs api worker gateway

# Enter a container shell
just sh api bash

# Stop all services
just down

# Stop all services and delete volumes (data loss!)
just nuke

# Check status of all containers
just ps

# Restart a service
just restart api

# Watch mode (automatic rebuild on code changes)
just watch admin marketing
```

---

## 11. Architecture Diagram

```
                          ┌──────────────────────┐
                          │   Caddy (Port 8088)   │
                          └──────────┬─────────────┘
         ┌───────────┬───────────┬───┴───┬──────────┬──────────┐
         │           │           │       │          │          │
    ┌────▼───┐ ┌─────▼──┐ ┌─────▼─┐ ┌───▼──┐ ┌────▼───┐ ┌───▼──┐
    │  API   │ │ Media  │ │Gateway│ │ SSO  │ │ Admin  │ │Metrics│
    │ :8080  │ │ Proxy  │ │  WS   │ │:8090 │ │ :8080  │ │ :8080 │
    └───┬────┘ │ :8080  │ │ :8080 │ └──┬───┘ └────────┘ └───────┘
        │      └────────┘ └───────┘    │
        │                              │
   ┌────▼──────────────────────────────▼────┐
   │          Shared Data Layer             │
   │  PostgreSQL │ ScyllaDB │ Valkey/Redis  │
   │  MinIO (S3) │ MeiliSearch │ ClickHouse │
   └────────────────────────────────────────┘
```

---

## 12. Troubleshooting

| Problem | Solution |
|---------|----------|
| `network fluxer-shared not found` | `docker network create fluxer-shared` or `just ensure-network` |
| Cassandra won't start | Needs ~90s to become healthy. Check: `docker compose ... ps` |
| API can't reach DB | Verify PostgreSQL is running: `just logs postgres` |
| `pnpm: not found` in container | Corepack must be enabled — happens automatically via `command` |
| MinIO buckets missing | Start `minio-setup` service: `just up minio minio-setup` |
| Port 8088 already in use | Configure a different port in `dev/Caddyfile.dev` and `dev/.env` |
| ClamAV healthcheck failed | Initial start takes ~5 min (signatures). Wait or set `CLAMAV_ENABLED=false` |
| SSO tokens invalid | Regenerate JWT keys with `pnpm generate-keys` and update `.env` |
