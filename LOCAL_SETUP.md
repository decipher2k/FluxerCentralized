# Fluxer — Lokales Testsystem aufsetzen

Anleitung zum Einrichten einer vollständigen lokalen Entwicklungsumgebung mit Docker Compose.

---

## Voraussetzungen

| Tool | Min. Version | Hinweis |
|------|-------------|---------|
| **Docker** | 24+ | inkl. Docker Compose v2 (`docker compose`) |
| **Node.js** | 24 LTS | Nur für lokale Skripte nötig; Container bringen eigene Runtime mit |
| **pnpm** | 10.x | Wird in Containern automatisch via Corepack aktiviert |
| **just** | 1.x | Task-Runner, optional aber empfohlen (`cargo install just` oder `brew install just`) |
| **Rust** | nightly | Nur für `fluxer_metrics` und Cassandra-Migration-Tool |
| **Erlang/OTP** | 28 | Nur wenn Gateway lokal (außerhalb Docker) gebaut wird |

**Empfohlene Ressourcen:** Mindestens 8 GB RAM frei für alle Container.

---

## 1. Repository klonen

```bash
git clone <repository-url> FluxerCentralized
cd FluxerCentralized
```

---

## 2. Environment-Datei einrichten

```bash
cp dev/.env.example dev/.env
```

Die `.env.example` enthält bereits funktionsfähige Defaults für lokale Entwicklung. Folgende Werte müssen ggf. angepasst werden:

| Variable | Standard | Beschreibung |
|----------|----------|-------------|
| `DATABASE_URL` | `postgresql://postgres:postgres@postgres:5432/fluxer` | PostgreSQL-Verbindung |
| `REDIS_URL` | `redis://redis:6379` | Valkey/Redis-Verbindung |
| `CASSANDRA_HOSTS` | `cassandra` | ScyllaDB-Host |
| `MEILISEARCH_API_KEY` | `masterKey` | Meilisearch Master-Key |
| `AWS_S3_ENDPOINT` | `http://minio:9000` | Lokaler MinIO S3-Endpoint |
| `SSO_ENABLED` | `false` | SSO aktivieren (siehe Abschnitt 7) |

> **Hinweis:** Alle Hostnamen (`postgres`, `redis`, `cassandra`, etc.) verweisen auf Docker-Service-Namen im gemeinsamen Netzwerk `fluxer-shared`.

---

## 3. Docker-Netzwerk erstellen

Alle Services teilen sich ein externes Docker-Netzwerk:

```bash
docker network create fluxer-shared
```

Oder via `just`:

```bash
just ensure-network
```

---

## 4. Services starten

### Variante A: Mit `just` (empfohlen)

```bash
# Ersteinrichtung (erstellt .env, Netzwerk, LiveKit-Config)
just setup

# Datenbank-Services starten
just up postgres redis cassandra meilisearch minio minio-setup

# Cassandra-Migration ausführen (benötigt vorher gebautes Migration-Tool)
just mig-up cassandra cassandra cassandra

# Alle Anwendungs-Services starten
just up api worker media gateway caddy
```

### Variante B: Direkt mit Docker Compose

```bash
# Datenbank-Services
docker compose --env-file dev/.env -f dev/compose.yaml up -d \
  postgres redis cassandra meilisearch minio minio-setup

# Warten bis Cassandra gesund ist (~90s)
docker compose --env-file dev/.env -f dev/compose.yaml ps

# Anwendungs-Services
docker compose --env-file dev/.env -f dev/compose.yaml up -d \
  api worker media gateway caddy
```

---

## 5. Service-Übersicht

Alle Services sind über den **Caddy Reverse Proxy** auf Port `8088` erreichbar:

| Service | Interner Port | URL (via Caddy) | Technologie |
|---------|--------------|-----------------|-------------|
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

### Datenbank-Services (nicht über Caddy exponiert)

| Service | Port | Zugangsdaten |
|---------|------|-------------|
| **PostgreSQL** | 5432 (intern) | `postgres` / `postgres` / DB: `fluxer` |
| **ScyllaDB** (Cassandra) | 9042 | `cassandra` / `cassandra` |
| **Valkey** (Redis) | 6379 (intern) | Kein Passwort |
| **MinIO** (S3) | 9000/9001 (intern) | `minioadmin` / `minioadmin` |
| **MeiliSearch** | 7700 (intern) | Key: `masterKey` |
| **ClamAV** | 3310 (intern) | — |
| **ClickHouse** | 8123/9000 | `fluxer` / `fluxer_dev` (Profil `clickhouse`) |

---

## 6. Cassandra-Migrationen

Das Migrations-Tool muss einmalig kompiliert werden:

```bash
# Migrations-Tool bauen
cargo build --release --manifest-path scripts/cassandra-migrate/Cargo.toml

# Migrationen ausführen (gegen lokale Cassandra)
just mig-up

# Oder direkt via Docker:
docker compose --env-file dev/.env -f dev/compose.yaml up cassandra-migrate
```

Neue Migration erstellen:

```bash
just mig "add_some_table"
```

---

## 7. SSO aktivieren (optional)

Für Cross-Instance-Session-Management:

### 7.1 JWT-Keys generieren

```bash
cd fluxer_sso
pnpm install
pnpm generate-keys
```

### 7.2 Keys in `dev/.env` eintragen

```dotenv
SSO_ENABLED=true
SSO_JWT_PRIVATE_KEY=<generierter Private Key>
SSO_JWT_PUBLIC_KEY=<generierter Public Key>
SSO_SERVICE_SECRET=dev-sso-secret-change-in-production
```

### 7.3 SSO-Server starten

```bash
just up sso
# oder
docker compose --env-file dev/.env -f dev/compose.yaml up -d sso
```

---

## 8. Multi-Instance-Test (SSO mit 3 API-Instanzen)

Für Tests mit mehreren API-Instanzen existiert eine spezielle Compose-Datei:

```bash
docker compose --env-file dev/.env \
  -f dev/compose.yaml \
  -f dev/compose.local-test.yaml \
  up -d sso api-1 api-2 api-3 postgres redis cassandra meilisearch minio minio-setup caddy
```

Dies startet 3 API-Instanzen (`fluxer-1`, `fluxer-2`, `fluxer-3`) auf den Ports 8080, 8081, 8082 — alle über den SSO-Server für globale Session-Verwaltung verbunden.

---

## 9. Optionale Services

### ClickHouse (Metriken-Persistierung)

```bash
docker compose --env-file dev/.env -f dev/compose.yaml --profile clickhouse up -d clickhouse metrics-clickhouse
```

### LiveKit (Voice/Video)

```bash
# LiveKit-Config generieren
just livekit-sync

# LiveKit starten
just up livekit
```

Ports: `7880` (HTTP), `7882/udp`, `7999/udp`

### ClamAV (Virenscanner)

```bash
just up clamav
```

In `dev/.env` aktivieren:

```dotenv
CLAMAV_ENABLED=true
```

> **Hinweis:** ClamAV benötigt ~5 Minuten für den ersten Start (Signaturen-Download).

### Docs (Dokumentation)

```bash
just up docs
```

---

## 10. Nützliche Befehle

```bash
# Logs verfolgen
just logs api worker gateway

# In Container-Shell einsteigen
just sh api bash

# Alle Services stoppen
just down

# Alle Services + Volumes löschen (Datenverlust!)
just nuke

# Status aller Container
just ps

# Service neustarten
just restart api

# Watch-Mode (automatischer Rebuild bei Code-Änderungen)
just watch admin marketing
```

---

## 11. Architektur-Diagramm

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

| Problem | Lösung |
|---------|--------|
| `network fluxer-shared not found` | `docker network create fluxer-shared` oder `just ensure-network` |
| Cassandra startet nicht | Braucht ~90s bis Healthy. Check: `docker compose ... ps` |
| API kann DB nicht erreichen | Prüfen ob PostgreSQL läuft: `just logs postgres` |
| `pnpm: not found` im Container | Corepack muss aktiviert sein — passiert automatisch via `command` |
| MinIO-Buckets fehlen | `minio-setup` Service starten: `just up minio minio-setup` |
| Port 8088 bereits belegt | Anderen Port in `dev/Caddyfile.dev` und `dev/.env` konfigurieren |
| ClamAV Healthcheck failed | Erster Start dauert ~5 Min (Signaturen). Warten oder `CLAMAV_ENABLED=false` |
| SSO-Tokens ungültig | JWT-Keys mit `pnpm generate-keys` neu generieren und in `.env` eintragen |
