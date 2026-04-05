# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MANTIS is a multi-protocol network honeypot and threat intelligence platform. It deploys 14 realistic decoy services that capture attacker credentials, commands, and payloads in real-time, presented through a live web dashboard with geolocation mapping and alerting. 100% asyncio-based (zero threads per connection), Python 3.10+.

## Commands

### Install dependencies
```bash
pip install -r requirements.txt
```

### Run (interactive mode with service selector)
```bash
python main.py
```

### Run (headless, all defaults)
```bash
python main.py --headless
```

### Run with a profile
```bash
python main.py --headless --config profiles/default.yaml    # all 14 services
python main.py --headless --config profiles/minimal.yaml     # SSH + Docker only
python main.py --headless --config profiles/database_trap.yaml
```

### View stats from database
```bash
python main.py stats
python main.py stats --db /path/to/honeypot.db
```

### Run endpoint tests (requires running instance)
```bash
python test_endpoints.py
python test_endpoints.py --host 10.0.0.5
python test_endpoints.py --skip-services   # dashboard API only
```

There is no lint, format, or unit test configuration in this repo. The only test mechanism is `test_endpoints.py`, which does live integration testing against a running instance.

## Architecture

### Entry Points
- `main.py` -> `honeypot/cli.py:main()` -> `honeypot/core.py:HoneypotOrchestrator.run()`
- `python -m honeypot` via `honeypot/__main__.py`

### Core Components

| Module | Role |
|--------|------|
| `honeypot/cli.py` | Argument parsing, interactive service selector UI, logging setup |
| `honeypot/config.py` | YAML config loading, per-service schemas, banner presets (79 presets across services) |
| `honeypot/core.py` | `HoneypotOrchestrator` — wires all components, manages startup/shutdown lifecycle |
| `honeypot/database.py` | Async SQLite (WAL mode), user auth, event/session/alert CRUD, pub/sub queues for WebSocket broadcast |
| `honeypot/alerts.py` | Alert engine with 50+ detection patterns (Log4Shell, reverse shells, miners, etc.), webhook dispatch |
| `honeypot/geo.py` | IP geolocation via ip-api.com with caching and rate-limiting (45 req/min) |
| `honeypot/models.py` | Dataclasses and enums: `EventType`, `ServiceType`, `AlertSeverity`, `Session`, `Event`, `Alert`, `GeoInfo` |

### Dashboard (`honeypot/dashboard/`)
- `server.py` — aiohttp REST API (40+ endpoints) + WebSocket broadcaster. Auth via session cookie or Bearer token.
- `templates.py` — Single-file SPA (HTML/CSS/JS embedded in Python string). All frontend code lives here.

### Services (`honeypot/services/`)

All 14 services extend `BaseHoneypotService` (defined in `__init__.py`) which provides:
- `start()` — bind to port, accept connections
- `_handle_client(reader, writer)` — protocol interaction loop
- `_create_session()` / `_end_session()` — session lifecycle
- `_log(session, event_type, data)` — persist event, trigger alert engine

Services: SSH (Paramiko), Docker API, FTP, SMB, MySQL, Telnet, SMTP, MongoDB, VNC, Redis, ADB, Elasticsearch, Kubernetes API, MQTT. Each implements its protocol's wire format directly (no external server libraries except Paramiko for SSH).

### Data Flow
```
Attacker -> Service._handle_client()
         -> _log() -> Database.save_event()
                   -> AlertEngine.process_event() -> pattern match -> save_alert()
                   -> WebSocket broadcast to dashboard
         -> GeoLocator.lookup(ip) -> ip-api.com (cached in SQLite)
```

### Configuration
- `mantis_config.yaml` — default runtime config (per-service enable/port/banner/extras, dashboard, alerts, database)
- `profiles/*.yaml` — deployment presets
- Config is also editable at runtime via dashboard REST API (`/api/config/service/{name}`, `/api/config/save`)

### Database
SQLite with tables: `sessions`, `events`, `alerts`, `geo_cache`, `users`. Default credentials: admin/admin.
