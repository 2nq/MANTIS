# Changelog

All notable changes to MANTIS are documented in this file.

## [2.5.0] - 2026-04-05

### Added
- **Health check endpoint** — `GET /api/health` (unauthenticated) returns service status, active connection counts per service, and uptime; useful for external monitoring (Uptime Kuma, Prometheus blackbox)
- **Dark/light theme toggle** — button in the dashboard header switches between dark and light themes; preference persisted in localStorage
- **CSV export across all tabs** — Events, Sessions, and Alerts tabs now have JSON and CSV export buttons; backend `?format=csv` already existed but was only exposed in Database and Attackers tabs
- **Per-service active connection counts** — honeypot status blobs in the overview now show a green badge with the number of currently connected clients

### Changed
- **Login brute-force protection** — `/api/auth` now tracks failed attempts per IP; after 10 failures, the IP is locked out for 5 minutes (429 response with countdown)
- **Session expiry** — dashboard sessions now include a `created_at` timestamp and are automatically evicted after 7 days; hourly cleanup task removes stale entries
- **Path traversal fix** — `POST /api/config/save` now restricts the `path` parameter to a basename (no directory components or dotfiles), preventing writes outside the project directory
- **Query parameter validation** — all `limit`/`offset` query parameters across 5 endpoints now use safe int parsing; invalid values (e.g. `?limit=abc`) return the default instead of a 500 error
- **Graceful shutdown of active connections** — `BaseHoneypotService.stop()` now tracks and cancels all in-flight `_handle_client` tasks for the 10 TCP-based services, preventing connections from hanging after Ctrl-C
- **WebSocket broadcast race fix** — all WebSocket broadcast loops now snapshot the `WeakSet` to a list before iterating, preventing iterator invalidation under concurrent connect/disconnect
- **ThreadPoolExecutor cleanup** — `Database.close()` now calls `shutdown(wait=True)` instead of `wait=False`, ensuring pending DB operations complete before exit

## [2.4.0] - 2026-02-21

### Added
- **Elasticsearch honeypot** (`honeypot/services/elasticsearch.py`, port 9200) — emulates open Elasticsearch cluster with `/_search` (data theft), `/_bulk` (injection), `/_scripts` (RCE), `/_snapshot` (exfil), `/_cat/indices`, `/_nodes`, `/_cluster/health`; returns fake customer/transaction data to keep attackers engaged
- **Kubernetes API honeypot** (`honeypot/services/kubernetes.py`, port 6443) — emulates unauthenticated K8s API server; captures pod creation specs (image, cmd, mounts, env, hostNetwork/hostPID), secret reads (returns honey AWS keys, DB creds, TLS certs), pod exec RCE attempts, namespace/node enumeration
- **MQTT broker honeypot** (`honeypot/services/mqtt.py`, port 1883) — full MQTT v3.1.1 binary protocol; captures CONNECT credentials, SUBSCRIBE topic filters, PUBLISH payloads (C2 commands, malware URLs) with QoS handling and hex fallback for binary data
- **Clickable toast alerts** — all alert toast notifications are now clickable, opening the full alert detail modal; payload/IOC toasts show source IP and service name
- **Event ID drill-down** — event IDs in alert detail modal are clickable links that fetch and display the source event with full payload data
- **`loadEventById()`** — new JS function for direct event lookup from alert drill-down
- **79 banner presets** across all 14 services (expanded from 25), including Elasticsearch (8.x, 7.x, OpenSearch), Kubernetes (1.26–1.28, K3s, MicroK8s), MQTT (Mosquitto, EMQX, HiveMQ, VerneMQ)

### Changed
- Service count increased from 11 to **14** (Elasticsearch, Kubernetes API, MQTT added)
- Clickable toasts stay visible 8 seconds (up from 5) with hover highlight effect
- All generic alert toasts are now clickable (not just payload/IOC)

## [2.3.0] - 2026-02-21

### Changed
- **Replaced HTTP honeypot with Docker API honeypot** — removed HTTP login-page honeypot (port 8080) in favor of a Docker Engine API honeypot on port 2375, emulating unauthenticated Docker daemon v1.41
- Dashboard service filters, color legend, and badges now show "Docker" instead of "HTTP"

### Added
- **Docker API honeypot** (`honeypot/services/docker.py`) — emulates `/_ping`, `/version`, `/info`, `/containers/json`, `/containers/create`, `/containers/{id}/start`, `/images/json`, `/images/create` with realistic JSON responses; captures container creation payloads (image, cmd, entrypoint, mounts, env) as `COMMAND` events; supports versioned API paths (`/v1.41/...`)
- **ADB AUTH_ATTEMPT logging** — ADB honeypot now logs `AUTH_ATTEMPT` events with auth type (TOKEN, SIGNATURE, RSAPUBLICKEY), raw auth data as hex, and data length
- **ADB client banner parsing** — connect events now include structured `banner_parsed` field (type, features list, or key=value pairs)
- **ADB oversized payload warnings** — payloads exceeding size limits (8KB connect, 64KB message loop) now generate `REQUEST` warning events with `data_len` instead of being silently dropped
- **ADB stream IDs in events** — OPEN and WRTE events now include `local_id`/`remote_id` (arg0/arg1) for protocol forensics

### Removed
- **HTTP honeypot** (`honeypot/services/http.py`) — replaced by Docker API honeypot

## [2.2.0] - 2026-02-21

### Added
- **Payload Intel tab** — dedicated analytics dashboard for payload detections and IOC aggregation, visually distinct from other tabs with cyan accent theme
- **Gradient header banner** with shield icon, refresh and export controls
- **6-stat summary row** — Total Payloads, Critical, High, URLs Found, Hashes Found, Unique Attackers with color-coded accent borders
- **3-column chart row** — Pattern Categories donut chart, IOC Types donut chart, Activity Timeline bar chart (last 48h with hover tooltips)
- **Top Patterns ranked list** — numbered circles, severity badges, proportional gradient progress bars
- **Recent IOCs feed** — scrollable list with compact type badges and monospace values
- **Payload Alerts table** — Time, Severity, Service, Source IP, Patterns, IOC count; click opens existing alert detail modal
- **Cross-service payload detection engine** — 33 regex patterns across 7 categories (Downloaders, Reverse Shells, Miners, Persistence, Encoded Payloads, Privilege Escalation, Other)
- **IOC extraction** — automatic extraction of URLs, IPs, domains, MD5/SHA1/SHA256 hashes, and email addresses from event data
- **`PayloadIOCDetector` alert rule** — stateless rule scanning SSH, Telnet, HTTP, MySQL, FTP, Redis, and all other service events
- **`GET /api/payload-stats` endpoint** — aggregated payload statistics (severity counts, pattern frequency, IOC type totals, timeline buckets, top IPs, recent alerts)
- **`idx_alerts_rule_name` index** for efficient payload_ioc alert queries
- **Live WebSocket updates** — Payload Intel tab auto-refreshes on new payload_ioc alerts with toast notification
- **Alert data field** — `data` dict on Alert model for storing structured pattern/IOC metadata

## [2.1.0] - 2026-02-20

### Changed
- **Interactive CLI** — replaced 20+ argparse flags with a single-screen interactive setup combining service selection and port configuration
- **Combined service selector** — custom prompt_toolkit control: `space` toggles services, `→` edits port inline, `a` toggles all, `enter` confirms — all from one screen
- **Cyan/teal theme** — custom `[x]`/`[ ]` checkbox indicators, cyan pointer and highlights, dim instruction text
- **`--headless` flag** for non-interactive/scripted use (systemd, Docker, CI) — runs with all defaults or loads from YAML config
- Removed `--profile`, `--port-*`, `--services`, `--webhook`, and `--auth-token` flags (use interactive prompts or YAML config instead)

### Fixed
- Shutdown crash (`RuntimeError: cannot schedule new futures after shutdown`) when active client sessions existed during Ctrl-C

### Added
- **Expanded Config page** — service-specific advanced settings (hostnames, prompts, credentials, databases, device models), banner preset dropdowns, collapsible sections per service
- **Global Settings panel** — toggle alerts, configure webhook URL/headers, change log level from the dashboard
- **Config persistence** — Save running config to YAML and export/download from the dashboard toolbar
- **New API endpoints** — `GET /api/config/full`, `PUT /api/config/global`, `POST /api/config/save`, `GET /api/config/export`
- **Mantis logo** — replaced stick-figure with detailed SVG mantis (compound eyes, raptorial forelegs, segmented abdomen, translucent wings)
- `questionary>=2.0` dependency

## [2.0.0] - 2026-02-20

### Added
- **11 honeypot services**: SSH, HTTP, FTP, SMB, MySQL, Telnet, SMTP, MongoDB, VNC, Redis, ADB with full wire-protocol emulation
- **Real-time dashboard** with WebSocket live feed, filterable event log, session tracking, and alert management
- **Attack origin map** with IP geolocation via ip-api.com
- **IP blocking / firewall** — click any IP in the dashboard to block via iptables; dedicated Firewall tab for managing blocked IPs
- **Dashboard authentication** — `--auth-token` flag protects the dashboard with token-based auth (cookie, Bearer header, WebSocket query param) and a styled login page
- **Automated alerts** with severity levels (Critical / High / Medium) for reconnaissance, credential harvesting, SQL injection, and shell commands
- **Profile system** — YAML configs for minimal, database-trap, and full deployments
- **SQLite storage** with full-text search, pagination, JSON export, and database reset
- **Endpoint test suite** (`test_endpoints.py`) — probes all 11 services and validates every dashboard API endpoint with auth token support
- **CLI interface** with per-service port overrides, service selection, webhook alerts, verbose/quiet modes
- **GitHub badges** for Python, MIT License, AI Assisted, Honeypot, asyncio, and Linux
