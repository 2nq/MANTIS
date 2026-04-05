<div align="center">

# MANTIS

### Multi-Protocol Network Honeypot & Threat Intelligence Platform

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)](LICENSE)
[![Services](https://img.shields.io/badge/Honeypots-14_Services-f59e0b?style=for-the-badge)](README.md#supported-services)
[![Async](https://img.shields.io/badge/100%25-asyncio-06b6d4?style=for-the-badge&logo=python&logoColor=white)](README.md#architecture)
[![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)](README.md)

Deploy 14 realistic decoy services that mimic production systems. Capture attacker credentials, commands, and payloads in real time. Analyze everything through a live dashboard with geolocation mapping, automated threat detection, and one-click IP blocking.

Built entirely in Python — zero threads, pure asyncio concurrency.

<br>

<img src="https://github.com/user-attachments/assets/b7af8ffd-e6e6-4ff1-a389-fff02ba12a42" alt="MANTIS Dashboard" width="100%">

</div>

<br>

## Highlights

<table>
<tr>
<td width="50%">

**14 Protocol-Level Honeypots**
SSH, Docker API, FTP, SMB, MySQL, Telnet, SMTP, MongoDB, VNC, Redis, ADB, Elasticsearch, Kubernetes API, MQTT — each implementing its wire protocol from scratch (no external server daemons).

</td>
<td width="50%">

**Real-Time Web Dashboard**
Live WebSocket event stream, filterable logs, session tracking, severity-based alerts, and interactive attack origin map — all in a single-page app served on port 8843.

</td>
</tr>
<tr>
<td width="50%">

**Automated Threat Detection**
50+ pattern rules detect Log4Shell, reverse shells, cryptominers, credential harvesting, SQL injection, privilege escalation, and encoded payloads with IOC extraction (URLs, hashes, IPs).

</td>
<td width="50%">

**One-Click Firewall**
Block attacker IPs via iptables directly from the dashboard. Click any IP in the event log to block it, or manage rules from the dedicated Firewall tab.

</td>
</tr>
</table>

---

## Quick Start

```bash
git clone https://github.com/Syn2Much/MANTIS.git && cd MANTIS
pip install -r requirements.txt
python main.py
```

This launches an interactive setup where you toggle services and configure ports:

```
? Select services & configure ports (space = toggle, → = set port, enter = confirm)
  ❯ [x] SSH       :2222
    [x] DOCKER    :2375
    [x] FTP       :21
    [ ] SMB       :4450
    [x] MYSQL     :3306
    [x] TELNET    :2323
    [x] SMTP      :25
    [x] MONGODB   :27017
    [x] VNC       :5900
    [x] REDIS     :6379
    [x] ADB       :5555
    [x] ELASTIC   :9200
    [x] K8S       :6443
    [x] MQTT      :1883
    ────────────────────────────
    [x] DASHBOARD :8843
```

| Key | Action |
|-----|--------|
| **Space** | Toggle service on/off |
| **→** | Edit port inline |
| **a** | Toggle all |
| **Enter** | Confirm and start |

Dashboard opens at **http://localhost:8843** — default login is `admin` / `admin`.

### Headless Mode

For scripted deployments, systemd, or Docker — skip all prompts:

```bash
python main.py --headless                                # all defaults
python main.py --headless --config profiles/default.yaml # from YAML profile
```

### CLI Options

```
python main.py [options]

  --headless           Non-interactive mode (all defaults)
  -c, --config FILE    YAML config file path
  --db PATH            Database file path
  -v, --verbose        Debug logging
  -q, --quiet          Errors only
  --version            Show version

python main.py stats               # view capture statistics
python main.py stats --db FILE     # from specific database
```

---

## Supported Services

| Service | Port | What It Captures |
|:--------|:-----|:-----------------|
| **SSH** | 2222 | Credentials, shell commands, interactive session replay (Paramiko) |
| **Docker** | 2375 | Container create/start payloads, image pulls, version/info probes (Engine API v1.41) |
| **FTP** | 21 | USER/PASS, directory traversal, file transfer attempts (RFC 959) |
| **SMB** | 4450 | SMB1/SMB2 negotiate, NTLM authentication hashes |
| **MySQL** | 3306 | Login credentials, SQL queries (v10 handshake protocol) |
| **Telnet** | 2323 | Login prompts, interactive commands, shell session history |
| **SMTP** | 25 | AUTH LOGIN/PLAIN credentials, MAIL FROM/RCPT TO/DATA (RFC 5321) |
| **MongoDB** | 27017 | SASL auth, isMaster, listDatabases (OP_QUERY + OP_MSG wire protocol) |
| **VNC** | 5900 | DES challenge/response auth capture (RFB 3.8) |
| **Redis** | 6379 | AUTH passwords, INFO/KEYS recon, CONFIG SET/SLAVEOF abuse (RESP protocol) |
| **ADB** | 5555 | Shell commands, auth tokens/keys, device enumeration (binary protocol) |
| **Elasticsearch** | 9200 | `_search` data theft, `_bulk` injection, `_scripts` RCE, `_snapshot` exfil attempts |
| **Kubernetes** | 6443 | Pod creation specs, secret reads (honey AWS keys), exec RCE, namespace enumeration |
| **MQTT** | 1883 | CONNECT credentials, SUBSCRIBE topics, PUBLISH payloads with QoS (v3.1.1) |

Every service emulates its protocol at the wire level with realistic responses to keep attackers engaged.

---

## Dashboard

<details>
<summary><b>Events</b> — Filterable log with clickable IPs across all 14 services</summary>
<br>
<img src="screenshots/02_events.png" alt="Events" width="100%">
</details>

<details>
<summary><b>Sessions</b> — All connections with color-coded service badges</summary>
<br>
<img src="screenshots/03_sessions.png" alt="Sessions" width="100%">
</details>

<details>
<summary><b>Alerts</b> — Severity-based threat alerts with acknowledgment and drill-down</summary>
<br>
<img src="screenshots/04_alerts.png" alt="Alerts" width="100%">
</details>

<details>
<summary><b>Database</b> — Advanced search with filters, date range, and JSON export</summary>
<br>
<img src="screenshots/05_database.png" alt="Database" width="100%">
</details>

<details>
<summary><b>Attack Map</b> — Geolocation of attack origins via ip-api.com</summary>
<br>
<img src="screenshots/06_map.png" alt="Map" width="100%">
</details>

<details>
<summary><b>Config</b> — Per-service settings, 79 banner presets, global config, save/export</summary>
<br>
<img src="screenshots/07_config.png" alt="Config" width="100%">
</details>

<details>
<summary><b>Firewall</b> — Block/unblock attacker IPs via iptables</summary>
<br>
<img src="screenshots/09_firewall.png" alt="Firewall" width="100%">
</details>

---

## Deployment Profiles

Profiles are YAML files that control which services run and on which ports.

| Profile | Services | Use Case |
|:--------|:---------|:---------|
| **`profiles/default.yaml`** | All 14 | Full deployment, maximum coverage |
| **`profiles/minimal.yaml`** | SSH + Docker | Lightweight, low-resource environments |
| **`profiles/database_trap.yaml`** | MySQL, MongoDB, Redis, FTP, SMB | Database-focused threat capture |

```bash
python main.py --headless --config profiles/minimal.yaml
```

Create your own by copying any profile and editing the YAML — each service has `enabled`, `port`, `banner`, and protocol-specific extras (hostnames, credentials, databases).

---

## API Reference

All endpoints require authentication (cookie, `Authorization: Bearer <token>`, or WebSocket `?token=`).

| Endpoint | Method | Description |
|:---------|:-------|:------------|
| `/api/auth` | POST | Login with username/password |
| `/api/stats` | GET | Aggregate statistics |
| `/api/events` | GET | Events (filterable: `service`, `type`, `ip`, `limit`) |
| `/api/sessions` | GET | Sessions (filterable: `service`, `ip`, `limit`) |
| `/api/sessions/<id>/events` | GET | Events for a specific session |
| `/api/alerts` | GET | Alerts (filterable: severity, status) |
| `/api/alerts/<id>/ack` | POST | Acknowledge an alert |
| `/api/geo/<ip>` | GET | GeoIP lookup |
| `/api/map` | GET | Map coordinates for all source IPs |
| `/api/attackers` | GET | Unique attacker IPs with event counts |
| `/api/ips` | GET | All unique source IPs |
| `/api/payload-stats` | GET | Payload detection analytics and IOC summary |
| `/api/firewall/blocked` | GET | Currently blocked IPs |
| `/api/firewall/block` | POST | Block IP via iptables `{"ip": "x.x.x.x"}` |
| `/api/firewall/unblock` | POST | Unblock IP `{"ip": "x.x.x.x"}` |
| `/api/config` | GET | Running service configuration |
| `/api/config/full` | GET | Config + schemas + banner presets |
| `/api/config/service/<name>` | PUT | Update a service's configuration |
| `/api/config/global` | PUT | Update global settings |
| `/api/config/save` | POST | Persist running config to YAML |
| `/api/config/export` | GET | Download config as YAML file |
| `/api/export` | GET | Full JSON export (events, sessions, alerts) |
| `/api/database/reset` | POST | Clear all captured data |
| `/ws` | WebSocket | Real-time event and alert stream |

---

## Testing

The included endpoint tester probes all 14 services and validates every API endpoint:

```bash
python test_endpoints.py                     # localhost defaults
python test_endpoints.py --host 10.0.0.5     # remote host
python test_endpoints.py --skip-services     # dashboard API only
```

```
MANTIS Endpoint Tester
Target: 127.0.0.1

============================================================
  Honeypot Service Probes
============================================================
  [PASS] SSH        banner: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
  [PASS] Docker     /_ping: OK, /version: v20.10.24
  [PASS] FTP        banner: 220 FTP Server ready.
  [PASS] MySQL      handshake=95b, auth_resp=11b, query_resp=55b
  [PASS] SMB        negotiate response=133b
  [PASS] Telnet     banner received
  [PASS] SMTP       banner: 220 mail.example.com ESMTP Postfix (Ubuntu)
  [PASS] MongoDB    isMaster resp=186b, listDatabases resp=315b
  [PASS] VNC        version: RFB 003.008, auth_ok=True
  [PASS] Redis      ping: +PONG, auth: +OK
  [PASS] ADB        device: Pixel 7
  [PASS] Elastic    cluster: elasticsearch, version: 8.12.0
  [PASS] K8s        /version: v1.28.2, /api/v1: 200
  [PASS] MQTT       CONNACK received, session established
  ...
  36 passed, 0 failed out of 36 checks
```

---

## Architecture

```
main.py → honeypot/cli.py → honeypot/core.py (HoneypotOrchestrator)
                                  │
                  ┌───────────────┼───────────────┐
                  │               │               │
            14 Services      Dashboard       Alert Engine
          (async TCP)     (aiohttp REST     (50+ patterns,
                           + WebSocket)     webhook dispatch)
                  │               │               │
                  └───────┬───────┘               │
                          │                       │
                    Database (SQLite)  ◄───────────┘
                          │
                   GeoLocator (ip-api.com, cached)
```

```
honeypot/
├── cli.py              # Interactive setup, arg parsing, logging
├── config.py           # YAML loading, service schemas, 79 banner presets
├── core.py             # Orchestrator — wires components, manages lifecycle
├── database.py         # Async SQLite (WAL), pub/sub for WebSocket broadcast
├── models.py           # EventType, ServiceType, AlertSeverity, dataclasses
├── alerts.py           # 50+ detection rules, IOC extraction, webhooks
├── geo.py              # IP geolocation with cache + rate limiting
├── dashboard/
│   ├── server.py       # aiohttp REST API (40+ endpoints) + WebSocket
│   └── templates.py    # Single-file HTML/CSS/JS dashboard (SPA)
└── services/
    ├── __init__.py     # BaseHoneypotService ABC
    └── *.py            # 14 protocol implementations
```

Each service extends `BaseHoneypotService` — implementing `_handle_client()` for protocol interaction and using `_log()` to push events through the pipeline (SQLite storage → alert engine → WebSocket broadcast).

---

## License

MIT
