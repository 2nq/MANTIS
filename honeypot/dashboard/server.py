"""Dashboard REST API and WebSocket server using aiohttp."""

import asyncio
import csv
import io
import json
import logging
import secrets
import shutil
import subprocess
import weakref

from aiohttp import web

from .templates import DASHBOARD_HTML, LOGIN_HTML

logger = logging.getLogger("honeypot.dashboard")


class DashboardServer:
    def __init__(self, database, geo_locator, config, orchestrator=None):
        self._db = database
        self._geo = geo_locator
        self._config = config
        self._orchestrator = orchestrator
        self._app = web.Application()
        self._runner = None
        self._websockets: weakref.WeakSet = weakref.WeakSet()
        self._event_queue = None
        self._alert_queue = None
        self._broadcast_task = None

        self._blocked_ips: set[str] = set()
        self._has_iptables = shutil.which("iptables") is not None
        self._sessions: dict[str, dict] = {}

        self._app.middlewares.append(self._auth_middleware)

        self._app.router.add_get("/", self._handle_dashboard)
        self._app.router.add_get("/login", self._handle_login)
        self._app.router.add_post("/api/auth", self._handle_auth)
        self._app.router.add_post("/api/logout", self._handle_logout)
        self._app.router.add_post("/api/users/change-password", self._handle_change_password)
        self._app.router.add_get("/ws", self._handle_ws)
        self._app.router.add_get("/api/stats", self._handle_stats)
        self._app.router.add_get("/api/events", self._handle_events)
        self._app.router.add_get("/api/sessions", self._handle_sessions)
        self._app.router.add_get("/api/alerts", self._handle_alerts)
        self._app.router.add_post("/api/alerts/{id}/ack", self._handle_ack_alert)
        self._app.router.add_get("/api/geo/{ip}", self._handle_geo)
        self._app.router.add_get("/api/map", self._handle_map)
        self._app.router.add_get("/api/config", self._handle_get_config)
        self._app.router.add_get("/api/config/full", self._handle_get_full_config)
        self._app.router.add_put("/api/config/service/{name}", self._handle_update_service_config)
        self._app.router.add_put("/api/config/global", self._handle_update_global_config)
        self._app.router.add_post("/api/config/save", self._handle_save_config)
        self._app.router.add_get("/api/config/export", self._handle_export_config)
        self._app.router.add_get("/api/ips", self._handle_ips)
        self._app.router.add_get("/api/sessions/{id}/events", self._handle_session_events)
        self._app.router.add_post("/api/database/reset", self._handle_database_reset)
        self._app.router.add_get("/api/attackers", self._handle_attackers)
        self._app.router.add_get("/api/payload-stats", self._handle_payload_stats)
        self._app.router.add_get("/api/export", self._handle_export)
        self._app.router.add_post("/api/events/delete", self._handle_delete_events)
        self._app.router.add_post("/api/alerts/delete", self._handle_delete_alerts)
        self._app.router.add_post("/api/sessions/delete", self._handle_delete_sessions)
        self._app.router.add_post("/api/events/delete-filtered", self._handle_delete_events_filtered)
        self._app.router.add_post("/api/payload-scan", self._handle_payload_scan)
        self._app.router.add_get("/api/firewall/blocked", self._handle_get_blocked)
        self._app.router.add_post("/api/firewall/block", self._handle_block_ip)
        self._app.router.add_post("/api/firewall/unblock", self._handle_unblock_ip)

    async def start(self):
        self._event_queue = self._db.subscribe_events()
        self._alert_queue = self._db.subscribe_alerts()
        self._broadcast_task = asyncio.create_task(self._broadcaster())

        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, self._config.host, self._config.port)
        await site.start()
        logger.info(
            "Dashboard running at http://%s:%d",
            self._config.host, self._config.port,
        )

    async def stop(self):
        if self._broadcast_task:
            self._broadcast_task.cancel()
            try:
                await self._broadcast_task
            except asyncio.CancelledError:
                pass
        if self._event_queue:
            self._db.unsubscribe_events(self._event_queue)
        if self._alert_queue:
            self._db.unsubscribe_alerts(self._alert_queue)
        for ws in set(self._websockets):
            await ws.close()
        if self._runner:
            await self._runner.cleanup()
        logger.info("Dashboard stopped")

    async def _broadcaster(self):
        """Read from event/alert queues and broadcast to WebSocket clients."""
        while True:
            tasks = [
                asyncio.create_task(self._event_queue.get()),
                asyncio.create_task(self._alert_queue.get()),
            ]
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for p in pending:
                p.cancel()

            for task in done:
                try:
                    item = task.result()
                except asyncio.CancelledError:
                    continue

                from ..models import Event, Alert
                if isinstance(item, Event):
                    msg = json.dumps({"type": "event", "data": item.to_dict()})
                elif isinstance(item, Alert):
                    msg = json.dumps({"type": "alert", "data": item.to_dict()})
                else:
                    continue

                dead = []
                for ws in self._websockets:
                    try:
                        await ws.send_str(msg)
                    except Exception:
                        dead.append(ws)
                for ws in dead:
                    self._websockets.discard(ws)

    @web.middleware
    async def _auth_middleware(self, request: web.Request, handler):
        # Allow login page and auth endpoint without session
        if request.path in ("/login", "/api/auth"):
            return await handler(request)
        # Check cookie or Authorization header
        token = request.cookies.get("mantis_token")
        if not token:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header[7:]
        if token and token in self._sessions:
            return await handler(request)
        # WebSocket — check token in query string
        if request.path == "/ws":
            qs_token = request.query.get("token")
            if qs_token and qs_token in self._sessions:
                return await handler(request)
        # Redirect HTML requests to login, reject API with 401
        if request.path.startswith("/api") or request.path == "/ws":
            return web.json_response({"error": "unauthorized"}, status=401)
        raise web.HTTPFound("/login")

    async def _handle_login(self, request: web.Request) -> web.Response:
        return web.Response(text=LOGIN_HTML, content_type="text/html")

    async def _handle_auth(self, request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "invalid JSON"}, status=400)
        username = body.get("username", "")
        password = body.get("password", "")
        user = await self._db.authenticate_user(username, password)
        if user:
            session_token = secrets.token_urlsafe(32)
            self._sessions[session_token] = {"username": user["username"], "id": user["id"]}
            resp = web.json_response({"status": "ok"})
            resp.set_cookie("mantis_token", session_token, httponly=True, samesite="Strict", max_age=86400 * 7)
            return resp
        return web.json_response({"error": "invalid credentials"}, status=403)

    async def _handle_logout(self, request: web.Request) -> web.Response:
        token = request.cookies.get("mantis_token")
        if token:
            self._sessions.pop(token, None)
        resp = web.json_response({"status": "ok"})
        resp.del_cookie("mantis_token")
        return resp

    async def _handle_change_password(self, request: web.Request) -> web.Response:
        token = request.cookies.get("mantis_token")
        session = self._sessions.get(token) if token else None
        if not session:
            return web.json_response({"error": "unauthorized"}, status=401)
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "invalid JSON"}, status=400)
        current_password = body.get("current_password", "")
        new_password = body.get("new_password", "")
        if not new_password:
            return web.json_response({"error": "new_password required"}, status=400)
        user = await self._db.authenticate_user(session["username"], current_password)
        if not user:
            return web.json_response({"error": "current password incorrect"}, status=403)
        await self._db.change_password(session["username"], new_password)
        return web.json_response({"status": "ok"})

    async def _handle_dashboard(self, request: web.Request) -> web.Response:
        return web.Response(text=DASHBOARD_HTML, content_type="text/html")

    async def _handle_ws(self, request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        self._websockets.add(ws)
        logger.debug("WebSocket client connected")

        try:
            async for msg in ws:
                pass  # We only push, don't need client messages
        finally:
            self._websockets.discard(ws)
        return ws

    async def _handle_stats(self, request: web.Request) -> web.Response:
        try:
            data = await self._db.get_stats()
            return web.json_response(data)
        except Exception as e:
            logger.exception("Stats query failed")
            return web.json_response({"error": str(e)}, status=500)

    async def _handle_events(self, request: web.Request) -> web.Response:
        try:
            limit = min(int(request.query.get("limit", 100)), 1000)
            offset = int(request.query.get("offset", 0))
            service = request.query.get("service")
            event_type = request.query.get("type")
            src_ip = request.query.get("ip")
            paginated = request.query.get("paginated", "").lower() in ("1", "true")
            services_param = request.query.get("services")
            services = [s.strip() for s in services_param.split(",")] if services_param else None
            types_param = request.query.get("types")
            event_types = [t.strip() for t in types_param.split(",")] if types_param else None
            search = request.query.get("search")
            time_from = request.query.get("from")
            time_to = request.query.get("to")
            data = await self._db.get_events(
                limit=limit, offset=offset, service=service,
                event_type=event_type, src_ip=src_ip,
                services=services, event_types=event_types,
                search=search, time_from=time_from, time_to=time_to,
                paginated=paginated,
            )
            return web.json_response(data)
        except Exception as e:
            logger.exception("Events query failed")
            return web.json_response({"error": str(e)}, status=500)

    async def _handle_sessions(self, request: web.Request) -> web.Response:
        try:
            limit = min(int(request.query.get("limit", 100)), 1000)
            offset = int(request.query.get("offset", 0))
            src_ip = request.query.get("ip")
            service = request.query.get("service")
            services_param = request.query.get("services")
            services = [s.strip() for s in services_param.split(",")] if services_param else None
            paginated = request.query.get("paginated", "").lower() in ("1", "true")
            data = await self._db.get_sessions(
                limit=limit, offset=offset,
                src_ip=src_ip, service=service,
                services=services,
                paginated=paginated,
            )
            return web.json_response(data)
        except Exception as e:
            logger.exception("Sessions query failed")
            return web.json_response({"error": str(e)}, status=500)

    async def _handle_alerts(self, request: web.Request) -> web.Response:
        try:
            limit = min(int(request.query.get("limit", 100)), 1000)
            unacked = request.query.get("unacknowledged", "").lower() in ("1", "true", "yes")
            data = await self._db.get_alerts(limit=limit, unacknowledged_only=unacked)
            return web.json_response(data)
        except Exception as e:
            logger.exception("Alerts query failed")
            return web.json_response({"error": str(e)}, status=500)

    async def _handle_ack_alert(self, request: web.Request) -> web.Response:
        try:
            alert_id = int(request.match_info["id"])
            await self._db.acknowledge_alert(alert_id)
            return web.json_response({"status": "ok"})
        except Exception as e:
            logger.exception("Alert ack failed")
            return web.json_response({"error": str(e)}, status=500)

    async def _handle_geo(self, request: web.Request) -> web.Response:
        try:
            ip = request.match_info["ip"]
            geo = await self._geo.lookup(ip)
            return web.json_response(geo.to_dict())
        except Exception as e:
            logger.exception("Geo lookup failed")
            return web.json_response({"error": str(e)}, status=500)

    async def _handle_map(self, request: web.Request) -> web.Response:
        try:
            data = await self._db.get_map_data()
            return web.json_response(data)
        except Exception as e:
            logger.exception("Map query failed")
            return web.json_response({"error": str(e)}, status=500)

    async def _handle_get_config(self, request: web.Request) -> web.Response:
        try:
            if self._orchestrator is None:
                return web.json_response({"error": "orchestrator not available"}, status=500)
            return web.json_response(self._orchestrator.get_config_dict())
        except Exception as e:
            logger.exception("Config query failed")
            return web.json_response({"error": str(e)}, status=500)

    async def _handle_get_full_config(self, request: web.Request) -> web.Response:
        """Return config + extra schema + banner presets for the config UI."""
        try:
            if self._orchestrator is None:
                return web.json_response({"error": "orchestrator not available"}, status=500)
            return web.json_response(self._orchestrator.get_full_config_dict())
        except Exception as e:
            logger.exception("Full config query failed")
            return web.json_response({"error": str(e)}, status=500)

    async def _handle_update_service_config(self, request: web.Request) -> web.Response:
        if self._orchestrator is None:
            return web.json_response({"error": "orchestrator not available"}, status=500)
        name = request.match_info["name"]
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "invalid JSON"}, status=400)
        try:
            new_config = await self._orchestrator.update_service_config(name, body)
        except ValueError as e:
            return web.json_response({"error": str(e)}, status=400)
        # Broadcast config change to WebSocket clients
        msg = json.dumps({"type": "config_change", "data": new_config})
        dead = []
        for ws in self._websockets:
            try:
                await ws.send_str(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._websockets.discard(ws)
        return web.json_response(new_config)

    async def _handle_update_global_config(self, request: web.Request) -> web.Response:
        if self._orchestrator is None:
            return web.json_response({"error": "orchestrator not available"}, status=500)
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "invalid JSON"}, status=400)
        new_config = self._orchestrator.update_global_config(body)
        # Broadcast
        msg = json.dumps({"type": "config_change", "data": new_config})
        dead = []
        for ws in self._websockets:
            try:
                await ws.send_str(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._websockets.discard(ws)
        return web.json_response(new_config)

    async def _handle_save_config(self, request: web.Request) -> web.Response:
        if self._orchestrator is None:
            return web.json_response({"error": "orchestrator not available"}, status=500)
        try:
            body = await request.json() if request.content_length else {}
        except Exception:
            body = {}
        path = body.get("path", "mantis_config.yaml")
        try:
            abs_path = self._orchestrator.save_running_config(path)
            return web.json_response({"status": "ok", "path": abs_path})
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)

    async def _handle_export_config(self, request: web.Request) -> web.Response:
        if self._orchestrator is None:
            return web.json_response({"error": "orchestrator not available"}, status=500)
        import yaml
        data = self._orchestrator.get_config_dict()
        # Flatten extras for clean YAML
        for name in ("ssh", "http", "ftp", "smb", "mysql", "telnet", "smtp", "mongodb", "vnc", "redis", "adb"):
            svc = data.get(name, {})
            extra = svc.pop("extra", None)
            if extra:
                svc.update(extra)
        yaml_str = yaml.dump(data, default_flow_style=False, sort_keys=False)
        return web.Response(
            text=yaml_str,
            content_type="application/x-yaml",
            headers={"Content-Disposition": "attachment; filename=mantis_config.yaml"},
        )

    async def _handle_ips(self, request: web.Request) -> web.Response:
        try:
            ips = await self._db.get_unique_ips()
            return web.json_response(ips)
        except Exception as e:
            logger.exception("IPs query failed")
            return web.json_response({"error": str(e)}, status=500)

    async def _handle_session_events(self, request: web.Request) -> web.Response:
        try:
            session_id = request.match_info["id"]
            events = await self._db.get_events_for_session(session_id)
            return web.json_response(events)
        except Exception as e:
            logger.exception("Session events query failed")
            return web.json_response({"error": str(e)}, status=500)

    async def _handle_database_reset(self, request: web.Request) -> web.Response:
        if self._orchestrator is None:
            return web.json_response({"error": "orchestrator not available"}, status=500)
        try:
            await self._orchestrator.reset_database()
            msg = json.dumps({"type": "database_reset"})
            dead = []
            for ws in self._websockets:
                try:
                    await ws.send_str(msg)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                self._websockets.discard(ws)
            return web.json_response({"status": "ok", "message": "Database reset complete"})
        except Exception as e:
            logger.exception("Database reset failed")
            return web.json_response({"error": str(e)}, status=500)

    # ── Attackers & Export ─────────────────────────────────────────────────

    async def _handle_attackers(self, request: web.Request) -> web.Response:
        try:
            limit = min(int(request.query.get("limit", 100)), 1000)
            offset = int(request.query.get("offset", 0))
            data = await self._db.get_attackers(limit=limit, offset=offset)
            return web.json_response(data)
        except Exception as e:
            logger.exception("Attackers query failed")
            return web.json_response({"error": str(e)}, status=500)

    async def _handle_payload_stats(self, request: web.Request) -> web.Response:
        try:
            data = await self._db.get_payload_stats()
            return web.json_response(data)
        except Exception as e:
            logger.exception("Payload stats query failed")
            return web.json_response({"error": str(e)}, status=500)

    async def _handle_export(self, request: web.Request) -> web.Response:
        """Export full database as JSON or CSV download."""
        try:
            table = request.query.get("table", "events")
            fmt = request.query.get("format", "json")
            if table not in ("events", "sessions", "alerts", "attackers"):
                return web.json_response({"error": "invalid table"}, status=400)
            data = await self._db.export_all(table)
            if fmt == "csv":
                output = io.StringIO()
                if data:
                    flat_rows = []
                    for row in data:
                        flat = {}
                        for k, v in row.items():
                            flat[k] = json.dumps(v) if isinstance(v, (dict, list)) else v
                        flat_rows.append(flat)
                    writer = csv.DictWriter(output, fieldnames=flat_rows[0].keys())
                    writer.writeheader()
                    writer.writerows(flat_rows)
                csv_str = output.getvalue()
                return web.Response(
                    text=csv_str,
                    content_type="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=mantis_{table}.csv"},
                )
            return web.Response(
                text=json.dumps(data, indent=2),
                content_type="application/json",
                headers={"Content-Disposition": f"attachment; filename=mantis_{table}.json"},
            )
        except Exception as e:
            logger.exception("Export failed")
            return web.json_response({"error": str(e)}, status=500)

    # ── Selective Delete ────────────────────────────────────────────────────

    async def _broadcast_ws(self, msg_dict: dict):
        """Helper to broadcast a JSON message to all WebSocket clients."""
        msg = json.dumps(msg_dict)
        dead = []
        for ws in self._websockets:
            try:
                await ws.send_str(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._websockets.discard(ws)

    async def _handle_delete_events(self, request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "invalid JSON"}, status=400)
        ids = body.get("ids", [])
        if not ids or not isinstance(ids, list):
            return web.json_response({"error": "ids list required"}, status=400)
        try:
            deleted = await self._db.delete_events([int(i) for i in ids])
            await self._broadcast_ws({"type": "events_deleted", "data": {"count": deleted}})
            return web.json_response({"status": "ok", "deleted": deleted})
        except Exception as e:
            logger.exception("Delete events failed")
            return web.json_response({"error": str(e)}, status=500)

    async def _handle_delete_alerts(self, request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "invalid JSON"}, status=400)
        ids = body.get("ids", [])
        if not ids or not isinstance(ids, list):
            return web.json_response({"error": "ids list required"}, status=400)
        try:
            deleted = await self._db.delete_alerts([int(i) for i in ids])
            await self._broadcast_ws({"type": "alerts_deleted", "data": {"count": deleted}})
            return web.json_response({"status": "ok", "deleted": deleted})
        except Exception as e:
            logger.exception("Delete alerts failed")
            return web.json_response({"error": str(e)}, status=500)

    async def _handle_delete_sessions(self, request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "invalid JSON"}, status=400)
        ids = body.get("ids", [])
        if not ids or not isinstance(ids, list):
            return web.json_response({"error": "ids list required"}, status=400)
        try:
            deleted = await self._db.delete_sessions([str(i) for i in ids])
            await self._broadcast_ws({"type": "sessions_deleted", "data": {"count": deleted}})
            return web.json_response({"status": "ok", "deleted": deleted})
        except Exception as e:
            logger.exception("Delete sessions failed")
            return web.json_response({"error": str(e)}, status=500)

    async def _handle_delete_events_filtered(self, request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "invalid JSON"}, status=400)
        services = body.get("services")
        event_types = body.get("event_types")
        src_ip = body.get("src_ip")
        time_from = body.get("time_from")
        time_to = body.get("time_to")
        if not any([services, event_types, src_ip, time_from, time_to]):
            return web.json_response({"error": "at least one filter required"}, status=400)
        try:
            deleted = await self._db.delete_events_by_filter(
                services=services, event_types=event_types,
                src_ip=src_ip, time_from=time_from, time_to=time_to,
            )
            await self._broadcast_ws({"type": "events_deleted_filtered", "data": {"count": deleted}})
            return web.json_response({"status": "ok", "deleted": deleted})
        except Exception as e:
            logger.exception("Filtered delete failed")
            return web.json_response({"error": str(e)}, status=500)

    # ── Payload Scan ─────────────────────────────────────────────────────

    async def _handle_payload_scan(self, request: web.Request) -> web.Response:
        """Scan historical events for payload/IOC patterns."""
        try:
            body = await request.json() if request.content_length else {}
        except Exception:
            body = {}
        services = body.get("services")
        try:
            from ..alerts import PayloadIOCDetector
            from ..models import Event
            detector = PayloadIOCDetector()
            offset = 0
            batch_size = 500
            total_scanned = 0
            new_alerts = 0
            while True:
                batch = await self._db.get_scannable_events(
                    services=services, batch_size=batch_size, offset=offset,
                )
                if not batch:
                    break
                # Check which events already have payload alerts
                batch_ids = [e["id"] for e in batch if e.get("id")]
                already_alerted = await self._db.check_existing_payload_alerts(batch_ids)
                for ev_dict in batch:
                    total_scanned += 1
                    if ev_dict.get("id") in already_alerted:
                        continue
                    event = Event(
                        id=ev_dict.get("id"),
                        session_id=ev_dict.get("session_id", ""),
                        event_type=ev_dict.get("event_type", ""),
                        service=ev_dict.get("service", ""),
                        src_ip=ev_dict.get("src_ip", ""),
                        timestamp=ev_dict.get("timestamp", ""),
                        data=ev_dict.get("data", {}),
                    )
                    alert = detector.check(event)
                    if alert:
                        await self._db.save_alert(alert)
                        new_alerts += 1
                offset += batch_size
            result = {
                "status": "ok",
                "total_scanned": total_scanned,
                "new_alerts": new_alerts,
            }
            await self._broadcast_ws({"type": "payload_scan_complete", "data": result})
            return web.json_response(result)
        except Exception as e:
            logger.exception("Payload scan failed")
            return web.json_response({"error": str(e)}, status=500)

    # ── Firewall / IP blocking ────────────────────────────────────────────

    async def _run_iptables(self, action: str, ip: str) -> tuple[bool, str]:
        """Run an iptables command. action is '-A' (add) or '-D' (delete)."""
        if not self._has_iptables:
            return False, "iptables not available on this system"
        try:
            proc = await asyncio.create_subprocess_exec(
                "iptables", action, "INPUT", "-s", ip, "-j", "DROP",
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            _, stderr = await proc.communicate()
            if proc.returncode == 0:
                return True, ""
            return False, stderr.decode().strip()
        except Exception as e:
            return False, str(e)

    async def _handle_get_blocked(self, request: web.Request) -> web.Response:
        return web.json_response({
            "blocked": sorted(self._blocked_ips),
            "iptables_available": self._has_iptables,
        })

    async def _handle_block_ip(self, request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "invalid JSON"}, status=400)
        ip = body.get("ip", "").strip()
        if not ip:
            return web.json_response({"error": "ip is required"}, status=400)
        if ip in self._blocked_ips:
            return web.json_response({"status": "already_blocked", "ip": ip})
        ok, err = await self._run_iptables("-A", ip)
        if ok or not self._has_iptables:
            self._blocked_ips.add(ip)
            logger.info("Blocked IP: %s (iptables=%s)", ip, ok)
            # Broadcast to WebSocket clients
            msg = json.dumps({"type": "ip_blocked", "data": {"ip": ip}})
            dead = []
            for ws in self._websockets:
                try:
                    await ws.send_str(msg)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                self._websockets.discard(ws)
            return web.json_response({
                "status": "blocked", "ip": ip,
                "iptables_applied": ok,
                "note": err if not ok else "",
            })
        return web.json_response({"error": f"iptables failed: {err}"}, status=500)

    async def _handle_unblock_ip(self, request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "invalid JSON"}, status=400)
        ip = body.get("ip", "").strip()
        if not ip:
            return web.json_response({"error": "ip is required"}, status=400)
        if ip not in self._blocked_ips:
            return web.json_response({"status": "not_blocked", "ip": ip})
        ok, err = await self._run_iptables("-D", ip)
        self._blocked_ips.discard(ip)
        logger.info("Unblocked IP: %s (iptables=%s)", ip, ok)
        # Broadcast to WebSocket clients
        msg = json.dumps({"type": "ip_unblocked", "data": {"ip": ip}})
        dead = []
        for ws in self._websockets:
            try:
                await ws.send_str(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._websockets.discard(ws)
        return web.json_response({
            "status": "unblocked", "ip": ip,
            "iptables_applied": ok,
            "note": err if not ok else "",
        })
