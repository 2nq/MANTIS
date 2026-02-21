"""Elasticsearch honeypot — emulates an open Elasticsearch cluster (REST API)."""

import json
import uuid
import time
from aiohttp import web
from ..models import EventType
from . import BaseHoneypotService

_CLUSTER_NAME = "production-cluster"
_NODE_NAME = "prod-es-node-01"
_ES_VERSION = "8.11.4"
_LUCENE_VERSION = "9.8.0"


def _fake_root(cluster_name: str, node_name: str) -> dict:
    return {
        "name": node_name,
        "cluster_name": cluster_name,
        "cluster_uuid": "x7Rz4kR3Qy-Wz3J5kLm8nA",
        "version": {
            "number": _ES_VERSION,
            "build_flavor": "default",
            "build_type": "deb",
            "build_hash": "d9ec3fa03a0edc0c",
            "build_date": "2024-01-29T09:48:45.639Z",
            "build_snapshot": False,
            "lucene_version": _LUCENE_VERSION,
            "minimum_wire_compatibility_version": "7.17.0",
            "minimum_index_compatibility_version": "7.0.0",
        },
        "tagline": "You Know, for Search",
    }


_FAKE_INDICES = [
    {"health": "green", "status": "open", "index": "customers", "uuid": "a1b2c3d4", "pri": "5", "rep": "1", "docs.count": "1284530", "docs.deleted": "4521", "store.size": "2.1gb", "pri.store.size": "1.1gb"},
    {"health": "green", "status": "open", "index": "transactions", "uuid": "e5f6g7h8", "pri": "5", "rep": "1", "docs.count": "8432100", "docs.deleted": "12044", "store.size": "12.8gb", "pri.store.size": "6.4gb"},
    {"health": "green", "status": "open", "index": "user_sessions", "uuid": "i9j0k1l2", "pri": "3", "rep": "1", "docs.count": "342100", "docs.deleted": "892", "store.size": "890mb", "pri.store.size": "445mb"},
    {"health": "yellow", "status": "open", "index": "logs-2024.01", "uuid": "m3n4o5p6", "pri": "5", "rep": "1", "docs.count": "24100000", "docs.deleted": "0", "store.size": "38.2gb", "pri.store.size": "19.1gb"},
    {"health": "green", "status": "open", "index": "api_keys", "uuid": "q7r8s9t0", "pri": "1", "rep": "1", "docs.count": "892", "docs.deleted": "23", "store.size": "1.2mb", "pri.store.size": "612kb"},
    {"health": "green", "status": "open", "index": ".kibana", "uuid": "u1v2w3x4", "pri": "1", "rep": "0", "docs.count": "145", "docs.deleted": "12", "store.size": "2.4mb", "pri.store.size": "2.4mb"},
]

_FAKE_SEARCH_HITS = [
    {"_index": "customers", "_id": "c1001", "_score": 1.0, "_source": {"name": "John Morrison", "email": "j.morrison@example.com", "phone": "+1-555-0142", "plan": "enterprise", "balance": 14520.00}},
    {"_index": "customers", "_id": "c1002", "_score": 0.95, "_source": {"name": "Sarah Chen", "email": "s.chen@example.com", "phone": "+1-555-0198", "plan": "business", "balance": 8340.50}},
    {"_index": "customers", "_id": "c1003", "_score": 0.91, "_source": {"name": "Mike Peters", "email": "m.peters@example.com", "phone": "+1-555-0256", "plan": "starter", "balance": 120.00}},
]


def _fake_cluster_health(cluster_name: str) -> dict:
    return {
        "cluster_name": cluster_name,
        "status": "green",
        "timed_out": False,
        "number_of_nodes": 3,
        "number_of_data_nodes": 3,
        "active_primary_shards": 25,
        "active_shards": 50,
        "relocating_shards": 0,
        "initializing_shards": 0,
        "unassigned_shards": 0,
        "delayed_unassigned_shards": 0,
        "number_of_pending_tasks": 0,
        "number_of_in_flight_fetch": 0,
        "task_max_waiting_in_queue_millis": 0,
        "active_shards_percent_as_number": 100.0,
    }


def _fake_nodes(node_name: str) -> dict:
    return {
        "_nodes": {"total": 3, "successful": 3, "failed": 0},
        "cluster_name": _CLUSTER_NAME,
        "nodes": {
            "node-id-001": {
                "name": node_name,
                "transport_address": "10.0.1.10:9300",
                "host": "10.0.1.10",
                "ip": "10.0.1.10",
                "version": _ES_VERSION,
                "roles": ["data", "ingest", "master"],
                "os": {
                    "name": "Linux",
                    "pretty_name": "Ubuntu 22.04.3 LTS",
                    "arch": "amd64",
                    "version": "5.15.0-88-generic",
                    "available_processors": 8,
                    "allocated_processors": 8,
                },
                "jvm": {
                    "version": "21.0.1",
                    "vm_name": "OpenJDK 64-Bit Server VM",
                    "mem": {"heap_init_in_bytes": 1073741824, "heap_max_in_bytes": 4294967296},
                },
            },
        },
    }


def _fake_search_response(body: dict) -> dict:
    size = body.get("size", 10) if body else 10
    hits = _FAKE_SEARCH_HITS[:min(size, len(_FAKE_SEARCH_HITS))]
    return {
        "took": 12,
        "timed_out": False,
        "_shards": {"total": 5, "successful": 5, "skipped": 0, "failed": 0},
        "hits": {
            "total": {"value": len(_FAKE_SEARCH_HITS), "relation": "eq"},
            "max_score": 1.0,
            "hits": hits,
        },
    }


class ElasticsearchHoneypot(BaseHoneypotService):
    service_name = "elasticsearch"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._app = None
        self._runner = None

    async def start(self):
        port = self.config.port
        self._app = web.Application()

        # Root
        self._app.router.add_get("/", self._handle_root)
        # Cluster health
        self._app.router.add_get("/_cluster/health", self._handle_cluster_health)
        self._app.router.add_get("/_cluster/settings", self._handle_cluster_settings)
        # Cat APIs — recon
        self._app.router.add_get("/_cat/health", self._handle_cat_health)
        self._app.router.add_get("/_cat/indices", self._handle_cat_indices)
        self._app.router.add_get("/_cat/nodes", self._handle_cat_nodes)
        # Nodes info — recon
        self._app.router.add_get("/_nodes", self._handle_nodes)
        self._app.router.add_get("/_nodes/{selector}", self._handle_nodes)
        # Search — data theft
        self._app.router.add_get("/_search", self._handle_search)
        self._app.router.add_post("/_search", self._handle_search)
        self._app.router.add_get("/{index}/_search", self._handle_search)
        self._app.router.add_post("/{index}/_search", self._handle_search)
        # Bulk — injection / cryptominer deployment
        self._app.router.add_post("/_bulk", self._handle_bulk)
        self._app.router.add_post("/{index}/_bulk", self._handle_bulk)
        # Scripts — RCE
        self._app.router.add_post("/_scripts/{script_id}", self._handle_script)
        self._app.router.add_put("/_scripts/{script_id}", self._handle_script)
        # Index ops
        self._app.router.add_put("/{index}", self._handle_index_create)
        # Snapshot — data exfil
        self._app.router.add_put("/_snapshot/{repo}", self._handle_snapshot)
        self._app.router.add_put("/_snapshot/{repo}/{snapshot}", self._handle_snapshot)
        self._app.router.add_post("/_snapshot/{repo}/{snapshot}/_restore", self._handle_snapshot)
        # Document indexing
        self._app.router.add_post("/{index}/_doc", self._handle_doc_index)
        self._app.router.add_put("/{index}/_doc/{doc_id}", self._handle_doc_index)
        # Catch-all
        self._app.router.add_route("*", "/{path:.*}", self._handle_catchall)

        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "0.0.0.0", port)
        await site.start()
        self.logger.info("Elasticsearch honeypot listening on port %d", port)

    async def stop(self):
        if self._runner:
            await self._runner.cleanup()
        self.logger.info("Elasticsearch service stopped")

    def _cluster(self) -> str:
        return self.config.extra.get("cluster_name", _CLUSTER_NAME)

    def _node(self) -> str:
        return self.config.extra.get("node_name", _NODE_NAME)

    async def _handle_root(self, request: web.Request) -> web.Response:
        src_ip = request.remote
        session = await self._create_session(src_ip, 0, self.config.port)
        await self._log(session, EventType.REQUEST, {
            "endpoint": "/",
            "method": "GET",
            "user_agent": request.headers.get("User-Agent", ""),
        })
        await self._end_session(session)
        return web.json_response(_fake_root(self._cluster(), self._node()))

    async def _handle_cluster_health(self, request: web.Request) -> web.Response:
        src_ip = request.remote
        session = await self._create_session(src_ip, 0, self.config.port)
        await self._log(session, EventType.REQUEST, {
            "endpoint": "/_cluster/health",
            "user_agent": request.headers.get("User-Agent", ""),
        })
        await self._end_session(session)
        return web.json_response(_fake_cluster_health(self._cluster()))

    async def _handle_cluster_settings(self, request: web.Request) -> web.Response:
        src_ip = request.remote
        session = await self._create_session(src_ip, 0, self.config.port)
        await self._log(session, EventType.REQUEST, {
            "endpoint": "/_cluster/settings",
            "user_agent": request.headers.get("User-Agent", ""),
        })
        await self._end_session(session)
        return web.json_response({"persistent": {}, "transient": {}})

    async def _handle_cat_health(self, request: web.Request) -> web.Response:
        src_ip = request.remote
        session = await self._create_session(src_ip, 0, self.config.port)
        await self._log(session, EventType.REQUEST, {
            "endpoint": "/_cat/health",
            "user_agent": request.headers.get("User-Agent", ""),
        })
        await self._end_session(session)
        ts = time.strftime("%H:%M:%S")
        text = f"epoch      timestamp cluster              status node.total node.data shards pri relo init unassign\n"
        text += f"{int(time.time())} {ts}  {self._cluster()} green           3         3     50  25    0    0        0\n"
        return web.Response(text=text, content_type="text/plain")

    async def _handle_cat_indices(self, request: web.Request) -> web.Response:
        src_ip = request.remote
        session = await self._create_session(src_ip, 0, self.config.port)
        await self._log(session, EventType.REQUEST, {
            "endpoint": "/_cat/indices",
            "user_agent": request.headers.get("User-Agent", ""),
        })
        await self._end_session(session)
        if "format" in request.query and request.query["format"] == "json":
            return web.json_response(_FAKE_INDICES)
        lines = "health status index          uuid     pri rep docs.count docs.deleted store.size pri.store.size\n"
        for idx in _FAKE_INDICES:
            lines += f"{idx['health']:6s} {idx['status']:6s} {idx['index']:14s} {idx['uuid']:8s} {idx['pri']:>3s} {idx['rep']:>3s} {idx['docs.count']:>10s} {idx['docs.deleted']:>12s} {idx['store.size']:>10s} {idx['pri.store.size']:>14s}\n"
        return web.Response(text=lines, content_type="text/plain")

    async def _handle_cat_nodes(self, request: web.Request) -> web.Response:
        src_ip = request.remote
        session = await self._create_session(src_ip, 0, self.config.port)
        await self._log(session, EventType.REQUEST, {
            "endpoint": "/_cat/nodes",
            "user_agent": request.headers.get("User-Agent", ""),
        })
        await self._end_session(session)
        text = "ip         heap.percent ram.percent cpu load_1m node.role master name\n"
        text += f"10.0.1.10           42          87  12    0.42 dim       *      {self._node()}\n"
        text += "10.0.1.11           38          82   8    0.31 di        -      prod-es-node-02\n"
        text += "10.0.1.12           55          91  15    0.58 di        -      prod-es-node-03\n"
        return web.Response(text=text, content_type="text/plain")

    async def _handle_nodes(self, request: web.Request) -> web.Response:
        src_ip = request.remote
        session = await self._create_session(src_ip, 0, self.config.port)
        await self._log(session, EventType.REQUEST, {
            "endpoint": "/_nodes",
            "user_agent": request.headers.get("User-Agent", ""),
        })
        await self._end_session(session)
        return web.json_response(_fake_nodes(self._node()))

    async def _handle_search(self, request: web.Request) -> web.Response:
        src_ip = request.remote
        session = await self._create_session(src_ip, 0, self.config.port)
        index = request.match_info.get("index", "*")

        body = {}
        if request.method == "POST":
            try:
                body = await request.json()
            except Exception:
                pass

        query = body.get("query", {})
        script = body.get("script_fields", body.get("script", {}))

        await self._log(session, EventType.COMMAND, {
            "endpoint": f"/{index}/_search",
            "index": index,
            "query": query,
            "script_fields": script if script else None,
            "raw_body": json.dumps(body)[:4096] if body else "",
            "user_agent": request.headers.get("User-Agent", ""),
        })
        await self._end_session(session)
        return web.json_response(_fake_search_response(body))

    async def _handle_bulk(self, request: web.Request) -> web.Response:
        src_ip = request.remote
        session = await self._create_session(src_ip, 0, self.config.port)
        index = request.match_info.get("index", "")

        body = ""
        try:
            body = await request.text()
        except Exception:
            pass

        lines = [l for l in body.split("\n") if l.strip()] if body else []

        await self._log(session, EventType.COMMAND, {
            "endpoint": "/_bulk",
            "index": index or None,
            "operation_count": len(lines) // 2,
            "raw_body": body[:8192],
            "user_agent": request.headers.get("User-Agent", ""),
        })
        await self._end_session(session)

        # Build fake response
        items = []
        for i in range(0, len(lines) - 1, 2):
            items.append({"index": {"_index": index or "data", "_id": uuid.uuid4().hex[:8], "status": 201, "result": "created"}})
        return web.json_response({"took": 30, "errors": False, "items": items})

    async def _handle_script(self, request: web.Request) -> web.Response:
        src_ip = request.remote
        session = await self._create_session(src_ip, 0, self.config.port)
        script_id = request.match_info.get("script_id", "unknown")

        body = {}
        try:
            body = await request.json()
        except Exception:
            pass

        await self._log(session, EventType.COMMAND, {
            "endpoint": f"/_scripts/{script_id}",
            "script_id": script_id,
            "script_lang": body.get("script", {}).get("lang", ""),
            "script_source": body.get("script", {}).get("source", ""),
            "raw_body": json.dumps(body)[:4096],
            "user_agent": request.headers.get("User-Agent", ""),
        })
        await self._end_session(session)
        return web.json_response({"acknowledged": True})

    async def _handle_index_create(self, request: web.Request) -> web.Response:
        src_ip = request.remote
        session = await self._create_session(src_ip, 0, self.config.port)
        index = request.match_info.get("index", "unknown")

        body = {}
        try:
            body = await request.json()
        except Exception:
            pass

        await self._log(session, EventType.COMMAND, {
            "endpoint": f"/{index}",
            "method": "PUT",
            "index": index,
            "mappings": body.get("mappings", {}),
            "settings": body.get("settings", {}),
            "user_agent": request.headers.get("User-Agent", ""),
        })
        await self._end_session(session)
        return web.json_response({"acknowledged": True, "shards_acknowledged": True, "index": index})

    async def _handle_snapshot(self, request: web.Request) -> web.Response:
        src_ip = request.remote
        session = await self._create_session(src_ip, 0, self.config.port)
        repo = request.match_info.get("repo", "")
        snapshot = request.match_info.get("snapshot", "")

        body = {}
        try:
            body = await request.json()
        except Exception:
            pass

        await self._log(session, EventType.COMMAND, {
            "endpoint": request.path,
            "method": request.method,
            "repository": repo,
            "snapshot": snapshot,
            "raw_body": json.dumps(body)[:4096] if body else "",
            "user_agent": request.headers.get("User-Agent", ""),
        })
        await self._end_session(session)
        return web.json_response({"acknowledged": True})

    async def _handle_doc_index(self, request: web.Request) -> web.Response:
        src_ip = request.remote
        session = await self._create_session(src_ip, 0, self.config.port)
        index = request.match_info.get("index", "unknown")
        doc_id = request.match_info.get("doc_id", uuid.uuid4().hex[:8])

        body = {}
        try:
            body = await request.json()
        except Exception:
            pass

        await self._log(session, EventType.COMMAND, {
            "endpoint": f"/{index}/_doc",
            "index": index,
            "doc_id": doc_id,
            "raw_body": json.dumps(body)[:4096],
            "user_agent": request.headers.get("User-Agent", ""),
        })
        await self._end_session(session)
        return web.json_response({
            "_index": index, "_id": doc_id, "_version": 1,
            "result": "created", "_shards": {"total": 2, "successful": 1, "failed": 0},
        }, status=201)

    async def _handle_catchall(self, request: web.Request) -> web.Response:
        src_ip = request.remote
        session = await self._create_session(src_ip, 0, self.config.port)

        body = ""
        try:
            body = await request.text()
        except Exception:
            pass

        await self._log(session, EventType.REQUEST, {
            "endpoint": request.path,
            "method": request.method,
            "body": body[:4096] if body else "",
            "user_agent": request.headers.get("User-Agent", ""),
        })
        await self._end_session(session)
        return web.json_response({"error": "not_found", "status": 404}, status=404)
