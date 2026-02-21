"""Kubernetes API honeypot — emulates unauthenticated kubelet/API server."""

import json
import time
import uuid
from aiohttp import web
from ..models import EventType
from . import BaseHoneypotService

_K8S_VERSION = "1.28.4"
_CLUSTER_NAME = "prod-cluster"
_NODE_NAME = "prod-k8s-node-01"


def _fake_version() -> dict:
    return {
        "major": "1",
        "minor": "28",
        "gitVersion": f"v{_K8S_VERSION}",
        "gitCommit": "bae2c62678db2b5053817bc97181fcc2e8388103",
        "gitTreeState": "clean",
        "buildDate": "2023-11-15T16:58:22Z",
        "goVersion": "go1.21.4",
        "compiler": "gc",
        "platform": "linux/amd64",
    }


_API_RESOURCES = {
    "kind": "APIResourceList",
    "groupVersion": "v1",
    "resources": [
        {"name": "pods", "singularName": "", "namespaced": True, "kind": "Pod", "verbs": ["create", "delete", "get", "list", "patch", "update", "watch"]},
        {"name": "services", "singularName": "", "namespaced": True, "kind": "Service", "verbs": ["create", "delete", "get", "list", "patch", "update", "watch"]},
        {"name": "secrets", "singularName": "", "namespaced": True, "kind": "Secret", "verbs": ["create", "delete", "get", "list", "patch", "update", "watch"]},
        {"name": "configmaps", "singularName": "", "namespaced": True, "kind": "ConfigMap", "verbs": ["create", "delete", "get", "list", "patch", "update", "watch"]},
        {"name": "namespaces", "singularName": "", "namespaced": False, "kind": "Namespace", "verbs": ["create", "delete", "get", "list", "patch", "update", "watch"]},
        {"name": "nodes", "singularName": "", "namespaced": False, "kind": "Node", "verbs": ["create", "delete", "get", "list", "patch", "update"]},
        {"name": "serviceaccounts", "singularName": "", "namespaced": True, "kind": "ServiceAccount", "verbs": ["create", "delete", "get", "list", "patch", "update", "watch"]},
    ],
}


def _fake_namespaces() -> dict:
    now = "2024-01-15T08:30:00Z"
    return {
        "kind": "NamespaceList",
        "apiVersion": "v1",
        "metadata": {"resourceVersion": "14892"},
        "items": [
            {"metadata": {"name": "default", "uid": uuid.uuid4().hex[:36], "creationTimestamp": now}, "status": {"phase": "Active"}},
            {"metadata": {"name": "kube-system", "uid": uuid.uuid4().hex[:36], "creationTimestamp": now}, "status": {"phase": "Active"}},
            {"metadata": {"name": "kube-public", "uid": uuid.uuid4().hex[:36], "creationTimestamp": now}, "status": {"phase": "Active"}},
            {"metadata": {"name": "production", "uid": uuid.uuid4().hex[:36], "creationTimestamp": now}, "status": {"phase": "Active"}},
            {"metadata": {"name": "monitoring", "uid": uuid.uuid4().hex[:36], "creationTimestamp": now}, "status": {"phase": "Active"}},
        ],
    }


def _fake_pods(namespace: str) -> dict:
    return {
        "kind": "PodList",
        "apiVersion": "v1",
        "metadata": {"resourceVersion": "15201"},
        "items": [
            {
                "metadata": {"name": "web-app-7d8f9b6c5-x2k4m", "namespace": namespace, "uid": uuid.uuid4().hex[:36]},
                "spec": {
                    "containers": [{"name": "web-app", "image": "nginx:1.25", "ports": [{"containerPort": 80}]}],
                    "nodeName": _NODE_NAME,
                },
                "status": {"phase": "Running", "podIP": "10.244.0.12", "startTime": "2024-01-15T08:35:00Z"},
            },
            {
                "metadata": {"name": "api-server-5f4d3c2b1-j8n7p", "namespace": namespace, "uid": uuid.uuid4().hex[:36]},
                "spec": {
                    "containers": [{"name": "api-server", "image": "node:20-alpine", "ports": [{"containerPort": 3000}]}],
                    "nodeName": _NODE_NAME,
                },
                "status": {"phase": "Running", "podIP": "10.244.0.13", "startTime": "2024-01-15T08:36:00Z"},
            },
        ],
    }


def _fake_nodes() -> dict:
    return {
        "kind": "NodeList",
        "apiVersion": "v1",
        "metadata": {"resourceVersion": "15300"},
        "items": [
            {
                "metadata": {"name": _NODE_NAME, "uid": uuid.uuid4().hex[:36]},
                "status": {
                    "capacity": {"cpu": "8", "memory": "32768Mi", "pods": "110"},
                    "allocatable": {"cpu": "7800m", "memory": "31744Mi", "pods": "110"},
                    "conditions": [{"type": "Ready", "status": "True"}],
                    "nodeInfo": {
                        "machineID": uuid.uuid4().hex,
                        "systemUUID": uuid.uuid4().hex,
                        "kernelVersion": "5.15.0-88-generic",
                        "osImage": "Ubuntu 22.04.3 LTS",
                        "containerRuntimeVersion": "containerd://1.7.11",
                        "kubeletVersion": f"v{_K8S_VERSION}",
                        "operatingSystem": "linux",
                        "architecture": "amd64",
                    },
                    "addresses": [
                        {"type": "InternalIP", "address": "10.0.1.20"},
                        {"type": "Hostname", "address": _NODE_NAME},
                    ],
                },
            },
        ],
    }


def _fake_secrets(namespace: str) -> dict:
    return {
        "kind": "SecretList",
        "apiVersion": "v1",
        "metadata": {"resourceVersion": "15400"},
        "items": [
            {"metadata": {"name": "default-token-x9k2m", "namespace": namespace}, "type": "kubernetes.io/service-account-token"},
            {"metadata": {"name": "db-credentials", "namespace": namespace}, "type": "Opaque"},
            {"metadata": {"name": "tls-cert-prod", "namespace": namespace}, "type": "kubernetes.io/tls"},
            {"metadata": {"name": "registry-pull-secret", "namespace": namespace}, "type": "kubernetes.io/dockerconfigjson"},
            {"metadata": {"name": "aws-credentials", "namespace": namespace}, "type": "Opaque"},
        ],
    }


class KubernetesHoneypot(BaseHoneypotService):
    service_name = "kubernetes"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._app = None
        self._runner = None

    async def start(self):
        port = self.config.port
        self._app = web.Application()

        # Health / version
        self._app.router.add_get("/healthz", self._handle_healthz)
        self._app.router.add_get("/version", self._handle_version)
        self._app.router.add_get("/api", self._handle_api)
        self._app.router.add_get("/api/v1", self._handle_api_v1)
        self._app.router.add_get("/apis", self._handle_apis)

        # Namespaces
        self._app.router.add_get("/api/v1/namespaces", self._handle_namespaces)

        # Pods — list and create (the money shot)
        self._app.router.add_get("/api/v1/pods", self._handle_pods_all)
        self._app.router.add_get("/api/v1/namespaces/{ns}/pods", self._handle_pods)
        self._app.router.add_post("/api/v1/namespaces/{ns}/pods", self._handle_pod_create)
        self._app.router.add_get("/api/v1/namespaces/{ns}/pods/{name}", self._handle_pod_get)
        self._app.router.add_delete("/api/v1/namespaces/{ns}/pods/{name}", self._handle_pod_delete)

        # Secrets — attacker gold
        self._app.router.add_get("/api/v1/secrets", self._handle_secrets_all)
        self._app.router.add_get("/api/v1/namespaces/{ns}/secrets", self._handle_secrets)
        self._app.router.add_get("/api/v1/namespaces/{ns}/secrets/{name}", self._handle_secret_get)

        # Nodes
        self._app.router.add_get("/api/v1/nodes", self._handle_nodes)

        # Service accounts
        self._app.router.add_get("/api/v1/namespaces/{ns}/serviceaccounts", self._handle_serviceaccounts)

        # Exec — RCE attempt on existing pod
        self._app.router.add_post("/api/v1/namespaces/{ns}/pods/{name}/exec", self._handle_exec)
        self._app.router.add_get("/api/v1/namespaces/{ns}/pods/{name}/exec", self._handle_exec)

        # Catch-all
        self._app.router.add_route("*", "/{path:.*}", self._handle_catchall)

        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "0.0.0.0", port)
        await site.start()
        self.logger.info("Kubernetes API honeypot listening on port %d", port)

    async def stop(self):
        if self._runner:
            await self._runner.cleanup()
        self.logger.info("Kubernetes API service stopped")

    # ── Health / version ──────────────────────────────────────────────────

    async def _handle_healthz(self, request: web.Request) -> web.Response:
        src_ip = request.remote
        session = await self._create_session(src_ip, 0, self.config.port)
        await self._log(session, EventType.REQUEST, {"endpoint": "/healthz", "user_agent": request.headers.get("User-Agent", "")})
        await self._end_session(session)
        return web.Response(text="ok", content_type="text/plain")

    async def _handle_version(self, request: web.Request) -> web.Response:
        src_ip = request.remote
        session = await self._create_session(src_ip, 0, self.config.port)
        await self._log(session, EventType.REQUEST, {"endpoint": "/version", "user_agent": request.headers.get("User-Agent", "")})
        await self._end_session(session)
        return web.json_response(_fake_version())

    async def _handle_api(self, request: web.Request) -> web.Response:
        src_ip = request.remote
        session = await self._create_session(src_ip, 0, self.config.port)
        await self._log(session, EventType.REQUEST, {"endpoint": "/api", "user_agent": request.headers.get("User-Agent", "")})
        await self._end_session(session)
        return web.json_response({"kind": "APIVersions", "versions": ["v1"]})

    async def _handle_api_v1(self, request: web.Request) -> web.Response:
        src_ip = request.remote
        session = await self._create_session(src_ip, 0, self.config.port)
        await self._log(session, EventType.REQUEST, {"endpoint": "/api/v1", "user_agent": request.headers.get("User-Agent", "")})
        await self._end_session(session)
        return web.json_response(_API_RESOURCES)

    async def _handle_apis(self, request: web.Request) -> web.Response:
        src_ip = request.remote
        session = await self._create_session(src_ip, 0, self.config.port)
        await self._log(session, EventType.REQUEST, {"endpoint": "/apis", "user_agent": request.headers.get("User-Agent", "")})
        await self._end_session(session)
        return web.json_response({"kind": "APIGroupList", "apiVersion": "v1", "groups": []})

    # ── Namespaces ────────────────────────────────────────────────────────

    async def _handle_namespaces(self, request: web.Request) -> web.Response:
        src_ip = request.remote
        session = await self._create_session(src_ip, 0, self.config.port)
        await self._log(session, EventType.REQUEST, {"endpoint": "/api/v1/namespaces", "user_agent": request.headers.get("User-Agent", "")})
        await self._end_session(session)
        return web.json_response(_fake_namespaces())

    # ── Pods ──────────────────────────────────────────────────────────────

    async def _handle_pods_all(self, request: web.Request) -> web.Response:
        src_ip = request.remote
        session = await self._create_session(src_ip, 0, self.config.port)
        await self._log(session, EventType.REQUEST, {"endpoint": "/api/v1/pods", "user_agent": request.headers.get("User-Agent", "")})
        await self._end_session(session)
        return web.json_response(_fake_pods("default"))

    async def _handle_pods(self, request: web.Request) -> web.Response:
        src_ip = request.remote
        ns = request.match_info["ns"]
        session = await self._create_session(src_ip, 0, self.config.port)
        await self._log(session, EventType.REQUEST, {"endpoint": f"/api/v1/namespaces/{ns}/pods", "namespace": ns, "user_agent": request.headers.get("User-Agent", "")})
        await self._end_session(session)
        return web.json_response(_fake_pods(ns))

    async def _handle_pod_create(self, request: web.Request) -> web.Response:
        """The money shot — attacker creating a pod (cryptominer, reverse shell, etc.)."""
        src_ip = request.remote
        ns = request.match_info["ns"]
        session = await self._create_session(src_ip, 0, self.config.port)

        body = {}
        try:
            body = await request.json()
        except Exception:
            pass

        spec = body.get("spec", {})
        containers = spec.get("containers", [])
        volumes = spec.get("volumes", [])
        host_network = spec.get("hostNetwork", False)
        host_pid = spec.get("hostPID", False)

        # Extract key intel from each container
        container_intel = []
        for c in containers:
            container_intel.append({
                "name": c.get("name", ""),
                "image": c.get("image", ""),
                "command": c.get("command", []),
                "args": c.get("args", []),
                "env": c.get("env", []),
                "volume_mounts": c.get("volumeMounts", []),
                "security_context": c.get("securityContext", {}),
            })

        await self._log(session, EventType.COMMAND, {
            "endpoint": f"/api/v1/namespaces/{ns}/pods",
            "method": "POST",
            "namespace": ns,
            "pod_name": body.get("metadata", {}).get("name", ""),
            "containers": container_intel,
            "volumes": volumes,
            "host_network": host_network,
            "host_pid": host_pid,
            "raw_body": json.dumps(body)[:8192],
            "user_agent": request.headers.get("User-Agent", ""),
        })
        await self._end_session(session)

        # Fake success
        pod_name = body.get("metadata", {}).get("name", f"pod-{uuid.uuid4().hex[:8]}")
        response = {
            "kind": "Pod",
            "apiVersion": "v1",
            "metadata": {
                "name": pod_name,
                "namespace": ns,
                "uid": str(uuid.uuid4()),
                "creationTimestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
            "spec": spec,
            "status": {"phase": "Pending"},
        }
        return web.json_response(response, status=201)

    async def _handle_pod_get(self, request: web.Request) -> web.Response:
        src_ip = request.remote
        ns = request.match_info["ns"]
        name = request.match_info["name"]
        session = await self._create_session(src_ip, 0, self.config.port)
        await self._log(session, EventType.REQUEST, {"endpoint": f"/api/v1/namespaces/{ns}/pods/{name}", "namespace": ns, "pod_name": name, "user_agent": request.headers.get("User-Agent", "")})
        await self._end_session(session)
        pods = _fake_pods(ns)
        for p in pods["items"]:
            if p["metadata"]["name"] == name:
                return web.json_response(p)
        return web.json_response({"kind": "Status", "apiVersion": "v1", "status": "Failure", "message": f"pods \"{name}\" not found", "reason": "NotFound", "code": 404}, status=404)

    async def _handle_pod_delete(self, request: web.Request) -> web.Response:
        src_ip = request.remote
        ns = request.match_info["ns"]
        name = request.match_info["name"]
        session = await self._create_session(src_ip, 0, self.config.port)
        await self._log(session, EventType.COMMAND, {"endpoint": f"/api/v1/namespaces/{ns}/pods/{name}", "method": "DELETE", "namespace": ns, "pod_name": name, "user_agent": request.headers.get("User-Agent", "")})
        await self._end_session(session)
        return web.json_response({"kind": "Status", "apiVersion": "v1", "status": "Success", "code": 200})

    # ── Secrets ───────────────────────────────────────────────────────────

    async def _handle_secrets_all(self, request: web.Request) -> web.Response:
        src_ip = request.remote
        session = await self._create_session(src_ip, 0, self.config.port)
        await self._log(session, EventType.COMMAND, {"endpoint": "/api/v1/secrets", "method": "GET", "user_agent": request.headers.get("User-Agent", "")})
        await self._end_session(session)
        return web.json_response(_fake_secrets("default"))

    async def _handle_secrets(self, request: web.Request) -> web.Response:
        src_ip = request.remote
        ns = request.match_info["ns"]
        session = await self._create_session(src_ip, 0, self.config.port)
        await self._log(session, EventType.COMMAND, {"endpoint": f"/api/v1/namespaces/{ns}/secrets", "method": "GET", "namespace": ns, "user_agent": request.headers.get("User-Agent", "")})
        await self._end_session(session)
        return web.json_response(_fake_secrets(ns))

    async def _handle_secret_get(self, request: web.Request) -> web.Response:
        src_ip = request.remote
        ns = request.match_info["ns"]
        name = request.match_info["name"]
        session = await self._create_session(src_ip, 0, self.config.port)
        await self._log(session, EventType.COMMAND, {
            "endpoint": f"/api/v1/namespaces/{ns}/secrets/{name}",
            "method": "GET",
            "namespace": ns,
            "secret_name": name,
            "user_agent": request.headers.get("User-Agent", ""),
        })
        await self._end_session(session)

        # Return fake secret data (base64 encoded honey tokens)
        import base64
        fake_data = {
            "db-credentials": {"username": base64.b64encode(b"db_admin").decode(), "password": base64.b64encode(b"S3cret!Pr0d#2024").decode()},
            "aws-credentials": {"AWS_ACCESS_KEY_ID": base64.b64encode(b"AKIAIOSFODNN7EXAMPLE").decode(), "AWS_SECRET_ACCESS_KEY": base64.b64encode(b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY").decode()},
            "tls-cert-prod": {"tls.crt": base64.b64encode(b"-----BEGIN CERTIFICATE-----\nMIIFake...\n-----END CERTIFICATE-----").decode(), "tls.key": base64.b64encode(b"-----BEGIN PRIVATE KEY-----\nMIIFake...\n-----END PRIVATE KEY-----").decode()},
        }
        return web.json_response({
            "kind": "Secret",
            "apiVersion": "v1",
            "metadata": {"name": name, "namespace": ns},
            "data": fake_data.get(name, {"token": base64.b64encode(b"fake-service-account-token").decode()}),
            "type": "Opaque",
        })

    # ── Nodes ─────────────────────────────────────────────────────────────

    async def _handle_nodes(self, request: web.Request) -> web.Response:
        src_ip = request.remote
        session = await self._create_session(src_ip, 0, self.config.port)
        await self._log(session, EventType.REQUEST, {"endpoint": "/api/v1/nodes", "user_agent": request.headers.get("User-Agent", "")})
        await self._end_session(session)
        return web.json_response(_fake_nodes())

    # ── Service Accounts ──────────────────────────────────────────────────

    async def _handle_serviceaccounts(self, request: web.Request) -> web.Response:
        src_ip = request.remote
        ns = request.match_info["ns"]
        session = await self._create_session(src_ip, 0, self.config.port)
        await self._log(session, EventType.REQUEST, {"endpoint": f"/api/v1/namespaces/{ns}/serviceaccounts", "namespace": ns, "user_agent": request.headers.get("User-Agent", "")})
        await self._end_session(session)
        return web.json_response({
            "kind": "ServiceAccountList", "apiVersion": "v1",
            "items": [
                {"metadata": {"name": "default", "namespace": ns}},
                {"metadata": {"name": "admin", "namespace": ns}},
            ],
        })

    # ── Exec (RCE on pod) ─────────────────────────────────────────────────

    async def _handle_exec(self, request: web.Request) -> web.Response:
        src_ip = request.remote
        ns = request.match_info["ns"]
        name = request.match_info["name"]
        session = await self._create_session(src_ip, 0, self.config.port)

        cmd = request.query.getall("command", [])
        container = request.query.get("container", "")

        await self._log(session, EventType.COMMAND, {
            "endpoint": f"/api/v1/namespaces/{ns}/pods/{name}/exec",
            "namespace": ns,
            "pod_name": name,
            "container": container,
            "command": cmd,
            "stdin": request.query.get("stdin", ""),
            "stdout": request.query.get("stdout", ""),
            "tty": request.query.get("tty", ""),
            "user_agent": request.headers.get("User-Agent", ""),
        })
        await self._end_session(session)
        return web.json_response({"kind": "Status", "apiVersion": "v1", "status": "Failure", "message": "upgrade request required", "reason": "BadRequest", "code": 400}, status=400)

    # ── Catch-all ─────────────────────────────────────────────────────────

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
        return web.json_response({"kind": "Status", "apiVersion": "v1", "status": "Failure", "message": "the server could not find the requested resource", "reason": "NotFound", "code": 404}, status=404)
