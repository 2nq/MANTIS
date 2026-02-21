"""Docker API honeypot — emulates unauthenticated Docker Engine API v1.41."""

import json
import uuid
from aiohttp import web
from ..models import EventType
from . import BaseHoneypotService

# Fake Docker Engine metadata
_DOCKER_VERSION = "20.10.24"
_API_VERSION = "1.41"
_DEFAULT_HOSTNAME = "prod-docker-01"
_GO_VERSION = "go1.19.13"
_OS_TYPE = "linux"
_ARCH = "amd64"
_KERNEL = "5.15.0-88-generic"


def _fake_version(hostname: str) -> dict:
    return {
        "Platform": {"Name": "Docker Engine - Community"},
        "Components": [
            {
                "Name": "Engine",
                "Version": _DOCKER_VERSION,
                "Details": {
                    "ApiVersion": _API_VERSION,
                    "Arch": _ARCH,
                    "BuildTime": "2023-09-06T21:58:35.000000000+00:00",
                    "Experimental": "false",
                    "GitCommit": "311b9ff",
                    "GoVersion": _GO_VERSION,
                    "KernelVersion": _KERNEL,
                    "MinAPIVersion": "1.12",
                    "Os": _OS_TYPE,
                },
            }
        ],
        "Version": _DOCKER_VERSION,
        "ApiVersion": _API_VERSION,
        "MinAPIVersion": "1.12",
        "GitCommit": "311b9ff",
        "GoVersion": _GO_VERSION,
        "Os": _OS_TYPE,
        "Arch": _ARCH,
        "KernelVersion": _KERNEL,
        "BuildTime": "2023-09-06T21:58:35.000000000+00:00",
    }


def _fake_info(hostname: str) -> dict:
    return {
        "ID": "XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX",
        "Containers": 3,
        "ContainersRunning": 2,
        "ContainersPaused": 0,
        "ContainersStopped": 1,
        "Images": 12,
        "Driver": "overlay2",
        "MemTotal": 8355520512,
        "Name": hostname,
        "ServerVersion": _DOCKER_VERSION,
        "OperatingSystem": "Ubuntu 22.04.3 LTS",
        "OSType": _OS_TYPE,
        "Architecture": "x86_64",
        "NCPU": 4,
        "KernelVersion": _KERNEL,
        "DockerRootDir": "/var/lib/docker",
        "HttpProxy": "",
        "HttpsProxy": "",
        "NoProxy": "",
        "Labels": [],
        "ExperimentalBuild": False,
        "LiveRestoreEnabled": False,
    }


def _fake_images() -> list[dict]:
    return [
        {
            "Containers": -1,
            "Created": 1693987200,
            "Id": "sha256:a]d5e10b226f3c928a4dbb56c3e4e4db58a0d0e tried9e0a6b0f",
            "Labels": None,
            "ParentId": "",
            "RepoDigests": ["alpine@sha256:abcdef1234567890"],
            "RepoTags": ["alpine:latest"],
            "SharedSize": -1,
            "Size": 7340032,
        },
        {
            "Containers": -1,
            "Created": 1693900800,
            "Id": "sha256:b1e4c3f2a8d9e7c6b5a4f3e2d1c0b9a8f7e6d5c4",
            "Labels": None,
            "ParentId": "",
            "RepoDigests": ["ubuntu@sha256:fedcba0987654321"],
            "RepoTags": ["ubuntu:22.04"],
            "SharedSize": -1,
            "Size": 77799936,
        },
    ]


class DockerAPIHoneypot(BaseHoneypotService):
    service_name = "docker"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._app = None
        self._runner = None

    async def start(self):
        port = self.config.port
        self._app = web.Application()
        self._app.router.add_get("/_ping", self._handle_ping)
        self._app.router.add_get("/version", self._handle_version)
        self._app.router.add_get("/v{ver}/version", self._handle_version)
        self._app.router.add_get("/info", self._handle_info)
        self._app.router.add_get("/v{ver}/info", self._handle_info)
        self._app.router.add_get("/containers/json", self._handle_containers_list)
        self._app.router.add_get("/v{ver}/containers/json", self._handle_containers_list)
        self._app.router.add_post("/containers/create", self._handle_container_create)
        self._app.router.add_post("/v{ver}/containers/create", self._handle_container_create)
        self._app.router.add_post("/containers/{id}/start", self._handle_container_start)
        self._app.router.add_post("/v{ver}/containers/{id}/start", self._handle_container_start)
        self._app.router.add_get("/images/json", self._handle_images_list)
        self._app.router.add_get("/v{ver}/images/json", self._handle_images_list)
        self._app.router.add_post("/images/create", self._handle_image_create)
        self._app.router.add_post("/v{ver}/images/create", self._handle_image_create)
        # Catch-all for any other path
        self._app.router.add_route("*", "/{path:.*}", self._handle_catchall)

        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "0.0.0.0", port)
        await site.start()
        self.logger.info("Docker API honeypot listening on port %d", port)

    async def stop(self):
        if self._runner:
            await self._runner.cleanup()
        self.logger.info("Docker API service stopped")

    def _hostname(self) -> str:
        return self.config.extra.get("hostname", _DEFAULT_HOSTNAME)

    # ── Endpoints ──────────────────────────────────────────────────────────

    async def _handle_ping(self, request: web.Request) -> web.Response:
        src_ip = request.remote
        session = await self._create_session(src_ip, 0, self.config.port)
        await self._log(session, EventType.REQUEST, {
            "endpoint": "/_ping",
            "method": "GET",
            "user_agent": request.headers.get("User-Agent", ""),
        })
        await self._end_session(session)
        return web.Response(text="OK", content_type="text/plain")

    async def _handle_version(self, request: web.Request) -> web.Response:
        src_ip = request.remote
        session = await self._create_session(src_ip, 0, self.config.port)
        await self._log(session, EventType.REQUEST, {
            "endpoint": "/version",
            "method": "GET",
            "user_agent": request.headers.get("User-Agent", ""),
        })
        await self._end_session(session)
        return web.json_response(_fake_version(self._hostname()))

    async def _handle_info(self, request: web.Request) -> web.Response:
        src_ip = request.remote
        session = await self._create_session(src_ip, 0, self.config.port)
        await self._log(session, EventType.REQUEST, {
            "endpoint": "/info",
            "method": "GET",
            "user_agent": request.headers.get("User-Agent", ""),
        })
        await self._end_session(session)
        return web.json_response(_fake_info(self._hostname()))

    async def _handle_containers_list(self, request: web.Request) -> web.Response:
        src_ip = request.remote
        session = await self._create_session(src_ip, 0, self.config.port)
        await self._log(session, EventType.REQUEST, {
            "endpoint": "/containers/json",
            "method": "GET",
            "user_agent": request.headers.get("User-Agent", ""),
        })
        await self._end_session(session)
        return web.json_response([])

    async def _handle_container_create(self, request: web.Request) -> web.Response:
        src_ip = request.remote
        session = await self._create_session(src_ip, 0, self.config.port)

        body = {}
        try:
            body = await request.json()
        except Exception:
            pass

        image = body.get("Image", "")
        cmd = body.get("Cmd", [])
        entrypoint = body.get("Entrypoint", [])
        mounts = body.get("Mounts", body.get("HostConfig", {}).get("Binds", []))
        env = body.get("Env", [])

        await self._log(session, EventType.COMMAND, {
            "endpoint": "/containers/create",
            "image": image,
            "cmd": cmd,
            "entrypoint": entrypoint,
            "mounts": mounts,
            "env": env,
            "user_agent": request.headers.get("User-Agent", ""),
            "raw_body": json.dumps(body)[:4096],
        })
        await self._end_session(session)

        container_id = uuid.uuid4().hex[:64]
        return web.json_response(
            {"Id": container_id, "Warnings": []},
            status=201,
        )

    async def _handle_container_start(self, request: web.Request) -> web.Response:
        src_ip = request.remote
        session = await self._create_session(src_ip, 0, self.config.port)
        container_id = request.match_info.get("id", "unknown")

        await self._log(session, EventType.COMMAND, {
            "endpoint": f"/containers/{container_id}/start",
            "container_id": container_id,
            "user_agent": request.headers.get("User-Agent", ""),
        })
        await self._end_session(session)
        return web.Response(status=204)

    async def _handle_images_list(self, request: web.Request) -> web.Response:
        src_ip = request.remote
        session = await self._create_session(src_ip, 0, self.config.port)
        await self._log(session, EventType.REQUEST, {
            "endpoint": "/images/json",
            "method": "GET",
            "user_agent": request.headers.get("User-Agent", ""),
        })
        await self._end_session(session)
        return web.json_response(_fake_images())

    async def _handle_image_create(self, request: web.Request) -> web.Response:
        src_ip = request.remote
        session = await self._create_session(src_ip, 0, self.config.port)

        from_image = request.query.get("fromImage", "")
        tag = request.query.get("tag", "latest")

        await self._log(session, EventType.COMMAND, {
            "endpoint": "/images/create",
            "from_image": from_image,
            "tag": tag,
            "user_agent": request.headers.get("User-Agent", ""),
        })
        await self._end_session(session)

        # Docker pull returns streamed JSON status lines
        pull_status = json.dumps({"status": f"Pulling from library/{from_image or 'unknown'}"}) + "\n"
        pull_status += json.dumps({"status": "Digest: sha256:" + uuid.uuid4().hex}) + "\n"
        pull_status += json.dumps({"status": f"Status: Downloaded newer image for {from_image}:{tag}"}) + "\n"
        return web.Response(text=pull_status, content_type="application/json")

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
            "headers": dict(request.headers),
            "body": body[:4096] if body else "",
            "user_agent": request.headers.get("User-Agent", ""),
        })
        await self._end_session(session)
        return web.json_response({"message": "page not found"}, status=404)
