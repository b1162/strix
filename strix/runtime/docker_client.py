"""StrixDockerSandboxClient — preserves the image's ENTRYPOINT and adds
NET_ADMIN/NET_RAW capabilities + host-gateway.

The SDK's ``DockerSandboxClient._create_container`` does not expose a hook for
extending ``create_kwargs`` before ``containers.create`` is called. We subclass
and reimplement the method body verbatim from the SDK source, with three
deltas:

1. Drop the SDK's ``entrypoint=["tail"]`` override; supply ``["tail", "-f",
   "/dev/null"]`` as ``command`` instead. This lets our image's
   ``docker-entrypoint.sh`` actually run — without it, ``caido-cli`` never
   starts inside the container and ``bootstrap_caido`` retries against a
   dead port.
2. Append NET_ADMIN/NET_RAW to ``cap_add`` (required by ``nmap -sS`` and
   other raw-socket tools).
3. Add ``host.docker.internal`` → host-gateway to ``extra_hosts`` so the
   agent can reach host-served apps.

Pinned to ``openai-agents==0.14.6``. Bumping the SDK requires
re-merging the parent body. Track upstream for an injection hook.
"""

from __future__ import annotations

import contextlib
import logging
import uuid
from typing import Any

import docker
from agents.sandbox.manifest import Manifest
from agents.sandbox.sandboxes.docker import (
    DockerSandboxClient,
    DockerSandboxClientOptions,
    DockerSandboxSession,
    DockerSandboxSessionState,
    _build_docker_volume_mounts,
    _docker_port_key,
    _manifest_requires_fuse,
    _manifest_requires_sys_admin,
)
from agents.sandbox.session import SandboxSession
from agents.sandbox.snapshot import SnapshotBase, SnapshotSpec, resolve_snapshot
from docker.models.containers import Container  # type: ignore[import-untyped, unused-ignore]
from docker.utils import parse_repository_tag  # type: ignore[import-untyped, unused-ignore]


logger = logging.getLogger(__name__)


class StrixDockerSandboxClient(DockerSandboxClient):
    async def _create_container(  # noqa: PLR0912
        self,
        image: str,
        *,
        manifest: Manifest | None = None,
        exposed_ports: tuple[int, ...] = (),
        session_id: uuid.UUID | None = None,
        use_random_ports: bool = False,
    ) -> Container:
        # ----- BEGIN VERBATIM COPY of DockerSandboxClient._create_container -----
        # SDK ref: src/agents/sandbox/sandboxes/docker.py:1434-1477 (v0.14.6).
        if not self.image_exists(image):
            repo, tag = parse_repository_tag(image)
            self.docker_client.images.pull(repo, tag=tag or None, all_tags=False)

        assert self.image_exists(image)
        environment: dict[str, str] | None = None
        if manifest:
            environment = await manifest.environment.resolve()
        # Strix delta from the SDK body: drop ``entrypoint`` override and
        # supply ``tail -f /dev/null`` as ``command`` so the image's
        # ENTRYPOINT (``docker-entrypoint.sh``) runs setup, then ``exec
        # "$@"`` becomes ``exec tail -f /dev/null`` for the keep-alive.
        # Without this, caido-cli + the in-container CA trust never get
        # initialized.
        create_kwargs: dict[str, Any] = {
            "image": image,
            "detach": True,
            "command": ["tail", "-f", "/dev/null"],
            "environment": environment,
        }
        if manifest is not None:
            docker_mounts = _build_docker_volume_mounts(
                manifest,
                session_id=session_id,
            )
            if docker_mounts:
                create_kwargs["mounts"] = docker_mounts
            if _manifest_requires_fuse(manifest):
                create_kwargs.update(
                    devices=["/dev/fuse"],
                    cap_add=["SYS_ADMIN"],
                    security_opt=["apparmor:unconfined"],
                )
            elif _manifest_requires_sys_admin(manifest):
                create_kwargs.update(
                    cap_add=["SYS_ADMIN"],
                    security_opt=["apparmor:unconfined"],
                )
        if exposed_ports:
            if 48080 in exposed_ports and 8080 in exposed_ports:
                if use_random_ports:
                    create_kwargs["ports"] = {
                        _docker_port_key(48080): ("0.0.0.0", None),
                        _docker_port_key(8080): ("0.0.0.0", None),
                    }
                else:
                    create_kwargs["ports"] = {
                        _docker_port_key(48080): ("0.0.0.0", 48080),
                        _docker_port_key(8080): ("0.0.0.0", 8080),
                    }
            else:
                create_kwargs["ports"] = {
                    _docker_port_key(port): ("0.0.0.0", None if use_random_ports else port)
                    for port in exposed_ports
                }
        # ----- END VERBATIM COPY -----

        # Strix injections — append, don't overwrite, so FUSE/SYS_ADMIN survives.
        cap_add = create_kwargs.setdefault("cap_add", [])
        if not isinstance(cap_add, list):
            cap_add = list(cap_add)
            create_kwargs["cap_add"] = cap_add
        for cap in ("NET_ADMIN", "NET_RAW"):
            if cap not in cap_add:
                cap_add.append(cap)

        extra_hosts = create_kwargs.setdefault("extra_hosts", {})
        extra_hosts["host.docker.internal"] = "host-gateway"

        logger.debug(
            "Creating sandbox container: image=%s caps=%s exposed_ports=%s",
            image,
            cap_add,
            list(exposed_ports),
        )
        container = self.docker_client.containers.create(**create_kwargs)
        logger.info(
            "Sandbox container created: id=%s image=%s",
            container.short_id if hasattr(container, "short_id") else "?",
            image,
        )
        return container

    async def create(
        self,
        *,
        snapshot: SnapshotSpec | SnapshotBase | None = None,
        manifest: Manifest | None = None,
        options: DockerSandboxClientOptions,
    ) -> SandboxSession:
        image = options.image
        session_id = uuid.uuid4()
        manifest = manifest or Manifest()

        try:
            container = await self._create_container(
                image,
                manifest=manifest,
                exposed_ports=options.exposed_ports,
                session_id=session_id,
                use_random_ports=False,
            )
            container.start()
        except docker.errors.APIError as e:
            err_msg = str(e)
            if "port" in err_msg or "address already in use" in err_msg or "bind" in err_msg:
                logger.warning(
                    "Port binding collision detected on host. "
                    "Falling back to dynamic/random ports. Error: %s",
                    err_msg,
                )
                with contextlib.suppress(Exception):
                    container.remove(force=True)

                container = await self._create_container(
                    image,
                    manifest=manifest,
                    exposed_ports=options.exposed_ports,
                    session_id=session_id,
                    use_random_ports=True,
                )
                container.start()
            else:
                raise

        container_id = container.id
        assert container_id is not None
        snapshot_id = str(session_id)
        snapshot_instance = resolve_snapshot(snapshot, snapshot_id)
        state = DockerSandboxSessionState(
            session_id=session_id,
            manifest=manifest,
            image=image,
            snapshot=snapshot_instance,
            container_id=container_id,
            exposed_ports=options.exposed_ports,
        )

        inner = DockerSandboxSession(
            docker_client=self.docker_client,
            container=container,
            state=state,
        )
        return self._wrap_session(inner, instrumentation=self._instrumentation)
