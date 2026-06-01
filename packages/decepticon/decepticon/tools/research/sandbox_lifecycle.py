"""Per-engagement sandbox container lifecycle (M4).

Each engagement gets its own sandbox container to eliminate:
  - Cross-engagement filesystem leaks (/tmp, /var/log, tmux state)
  - Background job race conditions
  - OPSEC posture transitions bleeding between engagements

This module wraps the Docker SDK to:
  1. Acquire: spin up a sandbox container with engagement-scoped volumes
  2. Release: tear down the container on engagement completion
  3. Reap: garbage-collect orphaned engagement containers

Deployment note:
  In OSS (single-host), the lifecycle runs on the host where Docker is
  available. In SaaS (Cloud Run), the lifecycle is delegated to the
  platform orchestrator — this module is only invoked in the OSS path.
"""

from __future__ import annotations

import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)

_CONTAINER_PREFIX = "decepticon-sandbox-"
_CONTAINER_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_DEFAULT_TIMEOUT = 120  # seconds to wait for container healthy


@dataclass(slots=True)
class SandboxHandle:
    """Handle to an acquired per-engagement sandbox container."""
    engagement_slug: str
    container_name: str
    container_id: str
    workspace_path: str  # host-side path mounted as /workspace
    daemon_url: str  # http://<container>:9999
    network: str = "sandbox-net"


def _container_name_for(slug: str) -> str:
    """Derive a safe container name from an engagement slug."""
    clean = re.sub(r"[^a-z0-9._-]", "-", slug.lower())
    clean = re.sub(r"^[^a-z0-9]", "a", clean)
    name = f"{_CONTAINER_PREFIX}{clean}"
    if len(name) > 63:
        name = name[:63].rstrip("-")
    return name


class SandboxLifecycle:
    """Manage per-engagement sandbox containers via the Docker SDK.

    This is a host-side control plane — it runs where docker.sock is
    accessible (OSS / local-docker / GCE Spot VMs). In Cloud Run
    multi-container deployments, the equivalent lifecycle is handled
    by the Cloud Run revision manager.
    """

    def __init__(self, docker_client: Any | None = None) -> None:
        if docker_client is None:
            try:
                import docker
                docker_client = docker.from_env()
            except Exception as exc:
                raise RuntimeError(
                    "Docker SDK unavailable — sandbox lifecycle requires "
                    "docker.sock access (OSS/local-docker deployments only)"
                ) from exc
        self._client = docker_client

    def list_engagement_containers(self) -> list[dict[str, Any]]:
        """List all per-engagement sandbox containers (running or stopped)."""
        try:
            containers = self._client.containers.list(
                all=True,
                filters={"name": _CONTAINER_PREFIX}
            )
            return [
                {
                    "name": c.name,
                    "slug": c.name[len(_CONTAINER_PREFIX):],
                    "status": c.status,
                    "id": c.short_id,
                    "created": c.attrs.get("Created", ""),
                }
                for c in containers
            ]
        except Exception as exc:
            log.warning("list_engagement_containers failed: %s", exc)
            return []

    def acquire(
        self,
        engagement_slug: str,
        workspace_host_path: str,
        *,
        image: str | None = None,
        network: str = "sandbox-net",
        mem_limit: str = "4g",
        timeout: int = _DEFAULT_TIMEOUT,
    ) -> SandboxHandle:
        """Spin up a per-engagement sandbox container.

        If a container already exists for this slug and is running,
        returns its handle. If it exists but is stopped, starts it.
        Otherwise creates a fresh one.

        Args:
            engagement_slug: Engagement identifier
            workspace_host_path: Host-side path to mount as /workspace
            image: Sandbox image (defaults to DECEPTICON_SANDBOX_IMAGE env)
            network: Docker network to attach
            mem_limit: Memory cap (e.g. '4g')
            timeout: Seconds to wait for healthy status

        Returns:
            SandboxHandle with connection details
        """
        container_name = _container_name_for(engagement_slug)
        if image is None:
            image = os.environ.get(
                "DECEPTICON_SANDBOX_IMAGE",
                "ghcr.io/purpleailab/decepticon-sandbox:latest"
            )

        # Check if container already exists
        try:
            existing = self._client.containers.get(container_name)
            if existing.status == "running":
                log.info("Reusing running sandbox %s", container_name)
                return SandboxHandle(
                    engagement_slug=engagement_slug,
                    container_name=container_name,
                    container_id=existing.short_id,
                    workspace_path=workspace_host_path,
                    daemon_url=f"http://{container_name}:9999",
                    network=network,
                )
            elif existing.status in ("exited", "paused"):
                log.info("Starting stopped sandbox %s", container_name)
                existing.start()
            else:
                existing.remove(force=True)
                existing = None
        except Exception:
            existing = None

        if existing is None:
            log.info(
                "Creating sandbox %s (image=%s, workspace=%s)",
                container_name, image, workspace_host_path
            )
            container = self._client.containers.run(
                image,
                name=container_name,
                detach=True,
                network=network,
                mem_limit=mem_limit,
                pids_limit=1024,
                security_opt=["no-new-privileges:true"],
                cap_drop=["ALL"],
                cap_add=[
                    "NET_RAW", "NET_ADMIN", "NET_BIND_SERVICE",
                    "SYS_PTRACE", "SETUID", "SETGID", "CHOWN",
                    "DAC_OVERRIDE", "FOWNER", "KILL",
                ],
                volumes={
                    workspace_host_path: {"bind": "/workspace", "mode": "rw"},
                },
                environment={
                    "DECEPTICON_ENGAGEMENT": engagement_slug,
                    "SANDBOX_DAEMON": "1",
                },
                labels={
                    "decepticon.engagement": engagement_slug,
                    "decepticon.component": "sandbox",
                    "decepticon.m4": "true",
                },
            )
        else:
            container = existing

        # Wait for healthy
        deadline = time.time() + timeout
        while time.time() < deadline:
            container.reload()
            if container.status == "running":
                health = (
                    container.attrs.get("State", {}).get("Health", {}).get("Status")
                )
                if health == "healthy":
                    break
                if health is None:
                    # No healthcheck defined — just wait for running
                    break
            time.sleep(2)
        else:
            log.warning(
                "Sandbox %s did not become healthy in %ds (status=%s)",
                container_name, timeout, container.status
            )

        return SandboxHandle(
            engagement_slug=engagement_slug,
            container_name=container_name,
            container_id=container.short_id,
            workspace_path=workspace_host_path,
            daemon_url=f"http://{container_name}:9999",
            network=network,
        )

    def release(self, engagement_slug: str, *, remove_volumes: bool = False) -> bool:
        """Tear down a per-engagement sandbox container.

        Args:
            engagement_slug: Engagement identifier
            remove_volumes: If True, also remove anonymous volumes

        Returns:
            True if container was removed, False if not found
        """
        container_name = _container_name_for(engagement_slug)
        try:
            container = self._client.containers.get(container_name)
            container.stop(timeout=10)
            container.remove(v=remove_volumes)
            log.info("Released sandbox %s", container_name)
            return True
        except Exception as exc:
            if "not found" in str(exc).lower() or "404" in str(exc):
                log.info("Sandbox %s already gone", container_name)
                return False
            raise

    def reap_stale(self, max_age_hours: int = 48) -> list[str]:
        """Remove sandbox containers older than max_age_hours that are stopped.

        Returns list of removed container names.
        """
        removed = []
        now = time.time()
        for info in self.list_engagement_containers():
            if info["status"] != "exited":
                continue
            try:
                container = self._client.containers.get(info["name"])
                finished_at = container.attrs.get("State", {}).get("FinishedAt", "")
                if not finished_at:
                    continue
                # Parse ISO timestamp (Docker format)
                from datetime import datetime, timezone
                try:
                    ft = datetime.fromisoformat(finished_at.replace("Z", "+00:00"))
                    age_hours = (now - ft.timestamp()) / 3600
                except Exception:
                    continue
                if age_hours > max_age_hours:
                    container.remove(v=True)
                    removed.append(info["name"])
                    log.info("Reaped stale sandbox %s (%.1fh old)", info["name"], age_hours)
            except Exception as exc:
                log.warning("Reap failed for %s: %s", info["name"], exc)
        return removed
