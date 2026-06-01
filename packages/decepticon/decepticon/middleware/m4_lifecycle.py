"""M4 Lifecycle Middleware — per-engagement Neo4j user + sandbox provisioning.

Runs in before_agent to:
  1. Ensure a per-engagement Neo4j user exists (create or rotate password)
  2. Export the engagement-scoped Bolt credentials as env vars so
     Neo4jStore picks them up automatically
  3. Optionally acquire a per-engagement sandbox container (OSS path only)

This middleware is opt-in via DECEPTICON_M4_ENABLED=1 in .env.
When disabled, the stack falls back to the shared neo4j user (Phase 1 behavior).
"""

from __future__ import annotations

import logging
import os
from typing import Any

from langchain.agents.middleware import AgentMiddleware

log = logging.getLogger(__name__)

_FALSY = frozenset({"", "0", "false", "no", "off"})


def _m4_enabled() -> bool:
    return os.environ.get("DECEPTICON_M4_ENABLED", "").strip().lower() not in _FALSY


class M4LifecycleMiddleware(AgentMiddleware):
    """Provision per-engagement Neo4j users and sandbox containers.

    Activates when DECEPTICON_M4_ENABLED=1 and an engagement_name is
    present in the run config. On before_agent:

      1. Connect as Neo4j admin (neo4j user)
      2. Create or rotate the engagement user password
      3. Set DECEPTICON_NEO4J_USER / DECEPTICON_NEO4J_PASSWORD env vars
         so Neo4jStore.from_env() picks up the scoped credentials
      4. (If DECEPTICON_M4_SANDBOX_LIFECYCLE=1) Acquire a per-engagement
         sandbox container and update SAAS_SANDBOX_URL

    On after_agent (optional): no teardown — containers persist across
    runs. Teardown happens via the CLI (`decepticon engagement close`).
    """

    def __init__(self) -> None:
        super().__init__()
        self._provisioned: set[str] = set()

    def before_agent(self, state: Any, runtime: Any) -> dict[str, Any] | None:
        if not _m4_enabled():
            return None

        # Get engagement slug from state or config
        slug = None
        if hasattr(state, "get"):
            slug = state.get("engagement_name")
        if not slug:
            try:
                from langgraph.config import get_config
                cfg = get_config()
                slug = cfg.get("configurable", {}).get("engagement_name")
            except Exception:
                pass

        if not slug:
            return None  # No engagement context — skip M4

        if slug in self._provisioned:
            return None  # Already provisioned this session

        # --- Neo4j user lifecycle ---
        try:
            from decepticon.tools.research.neo4j_lifecycle import Neo4jUserManager
            mgr = Neo4jUserManager.from_env()
            user = mgr.ensure_engagement_user(slug)

            # Override env vars so Neo4jStore picks up scoped credentials
            os.environ["DECEPTICON_NEO4J_USER"] = user.username
            os.environ["DECEPTICON_NEO4J_PASSWORD"] = user.password

            log.info(
                "M4: Neo4j user %s provisioned for engagement %s",
                user.username, slug
            )
            mgr.close()
        except Exception as exc:
            log.error("M4: Neo4j user provisioning failed: %s", exc)
            # Fall through — don't block the engagement

        # --- Sandbox lifecycle (optional) ---
        if os.environ.get("DECEPTICON_M4_SANDBOX_LIFECYCLE", "").strip().lower() not in _FALSY:
            try:
                from decepticon.tools.research.sandbox_lifecycle import SandboxLifecycle
                lifecycle = SandboxLifecycle()
                workspace = os.environ.get(
                    "DECEPTICON_ENGAGEMENT_WORKSPACE",
                    os.path.expanduser(f"~/.decepticon/workspace/{slug}")
                )
                os.makedirs(workspace, exist_ok=True)
                handle = lifecycle.acquire(slug, workspace)
                os.environ["SAAS_SANDBOX_URL"] = handle.daemon_url
                log.info(
                    "M4: Sandbox %s acquired (daemon=%s)",
                    handle.container_name, handle.daemon_url
                )
            except Exception as exc:
                log.warning("M4: Sandbox lifecycle failed (non-fatal): %s", exc)

        self._provisioned.add(slug)
        return None

    async def abefore_agent(self, state: Any, runtime: Any) -> dict[str, Any] | None:
        return self.before_agent(state, runtime)
