"""Per-engagement Neo4j user lifecycle management (M4).

Creates, rotates, and tears down per-engagement Cypher users so that:
  * Each sandbox engagement authenticates with its own Bolt credentials
  * A compromised sandbox can be rotated without affecting other engagements
  * The audit trail shows which engagement wrote which graph nodes

Neo4j Community Edition limitation:
  Community 5.x supports CREATE/DROP USER but NOT roles or fine-grained
  privileges (those are Enterprise-only). All users effectively have
  admin access. The security boundary is:
    1. Label-based engagement scoping (already in _engagement_scope.py)
    2. Credential isolation (this module)
    3. Network segmentation (sandbox-net only)

The per-engagement user pattern still provides:
  - Audit identity (Cypher writes attributed to engagement user)
  - Credential rotation (revoke one engagement without touching others)
  - Blast radius containment (if sandbox leaks creds, only that engagement
    is affected since label scoping prevents cross-engagement reads)
"""

from __future__ import annotations

import logging
import re
import secrets
import string
from dataclasses import dataclass
from typing import Any

log = logging.getLogger(__name__)

# Engagement usernames: decepticon_eng_<slug> (max ~140 chars total)
_USER_PREFIX = "decepticon_eng_"
_USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")


def _sanitize_username(slug: str) -> str:
    """Convert an engagement slug into a safe Neo4j username.
    
    Uses underscores instead of hyphens to avoid Cypher quoting issues.
    """
    clean = re.sub(r"[^a-z0-9._]", "_", slug.lower())
    clean = re.sub(r"^[^a-z0-9]", "a", clean)
    username = f"{_USER_PREFIX}{clean}"
    if len(username) > 128:
        username = username[:128]
    return username


def _quote_username(username: str) -> str:
    """Backtick-quote a username for safe Cypher interpolation.
    
    Neo4j requires backtick quoting for usernames containing special chars.
    Even 'safe' usernames are quoted for defense-in-depth.
    """
    # Escape any backticks in the username itself
    escaped = username.replace("`", "``")
    return f"`{escaped}`"


def generate_bolt_token(length: int = 32) -> str:
    """Generate a cryptographically random Bolt auth token."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


@dataclass(slots=True)
class EngagementUser:
    """Represents a per-engagement Neo4j user."""
    username: str
    password: str
    engagement_slug: str
    bolt_uri: str = "bolt://neo4j:7687"


class Neo4jUserManager:
    """Manage per-engagement Neo4j users via Cypher admin commands.

    Requires a connection as the admin user (neo4j) to create/drop users.
    """

    def __init__(self, driver: Any) -> None:
        self._driver = driver

    @classmethod
    def from_env(cls) -> Neo4jUserManager:
        """Create from DECEPTICON_NEO4J_* env vars (admin credentials)."""
        import neo4j as neo4j_lib
        from .neo4j_store import Neo4jConfig

        config = Neo4jConfig.from_env()
        driver = neo4j_lib.GraphDatabase.driver(
            config.uri, auth=(config.user, config.password)
        )
        return cls(driver)

    def user_exists(self, username: str) -> bool:
        """Check if a Neo4j user exists."""
        try:
            with self._driver.session() as session:
                result = session.run(
                    "SHOW USERS YIELD user WHERE user = $u RETURN count(*) > 0 AS exists",
                    {"u": username}
                )
                record = result.single()
                return record["exists"] if record else False
        except Exception as exc:
            log.warning("user_exists check failed for %s: %s", username, exc)
            return False

    def create_engagement_user(
        self, engagement_slug: str, password: str | None = None
    ) -> EngagementUser:
        """Create a new per-engagement Neo4j user.

        Args:
            engagement_slug: The engagement identifier (e.g. 'acme-corp-2026-06')
            password: Optional explicit password. If None, generates a random token.

        Returns:
            EngagementUser with credentials

        Raises:
            ValueError: If slug is invalid
            RuntimeError: If user creation fails
        """
        username = _sanitize_username(engagement_slug)
        if password is None:
            password = generate_bolt_token()

        quoted = _quote_username(username)
        log.info("Creating Neo4j user %s for engagement %s", username, engagement_slug)

        try:
            with self._driver.session() as session:
                # Backtick-quoted username avoids Cypher parser issues with
                # hyphens and other special chars in engagement slugs.
                session.run(
                    f"CREATE USER {quoted} IF NOT EXISTS "
                    f"SET PASSWORD $pwd CHANGE NOT REQUIRED",
                    {"pwd": password}
                )
        except Exception as exc:
            raise RuntimeError(
                f"Failed to create Neo4j user {username}: {exc}"
            ) from exc

        return EngagementUser(
            username=username,
            password=password,
            engagement_slug=engagement_slug,
        )

    def rotate_password(self, username: str) -> str:
        """Generate a new password for an existing user.

        Returns the new password string.
        """
        new_password = generate_bolt_token()
        quoted = _quote_username(username)

        try:
            with self._driver.session() as session:
                session.run(
                    f"ALTER USER {quoted} SET PASSWORD $pwd CHANGE NOT REQUIRED",
                    {"pwd": new_password}
                )
        except Exception as exc:
            raise RuntimeError(
                f"Failed to rotate password for {username}: {exc}"
            ) from exc

        log.info("Rotated password for Neo4j user %s", username)
        return new_password

    def drop_engagement_user(self, engagement_slug: str) -> bool:
        """Remove a per-engagement user. Returns True if user was dropped."""
        username = _sanitize_username(engagement_slug)
        quoted = _quote_username(username)

        if not self.user_exists(username):
            log.info("User %s does not exist, nothing to drop", username)
            return False

        try:
            with self._driver.session() as session:
                session.run(f"DROP USER {quoted}")
        except Exception as exc:
            raise RuntimeError(
                f"Failed to drop Neo4j user {username}: {exc}"
            ) from exc

        log.info("Dropped Neo4j user %s (engagement: %s)", username, engagement_slug)
        return True

    def list_engagement_users(self) -> list[str]:
        """List all per-engagement users (those starting with the prefix)."""
        try:
            with self._driver.session() as session:
                result = session.run(
                    "SHOW USERS YIELD user WHERE user STARTS WITH $prefix RETURN user",
                    {"prefix": _USER_PREFIX}
                )
                return [record["user"] for record in result]
        except Exception as exc:
            log.warning("list_engagement_users failed: %s", exc)
            return []

    def ensure_engagement_user(
        self, engagement_slug: str
    ) -> EngagementUser:
        """Ensure a per-engagement user exists; create if missing.

        This is the main entry point for the launcher/middleware.
        If the user already exists, rotates the password (fresh token
        per engagement run).
        """
        username = _sanitize_username(engagement_slug)

        if self.user_exists(username):
            new_password = self.rotate_password(username)
            return EngagementUser(
                username=username,
                password=new_password,
                engagement_slug=engagement_slug,
            )

        return self.create_engagement_user(engagement_slug)

    def close(self) -> None:
        """Close the Neo4j driver."""
        self._driver.close()
