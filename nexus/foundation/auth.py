"""Real authentication and role-based access control.

Replaces the historical stub (``AuthManager.check_access()`` always returned
``True`` — i.e. no authentication existed at all). Users are persisted,
encrypted at rest, in the secrets vault (:mod:`nexus.foundation.secrets`) so
this doesn't introduce a second plaintext credential store. Sessions are
in-memory and per-process by design — see the docstring on ``AuthManager``
for what that does and doesn't mean for multi-worker deployments.
"""
from __future__ import annotations

import logging
import secrets as _stdlib_secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional

from nexus.foundation.secrets import secrets as vault

logger = logging.getLogger("nexus.auth")

try:
    import bcrypt

    _HAVE_BCRYPT = True
except ImportError:  # pragma: no cover
    _HAVE_BCRYPT = False

try:
    import pyotp

    _HAVE_TOTP = True
except ImportError:  # pragma: no cover
    _HAVE_TOTP = False

_USERS_VAULT_KEY = "auth.users.v1"


class AuthError(Exception):
    pass


class AuthenticationError(AuthError):
    pass


class AuthorizationError(AuthError):
    pass


class Role(str, Enum):
    ADMIN = "admin"        # full control, including user management
    OPERATOR = "operator"  # can launch/stop scans, read/export reports
    ANALYST = "analyst"    # read-only on scans/reports, no execution
    VIEWER = "viewer"      # dashboard read-only


class Permission(str, Enum):
    SCAN_CREATE = "scan:create"
    SCAN_STOP = "scan:stop"
    REPORT_READ = "report:read"
    REPORT_EXPORT = "report:export"
    CONFIG_READ = "config:read"
    CONFIG_WRITE = "config:write"
    AUDIT_READ = "audit:read"
    USER_MANAGE = "user:manage"


ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.ADMIN: frozenset(Permission),
    Role.OPERATOR: frozenset({
        Permission.SCAN_CREATE, Permission.SCAN_STOP,
        Permission.REPORT_READ, Permission.REPORT_EXPORT,
        Permission.CONFIG_READ,
    }),
    Role.ANALYST: frozenset({
        Permission.REPORT_READ, Permission.REPORT_EXPORT, Permission.CONFIG_READ,
    }),
    Role.VIEWER: frozenset({Permission.REPORT_READ}),
}

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15
SESSION_TTL_HOURS = 8


@dataclass
class User:
    user_id: str
    username: str
    role: Role
    password_hash: str
    created_at: str
    is_active: bool = True
    totp_secret: Optional[str] = None
    failed_attempts: int = 0
    locked_until: Optional[str] = None

    def has_permission(self, permission: Permission) -> bool:
        return self.is_active and permission in ROLE_PERMISSIONS.get(self.role, frozenset())

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        d["role"] = self.role.value
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "User":
        d = dict(d)
        d["role"] = Role(d["role"])
        return cls(**d)


@dataclass
class Session:
    token: str
    user_id: str
    username: str
    role: Role
    created_at: datetime
    expires_at: datetime

    @property
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) >= self.expires_at


class AuthManager:
    """Password + optional-TOTP authentication with role-based permissions.

    Users are persisted encrypted in the secrets vault, so accounts survive
    process restarts. Sessions are held in memory only: this is correct for
    the single-process dashboard NEXUS ships today, but a deployment that
    runs multiple dashboard worker processes behind a load balancer would
    need a shared session store (e.g. Redis, which is already a Docker
    Compose service here) for session validation to work across workers.
    That wiring is not implemented — flagging it rather than pretending
    single-process sessions scale horizontally for free.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}
        self._lock = threading.RLock()

    # ── persistence ──────────────────────────────────────────────────
    def _load_users(self) -> dict[str, dict]:
        raw = vault.get(_USERS_VAULT_KEY, "")
        if not raw:
            return {}
        import json

        try:
            return json.loads(raw)
        except ValueError:
            logger.error("Corrupt user store in vault; treating as empty.")
            return {}

    def _save_users(self, users: dict[str, dict]) -> None:
        import json

        vault.set(_USERS_VAULT_KEY, json.dumps(users, sort_keys=True))

    # ── password hashing ────────────────────────────────────────────
    @staticmethod
    def _hash_password(password: str) -> str:
        if not _HAVE_BCRYPT:
            raise AuthError("bcrypt is required for password hashing. Install it with: pip install bcrypt")
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    @staticmethod
    def _verify_password(password: str, password_hash: str) -> bool:
        if not _HAVE_BCRYPT:
            return False
        try:
            return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
        except ValueError:
            return False

    # ── user management ─────────────────────────────────────────────
    def register_user(self, username: str, password: str, role: Role) -> User:
        if len(password) < 12:
            raise AuthError("Password must be at least 12 characters.")
        users = self._load_users()
        if username in users:
            raise AuthError(f"User '{username}' already exists.")
        user = User(
            user_id=_stdlib_secrets.token_urlsafe(12),
            username=username,
            role=role,
            password_hash=self._hash_password(password),
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        users[username] = user.to_dict()
        self._save_users(users)
        logger.info("User created: %s (role=%s)", username, role.value)
        return user

    def get_user(self, username: str) -> Optional[User]:
        raw = self._load_users().get(username)
        return User.from_dict(raw) if raw else None

    def enable_totp(self, username: str) -> str:
        """Generate and persist a TOTP secret for a user, returning the
        provisioning secret (caller is responsible for showing it to the
        user, e.g. as a QR code, exactly once)."""
        if not _HAVE_TOTP:
            raise AuthError("pyotp is required for 2FA. Install it with: pip install pyotp")
        users = self._load_users()
        raw = users.get(username)
        if not raw:
            raise AuthError(f"No such user: {username}")
        secret = pyotp.random_base32()
        raw["totp_secret"] = secret
        users[username] = raw
        self._save_users(users)
        return secret

    # ── authentication ──────────────────────────────────────────────
    def authenticate(self, username: str, password: str, totp_code: Optional[str] = None) -> Session:
        users = self._load_users()
        raw = users.get(username)
        if not raw:
            # Do a dummy hash so a nonexistent-username response takes
            # roughly the same time as a wrong-password one (defeats a
            # trivial user-enumeration timing side-channel).
            if _HAVE_BCRYPT:
                self._verify_password("decoy-password-for-timing", self._hash_password("decoy-password-for-timing"))
            raise AuthenticationError("Invalid username or password.")

        user = User.from_dict(raw)

        if user.locked_until:
            locked_until = datetime.fromisoformat(user.locked_until)
            if datetime.now(timezone.utc) < locked_until:
                raise AuthenticationError(f"Account locked until {user.locked_until}.")

        if not user.is_active:
            raise AuthenticationError("Account is disabled.")

        if not self._verify_password(password, user.password_hash):
            user.failed_attempts += 1
            if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
                user.locked_until = (datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
                logger.warning("User %s locked after %d failed attempts.", username, user.failed_attempts)
            raw = user.to_dict()
            users[username] = raw
            self._save_users(users)
            raise AuthenticationError("Invalid username or password.")

        if user.totp_secret:
            if not totp_code or not _HAVE_TOTP or not pyotp.TOTP(user.totp_secret).verify(totp_code, valid_window=1):
                raise AuthenticationError("Invalid or missing 2FA code.")

        user.failed_attempts = 0
        user.locked_until = None
        users[username] = user.to_dict()
        self._save_users(users)

        return self._create_session(user)

    def _create_session(self, user: User) -> Session:
        now = datetime.now(timezone.utc)
        session = Session(
            token=_stdlib_secrets.token_urlsafe(32),
            user_id=user.user_id,
            username=user.username,
            role=user.role,
            created_at=now,
            expires_at=now + timedelta(hours=SESSION_TTL_HOURS),
        )
        with self._lock:
            self._sessions[session.token] = session
        return session

    def validate_session(self, token: str) -> Optional[Session]:
        with self._lock:
            session = self._sessions.get(token)
            if session is None:
                return None
            if session.is_expired:
                del self._sessions[token]
                return None
            return session

    def revoke_session(self, token: str) -> None:
        with self._lock:
            self._sessions.pop(token, None)

    def revoke_all_sessions(self, username: str) -> None:
        with self._lock:
            for token, session in list(self._sessions.items()):
                if session.username == username:
                    del self._sessions[token]

    # ── authorization ────────────────────────────────────────────────
    def has_permission(self, session: Session, permission: Permission) -> bool:
        return permission in ROLE_PERMISSIONS.get(session.role, frozenset())

    def require_permission(self, session: Session, permission: Permission) -> None:
        if not self.has_permission(session, permission):
            raise AuthorizationError(f"User '{session.username}' lacks permission '{permission.value}'.")

    def check_access(self, session: Optional[Session], permission: Permission) -> bool:
        """Boolean form of ``require_permission`` for callers that want a
        check rather than an exception. Unauthenticated (``None``) sessions
        are always denied — this is the one-line summary of the whole file:
        the old stub returned ``True`` unconditionally here."""
        if session is None:
            return False
        return self.has_permission(session, permission)


auth_manager = AuthManager()
