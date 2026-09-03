import pytest

from nexus.foundation.auth import (
    AuthenticationError,
    AuthManager,
    AuthorizationError,
    Permission,
    Role,
)
from nexus.foundation.secrets import SecretsManager


@pytest.fixture
def auth(tmp_path, monkeypatch):
    """A fresh AuthManager backed by an isolated vault (never the real
    ~/.nexus one) so tests can't leak into or collide with a real install."""
    vault = SecretsManager(vault_dir=tmp_path)
    monkeypatch.setattr("nexus.foundation.auth.vault", vault)
    return AuthManager()


def test_register_and_authenticate(auth):
    auth.register_user("alice", "correct-horse-battery", Role.OPERATOR)
    session = auth.authenticate("alice", "correct-horse-battery")
    assert session.username == "alice"
    assert session.role == Role.OPERATOR


def test_wrong_password_rejected(auth):
    auth.register_user("alice", "correct-horse-battery", Role.OPERATOR)
    with pytest.raises(AuthenticationError):
        auth.authenticate("alice", "wrong-password")


def test_unknown_user_rejected(auth):
    with pytest.raises(AuthenticationError):
        auth.authenticate("nobody", "whatever-password")


def test_short_password_rejected(auth):
    with pytest.raises(Exception):
        auth.register_user("bob", "short", Role.VIEWER)


def test_duplicate_username_rejected(auth):
    auth.register_user("alice", "correct-horse-battery", Role.OPERATOR)
    with pytest.raises(Exception):
        auth.register_user("alice", "another-password-12", Role.VIEWER)


def test_account_locks_after_max_failed_attempts(auth):
    auth.register_user("alice", "correct-horse-battery", Role.OPERATOR)
    for _ in range(5):
        with pytest.raises(AuthenticationError):
            auth.authenticate("alice", "wrong-password")
    with pytest.raises(AuthenticationError, match="locked"):
        auth.authenticate("alice", "correct-horse-battery")


def test_role_permissions_are_enforced(auth):
    auth.register_user("viewer", "correct-horse-battery", Role.VIEWER)
    session = auth.authenticate("viewer", "correct-horse-battery")

    assert auth.has_permission(session, Permission.REPORT_READ) is True
    assert auth.has_permission(session, Permission.SCAN_CREATE) is False

    with pytest.raises(AuthorizationError):
        auth.require_permission(session, Permission.USER_MANAGE)


def test_admin_has_all_permissions(auth):
    auth.register_user("root", "correct-horse-battery", Role.ADMIN)
    session = auth.authenticate("root", "correct-horse-battery")
    for permission in Permission:
        assert auth.has_permission(session, permission) is True


def test_check_access_denies_none_session(auth):
    assert auth.check_access(None, Permission.REPORT_READ) is False


def test_check_access_allows_permitted_session(auth):
    auth.register_user("analyst", "correct-horse-battery", Role.ANALYST)
    session = auth.authenticate("analyst", "correct-horse-battery")
    assert auth.check_access(session, Permission.REPORT_READ) is True
    assert auth.check_access(session, Permission.SCAN_CREATE) is False


def test_session_validate_and_revoke(auth):
    auth.register_user("alice", "correct-horse-battery", Role.OPERATOR)
    session = auth.authenticate("alice", "correct-horse-battery")

    assert auth.validate_session(session.token) is not None
    auth.revoke_session(session.token)
    assert auth.validate_session(session.token) is None


def test_validate_session_rejects_unknown_token(auth):
    assert auth.validate_session("not-a-real-token") is None


def test_users_persist_across_manager_instances(tmp_path, monkeypatch):
    vault = SecretsManager(vault_dir=tmp_path)
    monkeypatch.setattr("nexus.foundation.auth.vault", vault)

    AuthManager().register_user("alice", "correct-horse-battery", Role.OPERATOR)

    # A brand-new AuthManager instance (simulating a fresh process) must
    # still see the user, since accounts are persisted in the vault, not
    # held only in memory.
    second = AuthManager()
    session = second.authenticate("alice", "correct-horse-battery")
    assert session.username == "alice"
