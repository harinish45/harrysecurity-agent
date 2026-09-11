import pytest

from nexus.foundation.secrets import SecretsManager


@pytest.fixture
def vault(tmp_path):
    return SecretsManager(vault_dir=tmp_path)


def test_get_missing_returns_default(vault):
    assert vault.get("nope", "fallback") == "fallback"
    assert vault.get("nope") == ""


def test_set_then_get_round_trips(vault):
    vault.set("api_key", "sk-super-secret-value")
    assert vault.get("api_key") == "sk-super-secret-value"


def test_store_is_encrypted_on_disk(vault, tmp_path):
    vault.set("api_key", "sk-super-secret-value")
    store_path = tmp_path / SecretsManager._STORE_FILE
    raw = store_path.read_bytes()
    assert b"sk-super-secret-value" not in raw


def test_delete_removes_key(vault):
    vault.set("temp", "value")
    vault.delete("temp")
    assert vault.get("temp", "gone") == "gone"


def test_list_keys(vault):
    vault.set("a", "1")
    vault.set("b", "2")
    assert vault.list_keys() == ["a", "b"]


def test_rotate_key_preserves_data(vault):
    vault.set("api_key", "sk-super-secret-value")
    vault.rotate_key()
    assert vault.get("api_key") == "sk-super-secret-value"


def test_wrong_key_falls_back_to_default_not_raise(tmp_path):
    v1 = SecretsManager(vault_dir=tmp_path)
    v1.set("api_key", "sk-super-secret-value")

    (tmp_path / SecretsManager._KEY_FILE).unlink()
    v2 = SecretsManager(vault_dir=tmp_path)  # will generate a brand-new key
    assert v2.get("api_key", "default-on-failure") == "default-on-failure"


def test_master_key_env_derives_a_stable_key(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_MASTER_KEY", "correct-horse-battery-staple")
    v1 = SecretsManager(vault_dir=tmp_path)
    v1.set("api_key", "sk-super-secret-value")

    v2 = SecretsManager(vault_dir=tmp_path)
    assert v2.get("api_key") == "sk-super-secret-value"


def test_explicit_new_master_key_on_rotate(vault):
    vault.set("api_key", "sk-super-secret-value")
    vault.rotate_key(new_master_key="a-brand-new-master-key")
    assert vault.get("api_key") == "sk-super-secret-value"
