# -*- coding: utf-8 -*-

"""
Tests for api_key_store.py.

These tests verify generated key persistence, hashing, scope enforcement,
and backward compatibility with the original PROXY_API_KEY.
"""

import json

import pytest

from kiro.api_key_store import ENV_KEY_ID, ApiKeyStore


class TestApiKeyStoreCreateAndVerify:
    """Tests for creating and validating generated API keys."""

    def test_create_key_stores_hash_not_plaintext(self, tmp_path):
        """
        What it does: Creates a generated key and inspects the persisted file.
        Purpose: Ensure plaintext generated keys are not stored on disk.
        """
        print("\n=== Test: Generated API key is hashed at rest ===")

        # Arrange
        store_file = tmp_path / "api_keys.json"
        store = ApiKeyStore(str(store_file))

        # Act
        plaintext, record = store.create_key("Test client", ["api"])
        persisted = json.loads(store_file.read_text())

        # Assert
        assert plaintext.startswith("kgw_")
        assert record["name"] == "Test client"
        assert persisted["keys"][0]["key_hash"] != plaintext
        assert plaintext not in store_file.read_text()

    def test_generated_key_with_api_scope_validates_for_api(self, tmp_path):
        """
        What it does: Validates a generated API key with api scope.
        Purpose: Ensure generated keys can authenticate API traffic.
        """
        print("\n=== Test: Generated API key validates for api scope ===")

        # Arrange
        store = ApiKeyStore(str(tmp_path / "api_keys.json"))
        plaintext, record = store.create_key("API client", ["api"])

        # Act
        validation = store.verify_key(plaintext, required_scope="api")

        # Assert
        assert validation.valid is True
        assert validation.key_id == record["id"]
        assert validation.name == "API client"

    def test_generated_key_without_admin_scope_rejects_admin(self, tmp_path):
        """
        What it does: Validates an API-only key against admin scope.
        Purpose: Ensure API-only keys cannot access admin APIs.
        """
        print("\n=== Test: API-only key rejects admin scope ===")

        # Arrange
        store = ApiKeyStore(str(tmp_path / "api_keys.json"))
        plaintext, _record = store.create_key("API client", ["api"])

        # Act
        validation = store.verify_key(plaintext, required_scope="admin")

        # Assert
        assert validation.valid is False

    def test_admin_scope_satisfies_api_scope(self, tmp_path):
        """
        What it does: Validates an admin key against api scope.
        Purpose: Ensure admin keys can also call gateway API endpoints.
        """
        print("\n=== Test: Admin key satisfies api scope ===")

        # Arrange
        store = ApiKeyStore(str(tmp_path / "api_keys.json"))
        plaintext, _record = store.create_key("Admin client", ["admin"])

        # Act
        validation = store.verify_key(plaintext, required_scope="api")

        # Assert
        assert validation.valid is True
        assert validation.scopes == ["admin"]

    def test_env_proxy_api_key_validates_for_admin(self, tmp_path, monkeypatch):
        """
        What it does: Validates the legacy PROXY_API_KEY against admin scope.
        Purpose: Preserve backward compatibility for existing deployments.
        """
        print("\n=== Test: PROXY_API_KEY validates for admin scope ===")

        # Arrange
        monkeypatch.setattr("kiro.config.PROXY_API_KEY", "legacy-admin-key")
        store = ApiKeyStore(str(tmp_path / "api_keys.json"))

        # Act
        validation = store.verify_key("legacy-admin-key", required_scope="admin")

        # Assert
        assert validation.valid is True
        assert validation.key_id == ENV_KEY_ID
        assert validation.scopes == ["api", "admin"]


class TestApiKeyStoreMutations:
    """Tests for disabling and deleting generated API keys."""

    def test_disabled_key_no_longer_validates(self, tmp_path):
        """
        What it does: Disables a generated key and tries to validate it.
        Purpose: Ensure disabled keys immediately stop working.
        """
        print("\n=== Test: Disabled generated key rejects validation ===")

        # Arrange
        store = ApiKeyStore(str(tmp_path / "api_keys.json"))
        plaintext, record = store.create_key("Client", ["api"])

        # Act
        updated = store.set_enabled(record["id"], False)
        validation = store.verify_key(plaintext, required_scope="api")

        # Assert
        assert updated["enabled"] is False
        assert validation.valid is False

    def test_deleted_key_no_longer_validates(self, tmp_path):
        """
        What it does: Deletes a generated key and tries to validate it.
        Purpose: Ensure deleted keys are removed from the key store.
        """
        print("\n=== Test: Deleted generated key rejects validation ===")

        # Arrange
        store = ApiKeyStore(str(tmp_path / "api_keys.json"))
        plaintext, record = store.create_key("Client", ["api"])

        # Act
        store.delete_key(record["id"])
        validation = store.verify_key(plaintext, required_scope="api")

        # Assert
        assert validation.valid is False
        assert store.list_keys(include_env_key=False) == []

    def test_environment_key_cannot_be_disabled_or_deleted(self, tmp_path):
        """
        What it does: Attempts to mutate the immutable environment key.
        Purpose: Ensure runtime API key management cannot remove PROXY_API_KEY.
        """
        print("\n=== Test: Environment API key is immutable ===")

        # Arrange
        store = ApiKeyStore(str(tmp_path / "api_keys.json"))

        # Act / Assert
        with pytest.raises(ValueError):
            store.set_enabled(ENV_KEY_ID, False)
        with pytest.raises(ValueError):
            store.delete_key(ENV_KEY_ID)

    def test_invalid_scope_raises_value_error(self, tmp_path):
        """
        What it does: Creates a key with an unsupported scope.
        Purpose: Ensure scope validation prevents ambiguous permissions.
        """
        print("\n=== Test: Invalid API key scope is rejected ===")

        # Arrange
        store = ApiKeyStore(str(tmp_path / "api_keys.json"))

        # Act / Assert
        with pytest.raises(ValueError):
            store.create_key("Bad scope", ["api", "root"])
