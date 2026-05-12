"""
Unit tests for gateway-managed Kiro account SQLite storage.
"""

import json
import sqlite3
from datetime import datetime, timezone

import pytest

from kiro.account_sqlite_store import (
    KiroAccountSqliteStore,
    KiroAccountSqliteStoreError,
    build_kiro_account_id,
)


class TestKiroAccountSqliteStore:
    """Tests for multi-account SQLite credential storage."""

    def test_upsert_token_creates_account_row(self, tmp_path):
        """
        What it does: Stores one social Kiro token in the account database.
        Purpose: Ensure browser OAuth can persist accounts without JSON files.
        """
        print("\n=== Test: Store Kiro OAuth token in account SQLite ===")

        # Arrange
        db_path = tmp_path / "kiro_accounts.sqlite3"
        store = KiroAccountSqliteStore(str(db_path))
        token = {
            "accessToken": "access",
            "refreshToken": "refresh",
            "expiresAt": "2099-01-01T00:00:00+00:00",
            "authMethod": "social",
            "provider": "Google",
            "profileArn": "arn:profile/test",
        }

        # Act
        record = store.upsert_token(token)

        # Assert
        assert db_path.exists()
        assert record["id"] == build_kiro_account_id(token)
        assert record["token"]["accessToken"] == "access"
        assert record["profile_arn"] == "arn:profile/test"

    def test_upsert_token_updates_existing_account_without_duplicate_rows(self, tmp_path):
        """
        What it does: Saves the same account ID twice.
        Purpose: Ensure repeated login refreshes the row instead of creating duplicates.
        """
        print("\n=== Test: Upsert Kiro account row ===")

        # Arrange
        db_path = tmp_path / "kiro_accounts.sqlite3"
        store = KiroAccountSqliteStore(str(db_path))
        token = {
            "accessToken": "access-1",
            "refreshToken": "refresh",
            "expiresAt": "2099-01-01T00:00:00+00:00",
            "authMethod": "social",
            "provider": "Google",
        }
        first = store.upsert_token(token)
        updated = dict(token)
        updated["accessToken"] = "access-2"

        # Act
        second = store.upsert_token(updated, account_id=first["id"])

        # Assert
        assert second["id"] == first["id"]
        assert second["token"]["accessToken"] == "access-2"
        assert len(store.list_accounts()) == 1

    def test_import_json_token_loads_idc_registration(self, tmp_path):
        """
        What it does: Imports legacy Kiro IDE token and sibling IdC registration JSON files.
        Purpose: Ensure old single-file setups can migrate into multi-account SQLite.
        """
        print("\n=== Test: Import legacy Kiro IDE JSON into account SQLite ===")

        # Arrange
        token_path = tmp_path / "kiro-auth-token.json"
        registration_path = tmp_path / "client-hash.json"
        token_path.write_text(
            json.dumps({
                "accessToken": "access",
                "refreshToken": "refresh",
                "expiresAt": "2099-01-01T00:00:00+00:00",
                "clientIdHash": "client-hash",
                "authMethod": "IdC",
                "provider": "BuilderId",
                "region": "us-east-1",
            }),
            encoding="utf-8",
        )
        registration_path.write_text(
            json.dumps({
                "clientId": "client-id",
                "clientSecret": "client-secret",
                "expiresAt": "2099-01-01T00:00:00+00:00",
            }),
            encoding="utf-8",
        )
        store = KiroAccountSqliteStore(str(tmp_path / "kiro_accounts.sqlite3"))

        # Act
        record = store.import_json_token(str(token_path))

        # Assert
        assert record["auth_method"] == "IdC"
        assert record["registration"]["clientId"] == "client-id"
        assert record["token"]["clientIdHash"] == "client-hash"

    def test_update_runtime_tokens_preserves_registration(self, tmp_path):
        """
        What it does: Updates refreshed token fields for an IdC account.
        Purpose: Ensure token refresh does not lose registration metadata.
        """
        print("\n=== Test: Update runtime tokens in account SQLite ===")

        # Arrange
        store = KiroAccountSqliteStore(str(tmp_path / "kiro_accounts.sqlite3"))
        record = store.upsert_token(
            token={
                "accessToken": "old-access",
                "refreshToken": "old-refresh",
                "expiresAt": "2099-01-01T00:00:00+00:00",
                "clientIdHash": "client-hash",
                "authMethod": "IdC",
                "provider": "BuilderId",
                "region": "us-east-1",
            },
            registration={"clientId": "client-id", "clientSecret": "client-secret"},
        )

        # Act
        store.update_runtime_tokens(
            account_id=record["id"],
            access_token="new-access",
            refresh_token="new-refresh",
            expires_at=datetime(2099, 1, 2, tzinfo=timezone.utc),
        )

        # Assert
        updated = store.get_account(record["id"])
        assert updated["token"]["accessToken"] == "new-access"
        assert updated["token"]["refreshToken"] == "new-refresh"
        assert updated["registration"]["clientSecret"] == "client-secret"

    def test_upsert_token_requires_refresh_token(self, tmp_path):
        """
        What it does: Attempts to store incomplete token data.
        Purpose: Ensure malformed imports fail before writing unusable accounts.
        """
        print("\n=== Test: Reject Kiro account token without refreshToken ===")

        # Arrange
        store = KiroAccountSqliteStore(str(tmp_path / "kiro_accounts.sqlite3"))

        # Act / Assert
        with pytest.raises(KiroAccountSqliteStoreError):
            store.upsert_token({"accessToken": "access"})

    def test_database_contains_expected_table(self, tmp_path):
        """
        What it does: Opens the generated database with sqlite3 directly.
        Purpose: Ensure the schema is a normal SQLite database for inspection and backups.
        """
        print("\n=== Test: Account store creates SQLite table ===")

        # Arrange
        db_path = tmp_path / "kiro_accounts.sqlite3"
        store = KiroAccountSqliteStore(str(db_path))

        # Act
        store.upsert_token({
            "accessToken": "access",
            "refreshToken": "refresh",
            "expiresAt": "2099-01-01T00:00:00+00:00",
        })

        # Assert
        conn = sqlite3.connect(str(db_path))
        try:
            row = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='kiro_accounts'"
            ).fetchone()
        finally:
            conn.close()
        assert row is not None
