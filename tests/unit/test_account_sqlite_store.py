"""
Unit tests for gateway-managed Kiro account SQLite storage.
"""

import base64
import json
import sqlite3
from datetime import datetime, timezone

import pytest

from kiro.account_sqlite_store import (
    KiroAccountSqliteStore,
    KiroAccountSqliteStoreError,
    build_kiro_account_id,
)


def _build_unsigned_jwt(claims):
    """Build a minimal unsigned JWT string for tests."""
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "JWT"}).encode("utf-8")
    ).rstrip(b"=")
    payload = base64.urlsafe_b64encode(
        json.dumps(claims).encode("utf-8")
    ).rstrip(b"=")
    return f"{header.decode('utf-8')}.{payload.decode('utf-8')}."


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

    def test_upsert_token_prefers_email_claim_for_label(self, tmp_path):
        """
        What it does: Stores a token whose access token contains an email claim.
        Purpose: Ensure persisted account labels are user-readable instead of opaque IDs.
        """
        print("\n=== Test: Account label prefers email claim ===")

        # Arrange
        db_path = tmp_path / "kiro_accounts.sqlite3"
        store = KiroAccountSqliteStore(str(db_path))
        token = {
            "accessToken": _build_unsigned_jwt({"email": "alice@example.com"}),
            "refreshToken": "refresh",
            "expiresAt": "2099-01-01T00:00:00+00:00",
            "authMethod": "social",
            "provider": "Google",
        }

        # Act
        record = store.upsert_token(token)

        # Assert
        assert record["label"] == "alice@example.com"

    def test_upsert_token_persists_csrf_token(self, tmp_path):
        """
        What it does: Stores an account row with an explicit Web Portal CSRF token.
        Purpose: Ensure admin features can reuse the browser session token later.
        """
        print("\n=== Test: Account store persists csrf_token ===")

        # Arrange
        db_path = tmp_path / "kiro_accounts.sqlite3"
        store = KiroAccountSqliteStore(str(db_path))
        token = {
            "accessToken": "access",
            "refreshToken": "refresh",
            "expiresAt": "2099-01-01T00:00:00+00:00",
            "authMethod": "social",
            "provider": "Google",
        }

        # Act
        record = store.upsert_token(token, csrf_token="csrf-token-1")

        # Assert
        assert record["csrf_token"] == "csrf-token-1"

    def test_upsert_token_persists_remote_display_name(self, tmp_path):
        """
        What it does: Stores an account row with an explicit persisted remote display name.
        Purpose: Ensure admin pages can reuse the last resolved Web Portal identity without another request.
        """
        print("\n=== Test: Account store persists remote display_name ===")

        # Arrange
        db_path = tmp_path / "kiro_accounts.sqlite3"
        store = KiroAccountSqliteStore(str(db_path))
        token = {
            "accessToken": "access",
            "refreshToken": "refresh",
            "expiresAt": "2099-01-01T00:00:00+00:00",
            "authMethod": "social",
            "provider": "Google",
        }

        # Act
        record = store.upsert_token(token, display_name="portal@example.com")

        # Assert
        assert record["display_name"] == "portal@example.com"

    def test_upsert_token_migrates_legacy_database_to_add_web_portal_columns(self, tmp_path):
        """
        What it does: Opens an older account database missing the Web Portal metadata columns.
        Purpose: Ensure existing SQLite installs upgrade in place without losing accounts.
        """
        print("\n=== Test: Account store migrates legacy schema with Web Portal metadata columns ===")

        # Arrange
        db_path = tmp_path / "kiro_accounts.sqlite3"
        conn = sqlite3.connect(str(db_path))
        try:
            conn.execute(
                """
                CREATE TABLE kiro_accounts (
                    id TEXT PRIMARY KEY,
                    label TEXT NOT NULL,
                    auth_method TEXT NOT NULL,
                    provider TEXT,
                    token_json TEXT NOT NULL,
                    registration_json TEXT,
                    region TEXT,
                    api_region TEXT,
                    profile_arn TEXT,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_used_at TEXT
                )
                """
            )
            conn.commit()
        finally:
            conn.close()

        store = KiroAccountSqliteStore(str(db_path))
        token = {
            "accessToken": "access",
            "refreshToken": "refresh",
            "expiresAt": "2099-01-01T00:00:00+00:00",
        }

        # Act
        record = store.upsert_token(
            token,
            csrf_token="csrf-token-2",
            display_name="portal@example.com",
        )

        # Assert
        assert record["csrf_token"] == "csrf-token-2"
        assert record["display_name"] == "portal@example.com"
        conn = sqlite3.connect(str(db_path))
        try:
            columns = {
                row[1]
                for row in conn.execute("PRAGMA table_info(kiro_accounts)").fetchall()
            }
        finally:
            conn.close()
        assert "csrf_token" in columns
        assert "display_name" in columns

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

    def test_update_runtime_tokens_preserves_existing_csrf_token(self, tmp_path):
        """
        What it does: Refreshes runtime tokens for an account that already has a csrf_token.
        Purpose: Ensure standard token refreshes do not erase Web Portal session state.
        """
        print("\n=== Test: Update runtime tokens preserves csrf_token ===")

        # Arrange
        store = KiroAccountSqliteStore(str(tmp_path / "kiro_accounts.sqlite3"))
        record = store.upsert_token(
            token={
                "accessToken": "old-access",
                "refreshToken": "old-refresh",
                "expiresAt": "2099-01-01T00:00:00+00:00",
            },
            csrf_token="csrf-token-3",
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
        assert updated["csrf_token"] == "csrf-token-3"

    def test_update_runtime_tokens_updates_stored_remote_display_name(self, tmp_path):
        """
        What it does: Refreshes runtime tokens while persisting new Web Portal identity fields.
        Purpose: Ensure token refresh can update the stored account name, provider, and user ID.
        """
        print("\n=== Test: Update runtime tokens persists remote display_name ===")

        # Arrange
        store = KiroAccountSqliteStore(str(tmp_path / "kiro_accounts.sqlite3"))
        record = store.upsert_token(
            token={
                "accessToken": "old-access",
                "refreshToken": "old-refresh",
                "expiresAt": "2099-01-01T00:00:00+00:00",
                "provider": "Google",
            },
        )

        # Act
        store.update_runtime_tokens(
            account_id=record["id"],
            access_token="new-access",
            refresh_token="new-refresh",
            expires_at=datetime(2099, 1, 2, tzinfo=timezone.utc),
            display_name="portal@example.com",
            user_id="portal-user",
            provider="Google",
        )

        # Assert
        updated = store.get_account(record["id"])
        assert updated["display_name"] == "portal@example.com"
        assert updated["token"]["userId"] == "portal-user"
        assert updated["provider"] == "Google"

    def test_delete_credential_entry_removes_unreferenced_sqlite_account_row(self, tmp_path):
        """
        What it does: Deletes a sqlite_account credential entry from the registry.
        Purpose: Ensure account deletion removes the backing kiro_accounts row instead of leaving an orphan.
        """
        print("\n=== Test: Delete sqlite_account credential removes backing row ===")

        # Arrange
        db_path = tmp_path / "kiro_accounts.sqlite3"
        store = KiroAccountSqliteStore(str(db_path))
        record = store.upsert_token(
            token={
                "accessToken": "access",
                "refreshToken": "refresh",
                "expiresAt": "2099-01-01T00:00:00+00:00",
                "authMethod": "social",
                "provider": "Google",
            }
        )
        store.upsert_credential_entry(
            {
                "type": "sqlite_account",
                "path": str(db_path),
                "account_id": record["id"],
                "enabled": True,
            }
        )

        # Act
        store.delete_credential_entry(0)

        # Assert
        assert store.list_credential_entries() == []
        assert store.get_account(record["id"]) is None

    def test_delete_credential_entry_removes_unreferenced_external_sqlite_account_row(self, tmp_path):
        """
        What it does: Deletes a registry entry that points at a different SQLite account database.
        Purpose: Ensure the gateway cleans up the real backing account row, not only the local registry row.
        """
        print("\n=== Test: Delete sqlite_account credential removes external backing row ===")

        # Arrange
        registry_db_path = tmp_path / "registry.sqlite3"
        account_db_path = tmp_path / "accounts.sqlite3"
        registry_store = KiroAccountSqliteStore(str(registry_db_path))
        account_store = KiroAccountSqliteStore(str(account_db_path))
        record = account_store.upsert_token(
            token={
                "accessToken": "access",
                "refreshToken": "refresh",
                "expiresAt": "2099-01-01T00:00:00+00:00",
                "authMethod": "social",
                "provider": "Google",
            }
        )
        registry_store.upsert_credential_entry(
            {
                "type": "sqlite_account",
                "path": str(account_db_path),
                "account_id": record["id"],
                "enabled": True,
            }
        )

        # Act
        registry_store.delete_credential_entry(0)

        # Assert
        assert registry_store.list_credential_entries() == []
        assert account_store.get_account(record["id"]) is None

    def test_delete_credential_entry_keeps_backing_row_when_duplicate_reference_remains(self, tmp_path):
        """
        What it does: Deletes one of two duplicate sqlite_account references inserted directly in SQLite.
        Purpose: Ensure the backing account row survives until the final reference is removed.
        """
        print("\n=== Test: Delete sqlite_account credential keeps backing row while another reference exists ===")

        # Arrange
        registry_db_path = tmp_path / "registry.sqlite3"
        account_db_path = tmp_path / "accounts.sqlite3"
        registry_store = KiroAccountSqliteStore(str(registry_db_path))
        account_store = KiroAccountSqliteStore(str(account_db_path))
        record = account_store.upsert_token(
            token={
                "accessToken": "access",
                "refreshToken": "refresh",
                "expiresAt": "2099-01-01T00:00:00+00:00",
            }
        )
        first_entry = registry_store.upsert_credential_entry(
            {
                "type": "sqlite_account",
                "path": str(account_db_path),
                "account_id": record["id"],
                "enabled": True,
            }
        )
        duplicate_created_at = datetime.now(timezone.utc).isoformat()
        conn = sqlite3.connect(str(registry_db_path))
        try:
            conn.execute(
                """
                INSERT INTO kiro_account_credentials (
                    credential_type,
                    path,
                    account_id,
                    refresh_token,
                    profile_arn,
                    region,
                    api_region,
                    enabled,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "sqlite_account",
                    str(account_db_path),
                    record["id"],
                    None,
                    None,
                    None,
                    None,
                    1,
                    duplicate_created_at,
                    duplicate_created_at,
                ),
            )
            conn.commit()
        finally:
            conn.close()

        # Act
        registry_store.delete_credential_entry(0)

        # Assert
        remaining_entries = registry_store.list_credential_entries()
        assert len(remaining_entries) == 1
        assert remaining_entries[0]["row_id"] != first_entry["row_id"]
        assert account_store.get_account(record["id"]) is not None

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
