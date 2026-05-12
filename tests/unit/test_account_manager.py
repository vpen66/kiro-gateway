# -*- coding: utf-8 -*-

"""
Tests for kiro/account_manager.py - Unified Account System.

Tests the AccountManager class that manages multiple Kiro accounts with:
- Lazy initialization
- Sticky behavior (prefer successful account)
- Circuit breaker with exponential backoff
- TTL-based model cache refresh
- State persistence
"""

import asyncio
import base64
import json
import pytest
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, Mock, patch

from kiro.account_manager import (
    Account,
    AccountStats,
    ModelAccountList,
    AccountManager,
    _format_duration
)
from kiro.account_errors import ErrorType
from kiro.account_sqlite_store import KiroAccountSqliteStore
from kiro.auth import KiroAuthManager, AuthType
from kiro.cache import ModelInfoCache
from kiro.model_resolver import ModelResolver


def _build_unsigned_jwt(claims):
    """Build a minimal unsigned JWT string for tests."""
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "JWT"}).encode("utf-8")
    ).rstrip(b"=")
    payload = base64.urlsafe_b64encode(
        json.dumps(claims).encode("utf-8")
    ).rstrip(b"=")
    return f"{header.decode('utf-8')}.{payload.decode('utf-8')}."


def _seed_credential_registry(state_file: Path, entries: list[dict]) -> Path:
    """Persist credential entries into the default AccountManager SQLite registry."""
    db_path = state_file.with_name("kiro_accounts.sqlite3")
    KiroAccountSqliteStore(str(db_path)).replace_credential_entries(entries)
    return db_path


class TestAccountDataclass:
    """
    Tests for Account and AccountStats dataclasses.
    """
    
    def test_account_creation_with_defaults(self):
        """
        Test Account creation with default values.
        
        What it does: Verifies Account dataclass initialization
        Purpose: Ensure default values are set correctly
        """
        print("\n=== Test: Account creation with defaults ===")
        
        # Act
        account = Account(id="/test/path.json")
        
        # Assert
        print(f"Account ID: {account.id}")
        print(f"Auth manager: {account.auth_manager}")
        print(f"Failures: {account.failures}")
        print(f"Last failure time: {account.last_failure_time}")
        
        assert account.id == "/test/path.json"
        assert account.auth_manager is None
        assert account.model_cache is None
        assert account.model_resolver is None
        assert account.failures == 0
        assert account.last_failure_time == 0.0
        assert account.models_cached_at == 0.0
        assert isinstance(account.stats, AccountStats)
    
    def test_account_stats_initialization(self):
        """
        Test AccountStats initialization with zeros.
        
        What it does: Verifies AccountStats default values
        Purpose: Ensure statistics start at zero
        """
        print("\n=== Test: AccountStats initialization ===")
        
        # Act
        stats = AccountStats()
        
        # Assert
        print(f"Total requests: {stats.total_requests}")
        print(f"Successful requests: {stats.successful_requests}")
        print(f"Failed requests: {stats.failed_requests}")
        
        assert stats.total_requests == 0
        assert stats.successful_requests == 0
        assert stats.failed_requests == 0


class TestAccountManagerLoadCredentials:
    """
    Tests for AccountManager.load_credentials() method.
    """
    
    @pytest.mark.asyncio
    async def test_load_credentials_json_type(self, tmp_path):
        """
        Test loading credentials with type=json.
        
        What it does: Loads single JSON credential file
        Purpose: Verify JSON type credential loading
        """
        print("\n=== Test: load_credentials with type=json ===")
        
        # Arrange
        creds_file = tmp_path / "credentials.json"
        test_json = tmp_path / "test.json"
        test_json.write_text(json.dumps({
            "refreshToken": "test_token",
            "accessToken": "test_access",
            "expiresAt": "2099-01-01T00:00:00.000Z"
        }))
        
        credentials = [
            {
                "type": "json",
                "path": str(test_json),
                "enabled": True
            }
        ]
        state_file = tmp_path / "state.json"
        _seed_credential_registry(state_file, credentials)
        
        manager = AccountManager(
            credentials_file=str(creds_file),
            state_file=str(state_file)
        )
        
        # Act
        await manager.load_credentials()
        
        # Assert
        print(f"Loaded accounts: {len(manager._accounts)}")
        print(f"Account IDs: {list(manager._accounts.keys())}")
        
        assert len(manager._accounts) == 1
        assert str(test_json.resolve()) in manager._accounts
    
    @pytest.mark.asyncio
    async def test_load_credentials_sqlite_type(self, tmp_path, temp_sqlite_db):
        """
        Test loading credentials with type=sqlite.
        
        What it does: Loads SQLite database credential
        Purpose: Verify SQLite type credential loading
        """
        print("\n=== Test: load_credentials with type=sqlite ===")
        
        # Arrange
        creds_file = tmp_path / "credentials.json"
        credentials = [
            {
                "type": "sqlite",
                "path": temp_sqlite_db,
                "enabled": True
            }
        ]
        state_file = tmp_path / "state.json"
        _seed_credential_registry(state_file, credentials)
        
        manager = AccountManager(
            credentials_file=str(creds_file),
            state_file=str(state_file)
        )
        
        # Act
        await manager.load_credentials()
        
        # Assert
        print(f"Loaded accounts: {len(manager._accounts)}")
        
        assert len(manager._accounts) == 1
        assert str(Path(temp_sqlite_db).resolve()) in manager._accounts

    @pytest.mark.asyncio
    async def test_load_credentials_sqlite_account_type(self, tmp_path):
        """
        Test loading credentials with type=sqlite_account.

        What it does: Loads a row from the gateway-managed Kiro account DB.
        Purpose: Verify browser OAuth accounts can be represented as separate runtime accounts.
        """
        print("\n=== Test: load_credentials with type=sqlite_account ===")

        # Arrange
        db_path = tmp_path / "kiro_accounts.sqlite3"
        store = KiroAccountSqliteStore(str(db_path))
        record = store.upsert_token({
            "accessToken": "access",
            "refreshToken": "refresh",
            "expiresAt": "2099-01-01T00:00:00+00:00",
            "authMethod": "social",
            "provider": "Google",
        })
        creds_file = tmp_path / "credentials.json"
        credentials = [
            {
                "type": "sqlite_account",
                "path": str(db_path),
                "account_id": record["id"],
                "enabled": True
            }
        ]
        state_file = tmp_path / "state.json"
        _seed_credential_registry(state_file, credentials)

        manager = AccountManager(
            credentials_file=str(creds_file),
            state_file=str(state_file)
        )

        # Act
        await manager.load_credentials()

        # Assert
        account_ids = list(manager._accounts.keys())
        assert len(account_ids) == 1
        assert account_ids[0].startswith("sqlite_account:")
        assert record["id"] in account_ids[0]

    @pytest.mark.asyncio
    async def test_load_credentials_sqlite_account_type_skips_missing_row(self, tmp_path):
        """
        Test loading stale sqlite_account credentials.

        What it does: Loads a sqlite_account entry whose database row no longer exists.
        Purpose: Ensure empty or reset account databases do not create broken runtime accounts.
        """
        print("\n=== Test: load_credentials skips missing sqlite_account row ===")

        # Arrange
        db_path = tmp_path / "kiro_accounts.sqlite3"
        store = KiroAccountSqliteStore(str(db_path))
        assert store.list_accounts() == []

        creds_file = tmp_path / "credentials.json"
        credentials = [
            {
                "type": "sqlite_account",
                "path": str(db_path),
                "account_id": "kiro_missing_account",
                "enabled": True,
            }
        ]
        state_file = tmp_path / "state.json"
        _seed_credential_registry(state_file, credentials)

        manager = AccountManager(
            credentials_file=str(creds_file),
            state_file=str(state_file)
        )

        # Act
        await manager.load_credentials()

        # Assert
        assert manager._accounts == {}

    @pytest.mark.asyncio
    async def test_delete_credential_entry_removes_backing_sqlite_account_row(self, tmp_path):
        """
        Test deleting a sqlite_account credential entry.

        What it does: Removes a persisted sqlite_account credential from AccountManager.
        Purpose: Ensure the backing kiro_accounts row is deleted instead of remaining orphaned in SQLite.
        """
        print("\n=== Test: delete_credential_entry removes backing sqlite_account row ===")

        # Arrange
        db_path = tmp_path / "kiro_accounts.sqlite3"
        store = KiroAccountSqliteStore(str(db_path))
        record = store.upsert_token(
            {
                "accessToken": "access",
                "refreshToken": "refresh",
                "expiresAt": "2099-01-01T00:00:00+00:00",
                "authMethod": "social",
                "provider": "Google",
            }
        )
        creds_file = tmp_path / "credentials.json"
        state_file = tmp_path / "state.json"
        _seed_credential_registry(
            state_file,
            [
                {
                    "type": "sqlite_account",
                    "path": str(db_path),
                    "account_id": record["id"],
                    "enabled": True,
                }
            ],
        )
        manager = AccountManager(
            credentials_file=str(creds_file),
            state_file=str(state_file),
        )
        await manager.load_credentials()

        # Act
        await manager.delete_credential_entry(0)

        # Assert
        assert manager.get_credential_entries() == []
        assert KiroAccountSqliteStore(str(db_path)).get_account(record["id"]) is None
    
    @pytest.mark.asyncio
    async def test_load_credentials_refresh_token_type(self, tmp_path):
        """
        Test loading credentials with type=refresh_token.
        
        What it does: Loads refresh token credential
        Purpose: Verify refresh_token type credential loading
        """
        print("\n=== Test: load_credentials with type=refresh_token ===")
        
        # Arrange
        creds_file = tmp_path / "credentials.json"
        credentials = [
            {
                "type": "refresh_token",
                "refresh_token": "test_refresh_token_abc123",
                "profile_arn": "arn:aws:codewhisperer:us-east-1:123456789:profile/test",
                "region": "us-east-1",
                "enabled": True
            }
        ]
        # Create state file to avoid errors
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps({"current_account_index": 0, "model_to_accounts": {}, "accounts": {}}))
        _seed_credential_registry(state_file, credentials)
        
        manager = AccountManager(
            credentials_file=str(creds_file),
            state_file=str(state_file)
        )
        
        # Act
        await manager.load_credentials()
        
        # Assert
        print(f"Loaded accounts: {len(manager._accounts)}")
        print(f"Account IDs: {list(manager._accounts.keys())}")
        
        assert len(manager._accounts) == 1
        # refresh_token type uses deterministic hash as ID
        account_id = list(manager._accounts.keys())[0]
        assert account_id.startswith("refresh_token_")
    
    @pytest.mark.asyncio
    async def test_load_credentials_folder_scanning(self, tmp_path):
        """
        Test folder scanning for credential files.
        
        What it does: Scans folder and loads all valid credential files
        Purpose: Verify folder scanning functionality
        """
        print("\n=== Test: load_credentials with folder scanning ===")
        
        # Arrange
        folder = tmp_path / "accounts"
        folder.mkdir()
        
        # Create valid files
        file1 = folder / "account1.json"
        file1.write_text(json.dumps({
            "refreshToken": "token1",
            "accessToken": "access1",
            "expiresAt": "2099-01-01T00:00:00.000Z"
        }))
        
        file2 = folder / "account2.json"
        file2.write_text(json.dumps({
            "refreshToken": "token2",
            "accessToken": "access2",
            "expiresAt": "2099-01-01T00:00:00.000Z"
        }))
        
        creds_file = tmp_path / "credentials.json"
        credentials = [
            {
                "type": "json",
                "path": str(folder),
                "enabled": True
            }
        ]
        state_file = tmp_path / "state.json"
        _seed_credential_registry(state_file, credentials)
        
        manager = AccountManager(
            credentials_file=str(creds_file),
            state_file=str(state_file)
        )
        
        # Act
        await manager.load_credentials()
        
        # Assert
        print(f"Loaded accounts: {len(manager._accounts)}")
        
        assert len(manager._accounts) == 2
    
    @pytest.mark.asyncio
    async def test_load_credentials_skip_invalid_files(self, tmp_path):
        """
        Test that invalid files are skipped with WARNING.
        
        What it does: Loads folder with invalid files
        Purpose: Verify invalid files are skipped gracefully
        """
        print("\n=== Test: load_credentials skips invalid files ===")
        
        # Arrange
        folder = tmp_path / "accounts"
        folder.mkdir()
        
        # Valid file
        valid_file = folder / "valid.json"
        valid_file.write_text(json.dumps({
            "refreshToken": "token",
            "accessToken": "access",
            "expiresAt": "2099-01-01T00:00:00.000Z"
        }))
        
        # Invalid JSON
        invalid_file = folder / "invalid.json"
        invalid_file.write_text("not a valid json {{{")
        
        # Non-JSON file
        text_file = folder / "readme.txt"
        text_file.write_text("This is not a credential file")
        
        creds_file = tmp_path / "credentials.json"
        credentials = [
            {
                "type": "json",
                "path": str(folder),
                "enabled": True
            }
        ]
        state_file = tmp_path / "state.json"
        _seed_credential_registry(state_file, credentials)
        
        manager = AccountManager(
            credentials_file=str(creds_file),
            state_file=str(state_file)
        )
        
        # Act
        await manager.load_credentials()
        
        # Assert
        print(f"Loaded accounts: {len(manager._accounts)}")
        
        assert len(manager._accounts) == 1  # Only valid file loaded
    
    @pytest.mark.asyncio
    async def test_load_credentials_skip_disabled(self, tmp_path):
        """
        Test that entries with enabled=false are skipped.
        
        What it does: Loads credentials with disabled entry
        Purpose: Verify enabled flag is respected
        """
        print("\n=== Test: load_credentials skips disabled entries ===")
        
        # Arrange
        test_json = tmp_path / "test.json"
        test_json.write_text(json.dumps({
            "refreshToken": "token",
            "accessToken": "access",
            "expiresAt": "2099-01-01T00:00:00.000Z"
        }))
        
        creds_file = tmp_path / "credentials.json"
        credentials = [
            {
                "type": "json",
                "path": str(test_json),
                "enabled": False  # Disabled
            }
        ]
        state_file = tmp_path / "state.json"
        _seed_credential_registry(state_file, credentials)
        
        manager = AccountManager(
            credentials_file=str(creds_file),
            state_file=str(state_file)
        )
        
        # Act
        await manager.load_credentials()
        
        # Assert
        print(f"Loaded accounts: {len(manager._accounts)}")
        
        assert len(manager._accounts) == 0
    
    @pytest.mark.asyncio
    async def test_load_credentials_missing_type(self, tmp_path):
        """
        Test that entries without type are skipped.
        
        What it does: Loads credentials with missing type field
        Purpose: Verify type validation
        """
        print("\n=== Test: load_credentials skips entries without type ===")
        
        # Arrange
        creds_file = tmp_path / "credentials.json"
        credentials = [
            {
                "path": "/some/path.json",
                "enabled": True
                # Missing "type" field
            }
        ]
        state_file = tmp_path / "state.json"
        
        manager = AccountManager(
            credentials_file=str(creds_file),
            state_file=str(state_file)
        )
        
        # Act
        with patch.object(manager, "_load_persisted_credential_entries", return_value=credentials):
            await manager.load_credentials()
        
        # Assert
        print(f"Loaded accounts: {len(manager._accounts)}")
        
        assert len(manager._accounts) == 0
    
    @pytest.mark.asyncio
    async def test_load_credentials_missing_path(self, tmp_path):
        """
        Test that json/sqlite entries without path are skipped.
        
        What it does: Loads credentials with missing path field
        Purpose: Verify path validation for json/sqlite types
        """
        print("\n=== Test: load_credentials skips json/sqlite without path ===")
        
        # Arrange
        creds_file = tmp_path / "credentials.json"
        credentials = [
            {
                "type": "json",
                "enabled": True
                # Missing "path" field
            }
        ]
        state_file = tmp_path / "state.json"
        _seed_credential_registry(state_file, credentials)
        
        manager = AccountManager(
            credentials_file=str(creds_file),
            state_file=str(state_file)
        )
        
        # Act
        await manager.load_credentials()
        
        # Assert
        print(f"Loaded accounts: {len(manager._accounts)}")
        
        assert len(manager._accounts) == 0
    
    @pytest.mark.asyncio
    async def test_load_credentials_missing_refresh_token(self, tmp_path):
        """
        Test that refresh_token entries without refresh_token field are skipped.
        
        What it does: Loads credentials with missing refresh_token field
        Purpose: Verify refresh_token validation
        """
        print("\n=== Test: load_credentials skips refresh_token without token ===")
        
        # Arrange
        creds_file = tmp_path / "credentials.json"
        credentials = [
            {
                "type": "refresh_token",
                "profile_arn": "arn:aws:codewhisperer:us-east-1:123456789:profile/test",
                "enabled": True
                # Missing "refresh_token" field
            }
        ]
        state_file = tmp_path / "state.json"
        _seed_credential_registry(state_file, credentials)
        
        manager = AccountManager(
            credentials_file=str(creds_file),
            state_file=str(state_file)
        )
        
        # Act
        await manager.load_credentials()
        
        # Assert
        print(f"Loaded accounts: {len(manager._accounts)}")
        
        assert len(manager._accounts) == 0
    
    @pytest.mark.asyncio
    async def test_load_credentials_ignores_legacy_credentials_file_when_registry_empty(self, tmp_path):
        """
        Test that legacy credentials.json contents are ignored.

        What it does: Creates a valid legacy credential file without any SQLite entries.
        Purpose: Verify AccountManager no longer reads credentials.json directly.
        """
        print("\n=== Test: load_credentials ignores legacy credentials.json ===")
        
        # Arrange
        creds_file = tmp_path / "nonexistent.json"
        test_json = tmp_path / "legacy.json"
        test_json.write_text(json.dumps({"refreshToken": "token"}))
        creds_file.write_text(json.dumps([{"type": "json", "path": str(test_json), "enabled": True}]))
        state_file = tmp_path / "state.json"

        manager = AccountManager(
            credentials_file=str(creds_file),
            state_file=str(state_file)
        )
        
        # Act
        await manager.load_credentials()
        
        # Assert
        print(f"Loaded accounts: {len(manager._accounts)}")
        
        assert len(manager._accounts) == 0


class TestAccountManagerLoadState:
    """
    Tests for AccountManager.load_state() method.
    """
    
    @pytest.mark.asyncio
    async def test_load_state_success(self, tmp_path):
        """
        Test loading existing state.json.
        
        What it does: Loads state from file
        Purpose: Verify state restoration
        """
        print("\n=== Test: load_state success ===")
        
        # Arrange
        # Create accounts first
        test_json = tmp_path / "test.json"
        test_json.write_text(json.dumps({"refreshToken": "token"}))
        account_id = str(test_json.resolve())

        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps({
            "current_account_index": 0,
            "model_to_accounts": {
                "claude-sonnet-4.5": {
                    "accounts": [account_id]
                }
            },
            "accounts": {
                account_id: {
                    "failures": 0,
                    "last_failure_time": 0.0,
                    "models_cached_at": 1704106800.0,
                    "stats": {
                        "total_requests": 10,
                        "successful_requests": 9,
                        "failed_requests": 1
                    }
                }
            }
        }))
        
        creds_file = tmp_path / "credentials.json"
        _seed_credential_registry(state_file, [
            {"type": "json", "path": str(test_json), "enabled": True}
        ])
        
        manager = AccountManager(
            credentials_file=str(creds_file),
            state_file=str(state_file)
        )
        
        await manager.load_credentials()
        
        # Act
        await manager.load_state()
        
        # Assert
        print(f"Model mappings: {len(manager._model_to_accounts)}")
        print(f"Current account index: {manager._current_account_index}")
        
        assert len(manager._model_to_accounts) > 0
    
    @pytest.mark.asyncio
    async def test_load_state_restore_current_account_index(self, tmp_path):
        """
        Test restoration of global current_account_index.
        
        What it does: Restores sticky index from state
        Purpose: Verify global sticky behavior persistence
        """
        print("\n=== Test: load_state restores current_account_index ===")
        
        # Arrange
        account_paths = []
        for index in range(3):
            account_path = tmp_path / f"account-{index}.json"
            account_path.write_text(json.dumps({"refreshToken": f"token-{index}"}))
            account_paths.append(account_path)

        state_data = {
            "current_account_index": 2,
            "model_to_accounts": {},
            "accounts": {}
        }
        
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps(state_data))
        
        creds_file = tmp_path / "creds.json"
        _seed_credential_registry(state_file, [
            {"type": "json", "path": str(account_path), "enabled": True}
            for account_path in account_paths
        ])

        manager = AccountManager(
            credentials_file=str(creds_file),
            state_file=str(state_file)
        )
        await manager.load_credentials()
        
        # Act
        await manager.load_state()
        
        # Assert
        print(f"Current account index: {manager._current_account_index}")
        
        assert manager._current_account_index == 2
    
    @pytest.mark.asyncio
    async def test_load_state_restore_model_to_accounts(self, tmp_path):
        """
        Test restoration of model_to_accounts mapping.
        
        What it does: Restores model mappings from state
        Purpose: Verify model-to-account mapping persistence
        """
        print("\n=== Test: load_state restores model_to_accounts ===")
        
        # Arrange
        account_paths = []
        for index in range(2):
            account_path = tmp_path / f"account-{index}.json"
            account_path.write_text(json.dumps({"refreshToken": f"token-{index}"}))
            account_paths.append(account_path)
        account_ids = [str(account_path.resolve()) for account_path in account_paths]

        state_data = {
            "current_account_index": 0,
            "model_to_accounts": {
                "claude-opus-4.5": {
                    "accounts": account_ids
                }
            },
            "accounts": {}
        }
        
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps(state_data))
        
        creds_file = tmp_path / "creds.json"
        _seed_credential_registry(state_file, [
            {"type": "json", "path": str(account_path), "enabled": True}
            for account_path in account_paths
        ])

        manager = AccountManager(
            credentials_file=str(creds_file),
            state_file=str(state_file)
        )
        await manager.load_credentials()
        
        # Act
        await manager.load_state()
        
        # Assert
        print(f"Model mappings: {manager._model_to_accounts}")
        
        assert "claude-opus-4.5" in manager._model_to_accounts
        assert len(manager._model_to_accounts["claude-opus-4.5"].accounts) == 2

    @pytest.mark.asyncio
    async def test_load_state_prunes_missing_runtime_accounts(self, tmp_path):
        """
        Test state restoration with stale account IDs.

        What it does: Restores state that references a removed SQLite account row.
        Purpose: Ensure stale model mappings are removed after an account database is reset.
        """
        print("\n=== Test: load_state prunes missing runtime accounts ===")

        # Arrange
        db_path = tmp_path / "kiro_accounts.sqlite3"
        store = KiroAccountSqliteStore(str(db_path))
        record = store.upsert_token({
            "accessToken": "access",
            "refreshToken": "refresh",
            "expiresAt": "2099-01-01T00:00:00+00:00",
            "authMethod": "social",
            "provider": "Google",
        })

        valid_account_id = AccountManager._runtime_id_for_sqlite_account(str(db_path), record["id"])
        stale_account_id = AccountManager._runtime_id_for_sqlite_account(str(db_path), "kiro_deleted")
        state_data = {
            "current_account_index": 99,
            "model_to_accounts": {
                "claude-opus-4.5": {
                    "accounts": [valid_account_id, stale_account_id]
                },
                "claude-missing-1.0": {
                    "accounts": [stale_account_id]
                },
            },
            "accounts": {
                valid_account_id: {
                    "failures": 1,
                    "last_failure_time": 1704110400.0,
                    "models_cached_at": 1704106800.0,
                    "stats": {
                        "total_requests": 2,
                        "successful_requests": 1,
                        "failed_requests": 1,
                    },
                },
                stale_account_id: {
                    "failures": 9,
                    "last_failure_time": 1704110500.0,
                    "models_cached_at": 1704106900.0,
                    "stats": {
                        "total_requests": 9,
                        "successful_requests": 0,
                        "failed_requests": 9,
                    },
                },
            },
        }
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps(state_data))
        creds_file = tmp_path / "credentials.json"
        _seed_credential_registry(state_file, [
            {
                "type": "sqlite_account",
                "path": str(db_path),
                "account_id": record["id"],
                "enabled": True,
            }
        ])

        manager = AccountManager(
            credentials_file=str(creds_file),
            state_file=str(state_file)
        )
        await manager.load_credentials()

        # Act
        await manager.load_state()

        # Assert
        assert manager._current_account_index == 0
        assert manager._model_to_accounts["claude-opus-4.5"].accounts == [valid_account_id]
        assert "claude-missing-1.0" not in manager._model_to_accounts
        assert stale_account_id not in manager._accounts
    
    @pytest.mark.asyncio
    async def test_load_state_restore_account_runtime_state(self, tmp_path):
        """
        Test restoration of account runtime state (failures, stats, etc).
        
        What it does: Restores account state from file
        Purpose: Verify runtime state persistence
        """
        print("\n=== Test: load_state restores account runtime state ===")
        
        # Arrange
        # Create account first to get correct resolved path
        test_json = tmp_path / "account.json"
        test_json.write_text(json.dumps({"refreshToken": "token"}))
        account_id = str(test_json.resolve())
        
        state_data = {
            "current_account_index": 0,
            "model_to_accounts": {},
            "accounts": {
                account_id: {
                    "failures": 3,
                    "last_failure_time": 1704110400.0,
                    "models_cached_at": 1704106800.0,
                    "stats": {
                        "total_requests": 100,
                        "successful_requests": 97,
                        "failed_requests": 3
                    }
                }
            }
        }
        
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps(state_data))
        
        creds_file = tmp_path / "credentials.json"
        _seed_credential_registry(state_file, [
            {"type": "json", "path": str(test_json), "enabled": True}
        ])
        
        manager = AccountManager(
            credentials_file=str(creds_file),
            state_file=str(state_file)
        )
        
        await manager.load_credentials()
        
        # Act
        await manager.load_state()
        
        # Assert
        account = manager._accounts[account_id]
        print(f"Account failures: {account.failures}")
        print(f"Account stats: {account.stats}")
        
        assert account.failures == 3
        assert account.last_failure_time == 1704110400.0
        assert account.models_cached_at == 1704106800.0
        assert account.stats.total_requests == 100
    
    @pytest.mark.asyncio
    async def test_load_state_file_not_found(self, tmp_path):
        """
        Test handling of non-existent state.json (empty state).
        
        What it does: Attempts to load non-existent state file
        Purpose: Verify graceful handling with empty state
        """
        print("\n=== Test: load_state with missing file ===")
        
        # Arrange
        manager = AccountManager(
            credentials_file=str(tmp_path / "creds.json"),
            state_file=str(tmp_path / "nonexistent.json")
        )
        
        # Act
        await manager.load_state()
        
        # Assert
        print(f"Model mappings: {len(manager._model_to_accounts)}")
        print(f"Current account index: {manager._current_account_index}")
        
        assert len(manager._model_to_accounts) == 0
        assert manager._current_account_index == 0
    
    @pytest.mark.asyncio
    async def test_load_state_corrupted_json(self, tmp_path):
        """
        Test handling of corrupted state.json.
        
        What it does: Attempts to load invalid JSON
        Purpose: Verify error handling for corrupted state
        """
        print("\n=== Test: load_state with corrupted JSON ===")
        
        # Arrange
        state_file = tmp_path / "state.json"
        state_file.write_text("not a valid json {{{")
        
        manager = AccountManager(
            credentials_file=str(tmp_path / "creds.json"),
            state_file=str(state_file)
        )
        
        # Act
        await manager.load_state()
        
        # Assert - should handle gracefully
        print(f"Model mappings: {len(manager._model_to_accounts)}")
        
        assert len(manager._model_to_accounts) == 0



class TestAccountManagerInitializeAccount:
    """
    Tests for AccountManager._initialize_account() method.
    """
    
    @pytest.mark.asyncio
    async def test_initialize_account_json_success(self, tmp_path, mock_list_models_response):
        """
        Test successful account initialization with type=json.
        
        What it does: Initializes account with JSON credentials
        Purpose: Verify complete initialization flow
        """
        print("\n=== Test: initialize_account with JSON ===")
        
        # Arrange
        test_json = tmp_path / "test.json"
        test_json.write_text(json.dumps({
            "refreshToken": "test_token",
            "accessToken": "test_access",
            "expiresAt": "2099-01-01T00:00:00.000Z",
            "profileArn": "arn:aws:codewhisperer:us-east-1:123456789:profile/test",
            "region": "us-east-1"
        }))
        
        creds_file = tmp_path / "credentials.json"
        state_file = tmp_path / "state.json"
        _seed_credential_registry(state_file, [
            {"type": "json", "path": str(test_json), "enabled": True}
        ])
        
        manager = AccountManager(
            credentials_file=str(creds_file),
            state_file=str(state_file)
        )
        
        await manager.load_credentials()
        account_id = str(test_json.resolve())
        
        # Mock HTTP client for ListAvailableModels
        with patch('kiro.account_manager.KiroHttpClient') as mock_http_class:
            mock_client = AsyncMock()
            mock_response = Mock()  # Response is not async
            mock_response.status_code = 200
            mock_response.json.return_value = mock_list_models_response
            mock_client.request_with_retry = AsyncMock(return_value=mock_response)
            mock_client.close = AsyncMock()
            mock_http_class.return_value = mock_client
            
            # Act
            success = await manager._initialize_account(account_id)
        
        # Assert
        print(f"Initialization success: {success}")
        assert success is True
        assert manager._accounts[account_id].auth_manager is not None
        assert manager._accounts[account_id].model_cache is not None
        assert manager._accounts[account_id].model_resolver is not None
    
    @pytest.mark.asyncio
    async def test_initialize_account_fetch_models_fallback(self, tmp_path):
        """
        Test fallback to FALLBACK_MODELS when API fails.
        
        What it does: Initializes account when ListAvailableModels fails
        Purpose: Verify fallback mechanism
        """
        print("\n=== Test: initialize_account with fallback models ===")
        
        # Arrange
        test_json = tmp_path / "test.json"
        test_json.write_text(json.dumps({
            "refreshToken": "test_token",
            "accessToken": "test_access",
            "expiresAt": "2099-01-01T00:00:00.000Z"
        }))
        
        creds_file = tmp_path / "credentials.json"
        state_file = tmp_path / "state.json"
        _seed_credential_registry(state_file, [
            {"type": "json", "path": str(test_json), "enabled": True}
        ])
        
        manager = AccountManager(
            credentials_file=str(creds_file),
            state_file=str(state_file)
        )
        
        await manager.load_credentials()
        account_id = str(test_json.resolve())
        
        # Mock HTTP client to fail
        with patch('kiro.account_manager.KiroHttpClient') as mock_http_class:
            mock_client = AsyncMock()
            mock_client.request_with_retry = AsyncMock(side_effect=Exception("Network error"))
            mock_client.close = AsyncMock()
            mock_http_class.return_value = mock_client
            
            # Act
            success = await manager._initialize_account(account_id)
        
        # Assert
        print(f"Initialization success: {success}")
        assert success is True  # Should succeed with fallback
        assert manager._accounts[account_id].model_cache is not None


class TestAccountManagerGetNextAccount:
    """
    Tests for AccountManager.get_next_account() method.
    """
    
    @pytest.mark.asyncio
    async def test_get_next_account_single_bypass_circuit_breaker(self, tmp_path, mock_list_models_response):
        """
        Test that single account bypasses Circuit Breaker.
        
        What it does: Gets account when only one exists
        Purpose: Verify single account always returns (no cooldown)
        """
        print("\n=== Test: get_next_account single account bypasses Circuit Breaker ===")
        
        # Arrange
        test_json = tmp_path / "test.json"
        test_json.write_text(json.dumps({
            "refreshToken": "test_token",
            "accessToken": "test_access",
            "expiresAt": "2099-01-01T00:00:00.000Z"
        }))
        
        creds_file = tmp_path / "credentials.json"
        state_file = tmp_path / "state.json"
        _seed_credential_registry(state_file, [
            {"type": "json", "path": str(test_json), "enabled": True}
        ])
        
        manager = AccountManager(
            credentials_file=str(creds_file),
            state_file=str(state_file)
        )
        
        await manager.load_credentials()
        account_id = str(test_json.resolve())
        
        # Initialize account
        with patch('kiro.account_manager.KiroHttpClient') as mock_http_class:
            mock_client = AsyncMock()
            mock_response = Mock()  # Response is not async
            mock_response.status_code = 200
            mock_response.json.return_value = mock_list_models_response
            mock_client.request_with_retry = AsyncMock(return_value=mock_response)
            mock_client.close = AsyncMock()
            mock_http_class.return_value = mock_client
            
            await manager._initialize_account(account_id)
        
        # Set failures (should be ignored for single account)
        manager._accounts[account_id].failures = 10
        manager._accounts[account_id].last_failure_time = time.time()
        
        # Act
        account = await manager.get_next_account("claude-opus-4.5")
        
        # Assert
        print(f"Got account: {account is not None}")
        assert account is not None  # Single account always returns


class TestAccountManagerReportSuccess:
    """
    Tests for AccountManager.report_success() method.
    """
    
    @pytest.mark.asyncio
    async def test_report_success_reset_failures(self, tmp_path, mock_list_models_response):
        """
        Test that report_success resets failures to 0.
        
        What it does: Reports success after failures
        Purpose: Verify failure counter reset
        """
        print("\n=== Test: report_success resets failures ===")
        
        # Arrange
        test_json = tmp_path / "test.json"
        test_json.write_text(json.dumps({
            "refreshToken": "test_token",
            "accessToken": "test_access",
            "expiresAt": "2099-01-01T00:00:00.000Z"
        }))
        
        creds_file = tmp_path / "credentials.json"
        state_file = tmp_path / "state.json"
        _seed_credential_registry(state_file, [
            {"type": "json", "path": str(test_json), "enabled": True}
        ])
        
        manager = AccountManager(
            credentials_file=str(creds_file),
            state_file=str(state_file)
        )
        
        await manager.load_credentials()
        account_id = str(test_json.resolve())
        
        # Initialize account
        with patch('kiro.account_manager.KiroHttpClient') as mock_http_class:
            mock_client = AsyncMock()
            mock_response = Mock()  # Response is not async
            mock_response.status_code = 200
            mock_response.json.return_value = mock_list_models_response
            mock_client.request_with_retry = AsyncMock(return_value=mock_response)
            mock_client.close = AsyncMock()
            mock_http_class.return_value = mock_client
            
            await manager._initialize_account(account_id)
        
        # Set failures
        manager._accounts[account_id].failures = 5
        
        # Act
        await manager.report_success(account_id, "claude-opus-4.5")
        
        # Assert
        print(f"Failures after success: {manager._accounts[account_id].failures}")
        assert manager._accounts[account_id].failures == 0
    
    @pytest.mark.asyncio
    async def test_report_success_update_stats(self, tmp_path, mock_list_models_response):
        """
        Test that report_success updates statistics.
        
        What it does: Reports success and checks stats
        Purpose: Verify statistics tracking
        """
        print("\n=== Test: report_success updates stats ===")
        
        # Arrange
        test_json = tmp_path / "test.json"
        test_json.write_text(json.dumps({
            "refreshToken": "test_token",
            "accessToken": "test_access",
            "expiresAt": "2099-01-01T00:00:00.000Z"
        }))
        
        creds_file = tmp_path / "credentials.json"
        state_file = tmp_path / "state.json"
        _seed_credential_registry(state_file, [
            {"type": "json", "path": str(test_json), "enabled": True}
        ])
        
        manager = AccountManager(
            credentials_file=str(creds_file),
            state_file=str(state_file)
        )
        
        await manager.load_credentials()
        account_id = str(test_json.resolve())
        
        # Initialize account
        with patch('kiro.account_manager.KiroHttpClient') as mock_http_class:
            mock_client = AsyncMock()
            mock_response = Mock()  # Response is not async
            mock_response.status_code = 200
            mock_response.json.return_value = mock_list_models_response
            mock_client.request_with_retry = AsyncMock(return_value=mock_response)
            mock_client.close = AsyncMock()
            mock_http_class.return_value = mock_client
            
            await manager._initialize_account(account_id)
        
        # Act
        await manager.report_success(account_id, "claude-opus-4.5")
        
        # Assert
        stats = manager._accounts[account_id].stats
        print(f"Stats: total={stats.total_requests}, successful={stats.successful_requests}")
        assert stats.total_requests == 1
        assert stats.successful_requests == 1

    @pytest.mark.asyncio
    async def test_report_success_round_robin_advances_to_next_account(self, tmp_path):
        """
        Test that round-robin mode advances the selection index after success.

        What it does: Reports success on the first account in round-robin mode
        Purpose: Verify the next request will start from the following account
        """
        print("\n=== Test: report_success advances index in round-robin mode ===")

        creds_file = tmp_path / "credentials.json"
        state_file = tmp_path / "state.json"
        account1 = tmp_path / "account1.json"
        account2 = tmp_path / "account2.json"
        account1.write_text(json.dumps({"refreshToken": "token1"}))
        account2.write_text(json.dumps({"refreshToken": "token2"}))
        _seed_credential_registry(state_file, [
            {"type": "json", "path": str(account1), "enabled": True},
            {"type": "json", "path": str(account2), "enabled": True},
        ])

        manager = AccountManager(
            credentials_file=str(creds_file),
            state_file=str(state_file)
        )
        await manager.load_credentials()

        account_ids = list(manager._accounts.keys())
        for account_id in account_ids:
            manager._accounts[account_id].auth_manager = MagicMock()
            manager._accounts[account_id].model_resolver = MagicMock()
            manager._accounts[account_id].model_resolver.get_available_models.return_value = ["claude-opus-4.5"]

        with patch("kiro.account_manager.get_account_selection_mode", return_value="round_robin"):
            await manager.report_success(account_ids[0], "claude-opus-4.5")

        print(f"Current selection index: {manager._current_account_index}")
        assert manager._current_account_index == 1


class TestAccountManagerReportFailure:
    """
    Tests for AccountManager.report_failure() method.
    """
    
    @pytest.mark.asyncio
    async def test_report_failure_recoverable_increment_failures(self, tmp_path, mock_list_models_response):
        """
        Test that RECOVERABLE errors increment failures.
        
        What it does: Reports RECOVERABLE failure
        Purpose: Verify failure counter increment
        """
        print("\n=== Test: report_failure RECOVERABLE increments failures ===")
        
        # Arrange
        test_json = tmp_path / "test.json"
        test_json.write_text(json.dumps({
            "refreshToken": "test_token",
            "accessToken": "test_access",
            "expiresAt": "2099-01-01T00:00:00.000Z"
        }))
        
        creds_file = tmp_path / "credentials.json"
        state_file = tmp_path / "state.json"
        _seed_credential_registry(state_file, [
            {"type": "json", "path": str(test_json), "enabled": True}
        ])
        
        manager = AccountManager(
            credentials_file=str(creds_file),
            state_file=str(state_file)
        )
        
        await manager.load_credentials()
        account_id = str(test_json.resolve())
        
        # Initialize account
        with patch('kiro.account_manager.KiroHttpClient') as mock_http_class:
            mock_client = AsyncMock()
            mock_response = Mock()  # Response is not async
            mock_response.status_code = 200
            mock_response.json.return_value = mock_list_models_response
            mock_client.request_with_retry = AsyncMock(return_value=mock_response)
            mock_client.close = AsyncMock()
            mock_http_class.return_value = mock_client
            
            await manager._initialize_account(account_id)
        
        # Act
        await manager.report_failure(
            account_id, "claude-opus-4.5",
            ErrorType.RECOVERABLE, 429, None
        )
        
        # Assert
        print(f"Failures: {manager._accounts[account_id].failures}")
        assert manager._accounts[account_id].failures == 1
    
    @pytest.mark.asyncio
    async def test_report_failure_fatal_no_increment(self, tmp_path, mock_list_models_response):
        """
        Test that FATAL errors do NOT increment failures.
        
        What it does: Reports FATAL failure
        Purpose: Verify failures not incremented for request errors
        """
        print("\n=== Test: report_failure FATAL does not increment failures ===")
        
        # Arrange
        test_json = tmp_path / "test.json"
        test_json.write_text(json.dumps({
            "refreshToken": "test_token",
            "accessToken": "test_access",
            "expiresAt": "2099-01-01T00:00:00.000Z"
        }))
        
        creds_file = tmp_path / "credentials.json"
        state_file = tmp_path / "state.json"
        _seed_credential_registry(state_file, [
            {"type": "json", "path": str(test_json), "enabled": True}
        ])
        
        manager = AccountManager(
            credentials_file=str(creds_file),
            state_file=str(state_file)
        )
        
        await manager.load_credentials()
        account_id = str(test_json.resolve())
        
        # Initialize account
        with patch('kiro.account_manager.KiroHttpClient') as mock_http_class:
            mock_client = AsyncMock()
            mock_response = Mock()  # Response is not async
            mock_response.status_code = 200
            mock_response.json.return_value = mock_list_models_response
            mock_client.request_with_retry = AsyncMock(return_value=mock_response)
            mock_client.close = AsyncMock()
            mock_http_class.return_value = mock_client
            
            await manager._initialize_account(account_id)
        
        # Act
        await manager.report_failure(
            account_id, "claude-opus-4.5",
            ErrorType.FATAL, 400, "CONTENT_LENGTH_EXCEEDS_THRESHOLD"
        )
        
        # Assert
        print(f"Failures: {manager._accounts[account_id].failures}")
        assert manager._accounts[account_id].failures == 0  # Not incremented


class TestAccountManagerSaveState:
    """
    Tests for AccountManager._save_state() and save_state_periodically().
    """
    
    @pytest.mark.asyncio
    async def test_save_state_atomic_write(self, tmp_path):
        """
        Test atomic state saving via tmp file.
        
        What it does: Saves state and checks tmp file usage
        Purpose: Verify atomic write pattern
        """
        print("\n=== Test: save_state atomic write ===")
        
        # Arrange
        state_file = tmp_path / "state.json"
        manager = AccountManager(
            credentials_file=str(tmp_path / "creds.json"),
            state_file=str(state_file)
        )
        
        # Act
        await manager._save_state()
        
        # Assert
        print(f"State file exists: {state_file.exists()}")
        assert state_file.exists()
        
        # Verify tmp file was cleaned up
        tmp_file = tmp_path / "state.json.tmp"
        print(f"Tmp file exists: {tmp_file.exists()}")
        assert not tmp_file.exists()


class TestAccountManagerGetFirstAccount:
    """
    Tests for AccountManager.get_first_account() method.
    """
    
    @pytest.mark.asyncio
    async def test_get_first_account_success(self, tmp_path, mock_list_models_response):
        """
        Test getting first initialized account.
        
        What it does: Gets first account for legacy mode
        Purpose: Verify legacy mode support
        """
        print("\n=== Test: get_first_account success ===")
        
        # Arrange
        test_json = tmp_path / "test.json"
        test_json.write_text(json.dumps({
            "refreshToken": "test_token",
            "accessToken": "test_access",
            "expiresAt": "2099-01-01T00:00:00.000Z"
        }))
        
        creds_file = tmp_path / "credentials.json"
        state_file = tmp_path / "state.json"
        _seed_credential_registry(state_file, [
            {"type": "json", "path": str(test_json), "enabled": True}
        ])
        
        manager = AccountManager(
            credentials_file=str(creds_file),
            state_file=str(state_file)
        )
        
        await manager.load_credentials()
        account_id = str(test_json.resolve())
        
        # Initialize account
        with patch('kiro.account_manager.KiroHttpClient') as mock_http_class:
            mock_client = AsyncMock()
            mock_response = Mock()  # Response is not async
            mock_response.status_code = 200
            mock_response.json.return_value = mock_list_models_response
            mock_client.request_with_retry = AsyncMock(return_value=mock_response)
            mock_client.close = AsyncMock()
            mock_http_class.return_value = mock_client
            
            await manager._initialize_account(account_id)
        
        # Act
        account = manager.get_first_account()
        
        # Assert
        print(f"Got account: {account is not None}")
        assert account is not None
        assert account.auth_manager is not None
    
    def test_get_first_account_no_initialized(self, tmp_path):
        """
        Test RuntimeError when no initialized accounts.
        
        What it does: Attempts to get account when none initialized
        Purpose: Verify error handling
        """
        print("\n=== Test: get_first_account with no initialized accounts ===")
        
        # Arrange
        manager = AccountManager(
            credentials_file=str(tmp_path / "creds.json"),
            state_file=str(tmp_path / "state.json")
        )
        
        # Act & Assert
        with pytest.raises(RuntimeError, match="No initialized accounts available"):
            manager.get_first_account()

    @pytest.mark.asyncio
    async def test_get_first_initialized_account_returns_existing(self, tmp_path):
        """
        Test returning an already initialized account without reinitializing.

        What it does: Gets the first account that already has an auth manager
        Purpose: Verify legacy request paths keep using initialized accounts
        """
        print("\n=== Test: get_first_initialized_account returns existing account ===")

        # Arrange
        manager = AccountManager(
            credentials_file=str(tmp_path / "creds.json"),
            state_file=str(tmp_path / "state.json")
        )
        manager._accounts["account1"] = Account(id="account1", auth_manager=MagicMock())

        with patch.object(manager, "_initialize_account", new_callable=AsyncMock) as mock_initialize:
            # Act
            account = await manager.get_first_initialized_account()

        # Assert
        assert account is not None
        assert account.id == "account1"
        mock_initialize.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_get_first_initialized_account_lazily_initializes_after_reload(self, tmp_path):
        """
        Test lazy initialization when accounts were reloaded without auth managers.

        What it does: Initializes an account on first legacy request
        Purpose: Prevent admin account reloads from causing request-time 500s
        """
        print("\n=== Test: get_first_initialized_account lazily initializes account ===")

        # Arrange
        manager = AccountManager(
            credentials_file=str(tmp_path / "creds.json"),
            state_file=str(tmp_path / "state.json")
        )
        manager._accounts["account1"] = Account(id="account1")

        async def initialize_account(account_id: str) -> bool:
            manager._accounts[account_id].auth_manager = MagicMock()
            return True

        with patch.object(manager, "_initialize_account", new_callable=AsyncMock) as mock_initialize:
            mock_initialize.side_effect = initialize_account

            # Act
            account = await manager.get_first_initialized_account()

        # Assert
        assert account is not None
        assert account.id == "account1"
        assert account.auth_manager is not None
        mock_initialize.assert_awaited_once_with("account1")

    @pytest.mark.asyncio
    async def test_get_first_initialized_account_tries_next_when_first_fails(self, tmp_path):
        """
        Test fallback to the next configured account when initialization fails.

        What it does: Fails the first lazy initialization and succeeds the second
        Purpose: Verify legacy request paths can recover from one bad account
        """
        print("\n=== Test: get_first_initialized_account tries next account ===")

        # Arrange
        manager = AccountManager(
            credentials_file=str(tmp_path / "creds.json"),
            state_file=str(tmp_path / "state.json")
        )
        manager._accounts["account1"] = Account(id="account1")
        manager._accounts["account2"] = Account(id="account2")

        async def initialize_account(account_id: str) -> bool:
            if account_id == "account1":
                return False
            manager._accounts[account_id].auth_manager = MagicMock()
            return True

        with patch.object(manager, "_initialize_account", new_callable=AsyncMock) as mock_initialize:
            mock_initialize.side_effect = initialize_account

            # Act
            account = await manager.get_first_initialized_account()

        # Assert
        assert account is not None
        assert account.id == "account2"
        assert mock_initialize.await_count == 2

    @pytest.mark.asyncio
    async def test_get_first_initialized_account_returns_none_when_all_fail(self, tmp_path):
        """
        Test None is returned when no account can be initialized.

        What it does: Attempts lazy initialization for all accounts
        Purpose: Let routes return a controlled 503 instead of raising RuntimeError
        """
        print("\n=== Test: get_first_initialized_account returns None when all fail ===")

        # Arrange
        manager = AccountManager(
            credentials_file=str(tmp_path / "creds.json"),
            state_file=str(tmp_path / "state.json")
        )
        manager._accounts["account1"] = Account(id="account1")
        manager._accounts["account2"] = Account(id="account2")

        with patch.object(manager, "_initialize_account", new_callable=AsyncMock) as mock_initialize:
            mock_initialize.return_value = False

            # Act
            account = await manager.get_first_initialized_account()

        # Assert
        assert account is None
        assert mock_initialize.await_count == 2


class TestAccountManagerGetAllAvailableModels:
    """
    Tests for AccountManager.get_all_available_models() method.
    """
    
    @pytest.mark.asyncio
    async def test_get_all_available_models_collect_from_all(self, tmp_path, mock_list_models_response):
        """
        Test collecting unique models from all accounts.
        
        What it does: Gets models from multiple accounts
        Purpose: Verify model aggregation for /v1/models endpoint
        """
        print("\n=== Test: get_all_available_models collects from all ===")
        
        # Arrange
        test_json = tmp_path / "test.json"
        test_json.write_text(json.dumps({
            "refreshToken": "test_token",
            "accessToken": "test_access",
            "expiresAt": "2099-01-01T00:00:00.000Z"
        }))
        
        creds_file = tmp_path / "credentials.json"
        state_file = tmp_path / "state.json"
        _seed_credential_registry(state_file, [
            {"type": "json", "path": str(test_json), "enabled": True}
        ])
        
        manager = AccountManager(
            credentials_file=str(creds_file),
            state_file=str(state_file)
        )
        
        await manager.load_credentials()
        account_id = str(test_json.resolve())
        
        # Initialize account
        with patch('kiro.account_manager.KiroHttpClient') as mock_http_class:
            mock_client = AsyncMock()
            mock_response = Mock()  # Response is not async
            mock_response.status_code = 200
            mock_response.json.return_value = mock_list_models_response
            mock_client.request_with_retry = AsyncMock(return_value=mock_response)
            mock_client.close = AsyncMock()
            mock_http_class.return_value = mock_client
            
            await manager._initialize_account(account_id)
        
        # Act
        models = manager.get_all_available_models()
        
        # Assert
        print(f"Available models: {len(models)}")
        assert len(models) > 0
        assert isinstance(models, list)
        assert all(isinstance(m, str) for m in models)


class TestAccountManagerGetAccountSnapshots:
    """
    Tests for AccountManager.get_account_snapshots() method.
    """

    def test_get_credential_entries_resolves_sqlite_account_display_name(self, tmp_path):
        """
        What it does: Builds a credential entry for a stored SQLite account with JWT claims.
        Purpose: Ensure admin APIs expose a readable account name instead of only the opaque row ID.
        """
        print("\n=== Test: get_credential_entries resolves SQLite account display name ===")

        db_path = tmp_path / "kiro_accounts.sqlite3"
        store = KiroAccountSqliteStore(str(db_path))
        record = store.upsert_token({
            "accessToken": _build_unsigned_jwt({"email": "alice@example.com"}),
            "refreshToken": "refresh",
            "expiresAt": "2099-01-01T00:00:00+00:00",
            "authMethod": "social",
            "provider": "Google",
        })

        manager = AccountManager(
            credentials_file=str(tmp_path / "credentials.json"),
            state_file=str(tmp_path / "state.json"),
        )
        manager._credentials_config = [{
            "type": "sqlite_account",
            "path": str(db_path),
            "account_id": record["id"],
            "enabled": True,
        }]

        entries = manager.get_credential_entries()

        assert len(entries) == 1
        assert entries[0]["display_name"] == "alice@example.com"
        assert entries[0]["account_id"] == record["id"]

    def test_get_credential_entries_prefers_stored_remote_display_name(self, tmp_path):
        """
        What it does: Resolves a SQLite account entry with a persisted remote display name.
        Purpose: Ensure admin account names read the stored Web Portal identity instead of re-fetching it.
        """
        print("\n=== Test: get_credential_entries prefers stored remote display name ===")

        db_path = tmp_path / "kiro_accounts.sqlite3"
        store = KiroAccountSqliteStore(str(db_path))
        record = store.upsert_token(
            {
                "accessToken": _build_unsigned_jwt({"email": "local@example.com"}),
                "refreshToken": "refresh",
                "expiresAt": "2099-01-01T00:00:00+00:00",
                "authMethod": "social",
                "provider": "Google",
            },
            display_name="portal@example.com",
        )

        manager = AccountManager(
            credentials_file=str(tmp_path / "credentials.json"),
            state_file=str(tmp_path / "state.json"),
        )
        manager._credentials_config = [{
            "type": "sqlite_account",
            "path": str(db_path),
            "account_id": record["id"],
            "enabled": True,
        }]

        with patch("kiro.account_manager.fetch_kiro_web_portal_user_info") as lookup:
            entries = manager.get_credential_entries()

        assert len(entries) == 1
        assert entries[0]["display_name"] == "portal@example.com"
        lookup.assert_not_called()

    def test_get_credential_entries_fall_back_to_local_display_name_when_stored_remote_display_name_missing(self, tmp_path):
        """
        What it does: Resolves a SQLite account entry without a persisted remote display name.
        Purpose: Ensure admin account names still use local token identity without any Web Portal request.
        """
        print("\n=== Test: get_credential_entries falls back to local display name ===")

        db_path = tmp_path / "kiro_accounts.sqlite3"
        store = KiroAccountSqliteStore(str(db_path))
        record = store.upsert_token(
            {
                "accessToken": _build_unsigned_jwt({"email": "alice@example.com"}),
                "refreshToken": "refresh",
                "expiresAt": "2099-01-01T00:00:00+00:00",
                "authMethod": "social",
                "provider": "Google",
            }
        )

        manager = AccountManager(
            credentials_file=str(tmp_path / "credentials.json"),
            state_file=str(tmp_path / "state.json"),
        )
        manager._credentials_config = [{
            "type": "sqlite_account",
            "path": str(db_path),
            "account_id": record["id"],
            "enabled": True,
        }]

        with patch("kiro.account_manager.fetch_kiro_web_portal_user_info") as lookup:
            entries = manager.get_credential_entries()

        assert len(entries) == 1
        assert entries[0]["display_name"] == "alice@example.com"
        lookup.assert_not_called()

    def test_get_account_snapshots_includes_available_models(self, tmp_path):
        """
        What it does: Builds an initialized account snapshot.
        Purpose: Ensure admin APIs can show the actual model list per account.
        """
        print("\n=== Test: get_account_snapshots includes available models ===")

        creds_file = tmp_path / "credentials.json"
        state_file = tmp_path / "state.json"
        test_json = tmp_path / "test.json"
        test_json.write_text(json.dumps({"refreshToken": "test"}))
        _seed_credential_registry(state_file, [{"type": "json", "path": str(test_json), "enabled": True}])

        manager = AccountManager(
            credentials_file=str(creds_file),
            state_file=str(state_file),
        )

        account_id = str(test_json.resolve())
        account = Account(id=account_id)
        account.auth_manager = MagicMock()
        account.auth_manager.auth_type.value = "kiro_desktop"
        account.model_resolver = MagicMock()
        account.model_resolver.get_available_models.return_value = [
            "claude-haiku-4.5",
            "claude-sonnet-4.5",
        ]
        manager._accounts[account_id] = account

        snapshots = manager.get_account_snapshots()

        assert len(snapshots) == 1
        assert snapshots[0]["models_count"] == 2
        assert snapshots[0]["available_models"] == ["claude-haiku-4.5", "claude-sonnet-4.5"]

    def test_get_account_snapshots_resolves_sqlite_account_display_name(self, tmp_path):
        """
        What it does: Builds a runtime snapshot for a stored SQLite account with JWT claims.
        Purpose: Ensure runtime account tables show a readable account name instead of only the runtime ID.
        """
        print("\n=== Test: get_account_snapshots resolves SQLite account display name ===")

        db_path = tmp_path / "kiro_accounts.sqlite3"
        store = KiroAccountSqliteStore(str(db_path))
        record = store.upsert_token({
            "accessToken": _build_unsigned_jwt({"email": "alice@example.com"}),
            "refreshToken": "refresh",
            "expiresAt": "2099-01-01T00:00:00+00:00",
            "authMethod": "social",
            "provider": "Google",
        })

        manager = AccountManager(
            credentials_file=str(tmp_path / "credentials.json"),
            state_file=str(tmp_path / "state.json"),
        )
        runtime_account_id = manager._runtime_id_for_sqlite_account(str(db_path), record["id"])
        account = Account(id=runtime_account_id)
        account.auth_manager = MagicMock()
        account.auth_manager.auth_type.value = "kiro_desktop"
        account.model_resolver = MagicMock()
        account.model_resolver.get_available_models.return_value = ["claude-haiku-4.5"]
        manager._accounts[runtime_account_id] = account

        snapshots = manager.get_account_snapshots()

        assert len(snapshots) == 1
        assert snapshots[0]["display_name"] == "alice@example.com"
        assert snapshots[0]["id"] == runtime_account_id

    def test_get_account_snapshots_use_stored_remote_display_name(self, tmp_path):
        """
        What it does: Builds a runtime snapshot for a stored SQLite account with a persisted remote display name.
        Purpose: Ensure runtime account tables read the stored Web Portal identity without a fresh RPC call.
        """
        print("\n=== Test: get_account_snapshots use stored remote display name ===")

        db_path = tmp_path / "kiro_accounts.sqlite3"
        store = KiroAccountSqliteStore(str(db_path))
        record = store.upsert_token(
            {
                "accessToken": _build_unsigned_jwt({"email": "local@example.com"}),
                "refreshToken": "refresh",
                "expiresAt": "2099-01-01T00:00:00+00:00",
                "authMethod": "social",
                "provider": "Google",
            },
            display_name="portal@example.com",
        )

        manager = AccountManager(
            credentials_file=str(tmp_path / "credentials.json"),
            state_file=str(tmp_path / "state.json"),
        )
        runtime_account_id = manager._runtime_id_for_sqlite_account(str(db_path), record["id"])
        account = Account(id=runtime_account_id)
        account.auth_manager = MagicMock()
        account.auth_manager.auth_type.value = "kiro_desktop"
        account.model_resolver = MagicMock()
        account.model_resolver.get_available_models.return_value = ["claude-haiku-4.5"]
        manager._accounts[runtime_account_id] = account

        with patch("kiro.account_manager.fetch_kiro_web_portal_user_info") as lookup:
            snapshots = manager.get_account_snapshots()

        assert len(snapshots) == 1
        assert snapshots[0]["display_name"] == "portal@example.com"
        lookup.assert_not_called()

    def test_get_admin_accounts_payload_uses_stored_remote_display_name(self, tmp_path):
        """
        What it does: Builds the combined admin payload for the same SQLite account in both tables.
        Purpose: Ensure one admin response reuses the stored remote display name without any Web Portal lookup.
        """
        print("\n=== Test: get_admin_accounts_payload uses stored remote display name ===")

        db_path = tmp_path / "kiro_accounts.sqlite3"
        store = KiroAccountSqliteStore(str(db_path))
        record = store.upsert_token(
            {
                "accessToken": "remote-access-token",
                "refreshToken": "refresh",
                "expiresAt": "2099-01-01T00:00:00+00:00",
                "authMethod": "social",
                "provider": "Google",
            },
            display_name="portal@example.com",
        )

        manager = AccountManager(
            credentials_file=str(tmp_path / "credentials.json"),
            state_file=str(tmp_path / "state.json"),
        )
        manager._credentials_config = [{
            "type": "sqlite_account",
            "path": str(db_path),
            "account_id": record["id"],
            "enabled": True,
        }]

        runtime_account_id = manager._runtime_id_for_sqlite_account(str(db_path), record["id"])
        account = Account(id=runtime_account_id)
        account.auth_manager = MagicMock()
        account.auth_manager.auth_type.value = "kiro_desktop"
        account.model_resolver = MagicMock()
        account.model_resolver.get_available_models.return_value = ["claude-haiku-4.5"]
        manager._accounts[runtime_account_id] = account

        with patch("kiro.account_manager.fetch_kiro_web_portal_user_info") as lookup:
            payload = manager.get_admin_accounts_payload()

        assert payload["credentials"][0]["display_name"] == "portal@example.com"
        assert payload["accounts"][0]["display_name"] == "portal@example.com"
        lookup.assert_not_called()


class TestFormatDuration:
    """
    Tests for _format_duration() helper function.
    """
    
    def test_format_duration_seconds(self):
        """Test formatting seconds."""
        assert _format_duration(30) == "30s"
        assert _format_duration(59) == "59s"
    
    def test_format_duration_minutes(self):
        """Test formatting minutes."""
        assert _format_duration(60) == "1m"
        assert _format_duration(300) == "5m"
        assert _format_duration(3599) == "59m"
    
    def test_format_duration_hours(self):
        """Test formatting hours."""
        assert _format_duration(3600) == "1h"
        assert _format_duration(7200) == "2h"
        assert _format_duration(86399) == "23h"
    
    def test_format_duration_days(self):
        """Test formatting days."""
        assert _format_duration(86400) == "1d"
        assert _format_duration(172800) == "2d"
