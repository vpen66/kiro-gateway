# -*- coding: utf-8 -*-

"""
Tests for main.py lifespan() function - Account System initialization.

Tests cover:
- Legacy fallback: env and legacy file migration into the SQLite credential registry
- AccountManager initialization
- First working account initialization
- Background task management
"""

import asyncio
import json
import pytest
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, Mock, patch, call
from contextlib import asynccontextmanager

from kiro.account_sqlite_store import KiroAccountSqliteStore


def _list_registry_entries(db_path: Path) -> list[dict]:
    """Return persisted credential entries from the test SQLite registry."""
    return KiroAccountSqliteStore(str(db_path)).list_credential_entries()


# =============================================================================
# Test Class: Legacy Fallback (Migration)
# =============================================================================

class TestLifespanLegacyFallback:
    """
    Tests for migration into the SQLite credential registry.
    
    What it does: Verifies automatic migration from legacy env/file inputs into
    the persisted SQLite credential registry.
    Purpose: Ensure backward compatibility without depending on credentials.json
    at runtime.
    """
    
    @pytest.mark.asyncio
    async def test_lifespan_legacy_mode_recreate_credentials(self, tmp_path, monkeypatch):
        """
        Test 92: ACCOUNT_SYSTEM=false rebuilds the SQLite registry from env on startup.

        What it does: Verifies that legacy mode always refreshes the persisted
        credential registry from legacy environment variables.
        Purpose: Ensure runtime credentials come from SQLite instead of
        credentials.json.
        """
        print("\n=== Test 92: Legacy mode rebuilds SQLite credential registry ===")
        
        # Arrange: Patch constants directly in main module (not os.environ)
        monkeypatch.setattr("main.ACCOUNT_SYSTEM", False)
        monkeypatch.setattr("main.REFRESH_TOKEN", "test_refresh_token")
        monkeypatch.setattr("main.PROFILE_ARN", "arn:aws:codewhisperer:us-east-1:123456789:profile/test")
        monkeypatch.setattr("main.REGION", "us-east-1")
        monkeypatch.setattr("main.KIRO_CREDS_FILE", None)
        monkeypatch.setattr("main.KIRO_CLI_DB_FILE", None)

        creds_file = tmp_path / "credentials.json"
        state_file = tmp_path / "state.json"
        accounts_db_file = tmp_path / "kiro_accounts.sqlite3"
        
        # Create old credentials.json
        old_creds = [{"type": "json", "path": "/old/path.json"}]
        creds_file.write_text(json.dumps(old_creds))
        print(f"Created legacy credentials.json: {old_creds}")
        
        # Mock config paths
        monkeypatch.setattr("main.ACCOUNTS_CONFIG_FILE", str(creds_file))
        monkeypatch.setattr("main.ACCOUNTS_STATE_FILE", str(state_file))
        monkeypatch.setattr("main.KIRO_ACCOUNTS_DB_FILE", "kiro_accounts.sqlite3")
        
        # Mock AccountManager to prevent actual initialization
        mock_manager = AsyncMock()
        mock_manager._accounts = {"test": MagicMock()}
        mock_manager._current_account_index = 0
        mock_manager._initialize_account = AsyncMock(return_value=True)
        mock_manager._save_state = AsyncMock()
        mock_manager.save_state_periodically = AsyncMock()
        
        with patch("main.AccountManager", return_value=mock_manager):
            with patch("main.httpx.AsyncClient") as mock_client_class:
                mock_client = AsyncMock()
                mock_client_class.return_value = mock_client
                
                # Import and run lifespan
                from main import lifespan, app
                
                async with lifespan(app):
                    pass
        
        # Assert: SQLite registry was rebuilt from env and the legacy file was ignored
        assert creds_file.exists()
        assert json.loads(creds_file.read_text()) == old_creds
        registry_entries = _list_registry_entries(accounts_db_file)
        print(f"SQLite credential registry: {registry_entries}")
        
        assert len(registry_entries) == 1
        assert registry_entries[0]["type"] == "refresh_token"
        assert registry_entries[0]["refresh_token"] == "test_refresh_token"
        print("✓ SQLite credential registry was rebuilt from .env in legacy mode")
    
    @pytest.mark.asyncio
    async def test_lifespan_account_system_one_time_migration(self, tmp_path, monkeypatch):
        """
        Test 93: ACCOUNT_SYSTEM=true populates SQLite only once.

        What it does: Verifies one-time migration in account system mode.
        Purpose: Ensure the persisted SQLite registry is not overwritten after
        initial population.
        """
        print("\n=== Test 93: Account system one-time SQLite migration ===")
        
        # Arrange: Patch constants directly
        monkeypatch.setattr("main.ACCOUNT_SYSTEM", True)
        monkeypatch.setattr("main.REFRESH_TOKEN", "test_refresh_token")
        monkeypatch.setattr("main.KIRO_CREDS_FILE", None)
        monkeypatch.setattr("main.KIRO_CLI_DB_FILE", None)
        
        creds_file = tmp_path / "credentials.json"
        state_file = tmp_path / "state.json"
        accounts_db_file = tmp_path / "kiro_accounts.sqlite3"
        
        # First run: no persisted SQLite registry
        monkeypatch.setattr("main.ACCOUNTS_CONFIG_FILE", str(creds_file))
        monkeypatch.setattr("main.ACCOUNTS_STATE_FILE", str(state_file))
        monkeypatch.setattr("main.KIRO_ACCOUNTS_DB_FILE", "kiro_accounts.sqlite3")
        
        mock_manager = AsyncMock()
        mock_manager._accounts = {"test": MagicMock()}
        mock_manager._current_account_index = 0
        mock_manager._initialize_account = AsyncMock(return_value=True)
        mock_manager._save_state = AsyncMock()
        mock_manager.save_state_periodically = AsyncMock()
        
        with patch("main.AccountManager", return_value=mock_manager):
            with patch("main.httpx.AsyncClient") as mock_client_class:
                mock_client = AsyncMock()
                mock_client_class.return_value = mock_client
                
                from main import lifespan, app
                
                # First run
                async with lifespan(app):
                    pass
        
        first_entries = _list_registry_entries(accounts_db_file)
        print(f"First run populated SQLite registry: {first_entries}")
        assert len(first_entries) == 1
        assert first_entries[0]["type"] == "refresh_token"
        assert first_entries[0]["refresh_token"] == "test_refresh_token"
        
        # Modify legacy credentials.json manually; it should not overwrite SQLite
        manual_creds = [{"type": "json", "path": "/manual/path.json"}]
        creds_file.write_text(json.dumps(manual_creds))
        print(f"Manually wrote legacy credentials.json: {manual_creds}")
        
        # Second run: SQLite registry already exists
        with patch("main.AccountManager", return_value=mock_manager):
            with patch("main.httpx.AsyncClient") as mock_client_class:
                mock_client = AsyncMock()
                mock_client_class.return_value = mock_client
                
                async with lifespan(app):
                    pass
        
        # Assert: persisted SQLite registry was NOT overwritten
        second_entries = _list_registry_entries(accounts_db_file)
        print(f"Second run kept SQLite registry: {second_entries}")
        
        assert second_entries == first_entries
        print("✓ SQLite credential registry was not overwritten on second run")
    
    @pytest.mark.asyncio
    async def test_lifespan_migration_priority_sqlite(self, tmp_path, monkeypatch):
        """
        Test 94: SQLite source has priority over JSON and refresh_token.

        What it does: Verifies credential source priority during migration.
        Purpose: Ensure the persisted registry uses the same source preference
        as KiroAuthManager.
        """
        print("\n=== Test 94: Migration priority SQLite > JSON > refresh_token ===")
        
        # Arrange: all three sources present
        # Create SQLite DB
        import sqlite3
        sqlite_db = tmp_path / "data.sqlite3"
        conn = sqlite3.connect(str(sqlite_db))
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE auth_kv (key TEXT PRIMARY KEY, value TEXT)")
        cursor.execute(
            "INSERT INTO auth_kv VALUES (?, ?)",
            ("codewhisperer:odic:token", json.dumps({"access_token": "sqlite_token"}))
        )
        conn.commit()
        conn.close()
        
        # Create JSON file
        json_file = tmp_path / "kiro-auth.json"
        json_file.write_text(json.dumps({"accessToken": "json_token"}))
        
        # Patch constants directly
        monkeypatch.setattr("main.ACCOUNT_SYSTEM", True)
        monkeypatch.setattr("main.REFRESH_TOKEN", "test_refresh_token")
        monkeypatch.setattr("main.KIRO_CLI_DB_FILE", str(sqlite_db))
        monkeypatch.setattr("main.KIRO_CREDS_FILE", str(json_file))
        
        creds_file = tmp_path / "credentials.json"
        state_file = tmp_path / "state.json"
        accounts_db_file = tmp_path / "kiro_accounts.sqlite3"
        
        monkeypatch.setattr("main.ACCOUNTS_CONFIG_FILE", str(creds_file))
        monkeypatch.setattr("main.ACCOUNTS_STATE_FILE", str(state_file))
        monkeypatch.setattr("main.KIRO_ACCOUNTS_DB_FILE", "kiro_accounts.sqlite3")
        
        mock_manager = AsyncMock()
        mock_manager._accounts = {"test": MagicMock()}
        mock_manager._current_account_index = 0
        mock_manager._initialize_account = AsyncMock(return_value=True)
        mock_manager._save_state = AsyncMock()
        mock_manager.save_state_periodically = AsyncMock()
        
        with patch("main.AccountManager", return_value=mock_manager):
            with patch("main.httpx.AsyncClient") as mock_client_class:
                mock_client = AsyncMock()
                mock_client_class.return_value = mock_client
                
                from main import lifespan, app
                
                async with lifespan(app):
                    pass
        
        # Assert: SQLite was chosen (highest priority)
        registry_entries = _list_registry_entries(accounts_db_file)
        print(f"Created SQLite credential registry: {registry_entries}")
        
        assert len(registry_entries) == 1
        assert registry_entries[0]["type"] == "sqlite"
        assert registry_entries[0]["path"] == str(sqlite_db)
        print("✓ SQLite was chosen (highest priority)")
    
    @pytest.mark.asyncio
    async def test_lifespan_migration_add_env_overrides(self, tmp_path, monkeypatch):
        """
        Test 95: env overrides are persisted in the SQLite registry.

        What it does: Verifies that env var overrides are added to migrated
        credentials.
        Purpose: Ensure per-account parameters are preserved during migration.
        """
        print("\n=== Test 95: Add env overrides during SQLite migration ===")
        
        # Arrange: Patch constants and also patch os.getenv for _add_env_overrides
        monkeypatch.setattr("main.ACCOUNT_SYSTEM", True)
        monkeypatch.setattr("main.REFRESH_TOKEN", "test_refresh_token")
        monkeypatch.setattr("main.KIRO_CREDS_FILE", None)
        monkeypatch.setattr("main.KIRO_CLI_DB_FILE", None)
        
        # Patch os.getenv for the helper function
        monkeypatch.setenv("PROFILE_ARN", "arn:aws:codewhisperer:eu-central-1:123456789:profile/test")
        monkeypatch.setenv("KIRO_REGION", "eu-west-1")
        monkeypatch.setenv("KIRO_API_REGION", "eu-central-1")
        
        creds_file = tmp_path / "credentials.json"
        state_file = tmp_path / "state.json"
        accounts_db_file = tmp_path / "kiro_accounts.sqlite3"
        
        monkeypatch.setattr("main.ACCOUNTS_CONFIG_FILE", str(creds_file))
        monkeypatch.setattr("main.ACCOUNTS_STATE_FILE", str(state_file))
        monkeypatch.setattr("main.KIRO_ACCOUNTS_DB_FILE", "kiro_accounts.sqlite3")
        
        mock_manager = AsyncMock()
        mock_manager._accounts = {"test": MagicMock()}
        mock_manager._current_account_index = 0
        mock_manager._initialize_account = AsyncMock(return_value=True)
        mock_manager._save_state = AsyncMock()
        mock_manager.save_state_periodically = AsyncMock()
        
        with patch("main.AccountManager", return_value=mock_manager):
            with patch("main.httpx.AsyncClient") as mock_client_class:
                mock_client = AsyncMock()
                mock_client_class.return_value = mock_client
                
                from main import lifespan, app
                
                async with lifespan(app):
                    pass
        
        # Assert: overrides were added
        registry_entries = _list_registry_entries(accounts_db_file)
        print(f"Created SQLite credential registry with overrides: {registry_entries}")
        
        assert registry_entries[0]["profile_arn"] == "arn:aws:codewhisperer:eu-central-1:123456789:profile/test"
        assert registry_entries[0]["region"] == "eu-west-1"
        assert registry_entries[0]["api_region"] == "eu-central-1"
        print("✓ Env overrides were added to the SQLite registry")
    
    @pytest.mark.asyncio
    async def test_lifespan_skip_migration_if_exists(self, tmp_path, monkeypatch):
        """
        Test 96: legacy file migration is skipped when the SQLite registry already exists.

        What it does: Verifies migration from credentials.json is skipped when
        the persisted registry is already populated.
        Purpose: Prevent legacy inputs from overwriting SQLite-backed state.
        """
        print("\n=== Test 96: Skip legacy file migration when SQLite registry exists ===")
        
        # Arrange: Patch constants
        monkeypatch.setattr("main.ACCOUNT_SYSTEM", True)
        monkeypatch.setattr("main.REFRESH_TOKEN", "test_refresh_token")
        monkeypatch.setattr("main.KIRO_CREDS_FILE", None)
        monkeypatch.setattr("main.KIRO_CLI_DB_FILE", None)
        
        creds_file = tmp_path / "credentials.json"
        state_file = tmp_path / "state.json"
        accounts_db_file = tmp_path / "kiro_accounts.sqlite3"
        
        # Pre-create SQLite registry and a conflicting legacy credentials file
        existing_registry = [{"type": "sqlite", "path": "/existing/path.sqlite3"}]
        KiroAccountSqliteStore(str(accounts_db_file)).replace_credential_entries(existing_registry)
        legacy_creds = [{"type": "json", "path": "/legacy/path.json"}]
        creds_file.write_text(json.dumps(legacy_creds))
        print(f"Pre-existing SQLite registry: {existing_registry}")
        print(f"Conflicting legacy credentials.json: {legacy_creds}")
        
        monkeypatch.setattr("main.ACCOUNTS_CONFIG_FILE", str(creds_file))
        monkeypatch.setattr("main.ACCOUNTS_STATE_FILE", str(state_file))
        monkeypatch.setattr("main.KIRO_ACCOUNTS_DB_FILE", "kiro_accounts.sqlite3")
        
        mock_manager = AsyncMock()
        mock_manager._accounts = {"test": MagicMock()}
        mock_manager._current_account_index = 0
        mock_manager._initialize_account = AsyncMock(return_value=True)
        mock_manager._save_state = AsyncMock()
        mock_manager.save_state_periodically = AsyncMock()
        
        with patch("main.AccountManager", return_value=mock_manager):
            with patch("main.httpx.AsyncClient") as mock_client_class:
                mock_client = AsyncMock()
                mock_client_class.return_value = mock_client
                
                from main import lifespan, app
                
                async with lifespan(app):
                    pass
        
        # Assert: SQLite registry was not modified by the legacy file
        final_registry = _list_registry_entries(accounts_db_file)
        print(f"Final SQLite registry: {final_registry}")
        
        assert len(final_registry) == 1
        assert final_registry[0]["type"] == "sqlite"
        assert final_registry[0]["path"] == "/existing/path.sqlite3"
        print("✓ Legacy credentials.json was ignored because SQLite already existed")


# =============================================================================
# Test Class: AccountManager Initialization
# =============================================================================

class TestLifespanAccountManagerInit:
    """
    Tests for AccountManager initialization and lifecycle.
    
    What it does: Verifies AccountManager creation, account initialization, and background tasks
    Purpose: Ensure proper startup and shutdown of Account System
    """
    
    @pytest.mark.asyncio
    async def test_lifespan_create_account_manager(self, tmp_path, monkeypatch):
        """
        Test 97: AccountManager receives the correct config and SQLite paths.

        What it does: Verifies AccountManager is created with correct file paths.
        Purpose: Ensure AccountManager receives proper registry configuration.
        """
        print("\n=== Test 97: Create AccountManager with correct paths ===")
        
        # Arrange: Patch constants
        monkeypatch.setattr("main.ACCOUNT_SYSTEM", True)
        monkeypatch.setattr("main.REFRESH_TOKEN", "test_token")
        monkeypatch.setattr("main.KIRO_CREDS_FILE", None)
        monkeypatch.setattr("main.KIRO_CLI_DB_FILE", None)
        
        creds_file = tmp_path / "credentials.json"
        state_file = tmp_path / "state.json"
        accounts_db_file = tmp_path / "kiro_accounts.sqlite3"
        
        monkeypatch.setattr("main.ACCOUNTS_CONFIG_FILE", str(creds_file))
        monkeypatch.setattr("main.ACCOUNTS_STATE_FILE", str(state_file))
        monkeypatch.setattr("main.KIRO_ACCOUNTS_DB_FILE", "kiro_accounts.sqlite3")
        
        # Track AccountManager creation
        manager_created_with = {}
        
        class MockAccountManager:
            def __init__(self, credentials_file, state_file, credentials_db_file):
                manager_created_with["credentials_file"] = credentials_file
                manager_created_with["state_file"] = state_file
                manager_created_with["credentials_db_file"] = credentials_db_file
                self._accounts = {"test": MagicMock()}
                self._current_account_index = 0
            
            async def load_credentials(self):
                pass
            
            async def load_state(self):
                pass
            
            async def _initialize_account(self, account_id):
                return True
            
            async def _save_state(self):
                pass
            
            async def save_state_periodically(self):
                await asyncio.sleep(1000)
        
        with patch("main.AccountManager", MockAccountManager):
            with patch("main.httpx.AsyncClient") as mock_client_class:
                mock_client = AsyncMock()
                mock_client_class.return_value = mock_client
                
                from main import lifespan, app
                
                async with lifespan(app):
                    pass
        
        # Assert
        print(f"AccountManager created with: {manager_created_with}")
        assert manager_created_with["credentials_file"] == str(creds_file)
        assert manager_created_with["state_file"] == str(state_file)
        assert manager_created_with["credentials_db_file"] == str(accounts_db_file)
        print("✓ AccountManager created with correct paths")
    
    @pytest.mark.asyncio
    async def test_lifespan_load_credentials_and_state(self, tmp_path, monkeypatch):
        """
        Test 98: Вызов load_credentials() и load_state()
        
        What it does: Verifies that load methods are called during startup
        Purpose: Ensure credentials and state are loaded before initialization
        """
        print("\n=== Test 98: Call load_credentials() and load_state() ===")
        
        # Arrange: Patch constants
        monkeypatch.setattr("main.ACCOUNT_SYSTEM", True)
        monkeypatch.setattr("main.REFRESH_TOKEN", "test_token")
        monkeypatch.setattr("main.KIRO_CREDS_FILE", None)
        monkeypatch.setattr("main.KIRO_CLI_DB_FILE", None)
        
        creds_file = tmp_path / "credentials.json"
        state_file = tmp_path / "state.json"
        
        monkeypatch.setattr("main.ACCOUNTS_CONFIG_FILE", str(creds_file))
        monkeypatch.setattr("main.ACCOUNTS_STATE_FILE", str(state_file))
        
        load_calls = {"credentials": False, "state": False}
        
        mock_manager = AsyncMock()
        mock_manager._accounts = {"test": MagicMock()}
        mock_manager._current_account_index = 0
        
        async def track_load_credentials():
            load_calls["credentials"] = True
        
        async def track_load_state():
            load_calls["state"] = True
        
        mock_manager.load_credentials = track_load_credentials
        mock_manager.load_state = track_load_state
        mock_manager._initialize_account = AsyncMock(return_value=True)
        mock_manager._save_state = AsyncMock()
        mock_manager.save_state_periodically = AsyncMock()
        
        with patch("main.AccountManager", return_value=mock_manager):
            with patch("main.httpx.AsyncClient") as mock_client_class:
                mock_client = AsyncMock()
                mock_client_class.return_value = mock_client
                
                from main import lifespan, app
                
                async with lifespan(app):
                    pass
        
        # Assert
        print(f"Load calls: {load_calls}")
        assert load_calls["credentials"] is True
        assert load_calls["state"] is True
        print("✓ load_credentials() and load_state() were called")
    
    @pytest.mark.asyncio
    async def test_lifespan_set_account_system_flag(self, tmp_path, monkeypatch):
        """
        Test 99: Установка app.state.account_system
        
        What it does: Verifies account_system flag is set in app.state
        Purpose: Ensure routes can check if account system is enabled
        """
        print("\n=== Test 99: Set app.state.account_system flag ===")
        
        # Arrange: Patch constants
        monkeypatch.setattr("main.ACCOUNT_SYSTEM", True)
        monkeypatch.setattr("main.REFRESH_TOKEN", "test_token")
        monkeypatch.setattr("main.KIRO_CREDS_FILE", None)
        monkeypatch.setattr("main.KIRO_CLI_DB_FILE", None)
        
        creds_file = tmp_path / "credentials.json"
        state_file = tmp_path / "state.json"
        
        monkeypatch.setattr("main.ACCOUNTS_CONFIG_FILE", str(creds_file))
        monkeypatch.setattr("main.ACCOUNTS_STATE_FILE", str(state_file))
        
        mock_manager = AsyncMock()
        mock_manager._accounts = {"test": MagicMock()}
        mock_manager._current_account_index = 0
        mock_manager._initialize_account = AsyncMock(return_value=True)
        mock_manager._save_state = AsyncMock()
        mock_manager.save_state_periodically = AsyncMock()
        
        with patch("main.AccountManager", return_value=mock_manager):
            with patch("main.httpx.AsyncClient") as mock_client_class:
                mock_client = AsyncMock()
                mock_client_class.return_value = mock_client
                
                from main import lifespan, app
                
                async with lifespan(app):
                    # Check flag during lifespan
                    assert hasattr(app.state, "account_system")
                    assert app.state.account_system is True
                    print(f"✓ app.state.account_system = {app.state.account_system}")
    
    @pytest.mark.asyncio
    async def test_lifespan_initialize_first_working_account(self, tmp_path, monkeypatch):
        """
        Test 100: Инициализация первого рабочего аккаунта
        
        What it does: Verifies first working account is initialized at startup
        Purpose: Ensure at least one account is ready before accepting requests
        """
        print("\n=== Test 100: Initialize first working account ===")
        
        # Arrange: Patch constants
        monkeypatch.setattr("main.ACCOUNT_SYSTEM", True)
        monkeypatch.setattr("main.REFRESH_TOKEN", "test_token")
        monkeypatch.setattr("main.KIRO_CREDS_FILE", None)
        monkeypatch.setattr("main.KIRO_CLI_DB_FILE", None)
        
        creds_file = tmp_path / "credentials.json"
        state_file = tmp_path / "state.json"
        
        monkeypatch.setattr("main.ACCOUNTS_CONFIG_FILE", str(creds_file))
        monkeypatch.setattr("main.ACCOUNTS_STATE_FILE", str(state_file))
        
        initialized_accounts = []
        
        mock_manager = AsyncMock()
        mock_manager._accounts = {
            "account1": MagicMock(),
            "account2": MagicMock()
        }
        mock_manager._current_account_index = 0
        
        async def track_initialize(account_id):
            initialized_accounts.append(account_id)
            return True  # Success on first account
        
        mock_manager._initialize_account = track_initialize
        mock_manager._save_state = AsyncMock()
        mock_manager.save_state_periodically = AsyncMock()
        
        with patch("main.AccountManager", return_value=mock_manager):
            with patch("main.httpx.AsyncClient") as mock_client_class:
                mock_client = AsyncMock()
                mock_client_class.return_value = mock_client
                
                from main import lifespan, app
                
                async with lifespan(app):
                    pass
        
        # Assert: all accounts were initialized
        print(f"Initialized accounts: {initialized_accounts}")
        assert len(initialized_accounts) == 2
        assert "account1" in initialized_accounts
        assert "account2" in initialized_accounts
        print("✓ All accounts were initialized")
    
    @pytest.mark.asyncio
    async def test_lifespan_full_circle_initialization(self, tmp_path, monkeypatch):
        """
        Test 101: Попытка инициализации всех аккаунтов по кругу
        
        What it does: Verifies full circle attempt if first accounts fail
        Purpose: Ensure all accounts are tried before giving up
        """
        print("\n=== Test 101: Full circle initialization attempt ===")
        
        # Arrange: Patch constants
        monkeypatch.setattr("main.ACCOUNT_SYSTEM", True)
        monkeypatch.setattr("main.REFRESH_TOKEN", "test_token")
        monkeypatch.setattr("main.KIRO_CREDS_FILE", None)
        monkeypatch.setattr("main.KIRO_CLI_DB_FILE", None)
        
        creds_file = tmp_path / "credentials.json"
        state_file = tmp_path / "state.json"
        
        monkeypatch.setattr("main.ACCOUNTS_CONFIG_FILE", str(creds_file))
        monkeypatch.setattr("main.ACCOUNTS_STATE_FILE", str(state_file))
        
        initialized_attempts = []
        
        mock_manager = AsyncMock()
        mock_manager._accounts = {
            "account1": MagicMock(),
            "account2": MagicMock(),
            "account3": MagicMock()
        }
        mock_manager._current_account_index = 0
        
        async def track_initialize(account_id):
            initialized_attempts.append(account_id)
            # First two fail, third succeeds
            if account_id == "account3":
                return True
            return False
        
        mock_manager._initialize_account = track_initialize
        mock_manager._save_state = AsyncMock()
        mock_manager.save_state_periodically = AsyncMock()
        
        with patch("main.AccountManager", return_value=mock_manager):
            with patch("main.httpx.AsyncClient") as mock_client_class:
                mock_client = AsyncMock()
                mock_client_class.return_value = mock_client
                
                from main import lifespan, app
                
                async with lifespan(app):
                    pass
        
        # Assert: all three accounts were tried
        print(f"Initialization attempts: {initialized_attempts}")
        assert initialized_attempts == ["account1", "account2", "account3"]
        print("✓ Full circle initialization was attempted")
    
    @pytest.mark.asyncio
    async def test_lifespan_starts_admin_mode_if_no_accounts(self, tmp_path, monkeypatch):
        """
        Test 102: Startup continues when no accounts are configured.

        What it does: Verifies application starts without runtime accounts.
        Purpose: Allow the admin console to add accounts after the account database is reset.
        """
        print("\n=== Test 102: Startup continues with no accounts ===")
        
        # Arrange: Patch constants
        monkeypatch.setattr("main.ACCOUNT_SYSTEM", True)
        monkeypatch.setattr("main.REFRESH_TOKEN", "test_token")
        monkeypatch.setattr("main.KIRO_CREDS_FILE", None)
        monkeypatch.setattr("main.KIRO_CLI_DB_FILE", None)
        
        creds_file = tmp_path / "credentials.json"
        state_file = tmp_path / "state.json"
        
        monkeypatch.setattr("main.ACCOUNTS_CONFIG_FILE", str(creds_file))
        monkeypatch.setattr("main.ACCOUNTS_STATE_FILE", str(state_file))
        
        mock_manager = AsyncMock()
        mock_manager._accounts = {}  # Empty accounts dict
        mock_manager._current_account_index = 0
        mock_manager._initialize_account = AsyncMock()
        mock_manager._save_state = AsyncMock()
        mock_manager.save_state_periodically = AsyncMock()
        
        with patch("main.AccountManager", return_value=mock_manager):
            with patch("main.httpx.AsyncClient") as mock_client_class:
                mock_client = AsyncMock()
                mock_client_class.return_value = mock_client
                
                from main import lifespan, app
                
                async with lifespan(app):
                    pass
                
                mock_manager._initialize_account.assert_not_awaited()
                assert mock_manager._save_state.await_count >= 1
                print("✓ Startup continued for empty accounts")
    
    @pytest.mark.asyncio
    async def test_lifespan_starts_admin_mode_if_all_accounts_fail(self, tmp_path, monkeypatch):
        """
        Test 103: Startup continues when all accounts fail to initialize.

        What it does: Verifies application starts in admin mode if all accounts fail.
        Purpose: Let users fix broken credentials from the admin console.
        """
        print("\n=== Test 103: Startup continues if all accounts failed ===")
        
        # Arrange: Patch constants
        monkeypatch.setattr("main.ACCOUNT_SYSTEM", True)
        monkeypatch.setattr("main.REFRESH_TOKEN", "test_token")
        monkeypatch.setattr("main.KIRO_CREDS_FILE", None)
        monkeypatch.setattr("main.KIRO_CLI_DB_FILE", None)
        
        creds_file = tmp_path / "credentials.json"
        state_file = tmp_path / "state.json"
        
        monkeypatch.setattr("main.ACCOUNTS_CONFIG_FILE", str(creds_file))
        monkeypatch.setattr("main.ACCOUNTS_STATE_FILE", str(state_file))
        
        mock_manager = AsyncMock()
        mock_manager._accounts = {
            "account1": MagicMock(),
            "account2": MagicMock()
        }
        mock_manager._current_account_index = 0
        mock_manager._initialize_account = AsyncMock(return_value=False)  # All fail
        mock_manager._save_state = AsyncMock()
        mock_manager.save_state_periodically = AsyncMock()
        
        with patch("main.AccountManager", return_value=mock_manager):
            with patch("main.httpx.AsyncClient") as mock_client_class:
                mock_client = AsyncMock()
                mock_client_class.return_value = mock_client
                
                from main import lifespan, app
                
                async with lifespan(app):
                    pass
                
                assert mock_manager._initialize_account.await_count == 2
                assert mock_manager._save_state.await_count >= 1
                print("✓ Startup continued when all accounts failed")
    
    @pytest.mark.asyncio
    async def test_lifespan_save_initial_state(self, tmp_path, monkeypatch):
        """
        Test 104: Сохранение начального state.json
        
        What it does: Verifies initial state is saved after first account initialization
        Purpose: Ensure state persistence starts immediately
        """
        print("\n=== Test 104: Save initial state ===")
        
        # Arrange: Patch constants
        monkeypatch.setattr("main.ACCOUNT_SYSTEM", True)
        monkeypatch.setattr("main.REFRESH_TOKEN", "test_token")
        monkeypatch.setattr("main.KIRO_CREDS_FILE", None)
        monkeypatch.setattr("main.KIRO_CLI_DB_FILE", None)
        
        creds_file = tmp_path / "credentials.json"
        state_file = tmp_path / "state.json"
        
        monkeypatch.setattr("main.ACCOUNTS_CONFIG_FILE", str(creds_file))
        monkeypatch.setattr("main.ACCOUNTS_STATE_FILE", str(state_file))
        
        save_state_called = False
        
        mock_manager = AsyncMock()
        mock_manager._accounts = {"test": MagicMock()}
        mock_manager._current_account_index = 0
        mock_manager._initialize_account = AsyncMock(return_value=True)
        
        async def track_save_state():
            nonlocal save_state_called
            save_state_called = True
        
        mock_manager._save_state = track_save_state
        mock_manager.save_state_periodically = AsyncMock()
        
        with patch("main.AccountManager", return_value=mock_manager):
            with patch("main.httpx.AsyncClient") as mock_client_class:
                mock_client = AsyncMock()
                mock_client_class.return_value = mock_client
                
                from main import lifespan, app
                
                async with lifespan(app):
                    pass
        
        # Assert
        print(f"_save_state called: {save_state_called}")
        assert save_state_called is True
        print("✓ Initial state was saved")
    
    @pytest.mark.asyncio
    async def test_lifespan_start_background_task(self, tmp_path, monkeypatch):
        """
        Test 105: Запуск save_state_periodically()
        
        What it does: Verifies background task is started for periodic state saving
        Purpose: Ensure state is saved periodically during runtime
        """
        print("\n=== Test 105: Start background task ===")
        
        # Arrange: Patch constants
        monkeypatch.setattr("main.ACCOUNT_SYSTEM", True)
        monkeypatch.setattr("main.REFRESH_TOKEN", "test_token")
        monkeypatch.setattr("main.KIRO_CREDS_FILE", None)
        monkeypatch.setattr("main.KIRO_CLI_DB_FILE", None)
        
        creds_file = tmp_path / "credentials.json"
        state_file = tmp_path / "state.json"
        
        monkeypatch.setattr("main.ACCOUNTS_CONFIG_FILE", str(creds_file))
        monkeypatch.setattr("main.ACCOUNTS_STATE_FILE", str(state_file))
        
        periodic_task_started = False
        
        mock_manager = AsyncMock()
        mock_manager._accounts = {"test": MagicMock()}
        mock_manager._current_account_index = 0
        mock_manager._initialize_account = AsyncMock(return_value=True)
        mock_manager._save_state = AsyncMock()
        
        async def track_periodic_save():
            nonlocal periodic_task_started
            periodic_task_started = True
            await asyncio.sleep(1000)  # Long sleep to keep task alive
        
        mock_manager.save_state_periodically = track_periodic_save
        
        with patch("main.AccountManager", return_value=mock_manager):
            with patch("main.httpx.AsyncClient") as mock_client_class:
                mock_client = AsyncMock()
                mock_client_class.return_value = mock_client
                
                from main import lifespan, app
                
                async with lifespan(app):
                    # Give task time to start
                    await asyncio.sleep(0.1)
                    assert periodic_task_started is True
                    print("✓ Background task was started")
    
    @pytest.mark.asyncio
    async def test_lifespan_shutdown_cancel_task(self, tmp_path, monkeypatch):
        """
        Test 106: Отмена background task при shutdown
        
        What it does: Verifies background task is cancelled during shutdown
        Purpose: Ensure clean shutdown without hanging tasks
        """
        print("\n=== Test 106: Cancel background task on shutdown ===")
        
        # Arrange: Patch constants
        monkeypatch.setattr("main.ACCOUNT_SYSTEM", True)
        monkeypatch.setattr("main.REFRESH_TOKEN", "test_token")
        monkeypatch.setattr("main.KIRO_CREDS_FILE", None)
        monkeypatch.setattr("main.KIRO_CLI_DB_FILE", None)
        
        creds_file = tmp_path / "credentials.json"
        state_file = tmp_path / "state.json"
        
        monkeypatch.setattr("main.ACCOUNTS_CONFIG_FILE", str(creds_file))
        monkeypatch.setattr("main.ACCOUNTS_STATE_FILE", str(state_file))
        
        task_cancelled = False
        
        mock_manager = AsyncMock()
        mock_manager._accounts = {"test": MagicMock()}
        mock_manager._current_account_index = 0
        mock_manager._initialize_account = AsyncMock(return_value=True)
        mock_manager._save_state = AsyncMock()
        
        async def periodic_save_with_cancel_check():
            try:
                await asyncio.sleep(1000)
            except asyncio.CancelledError:
                nonlocal task_cancelled
                task_cancelled = True
                raise
        
        mock_manager.save_state_periodically = periodic_save_with_cancel_check
        
        with patch("main.AccountManager", return_value=mock_manager):
            with patch("main.httpx.AsyncClient") as mock_client_class:
                mock_client = AsyncMock()
                mock_client_class.return_value = mock_client
                
                from main import lifespan, app
                
                async with lifespan(app):
                    await asyncio.sleep(0.1)
                
                # After context exit, task should be cancelled
                await asyncio.sleep(0.1)
        
        # Assert
        print(f"Task cancelled: {task_cancelled}")
        assert task_cancelled is True
        print("✓ Background task was cancelled on shutdown")
    
    @pytest.mark.asyncio
    async def test_lifespan_shutdown_final_save(self, tmp_path, monkeypatch):
        """
        Test 107: Финальное сохранение state.json при shutdown
        
        What it does: Verifies final state save happens during shutdown
        Purpose: Ensure no state is lost on graceful shutdown
        """
        print("\n=== Test 107: Final save on shutdown ===")
        
        # Arrange: Patch constants
        monkeypatch.setattr("main.ACCOUNT_SYSTEM", True)
        monkeypatch.setattr("main.REFRESH_TOKEN", "test_token")
        monkeypatch.setattr("main.KIRO_CREDS_FILE", None)
        monkeypatch.setattr("main.KIRO_CLI_DB_FILE", None)
        
        creds_file = tmp_path / "credentials.json"
        state_file = tmp_path / "state.json"
        
        monkeypatch.setattr("main.ACCOUNTS_CONFIG_FILE", str(creds_file))
        monkeypatch.setattr("main.ACCOUNTS_STATE_FILE", str(state_file))
        
        save_calls = []
        
        mock_manager = AsyncMock()
        mock_manager._accounts = {"test": MagicMock()}
        mock_manager._current_account_index = 0
        mock_manager._initialize_account = AsyncMock(return_value=True)
        
        async def track_save_state():
            save_calls.append("save")
        
        mock_manager._save_state = track_save_state
        mock_manager.save_state_periodically = AsyncMock()
        
        with patch("main.AccountManager", return_value=mock_manager):
            with patch("main.httpx.AsyncClient") as mock_client_class:
                mock_client = AsyncMock()
                mock_client_class.return_value = mock_client
                
                from main import lifespan, app
                
                async with lifespan(app):
                    pass
        
        # Assert: at least 2 saves (initial + final)
        print(f"Save calls: {len(save_calls)}")
        assert len(save_calls) >= 2
        print("✓ Final state save was performed on shutdown")
