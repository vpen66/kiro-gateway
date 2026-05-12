# -*- coding: utf-8 -*-

"""
Tests for routes_admin.py.

These tests cover admin authentication, account management routes,
generated API key management, request log routes, and OAuth CLI handling.
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from kiro.account_sqlite_store import KiroAccountSqliteStore
from kiro.request_log import RequestLogStore
from kiro.routes_admin import router


class FakeAccountManager:
    """Minimal account manager used by admin route tests."""

    def __init__(self):
        """Initialize fake state."""
        self.entries = []
        self.accounts = []

    def get_credential_entries(self):
        """Return fake credential entries."""
        return [
            {
                "index": index,
                "type": entry["type"],
                "enabled": entry.get("enabled", True),
                "display_name": entry.get("display_name", entry.get("account_id") or entry.get("path") or entry["type"]),
                "path": entry.get("path"),
                "account_id": entry.get("account_id"),
                "region": entry.get("region"),
                "api_region": entry.get("api_region"),
            }
            for index, entry in enumerate(self.entries)
        ]

    def get_account_snapshots(self):
        """Return fake runtime account snapshots."""
        return self.accounts

    def get_admin_accounts_payload(self):
        """Return fake admin payload with credentials and runtime accounts."""
        return {
            "credentials": self.get_credential_entries(),
            "accounts": self.get_account_snapshots(),
        }

    async def add_credential_entry(self, entry):
        """Record a credential entry."""
        self.entries.append(entry)

    async def update_credential_enabled(self, index, enabled):
        """Update a fake credential enabled state."""
        if index < 0 or index >= len(self.entries):
            raise ValueError(f"Credential entry not found: index={index}")
        self.entries[index]["enabled"] = enabled

    async def delete_credential_entry(self, index):
        """Delete a fake credential entry."""
        if index < 0 or index >= len(self.entries):
            raise ValueError(f"Credential entry not found: index={index}")
        del self.entries[index]


@pytest.fixture
def admin_client(tmp_path, monkeypatch):
    """
    Create an isolated FastAPI app with admin routes.
    """
    print("Creating isolated admin route test client...")
    monkeypatch.setattr("kiro.config.PROXY_API_KEY", "admin-secret")
    monkeypatch.setattr("kiro.config.API_KEYS_FILE", str(tmp_path / "api_keys.json"))
    monkeypatch.setattr("kiro.config.REQUEST_LOG_FILE", str(tmp_path / "request_logs" / "requests.jsonl"))
    monkeypatch.setattr("kiro.config.REQUEST_LOG_MAX_ENTRIES", 50)
    monkeypatch.setattr("kiro.config.ACCOUNTS_CONFIG_FILE", str(tmp_path / "credentials.json"))
    monkeypatch.setattr("kiro.config.ACCOUNTS_STATE_FILE", str(tmp_path / "state.json"))
    monkeypatch.setattr("kiro.config.KIRO_ACCOUNTS_DB_FILE", str(tmp_path / "kiro_accounts.sqlite3"))
    monkeypatch.setattr("kiro.config.KIRO_OAUTH_DB_FILE", str(tmp_path / "kiro_accounts.sqlite3"))
    monkeypatch.setattr("kiro.config.ACCOUNT_SELECTION_MODE", "sticky")
    monkeypatch.setattr("kiro.config.WEB_SEARCH_ENABLED", True)
    monkeypatch.setattr("kiro.config.AUTO_MODEL_ROUTING_ENABLED", False)
    monkeypatch.setattr("kiro.config.AUTO_MODEL_ROUTING_TRIGGER_MODELS", ["auto-kiro"])
    monkeypatch.setattr("kiro.config.AUTO_MODEL_ROUTING_SIMPLE_MODELS", ["claude-haiku-4.5", "auto-kiro"])
    monkeypatch.setattr("kiro.config.AUTO_MODEL_ROUTING_MEDIUM_MODELS", ["claude-sonnet-4.5", "claude-haiku-4.5"])
    monkeypatch.setattr("kiro.config.AUTO_MODEL_ROUTING_HARD_MODELS", ["claude-opus-4.7", "claude-sonnet-4.5"])

    app = FastAPI()
    app.state.account_manager = FakeAccountManager()
    app.include_router(router)

    with TestClient(app) as client:
        yield client


def admin_headers():
    """Return valid admin Authorization headers."""
    return {"Authorization": "Bearer admin-secret"}


class TestAdminConsolePage:
    """Tests for serving the browser admin console."""

    def test_admin_console_page_serves_html(self, admin_client):
        """
        What it does: Requests the admin console HTML page.
        Purpose: Ensure the browser UI is reachable.
        """
        print("\n=== Test: Admin console HTML is served ===")

        # Act
        response = admin_client.get("/admin")

        # Assert
        assert response.status_code == 200
        assert "Kiro Gateway Admin" in response.text
        assert 'label: "Path / Token"' not in response.text
        assert 'label: "Type"' not in response.text
        assert 'label: "Account ID"' not in response.text
        assert 'label: "Account"' in response.text

    def test_admin_request_logs_render_tokens_with_k_units(self, admin_client):
        """
        What it does: Requests the admin console HTML and inspects token rendering logic.
        Purpose: Ensure Request Logs show compact k-unit token totals while retaining raw details.
        """
        print("\n=== Test: Admin request logs render compact token totals ===")

        # Act
        response = admin_client.get("/admin")

        # Assert
        assert response.status_code == 200
        assert "function formatTokenCount(value)" in response.text
        assert "function formatTokenDetail(label, value)" in response.text
        assert "return `${formatted}k`;" in response.text
        assert "return `${label} ${compact} (${value})`;" in response.text
        assert "formatTokenCount(total)" in response.text
        assert 'const parts = [formatTokenDetail("total", total)];' in response.text


class TestAdminAuthentication:
    """Tests for admin API authentication."""

    def test_admin_api_requires_admin_key(self, admin_client):
        """
        What it does: Calls an admin API without Authorization.
        Purpose: Ensure management APIs are protected.
        """
        print("\n=== Test: Admin API requires authentication ===")

        # Act
        response = admin_client.get("/admin/api/accounts")

        # Assert
        assert response.status_code == 401

    def test_admin_api_accepts_proxy_api_key(self, admin_client):
        """
        What it does: Calls an admin API with PROXY_API_KEY.
        Purpose: Preserve backward-compatible admin access.
        """
        print("\n=== Test: Admin API accepts PROXY_API_KEY ===")

        # Act
        response = admin_client.get("/admin/api/accounts", headers=admin_headers())

        # Assert
        assert response.status_code == 200
        assert response.json() == {"credentials": [], "accounts": []}


class TestAdminAccountRoutes:
    """Tests for admin account management routes."""

    def test_add_json_account_validates_path_and_records_entry(self, admin_client, tmp_path):
        """
        What it does: Adds a JSON credential account through the admin API.
        Purpose: Ensure account creation validates server-side paths.
        """
        print("\n=== Test: Add JSON account through admin API ===")

        # Arrange
        credential_file = tmp_path / "kiro-auth-token.json"
        credential_file.write_text(json.dumps({"refreshToken": "refresh"}))

        # Act
        response = admin_client.post(
            "/admin/api/accounts",
            headers=admin_headers(),
            json={
                "type": "json",
                "path": str(credential_file),
                "region": "us-east-1",
                "enabled": True,
            },
        )

        # Assert
        assert response.status_code == 200
        payload = response.json()
        assert payload["credentials"][0]["type"] == "json"
        assert payload["credentials"][0]["path"] == str(credential_file)

    def test_add_json_account_rejects_missing_path(self, admin_client):
        """
        What it does: Attempts to add a JSON account without a path.
        Purpose: Ensure malformed account entries are rejected.
        """
        print("\n=== Test: Add JSON account rejects missing path ===")

        # Act
        response = admin_client.post(
            "/admin/api/accounts",
            headers=admin_headers(),
            json={"type": "json", "enabled": True},
        )

        # Assert
        assert response.status_code == 400
        assert "path is required" in response.json()["detail"]

    def test_enable_and_delete_account_entry(self, admin_client, tmp_path):
        """
        What it does: Adds, disables, and deletes a credential entry.
        Purpose: Ensure account management mutations work end-to-end.
        """
        print("\n=== Test: Disable and delete account entry ===")

        # Arrange
        credential_file = tmp_path / "kiro-auth-token.json"
        credential_file.write_text(json.dumps({"refreshToken": "refresh"}))
        admin_client.post(
            "/admin/api/accounts",
            headers=admin_headers(),
            json={"type": "json", "path": str(credential_file), "enabled": True},
        )

        # Act
        disabled = admin_client.patch(
            "/admin/api/accounts/0",
            headers=admin_headers(),
            json={"enabled": False},
        )
        deleted = admin_client.delete("/admin/api/accounts/0", headers=admin_headers())

        # Assert
        assert disabled.status_code == 200
        assert disabled.json()["credentials"][0]["enabled"] is False
        assert deleted.status_code == 200
        assert deleted.json()["credentials"] == []

    def test_list_accounts_includes_available_models(self, admin_client):
        """
        What it does: Returns runtime account snapshots with model details.
        Purpose: Ensure the admin console can display per-account model lists.
        """
        print("\n=== Test: Admin account list includes available models ===")

        admin_client.app.state.account_manager.accounts = [
            {
                "id": "account-1",
                "initialized": True,
                "auth_type": "kiro_desktop",
                "failures": 0,
                "models_cached_at": None,
                "models_count": 2,
                "available_models": ["claude-haiku-4.5", "claude-sonnet-4.5"],
                "stats": {
                    "total_requests": 3,
                    "successful_requests": 3,
                    "failed_requests": 0,
                },
            }
        ]

        response = admin_client.get("/admin/api/accounts", headers=admin_headers())

        assert response.status_code == 200
        payload = response.json()
        assert payload["accounts"][0]["models_count"] == 2
        assert payload["accounts"][0]["available_models"] == [
            "claude-haiku-4.5",
            "claude-sonnet-4.5",
        ]


class TestAdminApiKeyRoutes:
    """Tests for generated API key admin routes."""

    def test_create_admin_key_and_use_it_for_settings(self, admin_client):
        """
        What it does: Creates an admin-scoped key and uses it on another admin endpoint.
        Purpose: Ensure generated admin keys authenticate management APIs.
        """
        print("\n=== Test: Generated admin key can access settings ===")

        # Act
        created = admin_client.post(
            "/admin/api/api-keys",
            headers=admin_headers(),
            json={"name": "Admin browser", "scopes": ["admin"]},
        )
        plaintext = created.json()["key"]
        settings = admin_client.get(
            "/admin/api/settings",
            headers={"Authorization": f"Bearer {plaintext}"},
        )

        # Assert
        assert created.status_code == 200
        assert plaintext.startswith("kgw_")
        assert settings.status_code == 200
        assert settings.json()["readonly_settings"]["proxy_api_key_configured"] is True


class TestAdminSettingsRoutes:
    """Tests for runtime settings admin routes."""

    def test_get_settings_returns_editable_and_readonly_sections(self, admin_client):
        """
        What it does: Fetches the admin settings payload.
        Purpose: Ensure the UI receives runtime-editable and read-only sections separately.
        """
        print("\n=== Test: Admin settings payload is structured for editable runtime settings ===")

        response = admin_client.get("/admin/api/settings", headers=admin_headers())

        assert response.status_code == 200
        payload = response.json()
        assert payload["editable_settings"]["account_selection_mode"] == "sticky"
        assert payload["editable_metadata"]["account_selection_mode"]["input_type"] == "select"
        assert payload["readonly_settings"]["proxy_api_key_configured"] is True

    def test_patch_settings_persists_runtime_override(self, admin_client):
        """
        What it does: Updates one runtime setting through the admin API.
        Purpose: Ensure runtime overrides are written to SQLite and returned immediately.
        """
        print("\n=== Test: Admin settings update persists runtime override ===")

        response = admin_client.patch(
            "/admin/api/settings",
            headers=admin_headers(),
            json={
                "account_selection_mode": "round_robin",
                "auto_model_routing_trigger_models": "auto-kiro, auto",
            },
        )

        assert response.status_code == 200
        payload = response.json()
        assert payload["editable_settings"]["account_selection_mode"] == "round_robin"
        assert payload["editable_settings"]["auto_model_routing_trigger_models"] == ["auto-kiro", "auto"]
        assert payload["runtime_overrides"]["account_selection_mode"] == "round_robin"

        fetched = admin_client.get("/admin/api/settings", headers=admin_headers())
        assert fetched.status_code == 200
        fetched_payload = fetched.json()
        assert fetched_payload["editable_settings"]["account_selection_mode"] == "round_robin"

    def test_patch_settings_rejects_invalid_runtime_setting(self, admin_client):
        """
        What it does: Sends an invalid runtime setting update.
        Purpose: Ensure the admin API returns a user-facing validation error.
        """
        print("\n=== Test: Admin settings update rejects invalid runtime setting ===")

        response = admin_client.patch(
            "/admin/api/settings",
            headers=admin_headers(),
            json={"account_selection_mode": "random_mode"},
        )

        assert response.status_code == 400
        assert "account_selection_mode" in response.json()["detail"]

    def test_disable_generated_key(self, admin_client):
        """
        What it does: Creates and disables a generated API key.
        Purpose: Ensure generated key lifecycle routes mutate persisted records.
        """
        print("\n=== Test: Disable generated API key through admin API ===")

        # Arrange
        created = admin_client.post(
            "/admin/api/api-keys",
            headers=admin_headers(),
            json={"name": "Worker", "scopes": ["api"]},
        )
        key_id = created.json()["record"]["id"]

        # Act
        response = admin_client.patch(
            f"/admin/api/api-keys/{key_id}",
            headers=admin_headers(),
            json={"enabled": False},
        )

        # Assert
        assert response.status_code == 200
        assert response.json()["record"]["enabled"] is False


class TestAdminRequestLogRoutes:
    """Tests for request log management routes."""

    def test_list_and_clear_request_logs(self, admin_client, tmp_path, monkeypatch):
        """
        What it does: Lists and clears request logs through admin APIs.
        Purpose: Ensure log management endpoints read and clear the configured store.
        """
        print("\n=== Test: List and clear request logs ===")

        # Arrange
        log_file = tmp_path / "request_logs" / "requests.jsonl"
        monkeypatch.setattr("kiro.config.REQUEST_LOG_FILE", str(log_file))
        store = RequestLogStore(str(log_file), max_entries=50)
        store.append({"id": "req-1", "status_code": 200})

        # Act
        listed = admin_client.get("/admin/api/request-logs", headers=admin_headers())
        cleared = admin_client.delete("/admin/api/request-logs", headers=admin_headers())
        listed_after_clear = admin_client.get("/admin/api/request-logs", headers=admin_headers())

        # Assert
        assert listed.status_code == 200
        assert listed.json()["entries"][0]["id"] == "req-1"
        assert cleared.status_code == 200
        assert listed_after_clear.json()["entries"] == []

    def test_request_log_limit_is_validated(self, admin_client):
        """
        What it does: Requests an invalid log limit.
        Purpose: Ensure admin API validates query bounds.
        """
        print("\n=== Test: Request log limit validation ===")

        # Act
        response = admin_client.get("/admin/api/request-logs?limit=999", headers=admin_headers())

        # Assert
        assert response.status_code == 400


class TestAdminOAuthRoutes:
    """Tests for browser-assisted OAuth management routes."""

    def test_start_oauth_reports_missing_cli(self, admin_client):
        """
        What it does: Starts OAuth when the provider CLI is missing.
        Purpose: Ensure users get an actionable error instead of a crash.
        """
        print("\n=== Test: OAuth start reports missing CLI ===")

        # Act
        with patch("kiro.routes_admin.shutil.which", return_value=None):
            response = admin_client.post(
                "/admin/api/accounts/oauth/start",
                headers=admin_headers(),
                json={"provider": "kiro-cli"},
            )

        # Assert
        assert response.status_code == 404
        assert "command not found" in response.json()["detail"]

    def test_start_kiro_ide_oauth_returns_sqlite_account_guidance(self, admin_client):
        """
        What it does: Starts the Kiro IDE browser-login helper path.
        Purpose: Ensure Kiro IDE login returns a browser authorization URL.
        """
        print("\n=== Test: Kiro IDE OAuth returns SQLite account guidance ===")

        # Act
        service = MagicMock()
        service.start = AsyncMock(return_value={
            "status": "pending",
            "authorization_url": "https://app.kiro.dev/signin?state=test",
            "callback_url": "http://localhost:3128",
            "credential_path": None,
            "database_path": "/tmp/kiro_accounts.sqlite3",
            "account_id": None,
        })
        with patch("kiro.routes_admin.get_kiro_oauth_service", return_value=service):
            response = admin_client.post(
                "/admin/api/accounts/oauth/start",
                headers=admin_headers(),
                json={"provider": "kiro-ide", "database_path": "/tmp/kiro_accounts.sqlite3"},
            )

        # Assert
        assert response.status_code == 200
        payload = response.json()
        assert payload["pid"] is None
        assert payload["credential_type"] == "sqlite_account"
        assert payload["database_path"].endswith("kiro_accounts.sqlite3")
        assert payload["credential_path"] is None
        assert payload["authorization_url"].startswith("https://app.kiro.dev/signin")
        assert payload["callback_url"] == "http://localhost:3128"
        service.start.assert_awaited_once_with(region="us-east-1", database_path="/tmp/kiro_accounts.sqlite3")

    def test_kiro_ide_oauth_status_returns_current_flow(self, admin_client):
        """
        What it does: Reads current Kiro IDE OAuth flow status.
        Purpose: Ensure the admin UI can poll browser-login completion.
        """
        print("\n=== Test: Kiro IDE OAuth status ===")

        # Arrange
        service = MagicMock()
        service.status.return_value = {
            "status": "success",
            "credential_path": None,
            "database_path": "/tmp/kiro_accounts.sqlite3",
            "account_id": "kiro_abc",
            "authorization_url": None,
            "callback_url": "http://localhost:3128",
            "error_message": None,
            "login_option": "google",
        }

        # Act
        with patch("kiro.routes_admin.get_kiro_oauth_service", return_value=service):
            response = admin_client.get(
                "/admin/api/accounts/oauth/status",
                headers=admin_headers(),
            )

        # Assert
        assert response.status_code == 200
        assert response.json()["status"] == "success"
        assert response.json()["login_option"] == "google"

    def test_manual_kiro_ide_callback_is_forwarded_to_oauth_service(self, admin_client):
        """
        What it does: Submits a manual Kiro callback URL.
        Purpose: Ensure remote/browser fallback can complete the same OAuth flow.
        """
        print("\n=== Test: Manual Kiro IDE OAuth callback ===")

        # Arrange
        service = MagicMock()
        service.manual_callback = AsyncMock(return_value={
            "status": "success",
            "credential_path": None,
            "database_path": "/tmp/kiro_accounts.sqlite3",
            "account_id": "kiro_abc",
            "error_message": None,
        })

        # Act
        with patch("kiro.routes_admin.get_kiro_oauth_service", return_value=service):
            response = admin_client.post(
                "/admin/api/accounts/oauth/manual-callback",
                headers=admin_headers(),
                json={"callback_url": "http://localhost:3128/signin/callback?code=abc&state=state"},
            )

        # Assert
        assert response.status_code == 200
        assert response.json()["status"] == "success"
        service.manual_callback.assert_awaited_once()

    def test_start_oauth_launches_cli_when_available(self, admin_client):
        """
        What it does: Starts OAuth when a provider CLI is available.
        Purpose: Ensure the browser-assisted login command is launched safely.
        """
        print("\n=== Test: OAuth start launches CLI ===")

        # Arrange
        process = MagicMock()
        process.pid = 12345

        # Act
        with patch("kiro.routes_admin.shutil.which", return_value="/usr/bin/kiro-cli"):
            with patch("kiro.routes_admin.subprocess.Popen", return_value=process) as popen:
                response = admin_client.post(
                    "/admin/api/accounts/oauth/start",
                    headers=admin_headers(),
                    json={"provider": "kiro-cli"},
                )

        # Assert
        assert response.status_code == 200
        assert response.json()["pid"] == 12345
        popen.assert_called_once()

    def test_import_oauth_database_requires_existing_file(self, admin_client):
        """
        What it does: Imports a missing OAuth SQLite database.
        Purpose: Ensure users are told to complete browser login first.
        """
        print("\n=== Test: OAuth import requires existing database ===")

        # Act
        response = admin_client.post(
            "/admin/api/accounts/oauth/import",
            headers=admin_headers(),
            json={"provider": "kiro-cli", "database_path": "/missing/data.sqlite3"},
        )

        # Assert
        assert response.status_code == 404
        assert "Complete browser login first" in response.json()["detail"]

    def test_import_kiro_ide_json_credentials_adds_sqlite_account(self, admin_client, tmp_path):
        """
        What it does: Imports a Kiro IDE credentials JSON file.
        Purpose: Ensure legacy Kiro IDE credentials migrate into the multi-account SQLite store.
        """
        print("\n=== Test: Import Kiro IDE JSON credentials ===")

        # Arrange
        db_path = tmp_path / "kiro_accounts.sqlite3"
        credentials_file = tmp_path / "kiro-auth-token.json"
        credentials_file.write_text(json.dumps({
            "accessToken": "access",
            "refreshToken": "refresh",
            "expiresAt": "2099-01-01T00:00:00+00:00",
            "authMethod": "social",
            "provider": "Google",
        }))

        # Act
        response = admin_client.post(
            "/admin/api/accounts/oauth/import",
            headers=admin_headers(),
            json={
                "provider": "kiro-ide",
                "database_path": str(db_path),
                "credential_path": str(credentials_file),
            },
        )

        # Assert
        assert response.status_code == 200
        credential = response.json()["credentials"][0]
        assert credential["type"] == "sqlite_account"
        assert credential["path"] == str(db_path)
        assert credential["account_id"].startswith("kiro_")
        assert KiroAccountSqliteStore(str(db_path)).get_account(credential["account_id"]) is not None

    def test_import_kiro_ide_oauth_account_adds_existing_sqlite_row(self, admin_client, tmp_path):
        """
        What it does: Imports an account already stored by the Kiro IDE OAuth flow.
        Purpose: Ensure completed browser login creates a sqlite_account credential entry.
        """
        print("\n=== Test: Import Kiro IDE OAuth SQLite account ===")

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
        service = MagicMock()
        service.status.return_value = {"account_id": record["id"]}

        # Act
        with patch("kiro.routes_admin.get_kiro_oauth_service", return_value=service):
            response = admin_client.post(
                "/admin/api/accounts/oauth/import",
                headers=admin_headers(),
                json={"provider": "kiro-ide", "database_path": str(db_path)},
            )

        # Assert
        assert response.status_code == 200
        credential = response.json()["credentials"][0]
        assert credential["type"] == "sqlite_account"
        assert credential["account_id"] == record["id"]
