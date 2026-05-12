# -*- coding: utf-8 -*-

"""
Unit tests for usage_limits_service.py.
"""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from kiro.account_sqlite_store import KiroAccountSqliteStore
from kiro.usage_limits_service import UsageLimitsService


class FakeAccountManager:
    """Minimal account manager stub for usage polling tests."""

    def __init__(self, auth_manager):
        self._accounts = {
            "account-1": SimpleNamespace(auth_manager=auth_manager),
        }
        self._initialize_account = AsyncMock(return_value=True)

    def resolve_account_display_name(self, account_id):
        """Return a stable test display name."""
        return "alice@example.com"


class TestUsageLimitsService:
    """Tests for usage-limits polling and persistence."""

    @pytest.mark.asyncio
    async def test_run_periodically_polls_immediately_before_sleep(self, tmp_path):
        """
        What it does: Starts the periodic loop and cancels it on the first sleep.
        Purpose: Ensure startup triggers an immediate usage refresh instead of waiting 300 seconds.
        """
        print("\n=== Test: Usage limits periodic loop polls immediately ===")

        db_path = tmp_path / "kiro_accounts.sqlite3"
        auth_manager = SimpleNamespace(
            profile_arn="arn:aws:codewhisperer:us-east-1:123456789012:profile/test",
            q_host="https://q.us-east-1.amazonaws.com",
        )
        manager = FakeAccountManager(auth_manager)
        service = UsageLimitsService(
            account_manager=manager,
            shared_client=AsyncMock(),
            accounts_db_file=str(db_path),
            poll_interval_seconds=300,
        )
        service.poll_once = AsyncMock(return_value=1)

        async def cancel_on_sleep(_seconds):
            raise asyncio.CancelledError()

        with patch("kiro.usage_limits_service.asyncio.sleep", side_effect=cancel_on_sleep):
            with pytest.raises(asyncio.CancelledError):
                await service.run_periodically()

        service.poll_once.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_poll_once_persists_usage_snapshot_rows(self, tmp_path):
        """
        What it does: Polls GetUsageLimits once with a mocked Kiro response.
        Purpose: Ensure usageBreakdownList rows are written to SQLite.
        """
        print("\n=== Test: Usage limits poll persists SQLite rows ===")

        db_path = tmp_path / "kiro_accounts.sqlite3"
        store = KiroAccountSqliteStore(str(db_path))
        store.upsert_token(
            token={
                "accessToken": "access",
                "refreshToken": "refresh",
                "expiresAt": "2099-01-01T00:00:00+00:00",
            },
            account_id="account-1",
        )
        auth_manager = SimpleNamespace(
            profile_arn="arn:aws:codewhisperer:us-east-1:123456789012:profile/test",
            q_host="https://q.us-east-1.amazonaws.com",
        )
        manager = FakeAccountManager(auth_manager)
        service = UsageLimitsService(
            account_manager=manager,
            shared_client=AsyncMock(),
            accounts_db_file=str(db_path),
        )

        response = MagicMock()
        response.json.return_value = {
            "nextDateReset": "2026-06-01T00:00:00.000Z",
            "subscriptionInfo": {
                "subscriptionTitle": "KIRO FREE",
            },
            "usageBreakdownList": [
                {
                    "resourceType": "CREDIT",
                    "displayName": "Credit",
                    "displayNamePlural": "Credits",
                    "currentUsageWithPrecision": 8.68,
                    "usageLimitWithPrecision": 50,
                    "nextDateReset": "2026-06-01T00:00:00.000Z",
                }
            ],
        }

        mock_http_client = MagicMock()
        mock_http_client.request_with_retry = AsyncMock(return_value=response)
        mock_http_client.close = AsyncMock()

        with patch("kiro.usage_limits_service.KiroHttpClient", return_value=mock_http_client):
            saved_rows = await service.poll_once()

        updated_account = store.get_account("account-1")

        assert saved_rows == 1
        assert updated_account is not None
        assert updated_account["usage_subscription_title"] == "KIRO FREE"
        assert updated_account["usage_current_usage_with_precision"] == 8.68
        assert updated_account["usage_limit_with_precision"] == 50
