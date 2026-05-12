# -*- coding: utf-8 -*-

"""
Background polling for Kiro usage limits.

This service reuses the gateway's existing Kiro authentication and HTTP retry
stack to periodically call the same ``GetUsageLimits`` endpoint that Kiro IDE
uses for the account dashboard.
"""

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict

import httpx
from loguru import logger

from kiro.account_sqlite_store import KiroAccountSqliteStore
from kiro.http_client import KiroHttpClient


USAGE_LIMITS_POLL_INTERVAL_MS = 300000
USAGE_LIMITS_POLL_INTERVAL_SECONDS = USAGE_LIMITS_POLL_INTERVAL_MS / 1000


class UsageLimitsService:
    """
    Poll Kiro usage limits on a fixed interval and update account rows in SQLite.

    Args:
        account_manager: Runtime account manager used by the gateway.
        shared_client: Shared application ``httpx.AsyncClient``.
        accounts_db_file: SQLite path used by the gateway account system.
        poll_interval_seconds: Polling interval in seconds.
    """

    def __init__(
        self,
        account_manager: Any,
        shared_client: httpx.AsyncClient,
        accounts_db_file: str,
        poll_interval_seconds: float = USAGE_LIMITS_POLL_INTERVAL_SECONDS,
    ):
        self._account_manager = account_manager
        self._shared_client = shared_client
        self._store = KiroAccountSqliteStore(accounts_db_file)
        self._poll_interval_seconds = float(poll_interval_seconds)

    async def run_periodically(self) -> None:
        """
        Poll usage limits forever until cancelled.

        The first poll runs immediately so admin pages and database state are
        hydrated right after startup. Later polls follow the configured
        interval.
        """
        logger.info(
            "Usage limits polling started: "
            f"interval_ms={int(self._poll_interval_seconds * 1000)}"
        )

        while True:
            await self.poll_once()
            await asyncio.sleep(self._poll_interval_seconds)

    async def poll_once(self) -> int:
        """
        Poll all configured accounts once.

        Returns:
            Number of account rows updated.
        """
        account_ids = list(self._account_manager._accounts.keys())
        if not account_ids:
            logger.debug("Usage limits poll skipped because no runtime accounts are configured")
            return 0

        updated_rows = 0
        for account_id in account_ids:
            try:
                updated_rows += await self._poll_account(account_id)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.warning(f"Usage limits poll failed for account {account_id}: {e}")

        if updated_rows:
            logger.info(f"Updated usage fields for {updated_rows} account row(s)")
        return updated_rows

    async def _poll_account(self, account_id: str) -> int:
        """
        Poll usage limits for one runtime account.

        Args:
            account_id: Runtime account ID.

        Returns:
            Number of account rows updated for the account.
        """
        account = self._account_manager._accounts.get(account_id)
        if account is None:
            return 0

        if account.auth_manager is None:
            initialized = await self._account_manager._initialize_account(account_id)
            if not initialized:
                logger.warning(f"Usage limits poll skipped because account failed to initialize: {account_id}")
                return 0
            account = self._account_manager._accounts.get(account_id)
            if account is None or account.auth_manager is None:
                return 0

        auth_manager = account.auth_manager
        params: Dict[str, Any] = {
            "origin": "AI_EDITOR",
            "resourceType": "AGENTIC_REQUEST",
        }
        if auth_manager.profile_arn:
            params["profileArn"] = auth_manager.profile_arn

        client = KiroHttpClient(auth_manager, shared_client=self._shared_client)
        try:
            response = await client.request_with_retry(
                method="GET",
                url=f"{auth_manager.q_host}/getUsageLimits",
                params=params,
                stream=False,
            )
        finally:
            await client.close()

        payload = response.json()
        if not isinstance(payload, dict):
            logger.warning(f"Usage limits poll returned non-object payload for account {account_id}")
            return 0

        usage_breakdown_list = payload.get("usageBreakdownList")
        if not isinstance(usage_breakdown_list, list) or not usage_breakdown_list:
            logger.debug(f"Usage limits poll returned no usageBreakdownList entries for account {account_id}")
            return 0

        selected_breakdown = _select_primary_usage_breakdown(usage_breakdown_list)
        if selected_breakdown is None:
            logger.debug(f"Usage limits poll returned no usable usage breakdown for account {account_id}")
            return 0

        subscription_info = payload.get("subscriptionInfo")
        subscription_title = None
        if isinstance(subscription_info, dict):
            subscription_title = _normalize_optional_string(subscription_info.get("subscriptionTitle"))

        captured_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        target_store, persisted_account_id = self._resolve_persisted_account_target(account_id)
        if target_store is None or persisted_account_id is None:
            logger.debug(
                "Usage limits poll skipped persistence because runtime account has no backing kiro_accounts row: "
                f"account_id={account_id}"
            )
            return 0

        next_date_reset = _normalize_optional_string(
            selected_breakdown.get("nextDateReset") or payload.get("nextDateReset")
        )
        target_store.update_account_usage(
            account_id=persisted_account_id,
            subscription_title=subscription_title,
            resource_type=_normalize_optional_string(selected_breakdown.get("resourceType")),
            display_name=_normalize_optional_string(selected_breakdown.get("displayName")),
            display_name_plural=_normalize_optional_string(selected_breakdown.get("displayNamePlural")),
            current_usage_with_precision=_normalize_optional_number(
                selected_breakdown.get("currentUsageWithPrecision")
            ),
            usage_limit_with_precision=_normalize_optional_number(
                selected_breakdown.get("usageLimitWithPrecision")
            ),
            next_date_reset=next_date_reset,
            usage_updated_at=captured_at,
        )
        return 1

    def _resolve_persisted_account_target(
        self,
        runtime_account_id: str,
    ) -> tuple[KiroAccountSqliteStore | None, str | None]:
        """
        Resolve the backing ``kiro_accounts`` row for a runtime account.

        Args:
            runtime_account_id: Runtime account ID from ``AccountManager``.

        Returns:
            Tuple of ``(store, account_row_id)`` or ``(None, None)`` when the
            runtime account does not map to a gateway-managed account row.
        """
        direct_record = self._store.get_account(runtime_account_id)
        if direct_record is not None:
            return self._store, runtime_account_id

        sqlite_account = _parse_runtime_sqlite_account_id(runtime_account_id)
        if sqlite_account is None:
            return None, None

        path, account_row_id = sqlite_account
        return KiroAccountSqliteStore(path), account_row_id


def _normalize_optional_string(value: Any) -> str | None:
    """
    Normalize an optional display string.

    Args:
        value: Arbitrary source value.

    Returns:
        Trimmed string or ``None``.
    """
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def _normalize_optional_number(value: Any) -> float | None:
    """
    Normalize an optional numeric value.

    Args:
        value: Arbitrary source value.

    Returns:
        Float value or ``None`` when the source is empty.
    """
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _select_primary_usage_breakdown(usage_breakdown_list: list[Any]) -> dict[str, Any] | None:
    """
    Pick the usage breakdown row to persist on the account record.

    Preference order:
    1. First row whose ``resourceType`` is ``CREDIT``.
    2. Otherwise the first dictionary entry in the list.

    Args:
        usage_breakdown_list: Raw Kiro ``usageBreakdownList`` payload.

    Returns:
        Selected breakdown dictionary or ``None``.
    """
    for breakdown in usage_breakdown_list:
        if isinstance(breakdown, dict) and str(breakdown.get("resourceType") or "").upper() == "CREDIT":
            return breakdown

    for breakdown in usage_breakdown_list:
        if isinstance(breakdown, dict):
            return breakdown

    return None


def _parse_runtime_sqlite_account_id(runtime_account_id: str) -> tuple[str, str] | None:
    """
    Parse ``AccountManager`` runtime IDs for ``sqlite_account`` entries.

    Args:
        runtime_account_id: Runtime account ID string.

    Returns:
        Tuple of database path and account row ID, or ``None``.
    """
    prefix = "sqlite_account:"
    if not runtime_account_id.startswith(prefix):
        return None

    payload = runtime_account_id[len(prefix):]
    if "#" not in payload:
        return None

    path, account_id = payload.rsplit("#", 1)
    return path, account_id
