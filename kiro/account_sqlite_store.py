# -*- coding: utf-8 -*-

# Kiro Gateway
# https://github.com/jwadow/kiro-gateway
# Copyright (C) 2025 Jwadow
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""
SQLite-backed Kiro account store.

This module owns gateway-managed browser OAuth credentials. It intentionally
does not reuse the kiro-cli ``auth_kv`` schema because Kiro IDE browser login
must support multiple accounts without overwriting one token JSON file.
"""

import base64
import binascii
import hashlib
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from loguru import logger


KIRO_ACCOUNTS_TABLE = "kiro_accounts"
KIRO_ACCOUNT_CREDENTIALS_TABLE = "kiro_account_credentials"
KIRO_USAGE_SNAPSHOTS_TABLE = "kiro_usage_snapshots"
ACCOUNT_IDENTITY_FIELDS = (
    "email",
    "preferred_username",
    "preferredUsername",
    "upn",
    "unique_name",
    "username",
    "userName",
    "login",
    "cognito:username",
    "displayName",
    "display_name",
    "name",
)
ACCOUNT_NAME_FIELD_GROUPS = (
    ("givenName", "familyName"),
    ("given_name", "family_name"),
)
JWT_IDENTITY_TOKEN_FIELDS = (
    "idToken",
    "id_token",
    "accessToken",
    "access_token",
)


class KiroAccountSqliteStoreError(Exception):
    """
    Error raised when a gateway-managed account database cannot be used.

    Args:
        message: User-facing error message.
    """

    def __init__(self, message: str):
        """Initialize the store error."""
        super().__init__(message)
        self.message = message


class KiroAccountSqliteStore:
    """
    Store multiple Kiro account credentials in one SQLite database.

    Args:
        db_path: Path to the gateway-managed SQLite account database.
    """

    def __init__(self, db_path: str):
        """Initialize the account store."""
        self._db_path = str(Path(db_path).expanduser())

    @property
    def db_path(self) -> str:
        """Return the resolved database path."""
        return self._db_path

    def upsert_token(
        self,
        token: Dict[str, Any],
        registration: Optional[Dict[str, Any]] = None,
        label: Optional[str] = None,
        display_name: Optional[str] = None,
        enabled: bool = True,
        account_id: Optional[str] = None,
        api_region: Optional[str] = None,
        csrf_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Insert or update a Kiro account token row.

        Args:
            token: Kiro IDE-compatible token payload.
            registration: Optional AWS SSO OIDC client registration payload.
            label: Optional display label.
            display_name: Optional persisted remote display name.
            enabled: Whether the account should be enabled by default.
            account_id: Optional explicit account ID to update.
            api_region: Optional Q API region override.
            csrf_token: Optional Kiro Web Portal CSRF token associated with
                the current browser session.

        Returns:
            Stored account record.

        Raises:
            KiroAccountSqliteStoreError: If token data is incomplete.
        """
        if not _get_token_field(token, "refreshToken", "refresh_token"):
            raise KiroAccountSqliteStoreError("Kiro account token is missing refreshToken.")

        resolved_account_id = account_id or build_kiro_account_id(token)
        now = _utc_now()
        auth_method = str(_get_token_field(token, "authMethod", "auth_method") or "social")
        provider = _get_token_field(token, "provider")
        region = _get_token_field(token, "region")
        profile_arn = _get_token_field(token, "profileArn", "profile_arn")
        resolved_label = label or _build_account_label(token, resolved_account_id)

        with self._connect() as conn:
            existing = self.get_account(resolved_account_id)
            created_at = existing["created_at"] if existing else now
            resolved_csrf_token = (
                _normalize_identity_value(csrf_token)
                or _normalize_identity_value(_get_token_field(token, "csrfToken", "csrf_token"))
                or (_normalize_identity_value(existing.get("csrf_token")) if existing else None)
            )
            resolved_display_name = (
                _normalize_identity_value(display_name)
                or (_normalize_identity_value(existing.get("display_name")) if existing else None)
            )
            conn.execute(
                f"""
                INSERT INTO {KIRO_ACCOUNTS_TABLE} (
                    id,
                    label,
                    display_name,
                    auth_method,
                    provider,
                    token_json,
                    csrf_token,
                    registration_json,
                    region,
                    api_region,
                    profile_arn,
                    enabled,
                    created_at,
                    updated_at,
                    last_used_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    label = excluded.label,
                    display_name = excluded.display_name,
                    auth_method = excluded.auth_method,
                    provider = excluded.provider,
                    token_json = excluded.token_json,
                    csrf_token = excluded.csrf_token,
                    registration_json = excluded.registration_json,
                    region = excluded.region,
                    api_region = excluded.api_region,
                    profile_arn = excluded.profile_arn,
                    enabled = excluded.enabled,
                    updated_at = excluded.updated_at
                """,
                (
                    resolved_account_id,
                    resolved_label,
                    resolved_display_name,
                    auth_method,
                    provider,
                    json.dumps(token, ensure_ascii=False),
                    resolved_csrf_token,
                    json.dumps(registration, ensure_ascii=False) if registration else None,
                    region,
                    api_region,
                    profile_arn,
                    1 if enabled else 0,
                    created_at,
                    now,
                    existing["last_used_at"] if existing else None,
                ),
            )
            conn.commit()

        logger.info(f"Stored Kiro account in SQLite: account_id={resolved_account_id}, db={self._db_path}")
        record = self.get_account(resolved_account_id)
        if record is None:
            raise KiroAccountSqliteStoreError("Kiro account was not found after saving.")
        return record

    def import_json_token(
        self,
        token_path: str,
        label: Optional[str] = None,
        enabled: bool = True,
        api_region: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Import a legacy Kiro IDE token JSON file into the SQLite account store.

        Args:
            token_path: Path to ``kiro-auth-token.json`` or equivalent.
            label: Optional display label.
            enabled: Whether the imported account should be enabled.
            api_region: Optional Q API region override.

        Returns:
            Stored account record.

        Raises:
            FileNotFoundError: If the token file does not exist.
            json.JSONDecodeError: If the token JSON is malformed.
            KiroAccountSqliteStoreError: If required token fields are missing.
        """
        path = Path(token_path).expanduser()
        with open(path, "r", encoding="utf-8") as f:
            token = json.load(f)

        if not isinstance(token, dict):
            raise KiroAccountSqliteStoreError("Kiro token file must contain a JSON object.")

        registration = self._load_registration_for_token(token, path.parent)
        return self.upsert_token(
            token=token,
            registration=registration,
            label=label or _build_account_label(token, path.stem),
            enabled=enabled,
            api_region=api_region,
        )

    def list_credential_entries(self) -> List[Dict[str, Any]]:
        """
        List persisted account credential entries.

        Returns:
            Credential entries ordered by creation time.
        """
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT * FROM {KIRO_ACCOUNT_CREDENTIALS_TABLE}
                ORDER BY created_at ASC, id ASC
                """
            ).fetchall()
        return [_credential_row_to_record(row) for row in rows]

    def upsert_credential_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Insert or update one persisted credential entry.

        Args:
            entry: Credential entry payload.

        Returns:
            Stored credential entry record.

        Raises:
            KiroAccountSqliteStoreError: If the credential entry is incomplete.
        """
        resolved_entry = _normalize_credential_entry(entry)
        if not resolved_entry.get("type"):
            raise KiroAccountSqliteStoreError("Credential entry is missing type.")

        now = _utc_now()
        existing = self._find_matching_credential_entry(resolved_entry)
        created_at = str(existing.get("created_at")) if existing else now

        with self._connect() as conn:
            if existing:
                conn.execute(
                    f"""
                    UPDATE {KIRO_ACCOUNT_CREDENTIALS_TABLE}
                    SET credential_type = ?,
                        path = ?,
                        account_id = ?,
                        refresh_token = ?,
                        profile_arn = ?,
                        region = ?,
                        api_region = ?,
                        enabled = ?,
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        resolved_entry.get("type"),
                        resolved_entry.get("path"),
                        resolved_entry.get("account_id"),
                        resolved_entry.get("refresh_token"),
                        resolved_entry.get("profile_arn"),
                        resolved_entry.get("region"),
                        resolved_entry.get("api_region"),
                        1 if resolved_entry.get("enabled", True) else 0,
                        now,
                        existing["row_id"],
                    ),
                )
                row_id = int(existing["row_id"])
            else:
                cursor = conn.execute(
                    f"""
                    INSERT INTO {KIRO_ACCOUNT_CREDENTIALS_TABLE} (
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
                        resolved_entry.get("type"),
                        resolved_entry.get("path"),
                        resolved_entry.get("account_id"),
                        resolved_entry.get("refresh_token"),
                        resolved_entry.get("profile_arn"),
                        resolved_entry.get("region"),
                        resolved_entry.get("api_region"),
                        1 if resolved_entry.get("enabled", True) else 0,
                        created_at,
                        now,
                    ),
                )
                row_id = int(cursor.lastrowid)
            conn.commit()

        stored_entry = self.get_credential_entry_by_row_id(row_id)
        if stored_entry is None:
            raise KiroAccountSqliteStoreError("Credential entry was not found after saving.")
        return stored_entry

    def replace_credential_entries(self, entries: List[Dict[str, Any]]) -> None:
        """
        Replace all persisted credential entries atomically.

        Args:
            entries: Full credential entry set to store.
        """
        with self._connect() as conn:
            conn.execute(f"DELETE FROM {KIRO_ACCOUNT_CREDENTIALS_TABLE}")
            conn.commit()
        for entry in entries:
            self.upsert_credential_entry(entry)

    def update_credential_entry_enabled(self, index: int, enabled: bool) -> Dict[str, Any]:
        """
        Update the enabled state of a credential entry by list index.

        Args:
            index: Zero-based credential entry index.
            enabled: Desired enabled state.

        Returns:
            Updated credential entry record.

        Raises:
            KiroAccountSqliteStoreError: If the index is invalid.
        """
        entry = self.get_credential_entry_by_index(index)
        if entry is None:
            raise KiroAccountSqliteStoreError(f"Credential entry not found: index={index}")

        updated_entry = dict(entry)
        updated_entry["enabled"] = enabled
        return self.upsert_credential_entry(updated_entry)

    def delete_credential_entry(self, index: int) -> None:
        """
        Delete a credential entry by list index.

        When the deleted entry is a ``sqlite_account`` reference and no other
        credential entry still points at the same account row, the backing
        ``kiro_accounts`` row is removed as well.

        Args:
            index: Zero-based credential entry index.

        Raises:
            KiroAccountSqliteStoreError: If the index is invalid.
        """
        entry = self.get_credential_entry_by_index(index)
        if entry is None:
            raise KiroAccountSqliteStoreError(f"Credential entry not found: index={index}")

        sqlite_account_path = str(entry.get("path") or "").strip()
        sqlite_account_id = str(entry.get("account_id") or "").strip()
        should_delete_backing_account = False

        with self._connect() as conn:
            conn.execute(
                f"DELETE FROM {KIRO_ACCOUNT_CREDENTIALS_TABLE} WHERE id = ?",
                (int(entry["row_id"]),),
            )
            if entry.get("type") == "sqlite_account" and sqlite_account_path and sqlite_account_id:
                row = conn.execute(
                    f"""
                    SELECT COUNT(*) AS ref_count
                    FROM {KIRO_ACCOUNT_CREDENTIALS_TABLE}
                    WHERE credential_type = ? AND path = ? AND account_id = ?
                    """,
                    ("sqlite_account", sqlite_account_path, sqlite_account_id),
                ).fetchone()
                should_delete_backing_account = bool(row and int(row["ref_count"]) == 0)
            conn.commit()

        if should_delete_backing_account:
            backing_store_path = Path(sqlite_account_path).expanduser()
            if backing_store_path.exists():
                KiroAccountSqliteStore(str(backing_store_path)).delete_account(sqlite_account_id)
            else:
                logger.warning(
                    "Skipped deleting backing sqlite_account row because database path no longer exists: "
                    f"path={backing_store_path}, account_id={sqlite_account_id}"
                )

    def get_credential_entry_by_index(self, index: int) -> Optional[Dict[str, Any]]:
        """
        Return one persisted credential entry by list index.

        Args:
            index: Zero-based credential entry index.

        Returns:
            Credential entry record, or None when the index is invalid.
        """
        entries = self.list_credential_entries()
        if index < 0 or index >= len(entries):
            return None
        return entries[index]

    def get_credential_entry_by_row_id(self, row_id: int) -> Optional[Dict[str, Any]]:
        """
        Return one persisted credential entry by database row ID.

        Args:
            row_id: Internal SQLite row ID.

        Returns:
            Credential entry record, or None when missing.
        """
        with self._connect() as conn:
            row = conn.execute(
                f"SELECT * FROM {KIRO_ACCOUNT_CREDENTIALS_TABLE} WHERE id = ?",
                (row_id,),
            ).fetchone()
        return _credential_row_to_record(row) if row else None

    def get_account(self, account_id: str) -> Optional[Dict[str, Any]]:
        """
        Return one account record.

        Args:
            account_id: Account ID stored in SQLite.

        Returns:
            Account dictionary, or None when missing.
        """
        with self._connect() as conn:
            row = conn.execute(
                f"SELECT * FROM {KIRO_ACCOUNTS_TABLE} WHERE id = ?",
                (account_id,),
            ).fetchone()
        return _row_to_record(row) if row else None

    def list_accounts(self, enabled_only: bool = False) -> List[Dict[str, Any]]:
        """
        List account records in updated order.

        Args:
            enabled_only: When true, return only enabled accounts.

        Returns:
            Account records.
        """
        sql = f"SELECT * FROM {KIRO_ACCOUNTS_TABLE}"
        params: tuple = ()
        if enabled_only:
            sql += " WHERE enabled = ?"
            params = (1,)
        sql += " ORDER BY updated_at DESC, id ASC"

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [_row_to_record(row) for row in rows]

    def insert_usage_snapshot(
        self,
        account_id: str,
        account_display_name: Optional[str],
        subscription_title: Optional[str],
        resource_type: Optional[str],
        display_name: Optional[str],
        display_name_plural: Optional[str],
        current_usage_with_precision: Optional[float],
        usage_limit_with_precision: Optional[float],
        next_date_reset: Optional[str] = None,
        captured_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Insert one usage-limits snapshot row.

        Args:
            account_id: Runtime account ID used by the gateway.
            account_display_name: Human-readable account label.
            subscription_title: Package title returned by GetUsageLimits.
            resource_type: Usage resource type, for example ``CREDIT``.
            display_name: Singular resource label.
            display_name_plural: Plural resource label.
            current_usage_with_precision: Current usage value.
            usage_limit_with_precision: Usage limit value.
            next_date_reset: Next reset timestamp returned by Kiro.
            captured_at: Optional explicit capture timestamp.

        Returns:
            Stored usage snapshot record.
        """
        resolved_captured_at = captured_at or _utc_now()

        with self._connect() as conn:
            cursor = conn.execute(
                f"""
                INSERT INTO {KIRO_USAGE_SNAPSHOTS_TABLE} (
                    account_id,
                    account_display_name,
                    subscription_title,
                    resource_type,
                    display_name,
                    display_name_plural,
                    current_usage_with_precision,
                    usage_limit_with_precision,
                    next_date_reset,
                    captured_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    account_id,
                    account_display_name,
                    subscription_title,
                    resource_type,
                    display_name,
                    display_name_plural,
                    current_usage_with_precision,
                    usage_limit_with_precision,
                    next_date_reset,
                    resolved_captured_at,
                ),
            )
            conn.commit()
            row_id = int(cursor.lastrowid)

        record = self.get_usage_snapshot_by_id(row_id)
        if record is None:
            raise KiroAccountSqliteStoreError("Usage snapshot was not found after saving.")
        return record

    def get_usage_snapshot_by_id(self, row_id: int) -> Optional[Dict[str, Any]]:
        """
        Return one usage snapshot row by internal SQLite ID.

        Args:
            row_id: SQLite row ID.

        Returns:
            Usage snapshot record, or None when missing.
        """
        with self._connect() as conn:
            row = conn.execute(
                f"SELECT * FROM {KIRO_USAGE_SNAPSHOTS_TABLE} WHERE id = ?",
                (row_id,),
            ).fetchone()
        return _usage_snapshot_row_to_record(row) if row else None

    def list_usage_snapshots(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        List usage snapshot rows ordered from newest to oldest.

        Args:
            limit: Maximum number of rows to return.

        Returns:
            Usage snapshot records.
        """
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT * FROM {KIRO_USAGE_SNAPSHOTS_TABLE}
                ORDER BY captured_at DESC, id DESC
                LIMIT ?
                """,
                (int(limit),),
            ).fetchall()
        return [_usage_snapshot_row_to_record(row) for row in rows]

    def list_latest_usage_snapshots(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        List the newest usage snapshot for each account/resource pair.

        Args:
            limit: Maximum number of rows to return.

        Returns:
            Latest usage snapshot records grouped by ``account_id`` and
            ``resource_type``.
        """
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT * FROM {KIRO_USAGE_SNAPSHOTS_TABLE} AS snapshot
                WHERE snapshot.id = (
                    SELECT latest.id
                    FROM {KIRO_USAGE_SNAPSHOTS_TABLE} AS latest
                    WHERE latest.account_id = snapshot.account_id
                      AND COALESCE(latest.resource_type, '') = COALESCE(snapshot.resource_type, '')
                    ORDER BY latest.captured_at DESC, latest.id DESC
                    LIMIT 1
                )
                ORDER BY snapshot.captured_at DESC, snapshot.id DESC
                LIMIT ?
                """,
                (int(limit),),
            ).fetchall()
        return [_usage_snapshot_row_to_record(row) for row in rows]

    def latest_account_id(self) -> Optional[str]:
        """
        Return the most recently updated account ID.

        Returns:
            Latest account ID, or None when no accounts exist.
        """
        with self._connect() as conn:
            row = conn.execute(
                f"SELECT id FROM {KIRO_ACCOUNTS_TABLE} ORDER BY updated_at DESC, id ASC LIMIT 1",
            ).fetchone()
        return str(row["id"]) if row else None

    def update_runtime_tokens(
        self,
        account_id: str,
        access_token: Optional[str],
        refresh_token: Optional[str],
        expires_at: Optional[datetime],
        profile_arn: Optional[str] = None,
        csrf_token: Optional[str] = None,
        display_name: Optional[str] = None,
        user_id: Optional[str] = None,
        provider: Optional[str] = None,
    ) -> None:
        """
        Update token material after a successful refresh.

        Args:
            account_id: Account ID to update.
            access_token: New access token.
            refresh_token: New refresh token.
            expires_at: New expiration timestamp.
            profile_arn: Optional profile ARN returned by Kiro.
            csrf_token: Optional refreshed Kiro Web Portal CSRF token.
            display_name: Optional refreshed human-readable account name.
            user_id: Optional Kiro Web Portal user ID.
            provider: Optional identity provider value.

        Raises:
            KiroAccountSqliteStoreError: If the account does not exist.
        """
        record = self.get_account(account_id)
        if record is None:
            raise KiroAccountSqliteStoreError(f"Kiro account not found in SQLite store: {account_id}")

        token = dict(record["token"])
        _set_token_field(token, "accessToken", "access_token", access_token)
        _set_token_field(token, "refreshToken", "refresh_token", refresh_token)
        if expires_at:
            _set_token_field(token, "expiresAt", "expires_at", expires_at.isoformat())
        if profile_arn:
            token["profileArn"] = profile_arn
        if user_id:
            token["userId"] = user_id
        if provider:
            token["provider"] = provider

        self.upsert_token(
            token=token,
            registration=record["registration"],
            label=record["label"],
            display_name=display_name or str(record.get("display_name") or "") or None,
            enabled=record["enabled"],
            account_id=account_id,
            api_region=record["api_region"],
            csrf_token=csrf_token or str(record.get("csrf_token") or "") or None,
        )

    def update_account_usage(
        self,
        account_id: str,
        subscription_title: Optional[str],
        resource_type: Optional[str],
        display_name: Optional[str],
        display_name_plural: Optional[str],
        current_usage_with_precision: Optional[float],
        usage_limit_with_precision: Optional[float],
        next_date_reset: Optional[str] = None,
        usage_updated_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Update the latest usage-limit values stored on one account row.

        Args:
            account_id: Stored Kiro account row ID.
            subscription_title: Current package title.
            resource_type: Current usage resource type.
            display_name: Singular resource label.
            display_name_plural: Plural resource label.
            current_usage_with_precision: Current usage value.
            usage_limit_with_precision: Current usage limit value.
            next_date_reset: Next reset timestamp returned by Kiro.
            usage_updated_at: Optional explicit update timestamp.

        Returns:
            Updated account record.

        Raises:
            KiroAccountSqliteStoreError: If the account does not exist.
        """
        record = self.get_account(account_id)
        if record is None:
            raise KiroAccountSqliteStoreError(f"Kiro account not found in SQLite store: {account_id}")

        resolved_updated_at = usage_updated_at or _utc_now()
        with self._connect() as conn:
            conn.execute(
                f"""
                UPDATE {KIRO_ACCOUNTS_TABLE}
                SET usage_subscription_title = ?,
                    usage_resource_type = ?,
                    usage_display_name = ?,
                    usage_display_name_plural = ?,
                    usage_current_usage_with_precision = ?,
                    usage_limit_with_precision = ?,
                    usage_next_date_reset = ?,
                    usage_updated_at = ?
                WHERE id = ?
                """,
                (
                    subscription_title,
                    resource_type,
                    display_name,
                    display_name_plural,
                    current_usage_with_precision,
                    usage_limit_with_precision,
                    next_date_reset,
                    resolved_updated_at,
                    account_id,
                ),
            )
            conn.commit()

        updated_record = self.get_account(account_id)
        if updated_record is None:
            raise KiroAccountSqliteStoreError("Kiro account was not found after updating usage.")
        return updated_record

    def mark_used(self, account_id: str) -> None:
        """
        Update the last-used timestamp for an account.

        Args:
            account_id: Account ID to mark as used.
        """
        with self._connect() as conn:
            conn.execute(
                f"UPDATE {KIRO_ACCOUNTS_TABLE} SET last_used_at = ? WHERE id = ?",
                (_utc_now(), account_id),
            )
            conn.commit()

    def delete_account(self, account_id: str) -> None:
        """
        Delete one stored account row by account ID.

        Args:
            account_id: Account ID stored in SQLite.
        """
        with self._connect() as conn:
            cursor = conn.execute(
                f"DELETE FROM {KIRO_ACCOUNTS_TABLE} WHERE id = ?",
                (account_id,),
            )
            conn.commit()

        if cursor.rowcount:
            logger.info(f"Deleted Kiro account from SQLite: account_id={account_id}, db={self._db_path}")

    def _load_registration_for_token(
        self,
        token: Dict[str, Any],
        token_dir: Path,
    ) -> Optional[Dict[str, Any]]:
        """
        Load a Kiro IDE IdC client registration file for an imported token.

        Args:
            token: Kiro IDE token payload.
            token_dir: Directory containing the imported token file.

        Returns:
            Registration payload, or None if the token is not IdC or no file exists.
        """
        client_id_hash = _get_token_field(token, "clientIdHash", "client_id_hash")
        if not client_id_hash:
            return None

        candidate_paths = [
            token_dir / f"{client_id_hash}.json",
            Path.home() / ".aws" / "sso" / "cache" / f"{client_id_hash}.json",
        ]
        registration_path = next((path for path in candidate_paths if path.exists()), None)
        if registration_path is None:
            logger.warning(f"Kiro IdC registration file not found for imported token: {client_id_hash}")
            return None

        with open(registration_path, "r", encoding="utf-8") as f:
            registration = json.load(f)
        if not isinstance(registration, dict):
            raise KiroAccountSqliteStoreError("Kiro IdC registration file must contain a JSON object.")
        return registration

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """
        Open the SQLite database and ensure the schema exists.

        Yields:
            SQLite connection with row factory configured.
        """
        path = Path(self._db_path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(path), timeout=5.0)
        conn.row_factory = sqlite3.Row
        self._initialize_schema(conn)
        try:
            yield conn
        finally:
            conn.close()

    @staticmethod
    def _initialize_schema(conn: sqlite3.Connection) -> None:
        """
        Create account tables and indexes if they do not exist.

        Args:
            conn: Open SQLite connection.
        """
        conn.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {KIRO_ACCOUNTS_TABLE} (
                id TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                display_name TEXT,
                auth_method TEXT NOT NULL,
                provider TEXT,
                token_json TEXT NOT NULL,
                csrf_token TEXT,
                registration_json TEXT,
                region TEXT,
                api_region TEXT,
                profile_arn TEXT,
                usage_subscription_title TEXT,
                usage_resource_type TEXT,
                usage_display_name TEXT,
                usage_display_name_plural TEXT,
                usage_current_usage_with_precision REAL,
                usage_limit_with_precision REAL,
                usage_next_date_reset TEXT,
                usage_updated_at TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_used_at TEXT
            )
            """
        )
        conn.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {KIRO_ACCOUNT_CREDENTIALS_TABLE} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                credential_type TEXT NOT NULL,
                path TEXT,
                account_id TEXT,
                refresh_token TEXT,
                profile_arn TEXT,
                region TEXT,
                api_region TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            f"""
            CREATE INDEX IF NOT EXISTS idx_{KIRO_ACCOUNTS_TABLE}_enabled_updated
            ON {KIRO_ACCOUNTS_TABLE}(enabled, updated_at)
            """
        )
        conn.execute(
            f"""
            CREATE INDEX IF NOT EXISTS idx_{KIRO_ACCOUNT_CREDENTIALS_TABLE}_updated
            ON {KIRO_ACCOUNT_CREDENTIALS_TABLE}(updated_at)
            """
        )
        conn.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {KIRO_USAGE_SNAPSHOTS_TABLE} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id TEXT NOT NULL,
                account_display_name TEXT,
                subscription_title TEXT,
                resource_type TEXT,
                display_name TEXT,
                display_name_plural TEXT,
                current_usage_with_precision REAL,
                usage_limit_with_precision REAL,
                next_date_reset TEXT,
                captured_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            f"""
            CREATE INDEX IF NOT EXISTS idx_{KIRO_USAGE_SNAPSHOTS_TABLE}_captured
            ON {KIRO_USAGE_SNAPSHOTS_TABLE}(captured_at, id)
            """
        )
        conn.execute(
            f"""
            CREATE INDEX IF NOT EXISTS idx_{KIRO_USAGE_SNAPSHOTS_TABLE}_account_resource
            ON {KIRO_USAGE_SNAPSHOTS_TABLE}(account_id, resource_type, captured_at, id)
            """
        )
        columns = {
            str(row["name"])
            for row in conn.execute(f"PRAGMA table_info({KIRO_ACCOUNTS_TABLE})").fetchall()
        }
        if "csrf_token" not in columns:
            conn.execute(f"ALTER TABLE {KIRO_ACCOUNTS_TABLE} ADD COLUMN csrf_token TEXT")
        if "display_name" not in columns:
            conn.execute(f"ALTER TABLE {KIRO_ACCOUNTS_TABLE} ADD COLUMN display_name TEXT")
        if "usage_subscription_title" not in columns:
            conn.execute(f"ALTER TABLE {KIRO_ACCOUNTS_TABLE} ADD COLUMN usage_subscription_title TEXT")
        if "usage_resource_type" not in columns:
            conn.execute(f"ALTER TABLE {KIRO_ACCOUNTS_TABLE} ADD COLUMN usage_resource_type TEXT")
        if "usage_display_name" not in columns:
            conn.execute(f"ALTER TABLE {KIRO_ACCOUNTS_TABLE} ADD COLUMN usage_display_name TEXT")
        if "usage_display_name_plural" not in columns:
            conn.execute(f"ALTER TABLE {KIRO_ACCOUNTS_TABLE} ADD COLUMN usage_display_name_plural TEXT")
        if "usage_current_usage_with_precision" not in columns:
            conn.execute(
                f"ALTER TABLE {KIRO_ACCOUNTS_TABLE} ADD COLUMN usage_current_usage_with_precision REAL"
            )
        if "usage_limit_with_precision" not in columns:
            conn.execute(
                f"ALTER TABLE {KIRO_ACCOUNTS_TABLE} ADD COLUMN usage_limit_with_precision REAL"
            )
        if "usage_next_date_reset" not in columns:
            conn.execute(f"ALTER TABLE {KIRO_ACCOUNTS_TABLE} ADD COLUMN usage_next_date_reset TEXT")
        if "usage_updated_at" not in columns:
            conn.execute(f"ALTER TABLE {KIRO_ACCOUNTS_TABLE} ADD COLUMN usage_updated_at TEXT")
        conn.commit()

    def _find_matching_credential_entry(self, entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Find an existing persisted credential entry matching the same source.

        Args:
            entry: Normalized credential entry payload.

        Returns:
            Matching credential entry record, or None when absent.
        """
        entry_type = str(entry.get("type") or "")
        for existing in self.list_credential_entries():
            if str(existing.get("type") or "") != entry_type:
                continue
            if entry_type == "sqlite_account":
                if (
                    str(existing.get("path") or "") == str(entry.get("path") or "")
                    and str(existing.get("account_id") or "") == str(entry.get("account_id") or "")
                ):
                    return existing
                continue
            if entry_type == "refresh_token":
                if str(existing.get("refresh_token") or "") == str(entry.get("refresh_token") or ""):
                    return existing
                continue
            if str(existing.get("path") or "") == str(entry.get("path") or ""):
                return existing
        return None


def build_kiro_account_id(token: Dict[str, Any]) -> str:
    """
    Build a deterministic account ID from non-displayed account material.

    Args:
        token: Kiro token payload.

    Returns:
        Stable account ID for the same imported/login token lineage.
    """
    identity_parts = [
        _get_token_field(token, "authMethod", "auth_method") or "",
        _get_token_field(token, "provider") or "",
        _get_token_field(token, "profileArn", "profile_arn") or "",
        _get_token_field(token, "region") or "",
        _get_token_field(token, "clientIdHash", "client_id_hash") or "",
        _get_token_field(token, "refreshToken", "refresh_token") or "",
    ]
    digest = hashlib.sha256(
        json.dumps(identity_parts, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    return f"kiro_{digest[:20]}"


def build_account_display_name(
    token: Dict[str, Any],
    fallback: str,
    stored_label: Optional[str] = None,
    provider: Optional[str] = None,
    profile_arn: Optional[str] = None,
) -> str:
    """
    Build a human-readable account display name.

    Args:
        token: Token payload or token-like mapping.
        fallback: Final fallback label when no better identity is available.
        stored_label: Existing persisted label, if any.
        provider: Optional provider override.
        profile_arn: Optional profile ARN override.

    Returns:
        Human-readable account label suitable for admin UI display.
    """
    identity = _extract_account_identity(token)
    if identity:
        return identity

    normalized_stored_label = _normalize_identity_value(stored_label)
    if normalized_stored_label:
        return normalized_stored_label

    resolved_provider = (
        _normalize_identity_value(provider)
        or _normalize_identity_value(_get_token_field(token, "provider"))
        or _normalize_identity_value(_get_token_field(token, "authMethod", "auth_method"))
    )
    resolved_profile_arn = (
        _normalize_identity_value(profile_arn)
        or _normalize_identity_value(_get_token_field(token, "profileArn", "profile_arn"))
    )

    if resolved_provider and resolved_profile_arn:
        return f"{resolved_provider} {resolved_profile_arn.split('/')[-1]}"
    if resolved_profile_arn:
        return resolved_profile_arn.split("/")[-1]
    if resolved_provider:
        return f"Kiro {resolved_provider}"
    return fallback


def _row_to_record(row: sqlite3.Row) -> Dict[str, Any]:
    """
    Convert a SQLite row to a public account record.

    Args:
        row: SQLite account row.

    Returns:
        Account dictionary with parsed JSON fields.
    """
    registration_raw = row["registration_json"]
    return {
        "id": row["id"],
        "label": row["label"],
        "display_name": row["display_name"],
        "auth_method": row["auth_method"],
        "provider": row["provider"],
        "token": json.loads(row["token_json"]),
        "csrf_token": row["csrf_token"],
        "registration": json.loads(registration_raw) if registration_raw else None,
        "region": row["region"],
        "api_region": row["api_region"],
        "profile_arn": row["profile_arn"],
        "usage_subscription_title": row["usage_subscription_title"],
        "usage_resource_type": row["usage_resource_type"],
        "usage_display_name": row["usage_display_name"],
        "usage_display_name_plural": row["usage_display_name_plural"],
        "usage_current_usage_with_precision": row["usage_current_usage_with_precision"],
        "usage_limit_with_precision": row["usage_limit_with_precision"],
        "usage_next_date_reset": row["usage_next_date_reset"],
        "usage_updated_at": row["usage_updated_at"],
        "enabled": bool(row["enabled"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "last_used_at": row["last_used_at"],
    }


def _credential_row_to_record(row: sqlite3.Row) -> Dict[str, Any]:
    """
    Convert a persisted credential-entry row into a public dictionary.

    Args:
        row: SQLite credential entry row.

    Returns:
        Credential entry dictionary.
    """
    return {
        "row_id": int(row["id"]),
        "type": str(row["credential_type"]),
        "path": row["path"],
        "account_id": row["account_id"],
        "refresh_token": row["refresh_token"],
        "profile_arn": row["profile_arn"],
        "region": row["region"],
        "api_region": row["api_region"],
        "enabled": bool(row["enabled"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _usage_snapshot_row_to_record(row: sqlite3.Row) -> Dict[str, Any]:
    """
    Convert one usage snapshot SQLite row into an API-safe dictionary.

    Args:
        row: SQLite row from ``kiro_usage_snapshots``.

    Returns:
        Usage snapshot dictionary.
    """
    return {
        "id": int(row["id"]),
        "account_id": row["account_id"],
        "account_display_name": row["account_display_name"],
        "subscription_title": row["subscription_title"],
        "resource_type": row["resource_type"],
        "display_name": row["display_name"],
        "display_name_plural": row["display_name_plural"],
        "current_usage_with_precision": row["current_usage_with_precision"],
        "usage_limit_with_precision": row["usage_limit_with_precision"],
        "next_date_reset": row["next_date_reset"],
        "captured_at": row["captured_at"],
    }


def _build_account_label(token: Dict[str, Any], fallback: str) -> str:
    """
    Build a readable label without exposing token secrets.

    Args:
        token: Kiro token payload.
        fallback: Fallback label.

    Returns:
        Display label.
    """
    return build_account_display_name(token, fallback)


def _normalize_credential_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize a credential entry for database persistence.

    Args:
        entry: Raw credential entry payload.

    Returns:
        Normalized credential entry dictionary.
    """
    entry_type = str(entry.get("type") or "").strip()
    path = str(entry.get("path") or "").strip()
    account_id = str(entry.get("account_id") or "").strip()
    refresh_token = str(entry.get("refresh_token") or "").strip()
    profile_arn = str(entry.get("profile_arn") or "").strip()
    region = str(entry.get("region") or "").strip()
    api_region = str(entry.get("api_region") or "").strip()

    normalized_path = str(Path(path).expanduser()) if path else None
    return {
        "type": entry_type,
        "path": normalized_path,
        "account_id": account_id or None,
        "refresh_token": refresh_token or None,
        "profile_arn": profile_arn or None,
        "region": region or None,
        "api_region": api_region or None,
        "enabled": bool(entry.get("enabled", True)),
    }


def _extract_account_identity(token: Dict[str, Any]) -> Optional[str]:
    """
    Extract the most user-friendly identity from token-like data.

    Args:
        token: Token payload or token-like mapping.

    Returns:
        Best-effort identity string, or None when unavailable.
    """
    candidate_mappings = [token]
    for key in ("user", "profile", "claims"):
        nested_value = token.get(key)
        if isinstance(nested_value, dict):
            candidate_mappings.append(nested_value)

    for mapping in candidate_mappings:
        identity = _extract_identity_from_mapping(mapping)
        if identity:
            return identity

    for field_name in JWT_IDENTITY_TOKEN_FIELDS:
        token_value = _normalize_identity_value(token.get(field_name))
        if not token_value:
            continue
        claims = _decode_jwt_claims(token_value)
        if not claims:
            continue
        identity = _extract_identity_from_mapping(claims)
        if identity:
            return identity

    return None


def _extract_identity_from_mapping(data: Dict[str, Any]) -> Optional[str]:
    """
    Extract a displayable identity from a plain mapping.

    Args:
        data: Arbitrary claim or token mapping.

    Returns:
        Identity string, or None when no useful field is present.
    """
    for field_name in ACCOUNT_IDENTITY_FIELDS:
        identity = _normalize_identity_value(data.get(field_name))
        if identity:
            return identity

    for first_name_field, last_name_field in ACCOUNT_NAME_FIELD_GROUPS:
        combined_name = _join_identity_parts(
            _normalize_identity_value(data.get(first_name_field)),
            _normalize_identity_value(data.get(last_name_field)),
        )
        if combined_name:
            return combined_name

    return None


def _decode_jwt_claims(token_value: str) -> Optional[Dict[str, Any]]:
    """
    Decode JWT claims without verifying the signature.

    Args:
        token_value: JWT-like token string.

    Returns:
        Parsed payload mapping, or None when the token is not a JWT payload.
    """
    parts = token_value.split(".")
    if len(parts) < 2:
        return None

    payload_segment = parts[1]
    padded_payload = payload_segment + "=" * (-len(payload_segment) % 4)
    try:
        decoded_payload = base64.urlsafe_b64decode(padded_payload.encode("utf-8"))
        claims = json.loads(decoded_payload.decode("utf-8"))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError):
        return None

    if isinstance(claims, dict):
        return claims
    return None


def _join_identity_parts(first_part: Optional[str], second_part: Optional[str]) -> Optional[str]:
    """
    Join two identity fragments into one display name.

    Args:
        first_part: First identity fragment.
        second_part: Second identity fragment.

    Returns:
        Joined display name, or None when both fragments are empty.
    """
    parts = [part for part in (first_part, second_part) if part]
    if not parts:
        return None
    return " ".join(parts)


def _normalize_identity_value(value: Any) -> Optional[str]:
    """
    Normalize a candidate identity value.

    Args:
        value: Arbitrary candidate value.

    Returns:
        Trimmed string, or None when the value is empty or unusable.
    """
    if value is None:
        return None
    if isinstance(value, str):
        normalized_value = value.strip()
        return normalized_value or None
    if isinstance(value, (int, float)):
        return str(value)
    return None


def _get_token_field(token: Dict[str, Any], *names: str) -> Optional[Any]:
    """
    Return the first present token field.

    Args:
        token: Token payload.
        names: Candidate field names.

    Returns:
        Field value or None.
    """
    for name in names:
        if name in token:
            return token[name]
    return None


def _set_token_field(
    token: Dict[str, Any],
    camel_name: str,
    snake_name: str,
    value: Optional[str],
) -> None:
    """
    Update a token field while preserving its existing naming style.

    Args:
        token: Token payload to update.
        camel_name: Kiro IDE field name.
        snake_name: kiro-cli style field name.
        value: New value.
    """
    if value is None:
        return
    if snake_name in token and camel_name not in token:
        token[snake_name] = value
    else:
        token[camel_name] = value


def _utc_now() -> str:
    """
    Return an ISO UTC timestamp.

    Returns:
        Timestamp string.
    """
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
