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

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from loguru import logger


KIRO_ACCOUNTS_TABLE = "kiro_accounts"


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
        enabled: bool = True,
        account_id: Optional[str] = None,
        api_region: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Insert or update a Kiro account token row.

        Args:
            token: Kiro IDE-compatible token payload.
            registration: Optional AWS SSO OIDC client registration payload.
            label: Optional display label.
            enabled: Whether the account should be enabled by default.
            account_id: Optional explicit account ID to update.
            api_region: Optional Q API region override.

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
            conn.execute(
                f"""
                INSERT INTO {KIRO_ACCOUNTS_TABLE} (
                    id,
                    label,
                    auth_method,
                    provider,
                    token_json,
                    registration_json,
                    region,
                    api_region,
                    profile_arn,
                    enabled,
                    created_at,
                    updated_at,
                    last_used_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    label = excluded.label,
                    auth_method = excluded.auth_method,
                    provider = excluded.provider,
                    token_json = excluded.token_json,
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
                    auth_method,
                    provider,
                    json.dumps(token, ensure_ascii=False),
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
    ) -> None:
        """
        Update token material after a successful refresh.

        Args:
            account_id: Account ID to update.
            access_token: New access token.
            refresh_token: New refresh token.
            expires_at: New expiration timestamp.
            profile_arn: Optional profile ARN returned by Kiro.

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

        self.upsert_token(
            token=token,
            registration=record["registration"],
            label=record["label"],
            enabled=record["enabled"],
            account_id=account_id,
            api_region=record["api_region"],
        )

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

    def _connect(self) -> sqlite3.Connection:
        """
        Open the SQLite database and ensure the schema exists.

        Returns:
            SQLite connection with row factory configured.
        """
        path = Path(self._db_path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(path), timeout=5.0)
        conn.row_factory = sqlite3.Row
        self._initialize_schema(conn)
        return conn

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
        conn.execute(
            f"""
            CREATE INDEX IF NOT EXISTS idx_{KIRO_ACCOUNTS_TABLE}_enabled_updated
            ON {KIRO_ACCOUNTS_TABLE}(enabled, updated_at)
            """
        )
        conn.commit()


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
        "auth_method": row["auth_method"],
        "provider": row["provider"],
        "token": json.loads(row["token_json"]),
        "registration": json.loads(registration_raw) if registration_raw else None,
        "region": row["region"],
        "api_region": row["api_region"],
        "profile_arn": row["profile_arn"],
        "enabled": bool(row["enabled"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "last_used_at": row["last_used_at"],
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
    provider = _get_token_field(token, "provider") or _get_token_field(token, "authMethod", "auth_method")
    profile_arn = _get_token_field(token, "profileArn", "profile_arn")
    if provider and profile_arn:
        return f"{provider} {str(profile_arn).split('/')[-1]}"
    if provider:
        return f"Kiro {provider}"
    return fallback


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
