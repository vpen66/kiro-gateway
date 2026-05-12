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
SQLite-backed runtime settings overrides for Kiro Gateway.

This store persists admin-managed configuration values that should override
environment defaults without requiring a restart. The effective settings are
still defined by the regular configuration layer; this module only stores the
override payloads.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


RUNTIME_SETTINGS_TABLE = "gateway_settings"


class RuntimeSettingsStore:
    """
    Store runtime setting overrides in SQLite.

    Args:
        db_path: Path to the SQLite database.
    """

    def __init__(self, db_path: str):
        """Initialize the runtime settings store."""
        self._db_path = str(Path(db_path).expanduser())

    @property
    def db_path(self) -> str:
        """Return the resolved database path."""
        return self._db_path

    def get_all(self) -> Dict[str, Any]:
        """
        Return every persisted runtime setting override.

        Returns:
            Dictionary keyed by runtime setting name.
        """
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT key, value_json FROM {RUNTIME_SETTINGS_TABLE} ORDER BY key ASC"
            ).fetchall()

        settings: Dict[str, Any] = {}
        for row in rows:
            settings[str(row["key"])] = json.loads(row["value_json"])
        return settings

    def set_many(self, settings: Dict[str, Any]) -> Dict[str, Any]:
        """
        Insert or update multiple runtime setting overrides.

        Args:
            settings: Setting values keyed by runtime setting name.

        Returns:
            Current persisted overrides after the update.
        """
        if not settings:
            return self.get_all()

        now = _utc_now()
        with self._connect() as conn:
            for key, value in settings.items():
                conn.execute(
                    f"""
                    INSERT INTO {RUNTIME_SETTINGS_TABLE} (key, value_json, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET
                        value_json = excluded.value_json,
                        updated_at = excluded.updated_at
                    """,
                    (key, json.dumps(value, ensure_ascii=False), now),
                )
            conn.commit()

        return self.get_all()

    def clear_all(self) -> None:
        """Delete every persisted runtime setting override."""
        with self._connect() as conn:
            conn.execute(f"DELETE FROM {RUNTIME_SETTINGS_TABLE}")
            conn.commit()

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
        Create the runtime settings table when missing.

        Args:
            conn: Open SQLite connection.
        """
        conn.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {RUNTIME_SETTINGS_TABLE} (
                key TEXT PRIMARY KEY,
                value_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.commit()


_runtime_settings_store: Optional[RuntimeSettingsStore] = None
_runtime_settings_store_path: Optional[str] = None


def get_runtime_settings_store() -> RuntimeSettingsStore:
    """
    Return the singleton runtime settings store for the configured database.

    Returns:
        Runtime settings store bound to ``KIRO_ACCOUNTS_DB_FILE``.
    """
    global _runtime_settings_store
    global _runtime_settings_store_path

    import kiro.config as config

    resolved_path = str(Path(config.KIRO_ACCOUNTS_DB_FILE).expanduser())
    if _runtime_settings_store is None or _runtime_settings_store_path != resolved_path:
        _runtime_settings_store = RuntimeSettingsStore(resolved_path)
        _runtime_settings_store_path = resolved_path
    return _runtime_settings_store


def _utc_now() -> str:
    """
    Return an ISO UTC timestamp.

    Returns:
        Timestamp string.
    """
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
