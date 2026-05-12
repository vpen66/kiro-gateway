# -*- coding: utf-8 -*-

"""
Tests for kiro/runtime_settings_store.py.
"""

import sqlite3

from kiro.runtime_settings_store import RuntimeSettingsStore


class TestRuntimeSettingsStore:
    """Tests for SQLite-backed runtime settings persistence."""

    def test_set_many_and_get_all_round_trip_values(self, tmp_path):
        """
        What it does: Writes multiple runtime overrides and reads them back.
        Purpose: Ensure runtime settings persist typed JSON values in SQLite.
        """
        print("\n=== Test: Runtime settings store round-trips typed values ===")

        store = RuntimeSettingsStore(str(tmp_path / "runtime.sqlite3"))

        stored = store.set_many({
            "account_selection_mode": "round_robin",
            "web_search_enabled": False,
            "auto_model_routing_trigger_models": ["auto-kiro", "auto"],
        })

        assert stored["account_selection_mode"] == "round_robin"
        assert stored["web_search_enabled"] is False
        assert stored["auto_model_routing_trigger_models"] == ["auto-kiro", "auto"]

        loaded = store.get_all()
        assert loaded == stored

    def test_clear_all_removes_persisted_overrides(self, tmp_path):
        """
        What it does: Deletes every stored runtime override.
        Purpose: Ensure the runtime settings table can be reset cleanly.
        """
        print("\n=== Test: Runtime settings store clears all overrides ===")

        store = RuntimeSettingsStore(str(tmp_path / "runtime.sqlite3"))
        store.set_many({"account_selection_mode": "round_robin"})

        store.clear_all()

        assert store.get_all() == {}

    def test_store_creates_expected_table(self, tmp_path):
        """
        What it does: Opens the SQLite database directly after storing a value.
        Purpose: Ensure the runtime settings schema is created in a normal table.
        """
        print("\n=== Test: Runtime settings store creates gateway_settings table ===")

        db_path = tmp_path / "runtime.sqlite3"
        store = RuntimeSettingsStore(str(db_path))
        store.set_many({"web_search_enabled": True})

        conn = sqlite3.connect(str(db_path))
        try:
            row = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='gateway_settings'"
            ).fetchone()
        finally:
            conn.close()

        assert row is not None
