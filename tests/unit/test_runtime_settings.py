# -*- coding: utf-8 -*-

"""
Tests for kiro/runtime_settings.py.
"""

import pytest

import kiro.config as config
from kiro.runtime_settings import (
    get_auto_model_routing_settings,
    get_runtime_settings,
    get_runtime_settings_metadata,
    normalize_runtime_setting_value,
    update_runtime_settings,
)
from kiro.runtime_settings_store import get_runtime_settings_store


class TestRuntimeSettings:
    """Tests for runtime-overridable settings behavior."""

    def test_get_runtime_settings_uses_config_defaults_without_overrides(self, tmp_path, monkeypatch):
        """
        What it does: Reads runtime settings when SQLite contains no overrides.
        Purpose: Ensure environment-backed config values remain the defaults.
        """
        print("\n=== Test: Runtime settings use config defaults when SQLite is empty ===")

        monkeypatch.setattr(config, "KIRO_ACCOUNTS_DB_FILE", str(tmp_path / "runtime.sqlite3"))
        monkeypatch.setattr(config, "ACCOUNT_SELECTION_MODE", "sticky")
        monkeypatch.setattr(config, "WEB_SEARCH_ENABLED", True)
        monkeypatch.setattr(config, "AUTO_MODEL_ROUTING_ENABLED", False)
        monkeypatch.setattr(config, "AUTO_MODEL_ROUTING_TRIGGER_MODELS", ["auto-kiro"])

        store = get_runtime_settings_store()
        store.clear_all()

        settings = get_runtime_settings()

        assert settings["account_selection_mode"] == "sticky"
        assert settings["web_search_enabled"] is True
        assert settings["auto_model_routing_enabled"] is False
        assert settings["auto_model_routing_trigger_models"] == ["auto-kiro"]

    def test_update_runtime_settings_persists_normalized_values(self, tmp_path, monkeypatch):
        """
        What it does: Writes runtime overrides using mixed input formats.
        Purpose: Ensure admin updates are normalized and applied to effective settings.
        """
        print("\n=== Test: Runtime settings persist normalized override values ===")

        monkeypatch.setattr(config, "KIRO_ACCOUNTS_DB_FILE", str(tmp_path / "runtime.sqlite3"))
        monkeypatch.setattr(config, "ACCOUNT_SELECTION_MODE", "sticky")

        store = get_runtime_settings_store()
        store.clear_all()

        settings = update_runtime_settings({
            "account_selection_mode": "round-robin",
            "web_search_enabled": "false",
            "auto_model_routing_trigger_models": "auto-kiro, auto",
        })

        assert settings["account_selection_mode"] == "round_robin"
        assert settings["web_search_enabled"] is False
        assert settings["auto_model_routing_trigger_models"] == ["auto-kiro", "auto"]

        routing_settings = get_auto_model_routing_settings()
        assert routing_settings.trigger_models == ["auto-kiro", "auto"]

        persisted = store.get_all()
        assert persisted["account_selection_mode"] == "round_robin"

    def test_normalize_runtime_setting_value_rejects_invalid_mode(self):
        """
        What it does: Validates an unsupported account selection mode.
        Purpose: Ensure invalid admin values fail fast with a clear error.
        """
        print("\n=== Test: Invalid account selection mode is rejected ===")

        with pytest.raises(ValueError, match="account_selection_mode"):
            normalize_runtime_setting_value("account_selection_mode", "random_mode")

    def test_get_runtime_settings_metadata_includes_current_defaults(self, tmp_path, monkeypatch):
        """
        What it does: Reads settings metadata after patching config defaults.
        Purpose: Ensure the admin UI sees current default values rather than stale import-time state.
        """
        print("\n=== Test: Runtime settings metadata reflects current config defaults ===")

        monkeypatch.setattr(config, "KIRO_ACCOUNTS_DB_FILE", str(tmp_path / "runtime.sqlite3"))
        monkeypatch.setattr(config, "ACCOUNT_SELECTION_MODE", "sticky")
        monkeypatch.setattr(config, "AUTO_MODEL_ROUTING_SIMPLE_MODELS", ["claude-haiku-4.5", "auto-kiro"])

        metadata = get_runtime_settings_metadata()

        assert metadata["account_selection_mode"]["default"] == "sticky"
        assert metadata["auto_model_routing_simple_models"]["default"] == [
            "claude-haiku-4.5",
            "auto-kiro",
        ]
