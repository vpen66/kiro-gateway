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
Runtime-overridable settings for Kiro Gateway.

Environment variables remain the source of defaults, while this module layers
SQLite-backed overrides on top for settings that are safe to change without a
restart.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence

from loguru import logger

import kiro.config as config
from kiro.runtime_settings_store import get_runtime_settings_store


@dataclass(frozen=True)
class RuntimeSettingDefinition:
    """
    Metadata describing one runtime-overridable setting.

    Attributes:
        key: Internal setting key.
        label: Human-readable admin label.
        input_type: Admin UI input type.
        description: Short description shown in the admin UI.
        default_config_key: Name of the config attribute that provides the
            environment-backed default.
        options: Allowed select options when applicable.
    """

    key: str
    label: str
    input_type: str
    description: str
    default_config_key: str
    options: Optional[List[str]] = None


@dataclass(frozen=True)
class AutoModelRoutingSettings:
    """
    Effective automatic model routing settings.

    Attributes:
        enabled: Whether auto routing is enabled.
        trigger_models: Models that trigger routing.
        simple_models: Candidates for simple requests.
        medium_models: Candidates for medium requests.
        hard_models: Candidates for hard requests.
    """

    enabled: bool
    trigger_models: List[str]
    simple_models: List[str]
    medium_models: List[str]
    hard_models: List[str]


RUNTIME_SETTING_DEFINITIONS: Dict[str, RuntimeSettingDefinition] = {
    "account_selection_mode": RuntimeSettingDefinition(
        key="account_selection_mode",
        label="Account Selection Mode",
        input_type="select",
        description="Choose sticky failover or strict round-robin across healthy accounts.",
        default_config_key="ACCOUNT_SELECTION_MODE",
        options=["sticky", "round_robin"],
    ),
    "web_search_enabled": RuntimeSettingDefinition(
        key="web_search_enabled",
        label="Web Search Auto Injection",
        input_type="boolean",
        description="Automatically inject the MCP-style web_search tool on supported requests.",
        default_config_key="WEB_SEARCH_ENABLED",
    ),
    "auto_model_routing_enabled": RuntimeSettingDefinition(
        key="auto_model_routing_enabled",
        label="Auto Model Routing",
        input_type="boolean",
        description="Enable complexity-based routing for trigger models such as auto-kiro.",
        default_config_key="AUTO_MODEL_ROUTING_ENABLED",
    ),
    "auto_model_routing_trigger_models": RuntimeSettingDefinition(
        key="auto_model_routing_trigger_models",
        label="Routing Trigger Models",
        input_type="csv",
        description="Comma-separated models that activate automatic model routing.",
        default_config_key="AUTO_MODEL_ROUTING_TRIGGER_MODELS",
    ),
    "auto_model_routing_simple_models": RuntimeSettingDefinition(
        key="auto_model_routing_simple_models",
        label="Simple Tier Models",
        input_type="csv",
        description="Comma-separated model preference order for simple requests.",
        default_config_key="AUTO_MODEL_ROUTING_SIMPLE_MODELS",
    ),
    "auto_model_routing_medium_models": RuntimeSettingDefinition(
        key="auto_model_routing_medium_models",
        label="Medium Tier Models",
        input_type="csv",
        description="Comma-separated model preference order for medium-complexity requests.",
        default_config_key="AUTO_MODEL_ROUTING_MEDIUM_MODELS",
    ),
    "auto_model_routing_hard_models": RuntimeSettingDefinition(
        key="auto_model_routing_hard_models",
        label="Hard Tier Models",
        input_type="csv",
        description="Comma-separated model preference order for hard or agentic requests.",
        default_config_key="AUTO_MODEL_ROUTING_HARD_MODELS",
    ),
}


def get_runtime_settings() -> Dict[str, Any]:
    """
    Return effective runtime-overridable settings.

    Environment values provide defaults and SQLite values override them.

    Returns:
        Effective runtime settings dictionary.
    """
    settings = _get_default_runtime_setting_values()

    for key, value in get_runtime_settings_overrides().items():
        if key not in RUNTIME_SETTING_DEFINITIONS:
            logger.warning(f"Ignoring unknown runtime setting override from SQLite: {key}")
            continue
        try:
            settings[key] = normalize_runtime_setting_value(key, value)
        except ValueError as e:
            logger.warning(f"Ignoring invalid runtime setting override {key}: {e}")

    return settings


def get_runtime_settings_overrides() -> Dict[str, Any]:
    """
    Return raw persisted runtime setting overrides.

    Returns:
        Dictionary of SQLite-backed overrides.
    """
    return get_runtime_settings_store().get_all()


def get_runtime_settings_metadata() -> Dict[str, Dict[str, Any]]:
    """
    Return admin-facing metadata for editable runtime settings.

    Returns:
        Metadata keyed by runtime setting name.
    """
    metadata: Dict[str, Dict[str, Any]] = {}
    defaults = _get_default_runtime_setting_values()
    for key, definition in RUNTIME_SETTING_DEFINITIONS.items():
        metadata[key] = {
            "label": definition.label,
            "input_type": definition.input_type,
            "description": definition.description,
            "default": _clone_default(defaults[key]),
            "options": list(definition.options) if definition.options else None,
        }
    return metadata


def update_runtime_settings(updates: Mapping[str, Any]) -> Dict[str, Any]:
    """
    Validate and persist runtime setting overrides.

    Args:
        updates: Partial update mapping from the admin API.

    Returns:
        Effective runtime settings after persistence.

    Raises:
        ValueError: If the payload contains unsupported keys or invalid values.
    """
    if not updates:
        raise ValueError("At least one runtime setting must be provided.")

    normalized: Dict[str, Any] = {}
    for key, value in updates.items():
        normalized[key] = normalize_runtime_setting_value(key, value)

    get_runtime_settings_store().set_many(normalized)
    logger.info(f"Updated runtime settings in SQLite: keys={sorted(normalized.keys())}")
    return get_runtime_settings()


def normalize_runtime_setting_value(key: str, value: Any) -> Any:
    """
    Normalize one runtime setting value.

    Args:
        key: Runtime setting key.
        value: Raw input value.

    Returns:
        Normalized runtime setting value.

    Raises:
        ValueError: If the key is unsupported or the value is invalid.
    """
    if key not in RUNTIME_SETTING_DEFINITIONS:
        raise ValueError(f"Unsupported runtime setting: {key}")

    if key == "account_selection_mode":
        return _normalize_account_selection_mode(value)
    if key in {"web_search_enabled", "auto_model_routing_enabled"}:
        return _normalize_bool(value, key)
    if key in {
        "auto_model_routing_trigger_models",
        "auto_model_routing_simple_models",
        "auto_model_routing_medium_models",
        "auto_model_routing_hard_models",
    }:
        return _normalize_string_list(value, key)

    raise ValueError(f"Unsupported runtime setting: {key}")


def get_account_selection_mode() -> str:
    """
    Return the effective account selection mode.

    Returns:
        Account selection mode string.
    """
    return str(get_runtime_settings()["account_selection_mode"])


def get_web_search_enabled() -> bool:
    """
    Return whether web_search auto-injection is enabled.

    Returns:
        Boolean flag.
    """
    return bool(get_runtime_settings()["web_search_enabled"])


def get_auto_model_routing_settings() -> AutoModelRoutingSettings:
    """
    Return effective automatic model routing settings.

    Returns:
        Typed routing settings.
    """
    settings = get_runtime_settings()
    return AutoModelRoutingSettings(
        enabled=bool(settings["auto_model_routing_enabled"]),
        trigger_models=list(settings["auto_model_routing_trigger_models"]),
        simple_models=list(settings["auto_model_routing_simple_models"]),
        medium_models=list(settings["auto_model_routing_medium_models"]),
        hard_models=list(settings["auto_model_routing_hard_models"]),
    )


def _normalize_bool(value: Any, key: str) -> bool:
    """
    Normalize a boolean runtime setting.

    Args:
        value: Raw input value.
        key: Runtime setting key for error messages.

    Returns:
        Boolean value.

    Raises:
        ValueError: If the value cannot be interpreted as boolean.
    """
    if isinstance(value, bool):
        return value

    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "on"}:
            return True
        if normalized in {"false", "0", "no", "off"}:
            return False

    raise ValueError(f"{key} must be a boolean value.")


def _normalize_string_list(value: Any, key: str) -> List[str]:
    """
    Normalize a model preference list runtime setting.

    Args:
        value: Raw input value.
        key: Runtime setting key for error messages.

    Returns:
        Cleaned list of strings.

    Raises:
        ValueError: If the value is not a list-like or string input.
    """
    if isinstance(value, str):
        items = re.split(r"[\n,]", value)
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        items = [str(item) for item in value]
    else:
        raise ValueError(f"{key} must be a list of strings or a comma-separated string.")

    return [item.strip() for item in items if item and item.strip()]


def _normalize_account_selection_mode(value: Any) -> str:
    """
    Normalize the runtime account selection mode.

    Args:
        value: Raw input value.

    Returns:
        Sanitized selection mode.

    Raises:
        ValueError: If the mode is unsupported.
    """
    if not isinstance(value, str):
        raise ValueError("account_selection_mode must be a string.")

    normalized = value.strip().lower()
    if normalized == "round-robin":
        normalized = "round_robin"
    if normalized not in {"sticky", "round_robin"}:
        raise ValueError("account_selection_mode must be one of: sticky, round_robin.")
    return normalized


def _clone_default(value: Any) -> Any:
    """
    Clone a default setting value for safe mutation.

    Args:
        value: Default value.

    Returns:
        Cloned default for lists, otherwise the original immutable value.
    """
    if isinstance(value, list):
        return list(value)
    return value


def _get_default_runtime_setting_values() -> Dict[str, Any]:
    """
    Return current environment-backed defaults for runtime-overridable settings.

    Returns:
        Default runtime setting values derived from ``kiro.config``.
    """
    return {
        "account_selection_mode": config.ACCOUNT_SELECTION_MODE,
        "web_search_enabled": config.WEB_SEARCH_ENABLED,
        "auto_model_routing_enabled": config.AUTO_MODEL_ROUTING_ENABLED,
        "auto_model_routing_trigger_models": list(config.AUTO_MODEL_ROUTING_TRIGGER_MODELS),
        "auto_model_routing_simple_models": list(config.AUTO_MODEL_ROUTING_SIMPLE_MODELS),
        "auto_model_routing_medium_models": list(config.AUTO_MODEL_ROUTING_MEDIUM_MODELS),
        "auto_model_routing_hard_models": list(config.AUTO_MODEL_ROUTING_HARD_MODELS),
    }
