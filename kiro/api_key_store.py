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
Persistent API key management for Kiro Gateway.

Generated keys are stored as SHA-256 hashes so plaintext keys are only shown
once when they are created. The legacy PROXY_API_KEY environment value remains
valid and grants full admin access for backward compatibility.
"""

import hashlib
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger

import kiro.config as config


API_KEY_PREFIX = "kgw_"
ENV_KEY_ID = "env_proxy_api_key"
ENV_KEY_NAME = "PROXY_API_KEY"
STORE_VERSION = 1
VALID_SCOPES = frozenset({"api", "admin"})


@dataclass
class ApiKeyValidation:
    """
    Result of an API key validation attempt.

    Attributes:
        valid: Whether the key is accepted.
        key_id: Matching key identifier when valid.
        name: Human-readable key name when valid.
        scopes: Granted scopes when valid.
        source: Source of the key, either env or file.
    """

    valid: bool
    key_id: Optional[str] = None
    name: Optional[str] = None
    scopes: Optional[List[str]] = None
    source: Optional[str] = None


class ApiKeyStore:
    """
    Manages generated proxy API keys persisted in a JSON file.

    Args:
        file_path: Path to the API key store JSON file.
    """

    def __init__(self, file_path: str):
        """Initialize the API key store."""
        self.file_path = Path(file_path).expanduser()

    def list_keys(self, include_env_key: bool = True) -> List[Dict[str, Any]]:
        """
        List API keys without exposing plaintext secrets.

        Args:
            include_env_key: Whether to include the legacy PROXY_API_KEY entry.

        Returns:
            List of key metadata dictionaries.
        """
        data = self._load_data()
        records = []

        if include_env_key:
            records.append({
                "id": ENV_KEY_ID,
                "name": ENV_KEY_NAME,
                "prefix": "env",
                "enabled": True,
                "scopes": ["api", "admin"],
                "source": "env",
                "created_at": None,
                "last_used_at": None,
            })

        for record in data["keys"]:
            records.append(self._public_record(record))

        return records

    def create_key(self, name: str, scopes: Optional[List[str]] = None) -> Tuple[str, Dict[str, Any]]:
        """
        Create and persist a new API key.

        Args:
            name: Human-readable key name.
            scopes: Optional scopes. Defaults to API-only access.

        Returns:
            Tuple of plaintext key and public metadata record.

        Raises:
            ValueError: If name or scopes are invalid.
        """
        cleaned_name = name.strip()
        if not cleaned_name:
            raise ValueError("API key name is required.")

        cleaned_scopes = self._normalize_scopes(scopes or ["api"])
        plaintext = f"{API_KEY_PREFIX}{secrets.token_urlsafe(32)}"
        now = self._now()
        record = {
            "id": secrets.token_hex(12),
            "name": cleaned_name,
            "key_hash": self._hash_key(plaintext),
            "prefix": plaintext[:12],
            "enabled": True,
            "scopes": cleaned_scopes,
            "source": "file",
            "created_at": now,
            "last_used_at": None,
        }

        data = self._load_data()
        data["keys"].append(record)
        self._save_data(data)
        logger.info(f"Created generated API key: id={record['id']}, name={cleaned_name}")
        return plaintext, self._public_record(record)

    def set_enabled(self, key_id: str, enabled: bool) -> Dict[str, Any]:
        """
        Enable or disable a generated API key.

        Args:
            key_id: Generated key ID.
            enabled: Desired enabled state.

        Returns:
            Updated public metadata record.

        Raises:
            ValueError: If the key ID is immutable or unknown.
        """
        if key_id == ENV_KEY_ID:
            raise ValueError("The environment API key cannot be modified at runtime.")

        data = self._load_data()
        for record in data["keys"]:
            if record.get("id") == key_id:
                record["enabled"] = enabled
                self._save_data(data)
                logger.info(f"Updated generated API key: id={key_id}, enabled={enabled}")
                return self._public_record(record)

        raise ValueError(f"API key not found: {key_id}")

    def delete_key(self, key_id: str) -> None:
        """
        Delete a generated API key.

        Args:
            key_id: Generated key ID.

        Raises:
            ValueError: If the key ID is immutable or unknown.
        """
        if key_id == ENV_KEY_ID:
            raise ValueError("The environment API key cannot be deleted at runtime.")

        data = self._load_data()
        original_count = len(data["keys"])
        data["keys"] = [record for record in data["keys"] if record.get("id") != key_id]

        if len(data["keys"]) == original_count:
            raise ValueError(f"API key not found: {key_id}")

        self._save_data(data)
        logger.info(f"Deleted generated API key: id={key_id}")

    def verify_key(self, plaintext: str, required_scope: str) -> ApiKeyValidation:
        """
        Verify a plaintext API key and required scope.

        Args:
            plaintext: Plaintext API key supplied by the client.
            required_scope: Required scope, usually api or admin.

        Returns:
            Validation result with matching key metadata when valid.

        Raises:
            ValueError: If the required scope is unsupported.
        """
        if required_scope not in VALID_SCOPES:
            raise ValueError(f"Unsupported API key scope: {required_scope}")

        if secrets.compare_digest(plaintext, config.PROXY_API_KEY):
            return ApiKeyValidation(
                valid=True,
                key_id=ENV_KEY_ID,
                name=ENV_KEY_NAME,
                scopes=["api", "admin"],
                source="env",
            )

        data = self._load_data()
        key_hash = self._hash_key(plaintext)

        for record in data["keys"]:
            if not record.get("enabled", True):
                continue

            if not secrets.compare_digest(record.get("key_hash", ""), key_hash):
                continue

            scopes = list(record.get("scopes", []))
            if required_scope not in scopes and "admin" not in scopes:
                logger.warning(f"API key lacks required scope: id={record.get('id', 'unknown')}, scope={required_scope}")
                return ApiKeyValidation(valid=False)

            record["last_used_at"] = self._now()
            self._save_data(data)
            return ApiKeyValidation(
                valid=True,
                key_id=record.get("id"),
                name=record.get("name", "Generated API key"),
                scopes=scopes,
                source="file",
            )

        return ApiKeyValidation(valid=False)

    def _load_data(self) -> Dict[str, Any]:
        """
        Load key store data from disk.

        Returns:
            Normalized store data.
        """
        if not self.file_path.exists():
            return {"version": STORE_VERSION, "keys": []}

        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse API key store {self.file_path}: {e}")
            return {"version": STORE_VERSION, "keys": []}
        except OSError as e:
            logger.error(f"Failed to read API key store {self.file_path}: {e}")
            return {"version": STORE_VERSION, "keys": []}

        if not isinstance(data, dict):
            logger.error(f"Invalid API key store format in {self.file_path}: expected object")
            return {"version": STORE_VERSION, "keys": []}

        keys = data.get("keys", [])
        if not isinstance(keys, list):
            logger.error(f"Invalid API key store format in {self.file_path}: keys must be a list")
            keys = []

        return {"version": STORE_VERSION, "keys": keys}

    def _save_data(self, data: Dict[str, Any]) -> None:
        """
        Save key store data atomically.

        Args:
            data: Store data to persist.
        """
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self.file_path.with_suffix(f"{self.file_path.suffix}.tmp")

        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            tmp_path.replace(self.file_path)
        except OSError as e:
            logger.error(f"Failed to save API key store {self.file_path}: {e}")
            if tmp_path.exists():
                tmp_path.unlink()
            raise

    def _normalize_scopes(self, scopes: List[str]) -> List[str]:
        """
        Normalize and validate requested scopes.

        Args:
            scopes: Raw scope list.

        Returns:
            Sorted unique scopes.

        Raises:
            ValueError: If no valid scopes are provided or an unknown scope is present.
        """
        cleaned = sorted({scope.strip() for scope in scopes if isinstance(scope, str) and scope.strip()})
        if not cleaned:
            raise ValueError("At least one API key scope is required.")

        invalid = [scope for scope in cleaned if scope not in VALID_SCOPES]
        if invalid:
            raise ValueError(f"Unsupported API key scope(s): {', '.join(invalid)}")

        return cleaned

    def _public_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build a secret-free public API key record.

        Args:
            record: Internal persisted record.

        Returns:
            Public metadata dictionary.
        """
        return {
            "id": record.get("id", "unknown"),
            "name": record.get("name", "Generated API key"),
            "prefix": record.get("prefix", ""),
            "enabled": record.get("enabled", True),
            "scopes": list(record.get("scopes", [])),
            "source": record.get("source", "file"),
            "created_at": record.get("created_at"),
            "last_used_at": record.get("last_used_at"),
        }

    @staticmethod
    def _hash_key(plaintext: str) -> str:
        """
        Hash a plaintext API key.

        Args:
            plaintext: Plaintext key value.

        Returns:
            SHA-256 hex digest.
        """
        return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()

    @staticmethod
    def _now() -> str:
        """
        Return the current UTC time in ISO 8601 format.

        Returns:
            Current timestamp string.
        """
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def get_api_key_store() -> ApiKeyStore:
    """
    Create an API key store for the currently configured path.

    Returns:
        ApiKeyStore instance.
    """
    return ApiKeyStore(config.API_KEYS_FILE)


def extract_strict_bearer_token(auth_header: Optional[str]) -> Optional[str]:
    """
    Extract a token from a strict Authorization: Bearer header.

    Args:
        auth_header: Authorization header value.

    Returns:
        Token value if the header is strictly valid, otherwise None.
    """
    if not auth_header or not auth_header.startswith("Bearer "):
        return None

    token = auth_header.removeprefix("Bearer ")
    if not token or token.strip() != token or " " in token:
        return None

    return token
