# -*- coding: utf-8 -*-

# Kiro Gateway
# https://github.com/jwadow/kiro-gateway
# Copyright (C) 2025 Jwadow
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

"""
Unified Account System for Kiro Gateway.

Manages multiple Kiro accounts with intelligent failover, sticky behavior,
and circuit breaker pattern for reliability.

Key features:
- Lazy initialization (only first working account at startup)
- Sticky behavior (prefer successful account)
- Circuit breaker with exponential backoff
- Probabilistic retry for "dead" accounts
- TTL-based model cache refresh (only when using account)
- Atomic state persistence
"""

import asyncio
import hashlib
import json
import os
import random
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx
from loguru import logger

import kiro.config as kiro_config
from kiro.account_sqlite_store import (
    KiroAccountSqliteStore,
    build_account_display_name,
)
from kiro.auth import KiroAuthManager, AuthType, SQLITE_TOKEN_KEYS
from kiro.cache import ModelInfoCache
from kiro.model_resolver import ModelResolver, normalize_model_name
from kiro.config import (
    HIDDEN_MODELS,
    MODEL_ALIASES,
    HIDDEN_FROM_LIST,
    ACCOUNT_RECOVERY_TIMEOUT,
    ACCOUNT_MAX_BACKOFF_MULTIPLIER,
    ACCOUNT_PROBABILISTIC_RETRY_CHANCE,
    ACCOUNT_CACHE_TTL,
    STATE_SAVE_INTERVAL_SECONDS,
    FALLBACK_MODELS,
)
from kiro.utils import get_kiro_headers
from kiro.account_errors import ErrorType
from kiro.http_client import KiroHttpClient
from kiro.runtime_settings import get_account_selection_mode
from kiro.web_portal import (
    fetch_kiro_web_portal_session_metadata,
    fetch_kiro_web_portal_user_info,
    is_kiro_token_expiring_soon,
    refresh_kiro_account_tokens,
    resolve_kiro_web_portal_display_name,
)


def _format_duration(seconds: float) -> str:
    """
    Format duration in human-readable format.
    
    Args:
        seconds: Duration in seconds
    
    Returns:
        Formatted string (e.g., "30s", "5m", "2h", "1d")
    
    Examples:
        >>> _format_duration(30)
        '30s'
        >>> _format_duration(300)
        '5m'
        >>> _format_duration(7200)
        '2h'
        >>> _format_duration(86400)
        '1d'
    """
    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        return f"{int(seconds / 60)}m"
    elif seconds < 86400:
        return f"{int(seconds / 3600)}h"
    else:
        return f"{int(seconds / 86400)}d"


@dataclass
class AccountStats:
    """
    Statistics for account usage.
    
    Tracks request counts for monitoring and future web UI.
    """
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0


@dataclass
class Account:
    """
    Complete account entity with all dependencies.
    
    Represents a single Kiro account with its authentication,
    model cache, resolver, and runtime state.
    
    Attributes:
        id: Unique identifier (path to credentials file)
        auth_manager: Authentication manager (lazy initialized)
        model_cache: Model metadata cache (lazy initialized)
        model_resolver: Model resolver (lazy initialized)
        failures: Consecutive failure count (for Circuit Breaker)
        last_failure_time: Timestamp of last failure
        models_cached_at: Timestamp of last model cache update
        stats: Usage statistics
    """
    id: str
    auth_manager: Optional[KiroAuthManager] = None
    model_cache: Optional[ModelInfoCache] = None
    model_resolver: Optional[ModelResolver] = None
    failures: int = 0
    last_failure_time: float = 0.0
    models_cached_at: float = 0.0
    stats: AccountStats = field(default_factory=AccountStats)


@dataclass
class ModelAccountList:
    """
    List of accounts for a specific model.
    
    Attributes:
        accounts: List of account IDs that have this model
    
    Note: next_index removed - now using global _current_account_index
    """
    accounts: List[str] = field(default_factory=list)


class AccountManager:
    """
    Manages multiple Kiro accounts with intelligent failover.
    
    Responsibilities:
    - Load credentials from the SQLite registry
    - Lazy initialization of accounts
    - Select next available account (Circuit Breaker + Sticky)
    - Track statistics and failures
    - Persist state to state.json
    
    Example:
        >>> manager = AccountManager("unused-legacy-path", "state.json", "kiro_accounts.sqlite3")
        >>> await manager.load_credentials()
        >>> await manager.load_state()
        >>> account = await manager.get_next_account("claude-opus-4.5")
        >>> await manager.report_success(account.id, "claude-opus-4.5")
    """
    
    def __init__(self, credentials_file: str, state_file: str, credentials_db_file: Optional[str] = None):
        """
        Initialize AccountManager.
        
        Args:
            credentials_file: Reserved legacy path kept for constructor compatibility.
            state_file: Path to state.json.
            credentials_db_file: SQLite database path containing persisted
                account rows and credential-entry registry.
        """
        default_credentials_db_path = Path(state_file).expanduser().with_name(
            Path(kiro_config.KIRO_ACCOUNTS_DB_FILE).name
        )
        self._credentials_db_file = str(Path(credentials_db_file).expanduser()) if credentials_db_file else str(
            default_credentials_db_path
        )
        self._state_file = state_file
        self._accounts: Dict[str, Account] = {}
        self._model_to_accounts: Dict[str, ModelAccountList] = {}
        self._lock = asyncio.Lock()
        self._dirty = False
        self._credentials_config: List[Dict] = []
        self._current_account_index: int = 0  # GLOBAL selection index for all models

    def _get_next_selection_index_on_success(self, successful_index: int, total_accounts: int) -> int:
        """
        Compute the next global selection index after a successful request.

        Args:
            successful_index: Index of the account that succeeded.
            total_accounts: Total number of configured runtime accounts.

        Returns:
            Next global selection index according to the effective runtime
            account selection mode.
        """
        if total_accounts <= 0:
            return 0

        if get_account_selection_mode() == "round_robin":
            return (successful_index + 1) % total_accounts

        return successful_index
    
    async def load_credentials(self) -> None:
        """
        Load credential entries from the SQLite registry.
        """
        self._credentials_config = self._load_persisted_credential_entries()
        if not self._credentials_config:
            return

        self._materialize_accounts_from_entries(self._credentials_config)
        logger.info(f"Loaded {len(self._accounts)} account(s) from persisted credentials")

    def _load_persisted_credential_entries(self) -> List[Dict[str, Any]]:
        """
        Load persisted credential entries from the SQLite registry.

        Returns:
            Credential entry list.
        """
        store = self._get_accounts_store()
        try:
            db_entries = store.list_credential_entries()
        except (OSError, sqlite3.Error, ValueError) as e:
            logger.error(f"Failed to load credential entries from SQLite registry: {e}")
            db_entries = []

        if db_entries:
            logger.info(f"Loaded {len(db_entries)} credential entry/entries from SQLite registry")
            return db_entries

        logger.warning(f"No persisted credential entries found in SQLite registry: db={self._credentials_db_file}")
        return []

    def _materialize_accounts_from_entries(self, entries: List[Dict[str, Any]]) -> None:
        """
        Validate persisted credential entries and build runtime account stubs.

        Args:
            entries: Persisted credential entries.
        """
        for entry in entries:
            cred_type = entry.get("type")
            path = entry.get("path")
            enabled = entry.get("enabled", True)
            
            if not enabled:
                continue
            
            # Validate required fields based on type
            if not cred_type:
                logger.warning(f"Invalid credential entry (missing type): {entry}")
                continue
            
            # For json/sqlite/sqlite_account types, path is required
            if cred_type in ("json", "sqlite", "sqlite_account") and not path:
                logger.warning(f"Invalid credential entry (type={cred_type} requires path): {entry}")
                continue

            if cred_type == "sqlite_account" and not entry.get("account_id"):
                logger.warning(f"Invalid credential entry (type=sqlite_account requires account_id): {entry}")
                continue
            
            # For refresh_token type, refresh_token field is required
            if cred_type == "refresh_token" and not entry.get("refresh_token"):
                logger.warning(f"Invalid credential entry (type=refresh_token requires refresh_token field): {entry}")
                continue
            
            # Handle refresh_token type (no path processing needed)
            if cred_type == "refresh_token":
                account_id = self._build_refresh_token_account_id(str(entry.get("refresh_token", "")))
                self._accounts[account_id] = Account(id=account_id)
                logger.debug(f"Added account: {account_id}")
                continue  # Skip path processing for refresh_token

            if cred_type == "sqlite_account":
                expanded_path = Path(path).expanduser()
                sqlite_account_id = str(entry["account_id"])
                if not expanded_path.is_file():
                    logger.warning(f"Kiro account SQLite database not found: {path}")
                    continue

                if not self._sqlite_account_row_exists(str(expanded_path), sqlite_account_id):
                    logger.warning(
                        "Skipping stale SQLite account credential: "
                        f"account_id={sqlite_account_id}, db={expanded_path}"
                    )
                    continue

                account_id = self._runtime_id_for_sqlite_account(str(expanded_path), sqlite_account_id)
                self._accounts[account_id] = Account(id=account_id)
                logger.debug(f"Added SQLite account: {account_id}")
                continue
            
            # Handle folder scanning for json/sqlite types
            expanded_path = Path(path).expanduser()
            if expanded_path.is_dir():
                logger.info(f"Scanning folder for credentials: {path}")
                for file_path in expanded_path.iterdir():
                    if not file_path.is_file():
                        continue
                    
                    # Validate file before adding as account
                    account_id = str(file_path.resolve())
                    is_valid = False
                    
                    # Try JSON validation
                    if cred_type == "json":
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                data = json.load(f)
                                # Valid if has refreshToken or clientId
                                if 'refreshToken' in data or 'clientId' in data:
                                    is_valid = True
                        except Exception as e:
                            logger.warning(f"Invalid JSON credentials file {file_path.name}: {e}")
                    
                    # Try SQLite validation
                    elif cred_type == "sqlite":
                        try:
                            import sqlite3
                            conn = sqlite3.connect(str(file_path))
                            cursor = conn.cursor()
                            # Check if auth_kv table exists
                            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='auth_kv'")
                            if cursor.fetchone():
                                is_valid = True
                            conn.close()
                        except Exception as e:
                            logger.warning(f"Invalid SQLite database file {file_path.name}: {e}")
                    
                    if is_valid:
                        self._accounts[account_id] = Account(id=account_id)
                        logger.debug(f"Added account from folder: {account_id}")
                    else:
                        logger.warning(f"Skipping invalid credentials file: {file_path.name}")
            elif expanded_path.is_file() or cred_type == "refresh_token":
                # Single file or refresh_token type
                if cred_type == "refresh_token":
                    account_id = self._build_refresh_token_account_id(str(entry.get("refresh_token", "")))
                else:
                    account_id = str(expanded_path.resolve())
                self._accounts[account_id] = Account(id=account_id)
                logger.debug(f"Added account: {account_id}")
            else:
                logger.warning(f"Credential path not found: {path}")
        
    def _get_accounts_store(self) -> KiroAccountSqliteStore:
        """
        Return the gateway-managed account SQLite store.

        Returns:
            Account SQLite store.
        """
        return KiroAccountSqliteStore(self._credentials_db_file)
    
    async def load_state(self) -> None:
        """
        Load runtime state from state.json.
        
        Restores model_to_accounts mapping and account runtime state.
        Creates empty state if file doesn't exist.
        """
        state_path = Path(self._state_file)
        
        if not state_path.exists():
            logger.debug("State file not found, starting with empty state")
            return
        
        try:
            with open(state_path, 'r', encoding='utf-8') as f:
                state_data = json.load(f)
            # Restore global current_account_index
            self._current_account_index = state_data.get("current_account_index", 0)
            valid_account_ids = set(self._accounts.keys())
            
            # Restore model_to_accounts mapping (without next_index)
            for model, data in state_data.get("model_to_accounts", {}).items():
                account_ids = [
                    account_id
                    for account_id in data.get("accounts", [])
                    if account_id in valid_account_ids
                ]
                if not account_ids:
                    continue
                self._model_to_accounts[model] = ModelAccountList(
                    accounts=account_ids
                )
            
            # Restore account runtime state
            for account_id, data in state_data.get("accounts", {}).items():
                if account_id in self._accounts:
                    account = self._accounts[account_id]
                    account.failures = data.get("failures", 0)
                    account.last_failure_time = data.get("last_failure_time", 0.0)
                    account.models_cached_at = data.get("models_cached_at", 0.0)
                    
                    stats_data = data.get("stats", {})
                    account.stats = AccountStats(
                        total_requests=stats_data.get("total_requests", 0),
                        successful_requests=stats_data.get("successful_requests", 0),
                        failed_requests=stats_data.get("failed_requests", 0)
                    )

            if self._accounts:
                self._current_account_index = self._current_account_index % len(self._accounts)
            else:
                self._current_account_index = 0
            
            logger.info(f"Loaded state: {len(self._model_to_accounts)} model mappings, {len(self._accounts)} accounts")
        
        except Exception as e:
            logger.error(f"Failed to load state: {e}")
    
    async def _save_state(self) -> None:
        """
        Save runtime state to state.json atomically.
        
        Uses tmp file + rename for atomic write.
        """
        state_data = {
            "current_account_index": self._current_account_index,
            "accounts": {
                account_id: {
                    "failures": account.failures,
                    "last_failure_time": account.last_failure_time,
                    "models_cached_at": account.models_cached_at,
                    "stats": {
                        "total_requests": account.stats.total_requests,
                        "successful_requests": account.stats.successful_requests,
                        "failed_requests": account.stats.failed_requests
                    }
                }
                for account_id, account in self._accounts.items()
            },
            "model_to_accounts": {
                model: {
                    "accounts": mal.accounts
                }
                for model, mal in self._model_to_accounts.items()
            }
        }
        
        state_path = Path(self._state_file)
        tmp_path = state_path.with_suffix('.json.tmp')
        
        try:
            with open(tmp_path, 'w', encoding='utf-8') as f:
                json.dump(state_data, f, indent=2, ensure_ascii=False)
            
            # Atomic rename
            tmp_path.replace(state_path)
            logger.debug("State saved successfully")
        
        except Exception as e:
            logger.error(f"Failed to save state: {e}")
            if tmp_path.exists():
                tmp_path.unlink()
    
    async def save_state_periodically(self) -> None:
        """
        Background task for periodic state saving.
        
        Saves state every STATE_SAVE_INTERVAL_SECONDS if dirty flag is set.
        """
        while True:
            await asyncio.sleep(STATE_SAVE_INTERVAL_SECONDS)
            
            if self._dirty:
                async with self._lock:
                    await self._save_state()
                    self._dirty = False
    
    async def _initialize_account(self, account_id: str) -> bool:
        """
        Initialize account (lazy initialization).
        
        Creates auth_manager, fetches models, creates cache and resolver.
        
        Args:
            account_id: Account ID to initialize
        
        Returns:
            True if successful, False otherwise
        """
        account = self._accounts.get(account_id)
        if not account:
            return False
        
        try:
            # Find credentials config for this account
            creds_config = None
            for entry in self._credentials_config:
                path = entry.get("path", "")
                expanded_path = Path(path).expanduser()
                
                if entry.get("type") == "refresh_token":
                    # Match by deterministic hash for refresh_token type
                    token = entry.get('refresh_token', '')
                    token_hash = hashlib.sha256(token.encode()).hexdigest()[:16]
                    if account_id == f"refresh_token_{token_hash}":
                        creds_config = entry
                        break
                elif entry.get("type") == "sqlite_account":
                    entry_account_id = entry.get("account_id")
                    if entry_account_id:
                        runtime_id = self._runtime_id_for_sqlite_account(path, str(entry_account_id))
                        if account_id == runtime_id:
                            creds_config = entry
                            break
                elif str(expanded_path.resolve()) == account_id or (expanded_path.is_dir() and account_id.startswith(str(expanded_path.resolve()) + os.sep)):
                    creds_config = entry
                    break
            
            if not creds_config:
                logger.error(f"No credentials config found for account: {account_id}")
                return False
            
            # Create KiroAuthManager based on type
            cred_type = creds_config.get("type")
            if cred_type == "json":
                auth_manager = KiroAuthManager(
                    creds_file=account_id,
                    profile_arn=creds_config.get("profile_arn"),
                    region=creds_config.get("region", "us-east-1"),
                    api_region=creds_config.get("api_region")
                )
            elif cred_type == "sqlite":
                auth_manager = KiroAuthManager(
                    sqlite_db=account_id,
                    profile_arn=creds_config.get("profile_arn"),
                    region=creds_config.get("region", "us-east-1"),
                    api_region=creds_config.get("api_region")
                )
            elif cred_type == "sqlite_account":
                auth_manager = KiroAuthManager(
                    sqlite_db=str(Path(creds_config.get("path", "")).expanduser()),
                    sqlite_account_id=creds_config.get("account_id"),
                    profile_arn=creds_config.get("profile_arn"),
                    region=creds_config.get("region", "us-east-1"),
                    api_region=creds_config.get("api_region")
                )
            elif cred_type == "refresh_token":
                auth_manager = KiroAuthManager(
                    refresh_token=creds_config.get("refresh_token"),
                    profile_arn=creds_config.get("profile_arn"),
                    region=creds_config.get("region", "us-east-1"),
                    api_region=creds_config.get("api_region")
                )
            else:
                logger.error(f"Unknown credential type: {cred_type}")
                return False
            
            # Get token to verify credentials
            token = await auth_manager.get_access_token()
            
            # Fetch models list with retry + fallback
            params = {"origin": "AI_EDITOR"}
            if auth_manager.auth_type == AuthType.KIRO_DESKTOP and auth_manager.profile_arn:
                params["profileArn"] = auth_manager.profile_arn
            
            list_models_url = f"{auth_manager.q_host}/ListAvailableModels"
            
            # Use KiroHttpClient for retry logic (3 attempts with exponential backoff)
            http_client = KiroHttpClient(auth_manager, shared_client=None)
            
            try:
                response = await http_client.request_with_retry(
                    method="GET",
                    url=list_models_url,
                    json_data=None,
                    params=params,
                    stream=False
                )
                
                if response.status_code == 200:
                    data = response.json()
                    models_list = data.get("models", [])
                else:
                    # Shouldn't happen (retry handles non-200), but keep for safety
                    raise Exception(f"HTTP {response.status_code}")
            
            except Exception as e:
                # All retries exhausted - use fallback
                logger.error(f"Failed to fetch models for {account_id} after retries: {e}")
                logger.warning("Using pre-configured fallback models. Models will be refreshed on next TTL cycle when network recovers.")
                models_list = FALLBACK_MODELS
            
            finally:
                await http_client.close()
            
            # Create model cache and update
            model_cache = ModelInfoCache()
            await model_cache.update(models_list)
            
            # Add hidden models
            for display_name, internal_id in HIDDEN_MODELS.items():
                model_cache.add_hidden_model(display_name, internal_id)
            
            # Create model resolver
            model_resolver = ModelResolver(
                cache=model_cache,
                hidden_models=HIDDEN_MODELS,
                aliases=MODEL_ALIASES,
                hidden_from_list=HIDDEN_FROM_LIST
            )
            
            # Update account
            account.auth_manager = auth_manager
            account.model_cache = model_cache
            account.model_resolver = model_resolver
            account.models_cached_at = time.time()
            
            # Update model_to_accounts mapping
            available_models = model_resolver.get_available_models()
            for model in available_models:
                if model not in self._model_to_accounts:
                    self._model_to_accounts[model] = ModelAccountList()
                if account_id not in self._model_to_accounts[model].accounts:
                    self._model_to_accounts[model].accounts.append(account_id)
            
            logger.info(f"Initialized account: {account_id} ({len(available_models)} models)")
            self._dirty = True
            return True
        
        except Exception as e:
            logger.error(f"Failed to initialize account {account_id}: {e}")
            return False
    
    async def _refresh_account_models(self, account_id: str) -> None:
        """
        Refresh model cache for account (TTL refresh).
        
        Args:
            account_id: Account ID to refresh
        """
        account = self._accounts.get(account_id)
        if not account or not account.auth_manager:
            return
        
        # Use KiroHttpClient for retry logic
        http_client = KiroHttpClient(account.auth_manager, shared_client=None)
        
        try:
            params = {"origin": "AI_EDITOR"}
            if account.auth_manager.auth_type == AuthType.KIRO_DESKTOP and account.auth_manager.profile_arn:
                params["profileArn"] = account.auth_manager.profile_arn
            
            list_models_url = f"{account.auth_manager.q_host}/ListAvailableModels"
            
            response = await http_client.request_with_retry(
                method="GET",
                url=list_models_url,
                json_data=None,
                params=params,
                stream=False
            )
            
            if response.status_code == 200:
                data = response.json()
                models_list = data.get("models", [])
                await account.model_cache.update(models_list)
                account.models_cached_at = time.time()
                
                # Update model_to_accounts mapping (new models may have appeared)
                available_models = account.model_resolver.get_available_models()
                for model in available_models:
                    if model not in self._model_to_accounts:
                        self._model_to_accounts[model] = ModelAccountList()
                    if account_id not in self._model_to_accounts[model].accounts:
                        self._model_to_accounts[model].accounts.append(account_id)
                
                logger.debug(f"Refreshed models for {account_id}")
                self._dirty = True
        
        except Exception as e:
            # All retries exhausted - keep using stale cache
            logger.warning(f"Failed to refresh models for {account_id} after retries: {e}")
        
        finally:
            await http_client.close()
    
    async def get_next_account(self, model: str, exclude_accounts: Optional[set] = None) -> Optional[Account]:
        """
        Get next available account for model (Circuit Breaker + Sticky).
        
        Implements:
        - Sticky behavior (prefer successful account)
        - Circuit Breaker with exponential backoff
        - Probabilistic retry for "dead" accounts (10%)
        - TTL-based model cache refresh
        - Exclusion of already-tried accounts in current failover loop
        
        Args:
            model: Model name (will be normalized)
            exclude_accounts: Set of account IDs to exclude (already tried in current failover loop)
        
        Returns:
            Account object or None if no accounts available
        """
        async with self._lock:
            # Special case: single account - bypass Circuit Breaker
            # Circuit Breaker is meaningless for single account - user should see real Kiro API errors
            # instead of generic "Account unavailable" after cooldown kicks in
            if len(self._accounts) == 1:
                account_id = list(self._accounts.keys())[0]
                account = self._accounts[account_id]
                
                # Skip if already tried in current failover loop
                if exclude_accounts and account_id in exclude_accounts:
                    return None
                
                # Lazy initialization if needed
                if account.auth_manager is None:
                    success = await self._initialize_account(account_id)
                    if not success:
                        return None
                
                # Check TTL and refresh if needed
                if account.models_cached_at > 0:
                    age = time.time() - account.models_cached_at
                    if age > ACCOUNT_CACHE_TTL:
                        try:
                            await self._refresh_account_models(account_id)
                        except Exception as e:
                            logger.warning(f"Failed to refresh models for {account_id}: {e}")
                
                # Validate model availability
                if account.model_resolver:
                    normalized_model = normalize_model_name(model)
                    available_models = account.model_resolver.get_available_models()
                    if normalized_model not in available_models:
                        return None
                
                # Always return single account (ignore cooldown/failures)
                return account
            
            # Multi-account logic: GLOBAL selection index
            normalized_model = normalize_model_name(model)
            
            # ALWAYS start from the global selection index
            start_index = self._current_account_index
            
            # ALWAYS iterate over ALL accounts
            all_account_ids = list(self._accounts.keys())
            
            for i in range(len(all_account_ids)):
                current_index = (start_index + i) % len(all_account_ids)
                account_id = all_account_ids[current_index]
                account = self._accounts[account_id]
                
                # Skip accounts already tried in current failover loop
                if exclude_accounts and account_id in exclude_accounts:
                    continue
                
                # Check Circuit Breaker (Half-Open state with exponential backoff)
                if account.failures > 0:
                    time_since_failure = time.time() - account.last_failure_time
                    
                    # Exponential backoff: base * 2^(failures - 1), capped at MAX_MULTIPLIER
                    # 1 failure: 60s, 2: 120s, 3: 240s, ..., 12+: 86400s (1 day cap)
                    backoff_multiplier = min(2 ** (account.failures - 1), ACCOUNT_MAX_BACKOFF_MULTIPLIER)
                    effective_timeout = ACCOUNT_RECOVERY_TIMEOUT * backoff_multiplier
                    
                    if time_since_failure < effective_timeout:
                        # Probabilistic retry (10% chance)
                        if random.random() > ACCOUNT_PROBABILISTIC_RETRY_CHANCE:
                            continue
                        else:
                            logger.info(f"Probabilistic retry for broken account {account_id}")
                    else:
                        # Half-Open: recovery timeout passed
                        logger.info(f"Half-Open state for {account_id} (recovery timeout passed, effective={effective_timeout}s)")
                
                # Lazy initialization
                if account.auth_manager is None:
                    success = await self._initialize_account(account_id)
                    if not success:
                        account.failures += 1
                        self._dirty = True
                        continue
                
                # Check TTL and refresh if needed
                if account.models_cached_at > 0:
                    age = time.time() - account.models_cached_at
                    if age > ACCOUNT_CACHE_TTL:
                        try:
                            await self._refresh_account_models(account_id)
                        except Exception as e:
                            logger.warning(f"Failed to refresh models for {account_id}: {e}")
                
                # Check if model is available on this account
                available_models = account.model_resolver.get_available_models()
                if normalized_model not in available_models:
                    continue
                
                # Account is suitable!
                return account
            
            # All accounts unavailable
            return None
    
    async def report_success(self, account_id: str, model: str) -> None:
        """
        Report successful request (reset failures, update stats, selection index).
        
        Args:
            account_id: Account ID
            model: Model name
        """
        async with self._lock:
            account = self._accounts.get(account_id)
            if not account:
                return
            
            # Reset failures
            if account.failures > 0:
                account.failures = 0
                self._dirty = True
            
            # Update stats
            account.stats.total_requests += 1
            account.stats.successful_requests += 1
            self._dirty = True
            
            # Update global selection index according to the configured strategy.
            all_account_ids = list(self._accounts.keys())
            try:
                successful_index = all_account_ids.index(account_id)
                next_index = self._get_next_selection_index_on_success(
                    successful_index,
                    len(all_account_ids)
                )
                if self._current_account_index != next_index:
                    self._current_account_index = next_index
                    self._dirty = True
            except ValueError:
                pass
    
    async def report_failure(
        self,
        account_id: str,
        model: str,
        error_type: ErrorType,
        status_code: int,
        reason: Optional[str]
    ) -> None:
        """
        Report failed request (update failures, stats, failover).
        
        Args:
            account_id: Account ID
            model: Model name
            error_type: Error classification (FATAL or RECOVERABLE)
            status_code: HTTP status code
            reason: Error reason from Kiro API
        """
        async with self._lock:
            account = self._accounts.get(account_id)
            if not account:
                return
            
            # Update failure count (only for RECOVERABLE)
            if error_type == ErrorType.RECOVERABLE:
                account.failures += 1
                account.last_failure_time = time.time()
                self._dirty = True
                
                # Calculate backoff for logging
                backoff_multiplier = min(2 ** (account.failures - 1), ACCOUNT_MAX_BACKOFF_MULTIPLIER)
                effective_timeout = ACCOUNT_RECOVERY_TIMEOUT * backoff_multiplier
                logger.warning(
                    f"Account {account_id} failure #{account.failures}: "
                    f"status={status_code}, reason={reason}, "
                    f"cooldown={_format_duration(effective_timeout)}"
                )
            
            # Update stats
            account.stats.total_requests += 1
            account.stats.failed_requests += 1
            self._dirty = True
            
            # Do NOT change _current_account_index on failure.
            # Selection index advances only after a successful request.
            # Failover happens through exclude_accounts in get_next_account()
    
    def get_first_account(self) -> Account:
        """
        Get first initialized account (for legacy mode).
        
        Returns:
            First initialized account
        
        Raises:
            RuntimeError: If no initialized accounts available
        """
        for account in self._accounts.values():
            if account.auth_manager is not None:
                return account
        raise RuntimeError("No initialized accounts available")

    async def get_first_initialized_account(self) -> Optional[Account]:
        """
        Get the first initialized account, lazily initializing if needed.

        This is used by legacy single-account routes after account credentials
        are reloaded from admin APIs. Reloading rebuilds Account objects but does
        not perform network initialization, so request paths must initialize on
        demand instead of assuming startup state is still valid.

        Returns:
            First initialized account, or None if no account can be initialized.
        """
        async with self._lock:
            for account in self._accounts.values():
                if account.auth_manager is not None:
                    return account

            for account_id in list(self._accounts.keys()):
                success = await self._initialize_account(account_id)
                if success:
                    account = self._accounts.get(account_id)
                    if account and account.auth_manager is not None:
                        return account

            logger.warning("No initialized accounts available after lazy initialization")
            return None
    
    def get_all_available_models(self) -> List[str]:
        """
        Collect unique models from all initialized accounts.
        
        Used by /v1/models endpoint in account system to show
        all available models across all accounts.
        
        Returns:
            Sorted list of unique model IDs
        """
        all_models = set()
        for account in self._accounts.values():
            if account.model_resolver:
                all_models.update(account.model_resolver.get_available_models())
        return sorted(all_models)

    def get_credential_entries(self) -> List[Dict[str, Any]]:
        """
        Return sanitized credential configuration entries.

        Returns:
            List of credential entries with indexes and masked secrets.
        """
        return self._build_credential_entries(display_name_cache={})

    def get_account_snapshots(self) -> List[Dict[str, Any]]:
        """
        Return runtime account status snapshots for the admin console.

        Returns:
            List of account status dictionaries.
        """
        return self._build_account_snapshots(display_name_cache={})

    def resolve_account_display_name(self, account_id: str) -> str:
        """
        Resolve a runtime account ID to a human-readable display name.

        Args:
            account_id: Runtime account ID stored in request/account state.

        Returns:
            Best-effort account display name for logs and admin UI.
        """
        return self._resolve_runtime_account_display_name(account_id, display_name_cache={})

    def get_admin_accounts_payload(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Build the full admin account payload with shared display-name resolution.

        Returns:
            Dictionary containing credential entries and runtime account snapshots.
        """
        display_name_cache: Dict[Tuple[str, str], str] = {}
        return {
            "credentials": self._build_credential_entries(display_name_cache),
            "accounts": self._build_account_snapshots(display_name_cache),
        }

    def _build_credential_entries(
        self,
        display_name_cache: Dict[Tuple[str, str], str],
    ) -> List[Dict[str, Any]]:
        """
        Build sanitized credential entries for the admin console.

        Args:
            display_name_cache: Shared SQLite account display-name cache.

        Returns:
            List of credential entries with indexes and masked secrets.
        """
        return [
            self._sanitize_credential_entry(index, entry, display_name_cache)
            for index, entry in enumerate(self._credentials_config)
        ]

    def _build_account_snapshots(
        self,
        display_name_cache: Dict[Tuple[str, str], str],
    ) -> List[Dict[str, Any]]:
        """
        Build runtime account status snapshots for the admin console.

        Args:
            display_name_cache: Shared SQLite account display-name cache.

        Returns:
            List of account status dictionaries.
        """
        snapshots = []
        for account_id, account in self._accounts.items():
            auth_type = account.auth_manager.auth_type.value if account.auth_manager else None
            available_models = account.model_resolver.get_available_models() if account.model_resolver else []
            model_count = len(available_models)
            snapshots.append({
                "id": account_id,
                "display_name": self._resolve_runtime_account_display_name(account_id, display_name_cache),
                "initialized": account.auth_manager is not None,
                "auth_type": auth_type,
                "failures": account.failures,
                "last_failure_time": account.last_failure_time or None,
                "models_cached_at": account.models_cached_at or None,
                "models_count": model_count,
                "available_models": available_models,
                "stats": {
                    "total_requests": account.stats.total_requests,
                    "successful_requests": account.stats.successful_requests,
                    "failed_requests": account.stats.failed_requests,
                },
            })
        return snapshots

    async def add_credential_entry(self, entry: Dict[str, Any]) -> None:
        """
        Add or update a credential entry in SQLite and reload runtime accounts.

        Args:
            entry: Validated credential entry to persist.
        """
        async with self._lock:
            self._get_accounts_store().upsert_credential_entry(entry)
            await self._reload_credentials_from_storage_locked()
            self._dirty = True

    async def update_credential_enabled(self, index: int, enabled: bool) -> None:
        """
        Enable or disable a credential entry by index.

        Args:
            index: Credential entry index.
            enabled: Desired enabled state.

        Raises:
            ValueError: If the credential index is invalid.
        """
        async with self._lock:
            try:
                self._get_accounts_store().update_credential_entry_enabled(index, enabled)
            except ValueError as e:
                raise ValueError(str(e)) from e
            except (OSError, sqlite3.Error) as e:
                raise ValueError(str(e)) from e
            await self._reload_credentials_from_storage_locked()
            self._dirty = True

    async def delete_credential_entry(self, index: int) -> None:
        """
        Delete a credential entry by index and reload accounts.

        Args:
            index: Credential entry index.

        Raises:
            ValueError: If the credential index is invalid.
        """
        async with self._lock:
            try:
                self._get_accounts_store().delete_credential_entry(index)
            except ValueError as e:
                raise ValueError(str(e)) from e
            except (OSError, sqlite3.Error) as e:
                raise ValueError(str(e)) from e
            await self._reload_credentials_from_storage_locked()
            self._dirty = True

    async def initialize_account_now(self, account_id: str) -> bool:
        """
        Initialize a specific account immediately.

        Args:
            account_id: Runtime account ID.

        Returns:
            True if initialization succeeded, False otherwise.
        """
        async with self._lock:
            return await self._initialize_account(account_id)

    async def _reload_credentials_from_storage_locked(self) -> None:
        """
        Reload credentials and state while the caller holds the manager lock.
        """
        self._accounts = {}
        self._model_to_accounts = {}
        self._credentials_config = []
        await self.load_credentials()
        await self.load_state()

    def _validate_credential_index(self, index: int) -> None:
        """
        Validate a credential entry index.

        Args:
            index: Credential entry index.

        Raises:
            ValueError: If the index is outside the current credential list.
        """
        if index < 0 or index >= len(self._credentials_config):
            raise ValueError(f"Credential entry not found: index={index}")

    def _sanitize_credential_entry(
        self,
        index: int,
        entry: Dict[str, Any],
        display_name_cache: Dict[Tuple[str, str], str],
    ) -> Dict[str, Any]:
        """
        Build a secret-free credential entry for API responses.

        Args:
            index: Credential entry index.
            entry: Raw credential entry.
            display_name_cache: Shared SQLite account display-name cache.

        Returns:
            Sanitized credential entry.
        """
        sanitized = {
            "index": index,
            "type": entry.get("type"),
            "enabled": entry.get("enabled", True),
            "display_name": self._resolve_credential_entry_display_name(entry, display_name_cache),
            "path": entry.get("path"),
            "profile_arn": entry.get("profile_arn"),
            "region": entry.get("region"),
            "api_region": entry.get("api_region"),
        }
        if entry.get("refresh_token"):
            sanitized["refresh_token_preview"] = self._mask_secret(str(entry["refresh_token"]))
        if entry.get("account_id"):
            sanitized["account_id"] = entry.get("account_id")
        return sanitized

    @staticmethod
    def _build_refresh_token_account_id(refresh_token: str) -> str:
        """
        Build the stable runtime account ID for a refresh-token entry.

        Args:
            refresh_token: Raw refresh token string.

        Returns:
            Deterministic runtime account ID.
        """
        token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()[:16]
        return f"refresh_token_{token_hash}"

    def _resolve_credential_entry_display_name(
        self,
        entry: Dict[str, Any],
        display_name_cache: Optional[Dict[Tuple[str, str], str]] = None,
    ) -> str:
        """
        Resolve a human-readable display name for a credential entry.

        Args:
            entry: Raw credential entry from the SQLite credential registry.
            display_name_cache: Optional shared SQLite account display-name cache.

        Returns:
            Best-effort display name for the admin UI.
        """
        cred_type = str(entry.get("type") or "")
        path = str(entry.get("path") or "")
        account_id = str(entry.get("account_id") or "")

        if cred_type == "sqlite_account":
            return self._resolve_sqlite_account_display_name(
                path,
                account_id,
                fallback=account_id,
                display_name_cache=display_name_cache,
            )

        if cred_type == "refresh_token":
            refresh_token = str(entry.get("refresh_token") or "")
            fallback = str(entry.get("profile_arn") or self._build_refresh_token_account_id(refresh_token))
            return build_account_display_name(
                {
                    "refreshToken": refresh_token,
                    "profileArn": entry.get("profile_arn"),
                    "region": entry.get("region"),
                },
                fallback=fallback,
                profile_arn=str(entry.get("profile_arn") or "") or None,
            )

        return self._resolve_file_account_display_name(path, fallback=self._build_path_fallback_label(path))

    def _resolve_runtime_account_display_name(
        self,
        account_id: str,
        display_name_cache: Optional[Dict[Tuple[str, str], str]] = None,
    ) -> str:
        """
        Resolve a human-readable display name for a runtime account.

        Args:
            account_id: Runtime account ID.
            display_name_cache: Optional shared SQLite account display-name cache.

        Returns:
            Best-effort display name for the admin UI.
        """
        sqlite_account = self._parse_runtime_sqlite_account_id(account_id)
        if sqlite_account:
            path, sqlite_account_id = sqlite_account
            return self._resolve_sqlite_account_display_name(
                path,
                sqlite_account_id,
                fallback=sqlite_account_id,
                display_name_cache=display_name_cache,
            )

        if account_id.startswith("refresh_token_"):
            for entry in self._credentials_config:
                if entry.get("type") != "refresh_token":
                    continue
                refresh_token = str(entry.get("refresh_token") or "")
                if self._build_refresh_token_account_id(refresh_token) == account_id:
                    return self._resolve_credential_entry_display_name(entry)
            return account_id

        return self._resolve_file_account_display_name(account_id, fallback=self._build_path_fallback_label(account_id))

    def _resolve_file_account_display_name(self, path: str, fallback: str) -> str:
        """
        Resolve a display name from a JSON or SQLite credential file.

        Args:
            path: Credential file path.
            fallback: Fallback label.

        Returns:
            Best-effort display name.
        """
        json_token = self._load_json_token_data(path)
        if json_token is not None:
            return build_account_display_name(json_token, fallback=fallback)

        sqlite_token = self._load_external_sqlite_token_data(path)
        if sqlite_token is not None:
            return build_account_display_name(sqlite_token, fallback=fallback)

        return fallback

    @staticmethod
    def _build_sqlite_account_display_name_cache_key(path: str, account_id: str) -> Tuple[str, str]:
        """
        Build a stable cache key for SQLite account display-name resolution.

        Args:
            path: Gateway-managed SQLite database path.
            account_id: Stored SQLite row ID.

        Returns:
            Tuple cache key using normalized database path and account ID.
        """
        return (str(Path(path).expanduser()), account_id)

    def _resolve_sqlite_account_display_name(
        self,
        path: str,
        account_id: str,
        fallback: str,
        display_name_cache: Optional[Dict[Tuple[str, str], str]] = None,
    ) -> str:
        """
        Resolve a display name from a gateway-managed SQLite account row.

        Args:
            path: Gateway-managed SQLite database path.
            account_id: Stored SQLite row ID.
            fallback: Fallback label.
            display_name_cache: Optional shared SQLite account display-name cache.

        Returns:
            Best-effort display name.
        """
        cache_key = self._build_sqlite_account_display_name_cache_key(path, account_id)
        if display_name_cache is not None and cache_key in display_name_cache:
            return display_name_cache[cache_key]

        try:
            store = KiroAccountSqliteStore(cache_key[0])
            record = store.get_account(account_id)
        except (OSError, sqlite3.Error, ValueError) as e:
            logger.debug(f"Failed to resolve SQLite account display name: path={path}, account_id={account_id}, error={e}")
            return fallback

        if record is None:
            return fallback

        stored_remote_display_name = str(record.get("display_name") or "").strip()
        resolved_display_name = stored_remote_display_name or build_account_display_name(
            record["token"],
            fallback=fallback,
            stored_label=str(record.get("label") or "") or None,
            provider=str(record.get("provider") or "") or None,
            profile_arn=str(record.get("profile_arn") or "") or None,
        )
        if display_name_cache is not None:
            display_name_cache[cache_key] = resolved_display_name
        return resolved_display_name

    @staticmethod
    def _sqlite_account_row_exists(path: str, account_id: str) -> bool:
        """
        Check whether a gateway-managed SQLite account row exists.

        Args:
            path: Gateway-managed SQLite database path.
            account_id: Stored SQLite row ID.

        Returns:
            True when the database contains the requested account row.
        """
        try:
            store = KiroAccountSqliteStore(str(Path(path).expanduser()))
            return store.get_account(account_id) is not None
        except (OSError, sqlite3.Error, json.JSONDecodeError, ValueError) as e:
            logger.warning(
                "Failed to validate SQLite account credential: "
                f"account_id={account_id}, db={path}, error={e}"
            )
            return False

    def _prepare_sqlite_account_for_remote_lookup(
        self,
        store: KiroAccountSqliteStore,
        record: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare a SQLite account record for Kiro Web Portal lookups.

        Args:
            store: Gateway-managed SQLite account store.
            record: Current account record.

        Returns:
            Updated record after any best-effort token refresh or metadata bootstrap.
        """
        updated_record = record

        if self._sqlite_account_needs_token_refresh(updated_record):
            refreshed_record = self._refresh_sqlite_account_remote_tokens(store, updated_record)
            if refreshed_record is not None:
                updated_record = refreshed_record

        if not str(updated_record.get("csrf_token") or "").strip():
            bootstrapped_record = self._bootstrap_sqlite_account_remote_metadata(store, updated_record)
            if bootstrapped_record is not None:
                updated_record = bootstrapped_record

        return updated_record

    def _resolve_sqlite_account_remote_display_name(self, record: Dict[str, Any]) -> Optional[str]:
        """
        Resolve a display name from Kiro Web Portal user metadata.

        Args:
            record: Gateway-managed SQLite account record.

        Returns:
            Remote display name, or None when Web Portal lookup is unavailable.
        """
        token_data = record.get("token")
        if not isinstance(token_data, dict):
            return None

        access_token = str(
            token_data.get("accessToken")
            or token_data.get("access_token")
            or ""
        ).strip()
        csrf_token = str(record.get("csrf_token") or "").strip()
        if not access_token or not csrf_token:
            return None

        user_info = fetch_kiro_web_portal_user_info(
            access_token=access_token,
            csrf_token=csrf_token,
            user_id=self._extract_sqlite_account_web_user_id(record),
            provider=str(record.get("provider") or token_data.get("provider") or "").strip() or None,
        )
        if not user_info:
            return None
        return resolve_kiro_web_portal_display_name(user_info)

    @staticmethod
    def _sqlite_account_needs_token_refresh(record: Dict[str, Any]) -> bool:
        """
        Determine whether a SQLite account token should be refreshed before remote lookup.

        Args:
            record: Gateway-managed SQLite account record.

        Returns:
            True when the access token is missing or close to expiration.
        """
        token_data = record.get("token")
        if not isinstance(token_data, dict):
            return False
        return is_kiro_token_expiring_soon(token_data)

    def _refresh_sqlite_account_remote_tokens(
        self,
        store: KiroAccountSqliteStore,
        record: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """
        Refresh a SQLite account token before Web Portal metadata lookup.

        Args:
            store: Gateway-managed SQLite account store.
            record: Gateway-managed SQLite account record.

        Returns:
            Updated record, or None when refresh fails.
        """
        token_data = record.get("token")
        if not isinstance(token_data, dict):
            return None

        refreshed_token_data = refresh_kiro_account_tokens(
            token_data=token_data,
            registration_data=record.get("registration"),
        )
        if not refreshed_token_data:
            return None

        try:
            store.update_runtime_tokens(
                account_id=str(record["id"]),
                access_token=str(refreshed_token_data["access_token"]),
                refresh_token=str(refreshed_token_data["refresh_token"]),
                expires_at=refreshed_token_data["expires_at"],
                profile_arn=str(refreshed_token_data.get("profile_arn") or "") or None,
                csrf_token=str(record.get("csrf_token") or "") or None,
            )
            updated_record = store.get_account(str(record["id"]))
        except (OSError, sqlite3.Error, ValueError) as e:
            logger.debug(
                "Failed to persist refreshed SQLite account tokens for Web Portal lookup: "
                f"account_id={record.get('id')}, error={e}"
            )
            return None

        if updated_record is None:
            return None
        logger.debug(f"Refreshed SQLite account token before Web Portal lookup: account_id={record.get('id')}")
        return updated_record

    def _bootstrap_sqlite_account_remote_metadata(
        self,
        store: KiroAccountSqliteStore,
        record: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """
        Bootstrap missing Web Portal metadata for a SQLite account.

        Args:
            store: Gateway-managed SQLite account store.
            record: Gateway-managed SQLite account record.

        Returns:
            Updated record, or None when metadata bootstrap fails.
        """
        token_data = record.get("token")
        if not isinstance(token_data, dict):
            return None

        access_token = str(token_data.get("accessToken") or token_data.get("access_token") or "").strip()
        refresh_token = str(token_data.get("refreshToken") or token_data.get("refresh_token") or "").strip()
        if not access_token:
            return None

        metadata = fetch_kiro_web_portal_session_metadata(
            access_token=access_token,
            refresh_token=refresh_token or None,
            user_id=self._extract_sqlite_account_web_user_id(record),
            provider=str(record.get("provider") or token_data.get("provider") or "").strip() or None,
        )
        if not metadata:
            return None

        updated_token_data = dict(token_data)
        metadata_user_id = str(metadata.get("user_id") or "").strip()
        metadata_profile_arn = str(metadata.get("profile_arn") or "").strip()
        metadata_provider = str(metadata.get("provider") or "").strip()
        if metadata_user_id:
            updated_token_data["userId"] = metadata_user_id
        if metadata_profile_arn:
            updated_token_data["profileArn"] = metadata_profile_arn
        if metadata_provider and not updated_token_data.get("provider"):
            updated_token_data["provider"] = metadata_provider

        try:
            store.upsert_token(
                token=updated_token_data,
                registration=record.get("registration"),
                label=str(record.get("label") or "") or None,
                enabled=bool(record.get("enabled", True)),
                account_id=str(record["id"]),
                api_region=str(record.get("api_region") or "") or None,
                csrf_token=str(metadata.get("csrf_token") or record.get("csrf_token") or "") or None,
            )
            updated_record = store.get_account(str(record["id"]))
        except (OSError, sqlite3.Error, ValueError) as e:
            logger.debug(
                "Failed to persist bootstrapped Web Portal metadata: "
                f"account_id={record.get('id')}, error={e}"
            )
            return None

        if updated_record is None:
            return None
        logger.debug(f"Bootstrapped Web Portal metadata for SQLite account: account_id={record.get('id')}")
        return updated_record

    @staticmethod
    def _extract_sqlite_account_web_user_id(record: Dict[str, Any]) -> Optional[str]:
        """
        Extract a previously known Kiro Web Portal user ID from an account record.

        Args:
            record: Gateway-managed SQLite account record.

        Returns:
            User ID string, or None when unavailable.
        """
        token_data = record.get("token")
        if not isinstance(token_data, dict):
            return None

        for field_name in ("userId", "user_id"):
            value = token_data.get(field_name)
            if value is not None:
                normalized_value = str(value).strip()
                if normalized_value:
                    return normalized_value
        return None

    def _load_json_token_data(self, path: str) -> Optional[Dict[str, Any]]:
        """
        Load token-like data from a JSON credential file.

        Args:
            path: JSON credential path.

        Returns:
            Parsed token mapping, or None when the path is not a valid JSON token file.
        """
        candidate_path = Path(path).expanduser()
        if not candidate_path.is_file():
            return None

        try:
            with open(candidate_path, "r", encoding="utf-8") as f:
                token_data = json.load(f)
        except (OSError, json.JSONDecodeError):
            return None

        if isinstance(token_data, dict):
            return token_data
        return None

    def _load_external_sqlite_token_data(self, path: str) -> Optional[Dict[str, Any]]:
        """
        Load token-like data from a kiro-cli or Amazon Q SQLite database.

        Args:
            path: SQLite database path.

        Returns:
            Parsed token mapping, or None when no token row is available.
        """
        candidate_path = Path(path).expanduser()
        if not candidate_path.is_file():
            return None

        try:
            with sqlite3.connect(str(candidate_path)) as conn:
                cursor = conn.cursor()
                for key in SQLITE_TOKEN_KEYS:
                    cursor.execute("SELECT value FROM auth_kv WHERE key = ?", (key,))
                    row = cursor.fetchone()
                    if not row:
                        continue
                    token_data = json.loads(row[0])
                    if isinstance(token_data, dict):
                        return token_data
                    return None
        except (sqlite3.Error, json.JSONDecodeError, TypeError, ValueError):
            return None

        return None

    @staticmethod
    def _parse_runtime_sqlite_account_id(runtime_account_id: str) -> Optional[tuple[str, str]]:
        """
        Parse a runtime SQLite account ID into database path and row ID.

        Args:
            runtime_account_id: Runtime account ID string.

        Returns:
            Tuple of database path and row ID, or None when the ID is not a SQLite-account runtime ID.
        """
        prefix = "sqlite_account:"
        if not runtime_account_id.startswith(prefix):
            return None

        payload = runtime_account_id[len(prefix):]
        if "#" not in payload:
            return None

        path, account_id = payload.rsplit("#", 1)
        return path, account_id

    @staticmethod
    def _build_path_fallback_label(path: str) -> str:
        """
        Build a fallback display label from a filesystem path.

        Args:
            path: Filesystem path string.

        Returns:
            Basename-derived fallback label.
        """
        if not path:
            return "Account"

        candidate_path = Path(path).expanduser()
        if candidate_path.name:
            return candidate_path.stem or candidate_path.name
        return path

    @staticmethod
    def _runtime_id_for_sqlite_account(path: str, account_id: str) -> str:
        """
        Build a runtime account ID for a row in the gateway-managed account DB.

        Args:
            path: SQLite account database path.
            account_id: Account row ID.

        Returns:
            Stable runtime account ID.
        """
        resolved_path = Path(path).expanduser().resolve()
        return f"sqlite_account:{resolved_path}#{account_id}"

    @staticmethod
    def _mask_secret(secret: str) -> str:
        """
        Mask a secret while preserving enough characters for identification.

        Args:
            secret: Secret value.

        Returns:
            Masked secret preview.
        """
        if len(secret) <= 8:
            return "*" * len(secret)
        return f"{secret[:4]}...{secret[-4:]}"
