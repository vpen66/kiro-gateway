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
Admin console routes for Kiro Gateway.

The admin console exposes browser-friendly management APIs for accounts,
generated API keys, request logs, and read-only system settings.
"""

import platform
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Security
from fastapi.responses import FileResponse
from fastapi.security import APIKeyHeader
from loguru import logger
from pydantic import BaseModel, Field

import kiro.config as config
from kiro.account_sqlite_store import KiroAccountSqliteStore, KiroAccountSqliteStoreError
from kiro.api_key_store import extract_strict_bearer_token, get_api_key_store
from kiro.oauth_kiro import get_kiro_oauth_service
from kiro.request_log import get_request_log_store
from kiro.runtime_settings import (
    get_runtime_settings,
    get_runtime_settings_metadata,
    get_runtime_settings_overrides,
    update_runtime_settings,
)


ADMIN_STATIC_DIR = Path(__file__).parent / "static" / "admin"
OAUTH_PROVIDERS = {
    "kiro-ide": {
        "command": None,
        "credential_type": "sqlite_account",
        "default_path": config.KIRO_OAUTH_DB_FILE,
        "label": "Kiro IDE",
        "start_message": (
            "Open the generated Kiro IDE browser sign-in URL. "
            "Social logins complete directly; IdC logins continue with AWS SSO. "
            "The resulting account is stored in the gateway SQLite account database."
        ),
    },
    "kiro-cli": {
        "command": ["kiro-cli", "login"],
        "credential_type": "sqlite",
        "default_path": "~/.local/share/kiro-cli/data.sqlite3",
        "label": "Kiro CLI",
        "start_message": "Complete the OAuth flow in the browser, then import the detected SQLite database.",
    },
    "amazon-q": {
        "command": ["q", "login"],
        "credential_type": "sqlite",
        "default_path": "~/.local/share/amazon-q/data.sqlite3",
        "label": "Amazon Q Developer CLI",
        "start_message": "Complete the OAuth flow in the browser, then import the detected SQLite database.",
    },
}


admin_api_key_header = APIKeyHeader(name="Authorization", auto_error=False)


async def verify_admin_api_key(
    auth_header: str = Security(admin_api_key_header),
    request: Request = None,
) -> bool:
    """
    Verify an admin-scoped API key.

    Args:
        auth_header: Authorization header value.
        request: FastAPI request object.

    Returns:
        True when authentication succeeds.

    Raises:
        HTTPException: If the key is missing, invalid, or lacks admin scope.
    """
    token = extract_strict_bearer_token(auth_header)
    if not token:
        logger.warning("Admin access attempt with missing or malformed API key")
        raise HTTPException(status_code=401, detail="Invalid or missing admin API key")

    validation = get_api_key_store().verify_key(token, required_scope="admin")
    if not validation.valid:
        logger.warning("Admin access attempt with invalid API key")
        raise HTTPException(status_code=401, detail="Invalid or missing admin API key")

    if request is not None:
        request.state.api_key_id = validation.key_id
        request.state.api_key_name = validation.name
    return True


class AccountCreateRequest(BaseModel):
    """Request body for adding an account credential entry."""

    type: str = Field(..., description="Credential type: json, sqlite, sqlite_account, or refresh_token")
    path: Optional[str] = Field(None, description="Path for json, sqlite, or sqlite_account credentials")
    account_id: Optional[str] = Field(None, description="Account row ID for sqlite_account credentials")
    refresh_token: Optional[str] = Field(None, description="Refresh token for refresh_token credentials")
    profile_arn: Optional[str] = None
    region: Optional[str] = "us-east-1"
    api_region: Optional[str] = None
    enabled: bool = True


class CredentialEnabledRequest(BaseModel):
    """Request body for enabling or disabling a credential entry."""

    enabled: bool


class OAuthStartRequest(BaseModel):
    """Request body for starting browser-assisted OAuth via a local CLI."""

    provider: str = Field("kiro-ide", description="OAuth provider adapter: kiro-ide, kiro-cli, or amazon-q")
    credential_path: Optional[str] = None
    database_path: Optional[str] = None
    region: Optional[str] = None


class OAuthImportRequest(BaseModel):
    """Request body for importing a CLI OAuth SQLite database."""

    provider: str = Field("kiro-ide", description="OAuth provider adapter: kiro-ide, kiro-cli, or amazon-q")
    database_path: Optional[str] = None
    credential_path: Optional[str] = None
    account_id: Optional[str] = None
    region: Optional[str] = "us-east-1"
    api_region: Optional[str] = None
    enabled: bool = True


class OAuthManualCallbackRequest(BaseModel):
    """Request body for a manually pasted Kiro OAuth callback URL."""

    callback_url: str = Field(..., min_length=1)


class ApiKeyCreateRequest(BaseModel):
    """Request body for generating a new API key."""

    name: str = Field(..., min_length=1, max_length=120)
    scopes: List[str] = Field(default_factory=lambda: ["api"])


class ApiKeyEnabledRequest(BaseModel):
    """Request body for enabling or disabling a generated API key."""

    enabled: bool


def _open_incognito_browser(url: str) -> bool:
    """Try to open url in an incognito/private browser window. Returns True on success."""
    system = platform.system()

    if system == "Darwin":
        candidates = [
            (["open", "-na", "Google Chrome", "--args", "--incognito", url], True),
            (["open", "-na", "Brave Browser", "--args", "--incognito", url], True),
            (["open", "-na", "Microsoft Edge", "--args", "--inprivate", url], True),
            (["open", "-na", "Firefox", "--args", "--private-window", url], True),
        ]
    elif system == "Linux":
        candidates = []
        for browser, flag in [
            ("google-chrome", "--incognito"),
            ("google-chrome-stable", "--incognito"),
            ("chromium-browser", "--incognito"),
            ("chromium", "--incognito"),
            ("brave-browser", "--incognito"),
            ("microsoft-edge", "--inprivate"),
            ("firefox", "--private-window"),
        ]:
            exe = shutil.which(browser)
            if exe:
                candidates.append(([exe, flag, url], False))
    else:
        candidates = []
        for browser, flag in [
            ("chrome", "--incognito"),
            ("msedge", "--inprivate"),
            ("firefox", "--private-window"),
        ]:
            exe = shutil.which(browser)
            if exe:
                candidates.append(([exe, flag, url], False))

    for cmd, use_popen_directly in candidates:
        try:
            if use_popen_directly:
                subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            else:
                subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            logger.info(f"Opened incognito browser: {' '.join(cmd[:3])}")
            return True
        except OSError:
            continue

    return False


router = APIRouter(tags=["Admin Console"])


@router.get("/admin", include_in_schema=False)
@router.get("/admin/", include_in_schema=False)
async def admin_console() -> FileResponse:
    """
    Serve the browser admin console.

    Returns:
        Admin console HTML file.
    """
    index_file = ADMIN_STATIC_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="Admin console static file is missing")
    return FileResponse(index_file)


@router.get("/admin/api/accounts", dependencies=[Depends(verify_admin_api_key)])
async def list_accounts(request: Request) -> Dict[str, Any]:
    """
    List credential entries and runtime account status.

    Args:
        request: FastAPI request object.

    Returns:
        Account management payload.
    """
    manager = _get_account_manager(request)
    return manager.get_admin_accounts_payload()


@router.get("/admin/api/usage-snapshots", dependencies=[Depends(verify_admin_api_key)])
async def list_usage_snapshots(
    request: Request,
    limit: int = 50,
    latest_only: bool = True,
) -> Dict[str, Any]:
    """
    List persisted usage-limit snapshots for the admin console.

    Args:
        request: FastAPI request object.
        limit: Maximum number of rows to return.
        latest_only: When true, return only the newest row per account/resource.

    Returns:
        Usage snapshot payload.
    """
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 500")

    manager = _get_account_manager(request)
    entries = []
    for account in manager.get_account_snapshots():
        if (
            account.get("current_usage_with_precision") is None
            and account.get("usage_limit_with_precision") is None
            and not account.get("subscription_title")
        ):
            continue
        entries.append({
            "account_id": account.get("id"),
            "account_display_name": account.get("display_name"),
            "subscription_title": account.get("subscription_title"),
            "resource_type": account.get("resource_type"),
            "display_name": account.get("usage_display_name"),
            "display_name_plural": account.get("usage_display_name_plural"),
            "current_usage_with_precision": account.get("current_usage_with_precision"),
            "usage_limit_with_precision": account.get("usage_limit_with_precision"),
            "next_date_reset": account.get("usage_next_date_reset"),
            "captured_at": account.get("usage_updated_at"),
        })
    entries = entries[:limit]
    return {"entries": entries, "latest_only": latest_only}


@router.post("/admin/api/accounts", dependencies=[Depends(verify_admin_api_key)])
async def add_account(request: Request, request_data: AccountCreateRequest) -> Dict[str, Any]:
    """
    Add an account credential entry.

    Args:
        request: FastAPI request object.
        request_data: Account credential request.

    Returns:
        Updated account list.
    """
    manager = _get_account_manager(request)
    entry = _build_credential_entry(request_data)
    await manager.add_credential_entry(entry)
    logger.info(f"Admin added account credential entry: type={entry['type']}")
    return await list_accounts(request)


@router.patch("/admin/api/accounts/{index}", dependencies=[Depends(verify_admin_api_key)])
async def set_account_enabled(
    index: int,
    request: Request,
    request_data: CredentialEnabledRequest,
) -> Dict[str, Any]:
    """
    Enable or disable an account credential entry.

    Args:
        index: Credential entry index.
        request: FastAPI request object.
        request_data: Enabled state payload.

    Returns:
        Updated account list.
    """
    manager = _get_account_manager(request)
    try:
        await manager.update_credential_enabled(index, request_data.enabled)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    return await list_accounts(request)


@router.delete("/admin/api/accounts/{index}", dependencies=[Depends(verify_admin_api_key)])
async def delete_account(index: int, request: Request) -> Dict[str, Any]:
    """
    Delete an account credential entry.

    Args:
        index: Credential entry index.
        request: FastAPI request object.

    Returns:
        Updated account list.
    """
    manager = _get_account_manager(request)
    try:
        await manager.delete_credential_entry(index)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    return await list_accounts(request)


@router.post("/admin/api/accounts/oauth/start", dependencies=[Depends(verify_admin_api_key)])
async def start_oauth_login(request_data: OAuthStartRequest) -> Dict[str, Any]:
    """
    Start a browser-assisted OAuth login via a local CLI.

    Args:
        request_data: OAuth provider selection.

    Returns:
        Process and import guidance.
    """
    provider = _get_oauth_provider(request_data.provider)
    command = provider["command"]
    raw_path = request_data.database_path or request_data.credential_path or provider["default_path"]
    credential_path = str(Path(raw_path).expanduser())

    if command is None:
        oauth_status = await get_kiro_oauth_service().start(
            region=request_data.region or config.REGION,
            database_path=credential_path,
        )
        logger.info(f"Started browser Kiro IDE OAuth flow: provider={request_data.provider}")
        incognito_opened = False
        if oauth_status.get("authorization_url"):
            incognito_opened = _open_incognito_browser(oauth_status["authorization_url"])
        return {
            "provider": request_data.provider,
            "pid": None,
            "command": None,
            "credential_type": provider["credential_type"],
            "credential_path": None,
            "database_path": oauth_status["database_path"],
            "account_id": oauth_status["account_id"],
            "authorization_url": oauth_status["authorization_url"],
            "callback_url": oauth_status["callback_url"],
            "status": oauth_status["status"],
            "message": provider["start_message"],
            "incognito_opened": incognito_opened,
        }

    executable = shutil.which(command[0])
    if not executable:
        raise HTTPException(
            status_code=404,
            detail=f"{provider['label']} command not found. Install it on the server, then try again.",
        )

    try:
        process = subprocess.Popen(
            [executable, *command[1:]],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as e:
        logger.error(f"Failed to start OAuth login command: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to start OAuth login: {e}") from e

    logger.info(f"Started browser-assisted OAuth login: provider={request_data.provider}, pid={process.pid}")
    return {
        "provider": request_data.provider,
        "pid": process.pid,
        "command": " ".join(command),
        "credential_type": provider["credential_type"],
        "credential_path": credential_path,
        "database_path": credential_path,
        "message": provider["start_message"],
    }


@router.get("/admin/api/accounts/oauth/status", dependencies=[Depends(verify_admin_api_key)])
async def oauth_login_status() -> Dict[str, Any]:
    """
    Return status for the current Kiro browser OAuth flow.

    Returns:
        OAuth status payload.
    """
    return get_kiro_oauth_service().status()


@router.post("/admin/api/accounts/oauth/manual-callback", dependencies=[Depends(verify_admin_api_key)])
async def manual_oauth_callback(request_data: OAuthManualCallbackRequest) -> Dict[str, Any]:
    """
    Process a manually pasted Kiro OAuth callback URL.

    Args:
        request_data: Callback URL payload.

    Returns:
        OAuth status payload.
    """
    return await get_kiro_oauth_service().manual_callback(request_data.callback_url)


@router.post("/admin/api/accounts/oauth/cancel", dependencies=[Depends(verify_admin_api_key)])
async def cancel_oauth_login() -> Dict[str, Any]:
    """
    Cancel the current Kiro browser OAuth flow.

    Returns:
        OAuth status payload.
    """
    return await get_kiro_oauth_service().cancel()


class OAuthOpenBrowserRequest(BaseModel):
    """Request body for opening a URL in an incognito browser window."""

    url: str = Field(..., min_length=1)


@router.post("/admin/api/accounts/oauth/open-browser", dependencies=[Depends(verify_admin_api_key)])
async def open_browser_incognito(request_data: OAuthOpenBrowserRequest) -> Dict[str, Any]:
    """
    Open a URL in an incognito browser window on the server host.

    Returns:
        Whether the incognito window was successfully opened.
    """
    opened = _open_incognito_browser(request_data.url)
    return {"incognito_opened": opened}


@router.post("/admin/api/accounts/oauth/import", dependencies=[Depends(verify_admin_api_key)])
async def import_oauth_account(request: Request, request_data: OAuthImportRequest) -> Dict[str, Any]:
    """
    Import a CLI OAuth SQLite database as an account.

    Args:
        request: FastAPI request object.
        request_data: OAuth import request.

    Returns:
        Updated account list.
    """
    provider = _get_oauth_provider(request_data.provider)

    if provider["credential_type"] == "sqlite_account":
        entry = _build_kiro_ide_sqlite_import_entry(provider, request_data)
    else:
        raw_path = request_data.database_path or request_data.credential_path or provider["default_path"]
        credential_path = Path(raw_path).expanduser()
        if not credential_path.exists():
            raise HTTPException(
                status_code=404,
                detail=f"OAuth database not found at {credential_path}. Complete browser login first.",
            )

        entry = {
            "type": provider["credential_type"],
            "path": str(credential_path),
            "enabled": request_data.enabled,
        }

    if request_data.region:
        entry["region"] = request_data.region
    if request_data.api_region:
        entry["api_region"] = request_data.api_region

    manager = _get_account_manager(request)
    await manager.add_credential_entry(entry)
    logger.info(f"Imported OAuth account: provider={request_data.provider}, type={entry['type']}")
    return await list_accounts(request)


@router.get("/admin/api/api-keys", dependencies=[Depends(verify_admin_api_key)])
async def list_api_keys() -> Dict[str, Any]:
    """
    List generated API keys and the environment key metadata.

    Returns:
        API key list.
    """
    return {"keys": get_api_key_store().list_keys(include_env_key=True)}


@router.post("/admin/api/api-keys", dependencies=[Depends(verify_admin_api_key)])
async def create_api_key(request_data: ApiKeyCreateRequest) -> Dict[str, Any]:
    """
    Generate a new API key.

    Args:
        request_data: Key name and scopes.

    Returns:
        Plaintext key once and public metadata.
    """
    try:
        plaintext, record = get_api_key_store().create_key(request_data.name, request_data.scopes)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    return {
        "key": plaintext,
        "record": record,
        "message": "Store this key now. It will not be shown again.",
    }


@router.patch("/admin/api/api-keys/{key_id}", dependencies=[Depends(verify_admin_api_key)])
async def set_api_key_enabled(key_id: str, request_data: ApiKeyEnabledRequest) -> Dict[str, Any]:
    """
    Enable or disable a generated API key.

    Args:
        key_id: Generated key ID.
        request_data: Enabled state payload.

    Returns:
        Updated key metadata.
    """
    try:
        record = get_api_key_store().set_enabled(key_id, request_data.enabled)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    return {"record": record}


@router.delete("/admin/api/api-keys/{key_id}", dependencies=[Depends(verify_admin_api_key)])
async def delete_api_key(key_id: str) -> Dict[str, str]:
    """
    Delete a generated API key.

    Args:
        key_id: Generated key ID.

    Returns:
        Deletion status.
    """
    try:
        get_api_key_store().delete_key(key_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    return {"status": "deleted"}


@router.get("/admin/api/request-logs", dependencies=[Depends(verify_admin_api_key)])
async def list_request_logs(limit: int = 100) -> Dict[str, Any]:
    """
    List request logs.

    Args:
        limit: Maximum entries to return.

    Returns:
        Request log entries.
    """
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 500")
    entries = get_request_log_store().list_entries(limit=limit)
    return {"entries": entries}


@router.delete("/admin/api/request-logs", dependencies=[Depends(verify_admin_api_key)])
async def clear_request_logs() -> Dict[str, str]:
    """
    Clear request logs.

    Returns:
        Clear status.
    """
    get_request_log_store().clear()
    return {"status": "cleared"}


@router.get("/admin/api/settings", dependencies=[Depends(verify_admin_api_key)])
async def get_settings(request: Request) -> Dict[str, Any]:
    """
    Return read-only system settings for the admin console.

    Args:
        request: FastAPI request object.

    Returns:
        Safe system settings.
    """
    return _build_settings_payload(request)


@router.patch("/admin/api/settings", dependencies=[Depends(verify_admin_api_key)])
async def patch_settings(request: Request, request_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Update runtime-overridable settings persisted in SQLite.

    Args:
        request: FastAPI request object.
        request_data: Partial runtime settings update payload.

    Returns:
        Effective settings payload after the update.

    Raises:
        HTTPException: If the payload is invalid.
    """
    try:
        update_runtime_settings(request_data)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return _build_settings_payload(request)


def _get_account_manager(request: Request) -> Any:
    """
    Get AccountManager from application state.

    Args:
        request: FastAPI request object.

    Returns:
        AccountManager instance.

    Raises:
        HTTPException: If account manager is not initialized.
    """
    manager = getattr(request.app.state, "account_manager", None)
    if manager is None:
        raise HTTPException(status_code=503, detail="Account manager is not initialized")
    return manager


def _build_settings_payload(request: Request) -> Dict[str, Any]:
    """
    Build the admin settings payload.

    Args:
        request: FastAPI request object.

    Returns:
        Serialized settings payload for the admin console.
    """
    manager = _get_account_manager(request)
    return {
        "version": config.APP_VERSION,
        "editable_settings": get_runtime_settings(),
        "editable_metadata": get_runtime_settings_metadata(),
        "runtime_overrides": get_runtime_settings_overrides(),
        "readonly_settings": {
            "account_system": config.ACCOUNT_SYSTEM,
            "accounts_state_file": config.ACCOUNTS_STATE_FILE,
            "kiro_accounts_db_file": config.KIRO_ACCOUNTS_DB_FILE,
            "kiro_oauth_db_file": config.KIRO_OAUTH_DB_FILE,
            "kiro_oauth_token_file_legacy": config.KIRO_OAUTH_TOKEN_FILE,
            "api_keys_file": config.API_KEYS_FILE,
            "request_log_file": config.REQUEST_LOG_FILE,
            "request_log_max_entries": config.REQUEST_LOG_MAX_ENTRIES,
            "debug_mode": config.DEBUG_MODE,
            "debug_dir": config.DEBUG_DIR,
            "fake_reasoning_enabled": config.FAKE_REASONING_ENABLED,
            "proxy_api_key_configured": bool(config.PROXY_API_KEY),
            "credentials_count": len(manager.get_credential_entries()),
            "runtime_accounts_count": len(manager.get_account_snapshots()),
        },
    }


def _build_credential_entry(request_data: AccountCreateRequest) -> Dict[str, Any]:
    """
    Validate and build a credential entry.

    Args:
        request_data: Account create request.

    Returns:
        Credential entry suitable for the SQLite credential registry.

    Raises:
        HTTPException: If the entry is invalid.
    """
    cred_type = request_data.type.strip()
    if cred_type not in {"json", "sqlite", "sqlite_account", "refresh_token"}:
        raise HTTPException(status_code=400, detail="type must be one of: json, sqlite, sqlite_account, refresh_token")

    entry: Dict[str, Any] = {
        "type": cred_type,
        "enabled": request_data.enabled,
    }

    if cred_type in {"json", "sqlite", "sqlite_account"}:
        resolved_path = request_data.path
        if cred_type == "sqlite_account" and (resolved_path is None or not resolved_path.strip()):
            resolved_path = config.KIRO_ACCOUNTS_DB_FILE
        if not resolved_path or not resolved_path.strip():
            raise HTTPException(status_code=400, detail=f"path is required for {cred_type} credentials")
        credential_path = Path(resolved_path).expanduser()
        if not credential_path.exists():
            raise HTTPException(status_code=400, detail=f"Credential path does not exist: {credential_path}")
        entry["path"] = str(credential_path)
        if cred_type == "sqlite_account":
            if not request_data.account_id or not request_data.account_id.strip():
                raise HTTPException(status_code=400, detail="account_id is required for sqlite_account credentials")
            account_id = request_data.account_id.strip()
            if KiroAccountSqliteStore(str(credential_path)).get_account(account_id) is None:
                raise HTTPException(status_code=400, detail=f"SQLite account ID does not exist: {account_id}")
            entry["account_id"] = account_id
    else:
        if not request_data.refresh_token or not request_data.refresh_token.strip():
            raise HTTPException(status_code=400, detail="refresh_token is required for refresh_token credentials")
        entry["refresh_token"] = request_data.refresh_token.strip()

    optional_values = {
        "profile_arn": request_data.profile_arn,
        "region": request_data.region,
        "api_region": request_data.api_region,
    }
    for key, value in optional_values.items():
        if value and value.strip():
            entry[key] = value.strip()

    return entry


def _build_kiro_ide_sqlite_import_entry(
    provider: Dict[str, Any],
    request_data: OAuthImportRequest,
) -> Dict[str, Any]:
    """
    Build a credential entry for a Kiro IDE account stored in SQLite.

    Args:
        provider: Kiro IDE OAuth provider metadata.
        request_data: OAuth import request.

    Returns:
        sqlite_account credential entry.

    Raises:
        HTTPException: If no account can be imported.
    """
    json_import_path = _resolve_legacy_json_import_path(request_data)
    database_path = _resolve_kiro_account_database_path(provider, request_data, json_import_path)
    store = KiroAccountSqliteStore(str(database_path))

    if json_import_path is not None:
        if not json_import_path.exists():
            raise HTTPException(
                status_code=404,
                detail=f"Kiro IDE credentials file not found at {json_import_path}.",
            )
        try:
            record = store.import_json_token(
                token_path=str(json_import_path),
                enabled=request_data.enabled,
                api_region=request_data.api_region,
            )
        except (KiroAccountSqliteStoreError, OSError, ValueError) as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
    else:
        if not database_path.exists():
            raise HTTPException(
                status_code=404,
                detail=f"Kiro account database not found at {database_path}. Complete browser login first.",
            )
        account_id = request_data.account_id or get_kiro_oauth_service().status().get("account_id")
        if not account_id:
            account_id = store.latest_account_id()
        if not account_id:
            raise HTTPException(
                status_code=404,
                detail=f"No Kiro IDE OAuth accounts found in {database_path}. Complete browser login first.",
            )
        record = store.get_account(str(account_id))
        if record is None:
            raise HTTPException(
                status_code=404,
                detail=f"Kiro IDE OAuth account not found in {database_path}: {account_id}",
            )

    return {
        "type": "sqlite_account",
        "path": str(database_path),
        "account_id": record["id"],
        "enabled": request_data.enabled,
    }


def _resolve_legacy_json_import_path(request_data: OAuthImportRequest) -> Optional[Path]:
    """
    Resolve a legacy Kiro IDE JSON import path from an OAuth import request.

    Args:
        request_data: OAuth import request.

    Returns:
        JSON path when the caller supplied one, otherwise None.
    """
    if not request_data.credential_path:
        return None
    candidate = Path(request_data.credential_path).expanduser()
    if candidate.suffix.lower() == ".json":
        return candidate
    return None


def _resolve_kiro_account_database_path(
    provider: Dict[str, Any],
    request_data: OAuthImportRequest,
    json_import_path: Optional[Path],
) -> Path:
    """
    Resolve the gateway-managed Kiro account database path.

    Args:
        provider: Kiro IDE OAuth provider metadata.
        request_data: OAuth import request.
        json_import_path: Legacy JSON import path, if any.

    Returns:
        SQLite database path.
    """
    if request_data.database_path:
        return Path(request_data.database_path).expanduser()
    if request_data.credential_path and json_import_path is None:
        return Path(request_data.credential_path).expanduser()
    return Path(provider["default_path"]).expanduser()


def _get_oauth_provider(provider_name: str) -> Dict[str, Any]:
    """
    Resolve an OAuth provider adapter.

    Args:
        provider_name: Provider adapter name.

    Returns:
        Provider metadata.

    Raises:
        HTTPException: If the provider is unsupported.
    """
    provider = OAUTH_PROVIDERS.get(provider_name)
    if not provider:
        raise HTTPException(status_code=400, detail="provider must be one of: kiro-ide, kiro-cli, amazon-q")
    return provider
