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
Kiro IDE-compatible browser OAuth flow.

This module mirrors the Kiro IDE portal flow:
1. Generate a PKCE verifier/challenge and CSRF state.
2. Start a localhost callback listener on the Kiro IDE port set.
3. Build https://app.kiro.dev/signin?... with redirect_from=KiroIDE.
4. Exchange social-login codes directly, or run the Kiro IDE second-stage IdC flow.
5. Persist the result into the gateway-managed multi-account SQLite database.
"""

import asyncio
import base64
import hashlib
import json
import secrets
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse

import httpx
from loguru import logger

import kiro.config as config
from kiro.account_sqlite_store import KiroAccountSqliteStore, KiroAccountSqliteStoreError
from kiro.utils import get_machine_fingerprint


CALLBACK_PATHS = frozenset({"/oauth/callback", "/signin/callback"})
SOCIAL_LOGIN_OPTIONS = {
    "google": "Google",
    "github": "Github",
}
IDC_LOGIN_OPTIONS = {
    "builderid": ("BuilderId", "https://view.awsapps.com/start"),
    "internal": ("Internal", "https://amzn.awsapps.com/start"),
}
IDC_GRANT_SCOPES = [
    "codewhisperer:completions",
    "codewhisperer:analysis",
    "codewhisperer:conversations",
    "codewhisperer:transformations",
    "codewhisperer:taskassist",
]
IDC_REGISTER_REDIRECT_URI = "http://127.0.0.1/oauth/callback"


class KiroOAuthError(Exception):
    """
    Error raised when the Kiro browser OAuth flow cannot continue.

    Args:
        message: User-facing error message.
    """

    def __init__(self, message: str):
        """Initialize the OAuth error."""
        super().__init__(message)
        self.message = message


@dataclass
class KiroOAuthCallback:
    """
    Callback data returned by the Kiro auth portal.

    Attributes:
        login_option: Portal login option, such as google, github, or builderid.
        code: Authorization code for social login options.
        state: CSRF state returned by the portal.
        path: Callback path used by the portal.
        issuer_url: IdC issuer URL for non-social flows.
        idc_region: IdC region for non-social flows.
        client_id: External IdP client ID.
        scopes: External IdP scopes.
        login_hint: External IdP login hint.
        audience: External IdP audience.
    """

    login_option: str
    code: Optional[str]
    state: Optional[str]
    path: str
    issuer_url: Optional[str] = None
    idc_region: Optional[str] = None
    client_id: Optional[str] = None
    scopes: Optional[str] = None
    login_hint: Optional[str] = None
    audience: Optional[str] = None


@dataclass
class KiroOAuthState:
    """
    Current browser OAuth flow state.

    Attributes:
        status: idle, pending, success, or error.
        state_token: CSRF state token.
        code_verifier: PKCE code verifier.
        authorization_url: Portal URL to open.
        callback_url: Local redirect URI root.
        database_path: Gateway-managed account database path written after success.
        account_id: Stored account ID after success.
        error_message: Last error message.
        login_option: Login option used by the callback.
        server: Active callback server.
        idc_state_token: CSRF state token for second-stage IdC auth.
        idc_code_verifier: PKCE verifier for second-stage IdC auth.
        idc_client_id: AWS SSO OIDC client ID.
        idc_client_secret: AWS SSO OIDC client secret.
        idc_client_id_hash: Kiro IDE client registration cache key.
        idc_provider: Kiro IdC provider label.
        idc_region: AWS SSO OIDC region.
        idc_registration: AWS SSO OIDC client registration payload.
    """

    status: str = "idle"
    state_token: Optional[str] = None
    code_verifier: Optional[str] = None
    authorization_url: Optional[str] = None
    callback_url: Optional[str] = None
    database_path: Optional[str] = None
    account_id: Optional[str] = None
    credential_path: Optional[str] = None
    error_message: Optional[str] = None
    login_option: Optional[str] = None
    server: Optional["KiroOAuthCallbackServer"] = None
    idc_state_token: Optional[str] = None
    idc_code_verifier: Optional[str] = None
    idc_client_id: Optional[str] = None
    idc_client_secret: Optional[str] = None
    idc_client_id_hash: Optional[str] = None
    idc_provider: Optional[str] = None
    idc_region: Optional[str] = None
    idc_registration: Optional[Dict[str, Any]] = None


def pkce_challenge(verifier: str) -> str:
    """
    Build an OAuth S256 PKCE challenge.

    Args:
        verifier: Plain PKCE verifier.

    Returns:
        Base64url SHA-256 challenge without padding.
    """
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def generate_pkce_pair() -> Tuple[str, str]:
    """
    Generate a PKCE verifier and challenge.

    Returns:
        Tuple of verifier and S256 challenge.
    """
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
    return verifier, pkce_challenge(verifier)


def build_kiro_authorization_url(
    state: str,
    code_challenge: str,
    redirect_uri: str,
    portal_url: Optional[str] = None,
) -> str:
    """
    Build the Kiro IDE-compatible portal sign-in URL.

    Args:
        state: CSRF state token.
        code_challenge: PKCE S256 challenge.
        redirect_uri: Local redirect URI root.
        portal_url: Optional portal base URL override.

    Returns:
        Full authorization URL.
    """
    params = {
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "redirect_uri": redirect_uri,
        "redirect_from": "KiroIDE",
    }
    return f"{(portal_url or config.KIRO_AUTH_PORTAL_URL).rstrip('/')}/signin?{urlencode(params)}"


def idc_client_id_hash(start_url: str) -> str:
    """
    Build Kiro IDE's client registration cache key for an IdC start URL.

    Args:
        start_url: AWS IAM Identity Center start URL.

    Returns:
        SHA-1 hash matching Kiro IDE's JSON.stringify({startUrl}) input.
    """
    payload = json.dumps({"startUrl": start_url}, separators=(",", ":"))
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()


def build_idc_authorization_url(
    client_id: str,
    redirect_uri: str,
    state: str,
    code_challenge: str,
    region: str,
    scopes: Optional[List[str]] = None,
) -> str:
    """
    Build the second-stage AWS SSO OIDC authorization URL used by Kiro IDE.

    Args:
        client_id: Registered AWS SSO OIDC client ID.
        redirect_uri: Local callback URL ending with /oauth/callback.
        state: CSRF state token.
        code_challenge: PKCE S256 challenge.
        region: AWS SSO OIDC region.
        scopes: Optional scope list.

    Returns:
        Full AWS SSO OIDC authorization URL.
    """
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scopes": ",".join(scopes or IDC_GRANT_SCOPES),
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    return f"https://oidc.{region}.amazonaws.com/authorize?{urlencode(params)}"


class KiroOAuthCallbackServer:
    """
    Lightweight localhost callback server for the Kiro portal.

    Args:
        handler: Async callback invoked after validating the callback path.
        host: Host to bind.
        redirect_host: Hostname written into redirect URIs.
        ports: Candidate ports, tried in order.
    """

    def __init__(
        self,
        handler: Callable[[KiroOAuthCallback], Awaitable[Tuple[bool, str]]],
        host: str = "127.0.0.1",
        redirect_host: str = "localhost",
        ports: Optional[List[int]] = None,
    ):
        """Initialize the callback server."""
        self._handler = handler
        self._host = host
        self._redirect_host = redirect_host
        self._ports = ports or config.KIRO_OAUTH_CALLBACK_PORTS
        self._server: Optional[asyncio.AbstractServer] = None
        self._port: Optional[int] = None

    async def start(self) -> None:
        """
        Start listening on the first available callback port.

        Raises:
            KiroOAuthError: If no configured port can be bound.
        """
        errors = []
        for port in self._ports:
            try:
                self._server = await asyncio.start_server(self._handle_client, self._host, port)
                self._port = self._get_bound_port(port)
                logger.info(f"Kiro OAuth callback server listening on {self.redirect_uri}")
                return
            except OSError as e:
                errors.append(f"{port}: {e}")

        raise KiroOAuthError(f"Unable to start Kiro OAuth callback server. Tried ports: {', '.join(errors)}")

    async def stop(self) -> None:
        """Stop the callback server if it is running."""
        if not self._server:
            return
        self._server.close()
        await self._server.wait_closed()
        self._server = None
        logger.info("Kiro OAuth callback server stopped")

    @property
    def redirect_uri(self) -> str:
        """
        Return the local redirect URI root.

        Returns:
            Redirect URI such as http://localhost:3128.

        Raises:
            KiroOAuthError: If the server is not started.
        """
        if self._port is None:
            raise KiroOAuthError("Kiro OAuth callback server is not started.")
        return f"http://{self._redirect_host}:{self._port}"

    def _get_bound_port(self, requested_port: int) -> int:
        """
        Return the actual bound TCP port.

        Args:
            requested_port: Requested port, possibly 0 for an ephemeral port.

        Returns:
            Actual port assigned by the OS.
        """
        if self._server and self._server.sockets:
            sockname = self._server.sockets[0].getsockname()
            return int(sockname[1])
        return requested_port

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """
        Handle one HTTP callback request.

        Args:
            reader: Client stream reader.
            writer: Client stream writer.
        """
        try:
            request_line = await reader.readline()
            if not request_line:
                return
            method, target, _version = request_line.decode("iso-8859-1").strip().split(" ", 2)
            while True:
                line = await reader.readline()
                if line in (b"\r\n", b"\n", b""):
                    break

            if method.upper() != "GET":
                await self._send_response(writer, 405, "Method Not Allowed")
                return

            parsed = urlparse(target)
            if parsed.path not in CALLBACK_PATHS:
                await self._send_response(writer, 404, "Not Found")
                return

            callback = self._callback_from_query(parsed.path, parsed.query)
            success, message = await self._handler(callback)
            if success:
                await self._send_redirect(writer, _auth_status_url("success"))
            else:
                await self._send_redirect(writer, _auth_status_url("error", message))
        except (ValueError, UnicodeDecodeError) as e:
            logger.warning(f"Malformed Kiro OAuth callback request: {e}")
            await self._send_response(writer, 400, "Bad Request")
        except KiroOAuthError as e:
            logger.warning(f"Kiro OAuth callback failed: {e.message}")
            await self._send_redirect(writer, _auth_status_url("error", e.message))
        finally:
            writer.close()
            await writer.wait_closed()

    @staticmethod
    def _callback_from_query(path: str, query: str) -> KiroOAuthCallback:
        """
        Parse callback query parameters.

        Args:
            path: Callback path.
            query: Raw query string.

        Returns:
            Parsed callback data.
        """
        params = parse_qs(query)
        return KiroOAuthCallback(
            login_option=params.get("login_option", [""])[0],
            code=params.get("code", [None])[0],
            state=params.get("state", [None])[0],
            path=path,
            issuer_url=params.get("issuer_url", [None])[0],
            idc_region=params.get("idc_region", [None])[0],
            client_id=params.get("client_id", [None])[0],
            scopes=params.get("scopes", [None])[0],
            login_hint=params.get("login_hint", [None])[0],
            audience=params.get("audience", [None])[0],
        )

    @staticmethod
    async def _send_response(writer: asyncio.StreamWriter, status: int, body: str) -> None:
        """
        Write a plain HTTP response.

        Args:
            writer: Client stream writer.
            status: HTTP status code.
            body: Response body.
        """
        reason = {400: "Bad Request", 404: "Not Found", 405: "Method Not Allowed"}.get(status, "OK")
        encoded = body.encode("utf-8")
        writer.write(
            (
                f"HTTP/1.1 {status} {reason}\r\n"
                "Content-Type: text/plain; charset=utf-8\r\n"
                f"Content-Length: {len(encoded)}\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).encode("utf-8") + encoded
        )
        await writer.drain()

    @staticmethod
    async def _send_redirect(writer: asyncio.StreamWriter, location: str) -> None:
        """
        Write a redirect response.

        Args:
            writer: Client stream writer.
            location: Redirect target.
        """
        body = f"Redirecting to {location}"
        encoded = body.encode("utf-8")
        writer.write(
            (
                "HTTP/1.1 302 Found\r\n"
                f"Location: {location}\r\n"
                "Content-Type: text/plain; charset=utf-8\r\n"
                f"Content-Length: {len(encoded)}\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).encode("utf-8") + encoded
        )
        await writer.drain()


class KiroOAuthService:
    """
    Coordinates one Kiro IDE-compatible browser OAuth flow at a time.
    """

    def __init__(self) -> None:
        """Initialize service state."""
        self._lock = asyncio.Lock()
        self._state = KiroOAuthState()
        self._region = config.REGION

    async def start(
        self,
        region: str,
        database_path: Optional[str] = None,
        credential_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Start a Kiro browser OAuth flow.

        Args:
            region: Kiro auth region for token exchange.
            database_path: Optional SQLite account database destination.
            credential_path: Legacy alias for database_path.

        Returns:
            OAuth status payload with authorization URL.
        """
        async with self._lock:
            await self._cleanup_locked()

            verifier, challenge = generate_pkce_pair()
            state_token = str(uuid.uuid4())
            server = KiroOAuthCallbackServer(self._handle_callback)
            await server.start()

            resolved_database_path = str(Path(database_path or credential_path or config.KIRO_OAUTH_DB_FILE).expanduser())
            authorization_url = build_kiro_authorization_url(
                state=state_token,
                code_challenge=challenge,
                redirect_uri=server.redirect_uri,
            )
            self._state = KiroOAuthState(
                status="pending",
                state_token=state_token,
                code_verifier=verifier,
                authorization_url=authorization_url,
                callback_url=server.redirect_uri,
                database_path=resolved_database_path,
                server=server,
            )
            self._region = region
            logger.info(f"Started Kiro browser OAuth flow: redirect_uri={server.redirect_uri}")
            return self.status()

    def status(self) -> Dict[str, Any]:
        """
        Return the current OAuth status.

        Returns:
            Public status payload.
        """
        return {
            "status": self._state.status if self._state.status != "idle" else "idle",
            "authorization_url": self._state.authorization_url,
            "callback_url": self._state.callback_url,
            "credential_path": self._state.credential_path,
            "database_path": self._state.database_path,
            "account_id": self._state.account_id,
            "error_message": self._state.error_message,
            "login_option": self._state.login_option,
            "idc_provider": self._state.idc_provider,
            "idc_region": self._state.idc_region,
        }

    async def manual_callback(self, callback_url: str) -> Dict[str, Any]:
        """
        Process a callback URL pasted manually by the user.

        Args:
            callback_url: Full callback URL containing code and state.

        Returns:
            Updated OAuth status payload.
        """
        parsed = urlparse(callback_url)
        if parsed.path not in CALLBACK_PATHS:
            await self._set_error(f"Invalid callback path: {parsed.path}")
            return self.status()

        callback = KiroOAuthCallbackServer._callback_from_query(parsed.path, parsed.query)
        success, message = await self._handle_callback(callback)
        if not success:
            await self._set_error(message)
        return self.status()

    async def cancel(self) -> Dict[str, Any]:
        """
        Cancel the active OAuth flow.

        Returns:
            Updated status payload.
        """
        async with self._lock:
            await self._cleanup_locked()
            self._state = KiroOAuthState(status="idle")
            return self.status()

    async def _handle_callback(self, callback: KiroOAuthCallback) -> Tuple[bool, str]:
        """
        Validate, exchange, and persist a Kiro OAuth callback.

        Args:
            callback: Parsed callback data.

        Returns:
            Tuple of success flag and message.
        """
        async with self._lock:
            status = self._state.status

        if status == "pending":
            return await self._handle_portal_callback(callback)
        if status == "idc_pending":
            return await self._handle_idc_callback(callback)
        return False, "No pending Kiro OAuth flow."

    async def _handle_portal_callback(self, callback: KiroOAuthCallback) -> Tuple[bool, str]:
        """
        Process the first callback from the Kiro auth portal.

        Args:
            callback: Parsed Kiro portal callback data.

        Returns:
            Tuple of success flag and message.
        """
        async with self._lock:
            if self._state.status != "pending":
                return False, "No pending Kiro OAuth flow."
            if not callback.state or callback.state != self._state.state_token:
                self._state.status = "error"
                self._state.error_message = "Invalid OAuth callback state."
                return False, self._state.error_message
            if not self._state.code_verifier or not self._state.callback_url or not self._state.database_path:
                self._state.status = "error"
                self._state.error_message = "OAuth flow is missing verifier or callback configuration."
                return False, self._state.error_message

            self._state.login_option = callback.login_option
            code_verifier = self._state.code_verifier
            callback_url = self._state.callback_url
            database_path = self._state.database_path
            region = self._region

        login_option = callback.login_option.lower()
        if login_option not in SOCIAL_LOGIN_OPTIONS:
            try:
                await self._start_idc_flow(callback)
            except KiroOAuthError as e:
                await self._set_error(e.message)
                await self._stop_server()
                return False, e.message
            return True, "Kiro portal login accepted. Continue with AWS SSO authorization."

        try:
            token = await self._exchange_callback(callback, code_verifier, callback_url, region)
            account_id = await self._store_token(token, database_path)
        except KiroOAuthError as e:
            await self._set_error(e.message)
            await self._stop_server()
            return False, e.message

        async with self._lock:
            self._state.status = "success"
            self._state.account_id = account_id
            self._state.error_message = None

        await self._stop_server()
        return True, "Kiro OAuth login complete."

    async def _handle_idc_callback(self, callback: KiroOAuthCallback) -> Tuple[bool, str]:
        """
        Process the second-stage AWS SSO OIDC callback.

        Args:
            callback: Parsed AWS SSO OIDC callback data.

        Returns:
            Tuple of success flag and message.
        """
        async with self._lock:
            if self._state.status != "idc_pending":
                return False, "No pending Kiro IdC OAuth flow."
            if not callback.state or callback.state != self._state.idc_state_token:
                self._state.status = "error"
                self._state.error_message = "Invalid IdC OAuth callback state."
                return False, self._state.error_message
            required_values = [
                self._state.idc_code_verifier,
                self._state.callback_url,
                self._state.database_path,
                self._state.idc_client_id,
                self._state.idc_client_secret,
                self._state.idc_client_id_hash,
                self._state.idc_provider,
                self._state.idc_region,
                self._state.idc_registration,
            ]
            if any(value is None for value in required_values):
                self._state.status = "error"
                self._state.error_message = "IdC OAuth flow is missing client or callback configuration."
                return False, self._state.error_message

            database_path = self._state.database_path or ""
            redirect_uri = f"{self._state.callback_url}/oauth/callback"
            code_verifier = self._state.idc_code_verifier or ""
            client_id = self._state.idc_client_id or ""
            client_secret = self._state.idc_client_secret or ""
            client_id_hash = self._state.idc_client_id_hash or ""
            provider = self._state.idc_provider or ""
            region = self._state.idc_region or config.REGION
            registration = self._state.idc_registration or {}

        if not callback.code:
            await self._set_error("IdC OAuth callback is missing authorization code.")
            await self._stop_server()
            return False, "IdC OAuth callback is missing authorization code."

        try:
            response = await exchange_idc_token(
                client_id=client_id,
                client_secret=client_secret,
                code=callback.code,
                code_verifier=code_verifier,
                redirect_uri=redirect_uri,
                region=region,
            )
            token = idc_token_response_to_cache(response, client_id_hash, provider, region)
            account_id = await self._store_token(token, database_path, registration)
        except KiroOAuthError as e:
            await self._set_error(e.message)
            await self._stop_server()
            return False, e.message

        async with self._lock:
            self._state.status = "success"
            self._state.account_id = account_id
            self._state.error_message = None

        await self._stop_server()
        return True, "Kiro IdC OAuth login complete."

    async def _start_idc_flow(self, callback: KiroOAuthCallback) -> None:
        """
        Start the second-stage AWS SSO OIDC flow used by Kiro IDE IdC logins.

        Args:
            callback: First-stage Kiro portal callback.

        Raises:
            KiroOAuthError: If login option metadata is incomplete.
        """
        provider, start_url, region = self._resolve_idc_callback(callback)
        registration = await register_idc_client(start_url, region)
        client_id = registration["clientId"]
        client_secret = registration["clientSecret"]
        client_id_hash = idc_client_id_hash(start_url)

        verifier, challenge = generate_pkce_pair()
        state_token = str(uuid.uuid4())

        await self._stop_server()
        server = KiroOAuthCallbackServer(self._handle_callback, redirect_host="127.0.0.1", ports=[0])
        await server.start()
        redirect_uri = f"{server.redirect_uri}/oauth/callback"
        authorization_url = build_idc_authorization_url(
            client_id=client_id,
            redirect_uri=redirect_uri,
            state=state_token,
            code_challenge=challenge,
            region=region,
        )

        async with self._lock:
            self._state.status = "idc_pending"
            self._state.authorization_url = authorization_url
            self._state.callback_url = server.redirect_uri
            self._state.error_message = None
            self._state.server = server
            self._state.idc_state_token = state_token
            self._state.idc_code_verifier = verifier
            self._state.idc_client_id = client_id
            self._state.idc_client_secret = client_secret
            self._state.idc_client_id_hash = client_id_hash
            self._state.idc_provider = provider
            self._state.idc_region = region
            self._state.idc_registration = registration

        logger.info(f"Started Kiro IdC OAuth flow: provider={provider}, redirect_uri={redirect_uri}")

    def _resolve_idc_callback(self, callback: KiroOAuthCallback) -> Tuple[str, str, str]:
        """
        Resolve Kiro portal IdC callback metadata.

        Args:
            callback: First-stage Kiro portal callback.

        Returns:
            Tuple of provider label, start URL, and IdC region.

        Raises:
            KiroOAuthError: If callback metadata is incomplete.
        """
        login_option = callback.login_option.lower()
        if login_option == "awsidc":
            if not callback.issuer_url:
                raise KiroOAuthError("Kiro AWS IdC callback is missing issuer_url.")
            provider = "Enterprise"
            start_url = callback.issuer_url
        elif login_option in IDC_LOGIN_OPTIONS:
            provider, start_url = IDC_LOGIN_OPTIONS[login_option]
        else:
            raise KiroOAuthError(f"Unsupported Kiro portal login option: {callback.login_option or 'unknown'}")

        region = callback.idc_region or self._region or config.REGION
        return provider, start_url, region

    async def _exchange_callback(
        self,
        callback: KiroOAuthCallback,
        code_verifier: str,
        callback_url: str,
        region: str,
    ) -> Dict[str, Any]:
        """
        Exchange callback data for a Kiro token cache payload.

        Args:
            callback: Parsed callback data.
            code_verifier: PKCE verifier captured for the active flow.
            callback_url: Local redirect URI root captured for the active flow.
            region: Kiro auth region for token exchange.

        Returns:
            Kiro IDE-compatible token payload.

        Raises:
            KiroOAuthError: If the callback cannot be exchanged.
        """
        login_option = callback.login_option.lower()
        if login_option not in SOCIAL_LOGIN_OPTIONS:
            raise KiroOAuthError(f"Unsupported Kiro social login option: {callback.login_option or 'unknown'}")
        if not callback.code:
            raise KiroOAuthError("OAuth callback is missing authorization code.")

        redirect_uri = f"{callback_url}{callback.path}?login_option={login_option}"
        response = await exchange_social_token(
            code=callback.code,
            code_verifier=code_verifier,
            redirect_uri=redirect_uri,
            region=region,
        )
        return token_response_to_cache(response, SOCIAL_LOGIN_OPTIONS[login_option])

    async def _set_error(self, message: str) -> None:
        """
        Store an OAuth error status.

        Args:
            message: Error message.
        """
        async with self._lock:
            self._state.status = "error"
            self._state.error_message = message

    async def _stop_server(self) -> None:
        """Stop the active callback server outside the state lock."""
        server = self._state.server
        if server:
            await server.stop()

    async def _cleanup_locked(self) -> None:
        """Stop existing server while the state lock is held."""
        server = self._state.server
        if server:
            await server.stop()

    @staticmethod
    async def _store_token(
        token: Dict[str, Any],
        database_path: str,
        registration: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Persist a Kiro token into the gateway account database.

        Args:
            token: Token payload.
            database_path: Destination SQLite database.
            registration: Optional IdC registration payload.

        Returns:
            Stored account ID.

        Raises:
            KiroOAuthError: If SQLite persistence fails.
        """
        try:
            store = KiroAccountSqliteStore(database_path)
            record = store.upsert_token(token=token, registration=registration)
        except (KiroAccountSqliteStoreError, sqlite3.Error, OSError) as e:
            raise KiroOAuthError(f"Failed to store Kiro OAuth account in SQLite: {e}") from e
        return str(record["id"])


async def exchange_social_token(
    code: str,
    code_verifier: str,
    redirect_uri: str,
    region: str,
) -> Dict[str, Any]:
    """
    Exchange a Kiro portal social authorization code for tokens.

    Args:
        code: Authorization code.
        code_verifier: PKCE verifier.
        redirect_uri: Full callback URI including login_option.
        region: Kiro auth region.

    Returns:
        Raw token response.

    Raises:
        KiroOAuthError: If Kiro rejects the token exchange.
    """
    url = config.KIRO_OAUTH_TOKEN_URL_TEMPLATE.format(region=region)
    payload = {
        "code": code,
        "code_verifier": code_verifier,
        "redirect_uri": redirect_uri,
        "invitation_code": None,
    }
    headers = {
        "Content-Type": "application/json",
        "User-Agent": f"KiroIDE-0.7.45-{get_machine_fingerprint()}",
    }

    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(url, json=payload, headers=headers)

    if response.status_code >= 400:
        try:
            message = response.json().get("message") or response.text
        except (json.JSONDecodeError, ValueError):
            message = response.text
        raise KiroOAuthError(f"Kiro OAuth token exchange failed ({response.status_code}): {message}")

    data = response.json()
    if not data.get("accessToken") or not data.get("refreshToken"):
        raise KiroOAuthError("Kiro OAuth response is missing accessToken or refreshToken.")
    return data


async def register_idc_client(
    start_url: str,
    region: str,
    scopes: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Register a Kiro IDE-style AWS SSO OIDC public client.

    Args:
        start_url: AWS IAM Identity Center start URL.
        region: AWS SSO OIDC region.
        scopes: Optional grant scopes.

    Returns:
        Client registration response.

    Raises:
        KiroOAuthError: If registration fails or required fields are missing.
    """
    url = f"https://oidc.{region}.amazonaws.com/client/register"
    payload = {
        "clientName": "Kiro IDE",
        "clientType": "public",
        "scopes": scopes or IDC_GRANT_SCOPES,
        "grantTypes": ["authorization_code", "refresh_token"],
        "redirectUris": [IDC_REGISTER_REDIRECT_URI],
        "issuerUrl": start_url,
    }
    headers = {
        "Content-Type": "application/json",
        "User-Agent": f"KiroIDE-0.7.45-{get_machine_fingerprint()}",
    }

    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(url, json=payload, headers=headers)

    if response.status_code >= 400:
        message = _extract_error_message(response)
        raise KiroOAuthError(f"Kiro IdC client registration failed ({response.status_code}): {message}")

    data = response.json()
    if not data.get("clientId") or not data.get("clientSecret"):
        raise KiroOAuthError("Kiro IdC registration response is missing clientId or clientSecret.")
    return data


async def exchange_idc_token(
    client_id: str,
    client_secret: str,
    code: str,
    code_verifier: str,
    redirect_uri: str,
    region: str,
) -> Dict[str, Any]:
    """
    Exchange an AWS SSO OIDC authorization code for Kiro-compatible tokens.

    Args:
        client_id: Registered AWS SSO OIDC client ID.
        client_secret: Registered AWS SSO OIDC client secret.
        code: Authorization code from AWS SSO OIDC callback.
        code_verifier: PKCE verifier for the second-stage flow.
        redirect_uri: Full local callback URI.
        region: AWS SSO OIDC region.

    Returns:
        AWS SSO OIDC token response.

    Raises:
        KiroOAuthError: If token exchange fails or required fields are missing.
    """
    payload = {
        "clientId": client_id,
        "clientSecret": client_secret,
        "grantType": "authorization_code",
        "redirectUri": redirect_uri,
        "code": code,
        "codeVerifier": code_verifier,
    }
    headers = {
        "Content-Type": "application/json",
        "User-Agent": f"KiroIDE-0.7.45-{get_machine_fingerprint()}",
    }

    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(config.get_aws_sso_oidc_url(region), json=payload, headers=headers)

    if response.status_code >= 400:
        message = _extract_error_message(response)
        raise KiroOAuthError(f"Kiro IdC token exchange failed ({response.status_code}): {message}")

    data = response.json()
    if not data.get("accessToken") or not data.get("refreshToken"):
        raise KiroOAuthError("Kiro IdC token response is missing accessToken or refreshToken.")
    return data


def token_response_to_cache(response: Dict[str, Any], provider: str) -> Dict[str, Any]:
    """
    Convert Kiro token response into the IDE cache file format.

    Args:
        response: Raw token response.
        provider: Social provider label.

    Returns:
        Token cache dictionary.
    """
    expires_in = int(response.get("expiresIn", 3600))
    expires_at = datetime.fromtimestamp(
        datetime.now(timezone.utc).timestamp() + expires_in,
        tz=timezone.utc,
    ).replace(microsecond=0).isoformat()

    token = {
        "accessToken": response["accessToken"],
        "refreshToken": response["refreshToken"],
        "expiresAt": expires_at,
        "authMethod": "social",
        "provider": provider,
    }
    if response.get("profileArn"):
        token["profileArn"] = response["profileArn"]
    return token


def idc_token_response_to_cache(
    response: Dict[str, Any],
    client_id_hash: str,
    provider: str,
    region: str,
) -> Dict[str, Any]:
    """
    Convert AWS SSO OIDC token response into the Kiro IDE cache format.

    Args:
        response: AWS SSO OIDC token response.
        client_id_hash: Kiro IDE client registration cache key.
        provider: Kiro IdC provider label.
        region: AWS SSO OIDC region.

    Returns:
        Token cache dictionary.
    """
    expires_in = int(response.get("expiresIn", 3600))
    expires_at = datetime.fromtimestamp(
        datetime.now(timezone.utc).timestamp() + expires_in,
        tz=timezone.utc,
    ).replace(microsecond=0).isoformat()

    return {
        "accessToken": response["accessToken"],
        "refreshToken": response["refreshToken"],
        "expiresAt": expires_at,
        "clientIdHash": client_id_hash,
        "authMethod": "IdC",
        "provider": provider,
        "region": region,
    }


def _extract_error_message(response: httpx.Response) -> str:
    """
    Extract a useful error message from an HTTP response.

    Args:
        response: HTTP response object.

    Returns:
        Parsed error message or raw response text.
    """
    try:
        data = response.json()
    except (json.JSONDecodeError, ValueError):
        return response.text
    if isinstance(data, dict):
        return data.get("message") or data.get("error_description") or data.get("error") or response.text
    return response.text


def _auth_status_url(status: str, error_message: Optional[str] = None) -> str:
    """
    Build the Kiro portal auth status URL.

    Args:
        status: success or error.
        error_message: Optional error message.

    Returns:
        Portal status URL.
    """
    params = {
        "auth_status": status,
        "redirect_from": "KiroIDE",
    }
    if error_message:
        params["error_message"] = error_message
    return f"{config.KIRO_AUTH_PORTAL_URL.rstrip('/')}/signin?{urlencode(params)}"


_KIRO_OAUTH_SERVICE = KiroOAuthService()


def get_kiro_oauth_service() -> KiroOAuthService:
    """
    Return the process-wide Kiro OAuth service.

    Returns:
        KiroOAuthService singleton.
    """
    return _KIRO_OAUTH_SERVICE
