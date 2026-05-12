# -*- coding: utf-8 -*-

"""
Tests for Kiro IDE-compatible browser OAuth helpers.

These tests verify PKCE generation, portal URL construction, token exchange
payloads, and token cache conversion without making network calls.
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import parse_qs, urlparse

import pytest

from kiro.account_sqlite_store import KiroAccountSqliteStore
from kiro.oauth_kiro import (
    KiroOAuthCallback,
    KiroOAuthCallbackServer,
    KiroOAuthError,
    KiroOAuthService,
    KiroOAuthState,
    build_idc_authorization_url,
    build_kiro_authorization_url,
    exchange_idc_token,
    exchange_social_token,
    generate_pkce_pair,
    idc_client_id_hash,
    idc_token_response_to_cache,
    pkce_challenge,
    register_idc_client,
    token_response_to_cache,
)


class TestKiroOAuthPkce:
    """Tests for PKCE helpers."""

    def test_generate_pkce_pair_builds_matching_challenge(self):
        """
        What it does: Generates a PKCE pair.
        Purpose: Ensure challenge is derived from the verifier using S256.
        """
        print("\n=== Test: Kiro OAuth PKCE pair ===")

        # Act
        verifier, challenge = generate_pkce_pair()

        # Assert
        assert verifier
        assert challenge == pkce_challenge(verifier)
        assert "=" not in challenge

    def test_build_kiro_authorization_url_matches_ide_shape(self):
        """
        What it does: Builds a Kiro portal sign-in URL.
        Purpose: Ensure frontend opens the same URL shape as Kiro IDE.
        """
        print("\n=== Test: Kiro OAuth authorization URL shape ===")

        # Act
        url = build_kiro_authorization_url(
            state="state-id",
            code_challenge="challenge",
            redirect_uri="http://localhost:3128",
            portal_url="https://app.kiro.dev",
        )

        # Assert
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        assert parsed.scheme == "https"
        assert parsed.netloc == "app.kiro.dev"
        assert parsed.path == "/signin"
        assert params["state"] == ["state-id"]
        assert params["code_challenge"] == ["challenge"]
        assert params["code_challenge_method"] == ["S256"]
        assert params["redirect_uri"] == ["http://localhost:3128"]
        assert params["redirect_from"] == ["KiroIDE"]

    def test_build_idc_authorization_url_matches_ide_shape(self):
        """
        What it does: Builds an AWS SSO OIDC authorization URL.
        Purpose: Ensure Builder ID and AWS IdC second-stage URLs match Kiro IDE.
        """
        print("\n=== Test: Kiro IdC authorization URL shape ===")

        # Act
        url = build_idc_authorization_url(
            client_id="client-id",
            redirect_uri="http://127.0.0.1:49152/oauth/callback",
            state="idc-state",
            code_challenge="challenge",
            region="us-east-1",
        )

        # Assert
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        assert parsed.scheme == "https"
        assert parsed.netloc == "oidc.us-east-1.amazonaws.com"
        assert parsed.path == "/authorize"
        assert params["response_type"] == ["code"]
        assert params["client_id"] == ["client-id"]
        assert params["redirect_uri"] == ["http://127.0.0.1:49152/oauth/callback"]
        assert params["state"] == ["idc-state"]
        assert params["code_challenge"] == ["challenge"]
        assert params["code_challenge_method"] == ["S256"]
        assert params["scopes"] == [
            "codewhisperer:completions,codewhisperer:analysis,codewhisperer:conversations,"
            "codewhisperer:transformations,codewhisperer:taskassist"
        ]

    def test_idc_client_id_hash_matches_kiro_ide_json_input(self):
        """
        What it does: Hashes a Builder ID start URL.
        Purpose: Ensure generated client registration filenames match Kiro IDE.
        """
        print("\n=== Test: Kiro IdC client hash ===")

        # Act
        client_hash = idc_client_id_hash("https://view.awsapps.com/start")

        # Assert
        assert client_hash == "e909a0580879b06ece1202964fbe9dda95ea4ce3"


class TestKiroOAuthCallbackParsing:
    """Tests for Kiro portal callback parsing."""

    def test_callback_parser_extracts_social_and_idc_fields(self):
        """
        What it does: Parses a Kiro portal callback query.
        Purpose: Ensure social and IdC metadata from the portal are preserved.
        """
        print("\n=== Test: Kiro OAuth callback parser ===")

        # Act
        callback = KiroOAuthCallbackServer._callback_from_query(
            "/signin/callback",
            (
                "login_option=external_idp&code=auth-code&state=state-id"
                "&issuer_url=https%3A%2F%2Fissuer.example.com"
                "&idc_region=us-east-1&client_id=client"
                "&scopes=openid%20profile&login_hint=user%40example.com"
                "&audience=aud"
            ),
        )

        # Assert
        assert callback.login_option == "external_idp"
        assert callback.code == "auth-code"
        assert callback.state == "state-id"
        assert callback.path == "/signin/callback"
        assert callback.issuer_url == "https://issuer.example.com"
        assert callback.idc_region == "us-east-1"
        assert callback.client_id == "client"
        assert callback.scopes == "openid profile"
        assert callback.login_hint == "user@example.com"
        assert callback.audience == "aud"


class TestKiroOAuthTokenExchange:
    """Tests for Kiro social token exchange."""

    @pytest.mark.asyncio
    async def test_exchange_social_token_posts_kiro_desktop_payload(self):
        """
        What it does: Exchanges an authorization code with mocked HTTP.
        Purpose: Ensure the request matches Kiro IDE's token exchange contract.
        """
        print("\n=== Test: Kiro OAuth social token exchange payload ===")

        # Arrange
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {
            "accessToken": "access",
            "refreshToken": "refresh",
            "expiresIn": 3600,
            "profileArn": "arn:profile",
        }
        client = AsyncMock()
        client.post = AsyncMock(return_value=response)
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=None)

        # Act
        with patch("kiro.oauth_kiro.httpx.AsyncClient", return_value=client):
            result = await exchange_social_token(
                code="auth-code",
                code_verifier="verifier",
                redirect_uri="http://localhost:3128/signin/callback?login_option=google",
                region="us-east-1",
            )

        # Assert
        assert result["accessToken"] == "access"
        url = client.post.call_args.args[0]
        kwargs = client.post.call_args.kwargs
        assert url == "https://prod.us-east-1.auth.desktop.kiro.dev/oauth/token"
        assert kwargs["json"] == {
            "code": "auth-code",
            "code_verifier": "verifier",
            "redirect_uri": "http://localhost:3128/signin/callback?login_option=google",
            "invitation_code": None,
        }
        assert kwargs["headers"]["Content-Type"] == "application/json"
        assert kwargs["headers"]["User-Agent"].startswith("KiroIDE-")

    @pytest.mark.asyncio
    async def test_exchange_social_token_raises_on_kiro_error(self):
        """
        What it does: Exchanges a code when Kiro returns an error.
        Purpose: Ensure users receive the upstream rejection reason.
        """
        print("\n=== Test: Kiro OAuth social token exchange error ===")

        # Arrange
        response = MagicMock()
        response.status_code = 400
        response.json.return_value = {"message": "invalid code"}
        response.text = '{"message":"invalid code"}'
        client = AsyncMock()
        client.post = AsyncMock(return_value=response)
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=None)

        # Act / Assert
        with patch("kiro.oauth_kiro.httpx.AsyncClient", return_value=client):
            with pytest.raises(KiroOAuthError) as exc_info:
                await exchange_social_token(
                    code="bad-code",
                    code_verifier="verifier",
                    redirect_uri="http://localhost:3128/signin/callback?login_option=google",
                    region="us-east-1",
                )
        assert "invalid code" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_exchange_social_token_rejects_missing_tokens(self):
        """
        What it does: Exchanges a code when Kiro omits token fields.
        Purpose: Ensure malformed token responses do not get persisted.
        """
        print("\n=== Test: Kiro OAuth missing token response ===")

        # Arrange
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {"expiresIn": 3600}
        client = AsyncMock()
        client.post = AsyncMock(return_value=response)
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=None)

        # Act / Assert
        with patch("kiro.oauth_kiro.httpx.AsyncClient", return_value=client):
            with pytest.raises(KiroOAuthError) as exc_info:
                await exchange_social_token(
                    code="auth-code",
                    code_verifier="verifier",
                    redirect_uri="http://localhost:3128/signin/callback?login_option=google",
                    region="us-east-1",
                )
        assert "missing accessToken or refreshToken" in str(exc_info.value)

    def test_token_response_to_cache_matches_kiro_ide_json(self):
        """
        What it does: Converts token exchange response to cache format.
        Purpose: Ensure generated credentials can be read by KiroAuthManager.
        """
        print("\n=== Test: Kiro OAuth token cache format ===")

        # Act
        token = token_response_to_cache(
            {
                "accessToken": "access",
                "refreshToken": "refresh",
                "expiresIn": 3600,
                "profileArn": "arn:profile",
            },
            "Google",
        )

        # Assert
        assert token["accessToken"] == "access"
        assert token["refreshToken"] == "refresh"
        assert token["profileArn"] == "arn:profile"
        assert token["authMethod"] == "social"
        assert token["provider"] == "Google"
        assert "expiresAt" in token


class TestKiroIdcTokenExchange:
    """Tests for Kiro IDE IdC registration and token exchange."""

    @pytest.mark.asyncio
    async def test_register_idc_client_posts_kiro_ide_payload(self):
        """
        What it does: Registers an AWS SSO OIDC client with mocked HTTP.
        Purpose: Ensure Builder ID/AWS IdC login matches Kiro IDE's registration contract.
        """
        print("\n=== Test: Kiro IdC client registration payload ===")

        # Arrange
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {
            "clientId": "client-id",
            "clientSecret": "client-secret",
            "clientSecretExpiresAt": 2000000000,
        }
        client = AsyncMock()
        client.post = AsyncMock(return_value=response)
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=None)

        # Act
        with patch("kiro.oauth_kiro.httpx.AsyncClient", return_value=client):
            result = await register_idc_client("https://view.awsapps.com/start", "us-east-1")

        # Assert
        assert result["clientId"] == "client-id"
        url = client.post.call_args.args[0]
        kwargs = client.post.call_args.kwargs
        assert url == "https://oidc.us-east-1.amazonaws.com/client/register"
        assert kwargs["json"]["clientName"] == "Kiro IDE"
        assert kwargs["json"]["clientType"] == "public"
        assert kwargs["json"]["grantTypes"] == ["authorization_code", "refresh_token"]
        assert kwargs["json"]["redirectUris"] == ["http://127.0.0.1/oauth/callback"]
        assert kwargs["json"]["issuerUrl"] == "https://view.awsapps.com/start"
        assert "codewhisperer:completions" in kwargs["json"]["scopes"]

    @pytest.mark.asyncio
    async def test_exchange_idc_token_posts_authorization_code_payload(self):
        """
        What it does: Exchanges an AWS SSO OIDC authorization code with mocked HTTP.
        Purpose: Ensure second-stage IdC login sends camelCase CreateToken payload.
        """
        print("\n=== Test: Kiro IdC token exchange payload ===")

        # Arrange
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {
            "accessToken": "access",
            "refreshToken": "refresh",
            "expiresIn": 3600,
        }
        client = AsyncMock()
        client.post = AsyncMock(return_value=response)
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=None)

        # Act
        with patch("kiro.oauth_kiro.httpx.AsyncClient", return_value=client):
            result = await exchange_idc_token(
                client_id="client-id",
                client_secret="client-secret",
                code="auth-code",
                code_verifier="verifier",
                redirect_uri="http://127.0.0.1:49152/oauth/callback",
                region="us-east-1",
            )

        # Assert
        assert result["accessToken"] == "access"
        url = client.post.call_args.args[0]
        kwargs = client.post.call_args.kwargs
        assert url == "https://oidc.us-east-1.amazonaws.com/token"
        assert kwargs["json"] == {
            "clientId": "client-id",
            "clientSecret": "client-secret",
            "grantType": "authorization_code",
            "redirectUri": "http://127.0.0.1:49152/oauth/callback",
            "code": "auth-code",
            "codeVerifier": "verifier",
        }

    def test_idc_token_response_to_cache_matches_kiro_ide_json(self):
        """
        What it does: Converts AWS SSO OIDC token response to Kiro cache format.
        Purpose: Ensure generated Builder ID credentials can be read by KiroAuthManager.
        """
        print("\n=== Test: Kiro IdC token cache format ===")

        # Act
        token = idc_token_response_to_cache(
            {
                "accessToken": "access",
                "refreshToken": "refresh",
                "expiresIn": 3600,
            },
            "client-hash",
            "BuilderId",
            "us-east-1",
        )

        # Assert
        assert token["accessToken"] == "access"
        assert token["refreshToken"] == "refresh"
        assert token["clientIdHash"] == "client-hash"
        assert token["authMethod"] == "IdC"
        assert token["provider"] == "BuilderId"
        assert token["region"] == "us-east-1"
        assert "expiresAt" in token


class TestKiroOAuthServiceCallbacks:
    """Tests for callback handling and token persistence."""

    @pytest.mark.asyncio
    async def test_handle_callback_rejects_invalid_state(self, tmp_path):
        """
        What it does: Processes a callback with the wrong state.
        Purpose: Ensure CSRF state validation blocks stale or forged callbacks.
        """
        print("\n=== Test: Kiro OAuth invalid callback state ===")

        # Arrange
        service = KiroOAuthService()
        service._state = KiroOAuthState(
            status="pending",
            state_token="expected-state",
            code_verifier="verifier",
            callback_url="http://localhost:3128",
            database_path=str(tmp_path / "kiro_accounts.sqlite3"),
        )

        # Act
        success, message = await service._handle_callback(
            KiroOAuthCallback(
                login_option="google",
                code="auth-code",
                state="wrong-state",
                path="/signin/callback",
            )
        )

        # Assert
        assert success is False
        assert message == "Invalid OAuth callback state."
        assert service.status()["status"] == "error"

    @pytest.mark.asyncio
    async def test_handle_callback_rejects_unknown_login_option(self, tmp_path):
        """
        What it does: Processes an unknown Kiro portal callback.
        Purpose: Ensure unsupported portal login options fail clearly without writing tokens.
        """
        print("\n=== Test: Kiro OAuth unsupported login option ===")

        # Arrange
        db_path = tmp_path / "kiro_accounts.sqlite3"
        service = KiroOAuthService()
        service._state = KiroOAuthState(
            status="pending",
            state_token="state-id",
            code_verifier="verifier",
            callback_url="http://localhost:3128",
            database_path=str(db_path),
        )

        # Act
        success, message = await service._handle_callback(
            KiroOAuthCallback(
                login_option="mystery",
                code=None,
                state="state-id",
                path="/signin/callback",
            )
        )

        # Assert
        assert success is False
        assert "Unsupported Kiro portal login option" in message
        assert service.status()["status"] == "error"
        assert not db_path.exists()

    @pytest.mark.asyncio
    async def test_handle_callback_stores_social_token_in_sqlite(self, tmp_path):
        """
        What it does: Processes a successful Google portal callback.
        Purpose: Ensure token exchange output is persisted in the multi-account SQLite store.
        """
        print("\n=== Test: Kiro OAuth social callback stores token ===")

        # Arrange
        db_path = tmp_path / "kiro_accounts.sqlite3"
        service = KiroOAuthService()
        service._state = KiroOAuthState(
            status="pending",
            state_token="state-id",
            code_verifier="verifier",
            callback_url="http://localhost:3128",
            database_path=str(db_path),
        )
        token_response = {
            "accessToken": "access",
            "refreshToken": "refresh",
            "expiresIn": 3600,
            "profileArn": "arn:profile",
        }

        # Act
        with patch("kiro.oauth_kiro.exchange_social_token", new=AsyncMock(return_value=token_response)) as exchange:
            success, message = await service._handle_callback(
                KiroOAuthCallback(
                    login_option="google",
                    code="auth-code",
                    state="state-id",
                    path="/signin/callback",
                )
            )

        # Assert
        assert success is True
        assert message == "Kiro OAuth login complete."
        assert service.status()["status"] == "success"
        assert service.status()["account_id"].startswith("kiro_")
        exchange.assert_awaited_once_with(
            code="auth-code",
            code_verifier="verifier",
            redirect_uri="http://localhost:3128/signin/callback?login_option=google",
            region="us-east-1",
        )
        saved_token = KiroAccountSqliteStore(str(db_path)).get_account(service.status()["account_id"])["token"]
        assert saved_token["accessToken"] == "access"
        assert saved_token["refreshToken"] == "refresh"
        assert saved_token["authMethod"] == "social"
        assert saved_token["provider"] == "Google"

    @pytest.mark.asyncio
    async def test_handle_builderid_callback_starts_idc_stage(self, tmp_path):
        """
        What it does: Processes a Builder ID portal callback.
        Purpose: Ensure Kiro IDE second-stage IdC authorization is started and registration is cached.
        """
        print("\n=== Test: Kiro Builder ID callback starts IdC stage ===")

        # Arrange
        db_path = tmp_path / "kiro_accounts.sqlite3"
        service = KiroOAuthService()
        service._state = KiroOAuthState(
            status="pending",
            state_token="state-id",
            code_verifier="verifier",
            callback_url="http://localhost:3128",
            database_path=str(db_path),
        )
        registration = {
            "clientId": "client-id",
            "clientSecret": "client-secret",
            "clientSecretExpiresAt": 2000000000,
        }

        # Act
        with patch("kiro.oauth_kiro.register_idc_client", new=AsyncMock(return_value=registration)) as register:
            success, message = await service._handle_callback(
                KiroOAuthCallback(
                    login_option="builderid",
                    code=None,
                    state="state-id",
                    path="/signin/callback",
                    issuer_url="https://view.awsapps.com/start",
                    idc_region="us-east-1",
                )
            )

        # Assert
        try:
            assert success is True
            assert "Continue with AWS SSO authorization" in message
            register.assert_awaited_once_with("https://view.awsapps.com/start", "us-east-1")
            status = service.status()
            assert status["status"] == "idc_pending"
            assert status["authorization_url"].startswith("https://oidc.us-east-1.amazonaws.com/authorize?")
            assert status["callback_url"].startswith("http://127.0.0.1:")
            assert status["idc_provider"] == "BuilderId"
            assert service._state.idc_registration == registration
            assert not list(tmp_path.glob("*.json"))
        finally:
            await service.cancel()

    @pytest.mark.asyncio
    async def test_handle_idc_callback_stores_builder_id_token_in_sqlite(self, tmp_path):
        """
        What it does: Processes a successful second-stage Builder ID callback.
        Purpose: Ensure IdC token exchange output is persisted in the multi-account SQLite store.
        """
        print("\n=== Test: Kiro IdC callback stores token ===")

        # Arrange
        db_path = tmp_path / "kiro_accounts.sqlite3"
        service = KiroOAuthService()
        service._state = KiroOAuthState(
            status="idc_pending",
            callback_url="http://127.0.0.1:49152",
            database_path=str(db_path),
            idc_state_token="idc-state",
            idc_code_verifier="idc-verifier",
            idc_client_id="client-id",
            idc_client_secret="client-secret",
            idc_client_id_hash="client-hash",
            idc_provider="BuilderId",
            idc_region="us-east-1",
            idc_registration={"clientId": "client-id", "clientSecret": "client-secret"},
        )
        token_response = {
            "accessToken": "access",
            "refreshToken": "refresh",
            "expiresIn": 3600,
        }

        # Act
        with patch("kiro.oauth_kiro.exchange_idc_token", new=AsyncMock(return_value=token_response)) as exchange:
            success, message = await service._handle_callback(
                KiroOAuthCallback(
                    login_option="",
                    code="idc-code",
                    state="idc-state",
                    path="/oauth/callback",
                )
            )

        # Assert
        assert success is True
        assert message == "Kiro IdC OAuth login complete."
        assert service.status()["status"] == "success"
        assert service.status()["account_id"].startswith("kiro_")
        exchange.assert_awaited_once_with(
            client_id="client-id",
            client_secret="client-secret",
            code="idc-code",
            code_verifier="idc-verifier",
            redirect_uri="http://127.0.0.1:49152/oauth/callback",
            region="us-east-1",
        )
        saved_record = KiroAccountSqliteStore(str(db_path)).get_account(service.status()["account_id"])
        saved_token = saved_record["token"]
        assert saved_token["accessToken"] == "access"
        assert saved_token["refreshToken"] == "refresh"
        assert saved_token["authMethod"] == "IdC"
        assert saved_token["provider"] == "BuilderId"
        assert saved_token["clientIdHash"] == "client-hash"
        assert saved_record["registration"]["clientId"] == "client-id"
