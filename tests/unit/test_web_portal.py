"""
Unit tests for Kiro Web Portal helpers.
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from kiro.web_portal import (
    apply_kiro_web_portal_account_identity,
    decode_cbor_document,
    extract_kiro_web_portal_session_metadata,
    fetch_kiro_web_portal_account_identity,
    fetch_kiro_web_portal_user_info,
    fetch_kiro_web_portal_session_metadata,
    is_kiro_token_expiring_soon,
    refresh_kiro_account_tokens,
    resolve_kiro_web_portal_display_name,
)


def _encode_cbor(value):
    """Encode a limited subset of CBOR values for tests."""
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        if value >= 0:
            return _encode_cbor_major(0, value)
        return _encode_cbor_major(1, -1 - value)
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return _encode_cbor_major(3, len(encoded)) + encoded
    if isinstance(value, bytes):
        return _encode_cbor_major(2, len(value)) + value
    if isinstance(value, list):
        return _encode_cbor_major(4, len(value)) + b"".join(_encode_cbor(item) for item in value)
    if isinstance(value, dict):
        encoded_items = []
        for key, item_value in value.items():
            encoded_items.append(_encode_cbor(key))
            encoded_items.append(_encode_cbor(item_value))
        return _encode_cbor_major(5, len(value)) + b"".join(encoded_items)
    raise TypeError(f"Unsupported test CBOR value: {type(value).__name__}")


def _encode_cbor_major(major_type, value):
    """Encode a major type and small integer payload for tests."""
    if value < 24:
        return bytes([(major_type << 5) | value])
    if value < 256:
        return bytes([(major_type << 5) | 24, value])
    if value < 65536:
        return bytes([(major_type << 5) | 25]) + value.to_bytes(2, "big")
    return bytes([(major_type << 5) | 26]) + value.to_bytes(4, "big")


class TestDecodeCborDocument:
    """Tests for minimal CBOR decoding."""

    def test_decode_cbor_document_supports_indefinite_maps(self):
        """
        What it does: Decodes a Kiro RPC error payload captured from the live endpoint.
        Purpose: Ensure the decoder handles indefinite-length CBOR maps used by Smithy RPC errors.
        """
        print("\n=== Test: decode_cbor_document supports indefinite maps ===")

        payload = (
            b"\xbf"
            b"f__type"
            b"x5com.amazon.kirowebportalservice#UnauthorizedException"
            b"gmessage"
            b"x\x18Access token is required"
            b"\xff"
        )

        decoded = decode_cbor_document(payload)

        assert decoded["__type"] == "com.amazon.kirowebportalservice#UnauthorizedException"
        assert decoded["message"] == "Access token is required"


class TestFetchKiroWebPortalUserInfo:
    """Tests for GetUserInfo RPC requests."""

    def test_fetch_kiro_web_portal_user_info_decodes_success_payload(self):
        """
        What it does: Sends a mocked successful GetUserInfo response through the helper.
        Purpose: Ensure the helper builds the Smithy RPC request and returns decoded user info.
        """
        print("\n=== Test: fetch_kiro_web_portal_user_info decodes success payload ===")

        response = MagicMock()
        response.status_code = 200
        response.headers = {"content-type": "application/cbor"}
        response.content = _encode_cbor(
            {
                "email": "portal@example.com",
                "userId": "user-123",
                "featureFlags": ["a", "b"],
                "studentVerificationEligible": True,
            }
        )

        client = MagicMock()
        client.__enter__.return_value = client
        client.post.return_value = response

        with patch("kiro.web_portal.httpx.Client", return_value=client) as client_factory, patch(
            "kiro.web_portal.logger.info"
        ) as info_log:
            payload = fetch_kiro_web_portal_user_info(
                access_token="access-token",
                csrf_token="csrf-token",
                user_id="user-123",
                provider="Google",
                visitor_id="visitor-123",
            )

        assert payload["email"] == "portal@example.com"
        client.post.assert_called_once()
        request_kwargs = client.post.call_args.kwargs
        assert request_kwargs["params"] == {"origin": "KIRO_IDE"}
        assert request_kwargs["headers"]["authorization"] == "Bearer access-token"
        assert request_kwargs["headers"]["x-csrf-token"] == "csrf-token"
        assert request_kwargs["headers"]["x-kiro-userid"] == "user-123"
        assert request_kwargs["headers"]["x-kiro-visitorid"] == "visitor-123"
        assert request_kwargs["content"] == b"\xa0"
        assert client_factory.call_args.kwargs["cookies"] == {
            "AccessToken": "access-token",
            "UserId": "user-123",
            "Idp": "Google",
        }
        info_log.assert_called_once()
        assert "portal@example.com" in info_log.call_args.args[0]

    def test_fetch_kiro_web_portal_user_info_returns_none_on_http_error(self):
        """
        What it does: Sends a mocked Unauthorized CBOR response through the helper.
        Purpose: Ensure admin display-name resolution gracefully falls back on RPC errors.
        """
        print("\n=== Test: fetch_kiro_web_portal_user_info returns None on HTTP error ===")

        response = MagicMock()
        response.status_code = 401
        response.headers = {"content-type": "application/cbor"}
        response.content = (
            b"\xbf"
            b"f__type"
            b"x5com.amazon.kirowebportalservice#UnauthorizedException"
            b"gmessage"
            b"x\x18Access token is required"
            b"\xff"
        )

        client = MagicMock()
        client.__enter__.return_value = client
        client.post.return_value = response

        with patch("kiro.web_portal.httpx.Client", return_value=client):
            payload = fetch_kiro_web_portal_user_info(
                access_token="access-token",
                csrf_token="csrf-token",
            )

        assert payload is None


class TestFetchKiroWebPortalSessionMetadata:
    """Tests for authenticated HTML metadata bootstrapping."""

    def test_extract_kiro_web_portal_session_metadata_reads_meta_tags(self):
        """
        What it does: Parses an authenticated-looking Kiro Web Portal HTML shell.
        Purpose: Ensure csrf_token and related metadata can be recovered from page meta tags.
        """
        print("\n=== Test: extract_kiro_web_portal_session_metadata reads meta tags ===")

        html = """
        <html>
          <head>
            <meta name="csrf-token" content="csrf-token-1" />
            <meta name="user-id" content="user-123" />
            <meta name="idp" content="Google" />
            <meta name="profile-arn" content="arn:profile/test" />
            <meta name="user-status" content="registered" />
          </head>
        </html>
        """

        metadata = extract_kiro_web_portal_session_metadata(html)

        assert metadata == {
            "csrf_token": "csrf-token-1",
            "user_id": "user-123",
            "provider": "Google",
            "profile_arn": "arn:profile/test",
            "user_status": "registered",
        }

    def test_fetch_kiro_web_portal_session_metadata_uses_access_and_refresh_cookies(self):
        """
        What it does: Fetches a mocked authenticated HTML page with AccessToken and RefreshToken cookies.
        Purpose: Ensure login/bootstrap code can obtain csrf_token without browser-side JavaScript.
        """
        print("\n=== Test: fetch_kiro_web_portal_session_metadata uses cookies ===")

        response = MagicMock()
        response.status_code = 200
        response.headers = {"content-type": "text/html; charset=utf-8"}
        response.text = """
        <meta name="csrf-token" content="csrf-token-2" />
        <meta name="user-id" content="user-456" />
        <meta name="idp" content="Google" />
        """

        client = MagicMock()
        client.__enter__.return_value = client
        client.get.return_value = response

        with patch("kiro.web_portal.httpx.Client", return_value=client) as client_factory:
            metadata = fetch_kiro_web_portal_session_metadata(
                access_token="access-token",
                refresh_token="refresh-token",
                user_id="user-456",
                provider="Google",
            )

        assert metadata["csrf_token"] == "csrf-token-2"
        assert client_factory.call_args.kwargs["cookies"] == {
            "AccessToken": "access-token",
            "RefreshToken": "refresh-token",
            "UserId": "user-456",
            "Idp": "Google",
        }


class TestFetchKiroWebPortalAccountIdentity:
    """Tests for combined Kiro Web Portal identity hydration."""

    def test_fetch_kiro_web_portal_account_identity_merges_metadata_and_user_info(self):
        """
        What it does: Combines mocked authenticated HTML metadata with a mocked GetUserInfo payload.
        Purpose: Ensure login/refresh flows can persist one merged identity record to SQLite.
        """
        print("\n=== Test: fetch_kiro_web_portal_account_identity merges metadata and user info ===")

        with patch(
            "kiro.web_portal.fetch_kiro_web_portal_session_metadata",
            return_value={
                "csrf_token": "csrf-token-1",
                "user_id": "user-123",
                "provider": "Google",
                "profile_arn": "arn:profile/test",
            },
        ) as metadata_lookup, patch(
            "kiro.web_portal.fetch_kiro_web_portal_user_info",
            return_value={"email": "portal@example.com", "userId": "user-123", "idp": "Google"},
        ) as user_info_lookup:
            identity = fetch_kiro_web_portal_account_identity(
                access_token="access-token",
                refresh_token="refresh-token",
                provider="Google",
            )

        assert identity == {
            "csrf_token": "csrf-token-1",
            "display_name": "portal@example.com",
            "user_id": "user-123",
            "provider": "Google",
            "profile_arn": "arn:profile/test",
        }
        metadata_lookup.assert_called_once()
        user_info_lookup.assert_called_once_with(
            access_token="access-token",
            csrf_token="csrf-token-1",
            user_id="user-123",
            provider="Google",
            base_url="https://app.kiro.dev",
            timeout_seconds=3.0,
        )

    def test_apply_kiro_web_portal_account_identity_updates_token_fields(self):
        """
        What it does: Merges a persisted Web Portal identity mapping into token data.
        Purpose: Ensure callers store userId, provider, and profileArn alongside refreshed tokens.
        """
        print("\n=== Test: apply_kiro_web_portal_account_identity updates token fields ===")

        updated_token = apply_kiro_web_portal_account_identity(
            {"accessToken": "access-token", "refreshToken": "refresh-token"},
            {
                "user_id": "user-123",
                "provider": "Google",
                "profile_arn": "arn:profile/test",
            },
        )

        assert updated_token["userId"] == "user-123"
        assert updated_token["provider"] == "Google"
        assert updated_token["profileArn"] == "arn:profile/test"


class TestRefreshKiroAccountTokens:
    """Tests for token refresh helpers."""

    def test_is_kiro_token_expiring_soon_detects_expired_token(self):
        """
        What it does: Evaluates a token with a past expiresAt timestamp.
        Purpose: Ensure Web Portal bootstrap refreshes stale access tokens automatically.
        """
        print("\n=== Test: is_kiro_token_expiring_soon detects expired token ===")

        result = is_kiro_token_expiring_soon({"expiresAt": "2000-01-01T00:00:00+00:00"})

        assert result is True

    def test_refresh_kiro_account_tokens_uses_desktop_auth_for_social_accounts(self):
        """
        What it does: Refreshes a social-login token payload without client credentials.
        Purpose: Ensure browser OAuth accounts can auto-refresh before fetching csrf metadata.
        """
        print("\n=== Test: refresh_kiro_account_tokens uses Desktop Auth ===")

        response = MagicMock()
        response.raise_for_status.return_value = None
        response.json.return_value = {
            "accessToken": "new-access-token",
            "refreshToken": "new-refresh-token",
            "expiresIn": 3600,
            "profileArn": "arn:profile/test",
        }

        client = MagicMock()
        client.__enter__.return_value = client
        client.post.return_value = response

        with patch("kiro.web_portal.httpx.Client", return_value=client):
            refreshed = refresh_kiro_account_tokens(
                token_data={
                    "refreshToken": "old-refresh-token",
                    "region": "us-east-1",
                }
            )

        assert refreshed["access_token"] == "new-access-token"
        assert refreshed["refresh_token"] == "new-refresh-token"
        assert refreshed["profile_arn"] == "arn:profile/test"
        assert refreshed["expires_at"] > datetime.now(timezone.utc)

    def test_refresh_kiro_account_tokens_uses_oidc_registration_when_available(self):
        """
        What it does: Refreshes an IdC token payload with stored client credentials.
        Purpose: Ensure Builder ID accounts can auto-refresh before Web Portal bootstrap too.
        """
        print("\n=== Test: refresh_kiro_account_tokens uses AWS SSO OIDC ===")

        response = MagicMock()
        response.raise_for_status.return_value = None
        response.json.return_value = {
            "accessToken": "new-access-token",
            "refreshToken": "new-refresh-token",
            "expiresIn": 3600,
        }

        client = MagicMock()
        client.__enter__.return_value = client
        client.post.return_value = response

        with patch("kiro.web_portal.httpx.Client", return_value=client):
            refreshed = refresh_kiro_account_tokens(
                token_data={
                    "refreshToken": "old-refresh-token",
                    "region": "us-east-1",
                    "clientIdHash": "client-hash",
                },
                registration_data={
                    "clientId": "client-id",
                    "clientSecret": "client-secret",
                },
            )

        assert refreshed["access_token"] == "new-access-token"
        request_kwargs = client.post.call_args.kwargs
        assert request_kwargs["json"]["clientId"] == "client-id"
        assert request_kwargs["json"]["clientSecret"] == "client-secret"


class TestResolveKiroWebPortalDisplayName:
    """Tests for Kiro Web Portal identity extraction."""

    def test_resolve_kiro_web_portal_display_name_prefers_email(self):
        """
        What it does: Extracts a display name from a decoded GetUserInfo payload.
        Purpose: Ensure admin UI uses the most human-readable remote identity field first.
        """
        print("\n=== Test: resolve_kiro_web_portal_display_name prefers email ===")

        display_name = resolve_kiro_web_portal_display_name(
            {
                "email": "portal@example.com",
                "userId": "user-123",
            }
        )

        assert display_name == "portal@example.com"
