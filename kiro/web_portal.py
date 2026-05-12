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
Helpers for Kiro Web Portal RPC operations.

This module currently implements the minimal RPCv2-CBOR client needed for
``GetUserInfo`` so browser OAuth accounts can persist human-readable names and
authenticated Web Portal metadata. It also bootstraps authenticated HTML
metadata so accounts can persist ``csrf_token`` automatically after login and
after token refresh.
"""

import re
import struct
import time
import uuid
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
import json
from typing import Any, Dict, Optional

import httpx
from loguru import logger

from kiro.config import TOKEN_REFRESH_THRESHOLD, get_aws_sso_oidc_url, get_kiro_refresh_url
from kiro.utils import get_machine_fingerprint


KIRO_WEB_PORTAL_BASE_URL = "https://app.kiro.dev"
KIRO_WEB_PORTAL_GET_USER_INFO_PATH = "/service/KiroWebPortalService/operation/GetUserInfo"
KIRO_WEB_PORTAL_GET_USER_INFO_ORIGIN = "KIRO_IDE"
KIRO_WEB_PORTAL_USAGE_PATH = "/account/usage"
KIRO_WEB_PORTAL_TIMEOUT_SECONDS = 3.0
KIRO_WEB_PORTAL_DISPLAY_NAME_FIELDS = (
    "email",
    "preferred_username",
    "preferredUsername",
    "username",
    "userName",
    "name",
    "userId",
)
KIRO_WEB_PORTAL_METADATA_NAME_MAP = {
    "csrf-token": "csrf_token",
    "user-id": "user_id",
    "idp": "provider",
    "profile-arn": "profile_arn",
    "user-status": "user_status",
}
_CBOR_BREAK = object()
_EMPTY_CBOR_MAP = b"\xa0"


class CborDecodeError(ValueError):
    """
    Error raised when a CBOR document cannot be decoded.

    Args:
        message: User-facing decode failure description.
    """

    def __init__(self, message: str):
        """Initialize the CBOR decode error."""
        super().__init__(message)
        self.message = message


def fetch_kiro_web_portal_user_info(
    access_token: str,
    csrf_token: str,
    user_id: Optional[str] = None,
    provider: Optional[str] = None,
    visitor_id: Optional[str] = None,
    base_url: str = KIRO_WEB_PORTAL_BASE_URL,
    timeout_seconds: float = KIRO_WEB_PORTAL_TIMEOUT_SECONDS,
) -> Optional[Dict[str, Any]]:
    """
    Fetch user metadata from the Kiro Web Portal ``GetUserInfo`` operation.

    Args:
        access_token: Browser OAuth access token.
        csrf_token: Kiro Web Portal CSRF token for the same browser session.
        user_id: Optional previously known Kiro Web Portal user ID.
        provider: Optional identity provider cookie value.
        visitor_id: Optional visitor ID. When omitted, one is generated.
        base_url: Base Kiro Web Portal URL.
        timeout_seconds: Request timeout in seconds.

    Returns:
        Parsed user info payload, or None when the request cannot be completed.
    """
    normalized_access_token = _normalize_optional_text(access_token)
    normalized_csrf_token = _normalize_optional_text(csrf_token)
    if not normalized_access_token or not normalized_csrf_token:
        logger.warning(
            "Kiro Web Portal GetUserInfo skipped: "
            f"has_access_token={bool(normalized_access_token)}, "
            f"has_csrf_token={bool(normalized_csrf_token)}"
        )
        return None

    normalized_base_url = base_url.rstrip("/")
    resolved_visitor_id = _normalize_optional_text(visitor_id) or _build_visitor_id()
    resolved_user_id = _normalize_optional_text(user_id)
    resolved_provider = _normalize_optional_text(provider)

    headers = {
        "accept": "application/cbor",
        "content-type": "application/cbor",
        "authorization": f"Bearer {normalized_access_token}",
        "smithy-protocol": "rpc-v2-cbor",
        "amz-sdk-invocation-id": str(uuid.uuid4()),
        "amz-sdk-request": "attempt=1; max=1",
        "origin": normalized_base_url,
        "referer": f"{normalized_base_url}/account/usage",
        "x-csrf-token": normalized_csrf_token,
        "x-kiro-visitorid": resolved_visitor_id,
    }
    if resolved_user_id:
        headers["x-kiro-userid"] = resolved_user_id

    cookies = {"AccessToken": normalized_access_token}
    if resolved_user_id:
        cookies["UserId"] = resolved_user_id
    if resolved_provider:
        cookies["Idp"] = resolved_provider

    try:
        with httpx.Client(timeout=timeout_seconds, follow_redirects=False, cookies=cookies) as client:
            response = client.post(
                url=f"{normalized_base_url}{KIRO_WEB_PORTAL_GET_USER_INFO_PATH}",
                params={"origin": KIRO_WEB_PORTAL_GET_USER_INFO_ORIGIN},
                headers=headers,
                content=_EMPTY_CBOR_MAP,
            )
    except httpx.HTTPError as e:
        logger.warning(
            "Kiro Web Portal GetUserInfo request failed: "
            f"user_id={resolved_user_id or 'missing'}, error={e}"
        )
        return None

    content_type = str(response.headers.get("content-type") or "").split(";", 1)[0].strip().lower()
    if content_type != "application/cbor":
        logger.warning(
            "Kiro Web Portal GetUserInfo returned unexpected content type: "
            f"status={response.status_code}, content_type={content_type or 'missing'}"
        )
        return None

    try:
        payload = decode_cbor_document(response.content)
    except CborDecodeError as e:
        logger.warning(f"Failed to decode Kiro Web Portal GetUserInfo response: {e}")
        return None

    if response.status_code >= 400:
        logger.warning(
            "Kiro Web Portal GetUserInfo request was rejected: "
            f"status={response.status_code}, "
            f"user_id={resolved_user_id or 'missing'}, "
            f"detail={_extract_cbor_error_message(payload)}"
        )
        return None

    if not isinstance(payload, dict):
        logger.warning(
            "Kiro Web Portal GetUserInfo returned a non-object payload: "
            f"type={type(payload).__name__}"
        )
        return None

    logger.info(f"Kiro Web Portal GetUserInfo payload: {_serialize_log_payload(payload)}")
    return payload


def resolve_kiro_web_portal_display_name(user_info: Dict[str, Any]) -> Optional[str]:
    """
    Extract a readable account name from a ``GetUserInfo`` payload.

    Args:
        user_info: Parsed Kiro Web Portal user payload.

    Returns:
        Display name string, or None when no suitable identity field exists.
    """
    for field_name in KIRO_WEB_PORTAL_DISPLAY_NAME_FIELDS:
        identity = _normalize_optional_text(user_info.get(field_name))
        if identity:
            return identity
    return None


def fetch_kiro_web_portal_account_identity(
    access_token: str,
    refresh_token: Optional[str] = None,
    csrf_token: Optional[str] = None,
    user_id: Optional[str] = None,
    provider: Optional[str] = None,
    base_url: str = KIRO_WEB_PORTAL_BASE_URL,
    timeout_seconds: float = KIRO_WEB_PORTAL_TIMEOUT_SECONDS,
) -> Dict[str, str]:
    """
    Fetch authenticated Kiro Web Portal identity metadata for persistence.

    Args:
        access_token: Browser OAuth access token.
        refresh_token: Optional browser OAuth refresh token.
        csrf_token: Optional previously stored Web Portal CSRF token.
        user_id: Optional previously known Kiro Web Portal user ID.
        provider: Optional identity provider cookie value.
        base_url: Base Kiro Web Portal URL.
        timeout_seconds: Request timeout in seconds.

    Returns:
        Mapping containing any discovered ``display_name``, ``csrf_token``,
        ``user_id``, ``provider``, and ``profile_arn`` fields.
    """
    normalized_access_token = _normalize_optional_text(access_token)
    if not normalized_access_token:
        return {}

    resolved_identity: Dict[str, str] = {}
    metadata = fetch_kiro_web_portal_session_metadata(
        access_token=normalized_access_token,
        refresh_token=refresh_token,
        user_id=user_id,
        provider=provider,
        base_url=base_url,
        timeout_seconds=timeout_seconds,
    )
    if metadata:
        for field_name in ("csrf_token", "user_id", "provider", "profile_arn"):
            field_value = _normalize_optional_text(metadata.get(field_name))
            if field_value:
                resolved_identity[field_name] = field_value

    resolved_csrf_token = (
        _normalize_optional_text(resolved_identity.get("csrf_token"))
        or _normalize_optional_text(csrf_token)
    )
    resolved_user_id = (
        _normalize_optional_text(resolved_identity.get("user_id"))
        or _normalize_optional_text(user_id)
    )
    resolved_provider = (
        _normalize_optional_text(resolved_identity.get("provider"))
        or _normalize_optional_text(provider)
    )

    if resolved_csrf_token:
        user_info = fetch_kiro_web_portal_user_info(
            access_token=normalized_access_token,
            csrf_token=resolved_csrf_token,
            user_id=resolved_user_id,
            provider=resolved_provider,
            base_url=base_url,
            timeout_seconds=timeout_seconds,
        )
        if user_info:
            display_name = resolve_kiro_web_portal_display_name(user_info)
            if display_name:
                resolved_identity["display_name"] = display_name
            resolved_user_id = _normalize_optional_text(user_info.get("userId") or user_info.get("user_id"))
            resolved_provider = _normalize_optional_text(user_info.get("idp") or user_info.get("provider"))
            if resolved_user_id and "user_id" not in resolved_identity:
                resolved_identity["user_id"] = resolved_user_id
            if resolved_provider and "provider" not in resolved_identity:
                resolved_identity["provider"] = resolved_provider

    if resolved_identity:
        logger.debug(
            "Hydrated Kiro Web Portal account identity: "
            f"has_display_name={bool(resolved_identity.get('display_name'))}, "
            f"has_csrf_token={bool(resolved_identity.get('csrf_token'))}, "
            f"has_user_id={bool(resolved_identity.get('user_id'))}, "
            f"has_provider={bool(resolved_identity.get('provider'))}"
        )
    return resolved_identity


def apply_kiro_web_portal_account_identity(
    token_data: Dict[str, Any],
    identity: Dict[str, str],
) -> Dict[str, Any]:
    """
    Merge persisted Kiro Web Portal identity fields into token data.

    Args:
        token_data: Existing Kiro token payload.
        identity: Resolved Web Portal identity metadata.

    Returns:
        Copy of ``token_data`` with any available user, provider, and profile
        fields applied.
    """
    updated_token_data = dict(token_data)

    resolved_user_id = _normalize_optional_text(identity.get("user_id"))
    resolved_provider = _normalize_optional_text(identity.get("provider"))
    resolved_profile_arn = _normalize_optional_text(identity.get("profile_arn"))

    if resolved_user_id:
        updated_token_data["userId"] = resolved_user_id
    if resolved_provider:
        updated_token_data["provider"] = resolved_provider
    if resolved_profile_arn:
        updated_token_data["profileArn"] = resolved_profile_arn

    return updated_token_data


def fetch_kiro_web_portal_session_metadata(
    access_token: str,
    refresh_token: Optional[str] = None,
    user_id: Optional[str] = None,
    provider: Optional[str] = None,
    base_url: str = KIRO_WEB_PORTAL_BASE_URL,
    timeout_seconds: float = KIRO_WEB_PORTAL_TIMEOUT_SECONDS,
) -> Optional[Dict[str, str]]:
    """
    Fetch authenticated HTML metadata from the Kiro Web Portal.

    Args:
        access_token: Browser OAuth access token.
        refresh_token: Optional browser OAuth refresh token.
        user_id: Optional previously known Web Portal user ID.
        provider: Optional identity provider cookie value.
        base_url: Base Kiro Web Portal URL.
        timeout_seconds: Request timeout in seconds.

    Returns:
        Parsed metadata mapping, or None when no authenticated metadata is available.
    """
    normalized_access_token = _normalize_optional_text(access_token)
    if not normalized_access_token:
        return None

    normalized_base_url = base_url.rstrip("/")
    cookies = {"AccessToken": normalized_access_token}
    normalized_refresh_token = _normalize_optional_text(refresh_token)
    normalized_user_id = _normalize_optional_text(user_id)
    normalized_provider = _normalize_optional_text(provider)
    if normalized_refresh_token:
        cookies["RefreshToken"] = normalized_refresh_token
    if normalized_user_id:
        cookies["UserId"] = normalized_user_id
    if normalized_provider:
        cookies["Idp"] = normalized_provider

    headers = {
        "accept": "text/html,application/xhtml+xml",
        "referer": f"{normalized_base_url}{KIRO_WEB_PORTAL_USAGE_PATH}",
    }

    try:
        with httpx.Client(timeout=timeout_seconds, follow_redirects=True, cookies=cookies) as client:
            response = client.get(
                url=f"{normalized_base_url}{KIRO_WEB_PORTAL_USAGE_PATH}",
                headers=headers,
            )
    except httpx.HTTPError as e:
        logger.debug(f"Kiro Web Portal metadata request failed: {e}")
        return None

    content_type = str(response.headers.get("content-type") or "").split(";", 1)[0].strip().lower()
    if content_type not in ("text/html", "application/xhtml+xml"):
        logger.debug(
            "Kiro Web Portal metadata request returned unexpected content type: "
            f"status={response.status_code}, content_type={content_type or 'missing'}"
        )
        return None

    metadata = extract_kiro_web_portal_session_metadata(response.text)
    if not metadata:
        return None
    if metadata.get("user_status") == "anonymous" and not metadata.get("csrf_token"):
        return None
    return metadata


def extract_kiro_web_portal_session_metadata(html: str) -> Dict[str, str]:
    """
    Extract authenticated metadata values from a Kiro Web Portal HTML page.

    Args:
        html: Raw HTML response body.

    Returns:
        Mapping of normalized metadata fields.
    """
    if not html:
        return {}
    parser = _KiroWebPortalMetaParser()
    parser.feed(html)
    parser.close()
    return parser.metadata


def is_kiro_token_expiring_soon(
    token_data: Dict[str, Any],
    threshold_seconds: int = TOKEN_REFRESH_THRESHOLD,
) -> bool:
    """
    Determine whether a token is missing or close to expiration.

    Args:
        token_data: Kiro token payload.
        threshold_seconds: Refresh threshold in seconds.

    Returns:
        True when the token is missing an expiry or expires soon.
    """
    expires_at = _parse_kiro_token_expiration(token_data)
    if expires_at is None:
        return True
    return expires_at <= datetime.now(timezone.utc) + timedelta(seconds=threshold_seconds)


def refresh_kiro_account_tokens(
    token_data: Dict[str, Any],
    registration_data: Optional[Dict[str, Any]] = None,
    region: Optional[str] = None,
    timeout_seconds: float = KIRO_WEB_PORTAL_TIMEOUT_SECONDS,
) -> Optional[Dict[str, Any]]:
    """
    Refresh Kiro account tokens for either Desktop Auth or AWS SSO OIDC accounts.

    Args:
        token_data: Existing token payload.
        registration_data: Optional registration payload for IdC accounts.
        region: Optional explicit region override.
        timeout_seconds: Request timeout in seconds.

    Returns:
        Refreshed token material, or None when refresh fails.
    """
    refresh_token = _normalize_optional_text(token_data.get("refreshToken") or token_data.get("refresh_token"))
    if not refresh_token:
        return None

    registration_region = _normalize_optional_text(registration_data.get("region")) if registration_data else None
    resolved_region = (
        _normalize_optional_text(region)
        or _normalize_optional_text(token_data.get("region"))
        or registration_region
        or "us-east-1"
    )
    client_id = _normalize_optional_text(token_data.get("clientId") or token_data.get("client_id"))
    client_secret = _normalize_optional_text(token_data.get("clientSecret") or token_data.get("client_secret"))
    if registration_data:
        client_id = client_id or _normalize_optional_text(registration_data.get("clientId") or registration_data.get("client_id"))
        client_secret = client_secret or _normalize_optional_text(
            registration_data.get("clientSecret") or registration_data.get("client_secret")
        )

    if client_id and client_secret:
        return _refresh_aws_sso_oidc_tokens(
            refresh_token=refresh_token,
            client_id=client_id,
            client_secret=client_secret,
            region=resolved_region,
            timeout_seconds=timeout_seconds,
        )
    return _refresh_kiro_desktop_tokens(
        refresh_token=refresh_token,
        region=resolved_region,
        timeout_seconds=timeout_seconds,
    )


def decode_cbor_document(data: bytes) -> Any:
    """
    Decode a CBOR document into Python values.

    Args:
        data: Raw CBOR bytes.

    Returns:
        Decoded Python value.

    Raises:
        CborDecodeError: If the payload is malformed or unsupported.
    """
    if not data:
        raise CborDecodeError("CBOR payload is empty.")
    return _CborDecoder(data).decode()


class _CborDecoder:
    """
    Minimal CBOR decoder for Kiro Web Portal RPC payloads.

    The implementation supports the types observed in ``GetUserInfo`` and
    Kiro RPC error documents: integers, strings, byte strings, arrays, maps,
    booleans, null, and floats, including indefinite-length collections.
    """

    def __init__(self, data: bytes):
        """Initialize the decoder for one CBOR document."""
        self._data = data
        self._offset = 0

    def decode(self) -> Any:
        """
        Decode the full CBOR document.

        Returns:
            Decoded Python value.

        Raises:
            CborDecodeError: If trailing bytes remain or the payload is malformed.
        """
        value = self._decode_item(allow_break=False)
        if self._offset != len(self._data):
            raise CborDecodeError("CBOR payload contains trailing bytes.")
        return value

    def _decode_item(self, allow_break: bool) -> Any:
        """
        Decode one CBOR item.

        Args:
            allow_break: Whether the special break marker is valid at this point.

        Returns:
            Decoded Python value or the break sentinel.

        Raises:
            CborDecodeError: If the CBOR item is malformed or unsupported.
        """
        initial_byte = self._read_byte()
        if initial_byte == 0xFF:
            if allow_break:
                return _CBOR_BREAK
            raise CborDecodeError("Unexpected CBOR break marker.")

        major_type = initial_byte >> 5
        additional_info = initial_byte & 0x1F

        if major_type == 0:
            return self._read_length(additional_info)
        if major_type == 1:
            return -1 - self._read_length(additional_info)
        if major_type == 2:
            return self._decode_byte_string(additional_info)
        if major_type == 3:
            return self._decode_text_string(additional_info)
        if major_type == 4:
            return self._decode_array(additional_info)
        if major_type == 5:
            return self._decode_map(additional_info)
        if major_type == 7:
            return self._decode_simple_value(additional_info)
        raise CborDecodeError(f"Unsupported CBOR major type: {major_type}")

    def _decode_byte_string(self, additional_info: int) -> bytes:
        """
        Decode a CBOR byte string.

        Args:
            additional_info: Additional-info field from the initial byte.

        Returns:
            Decoded bytes.

        Raises:
            CborDecodeError: If the byte string is malformed.
        """
        length = self._read_length(additional_info)
        if length is None:
            chunks = []
            while True:
                chunk = self._decode_item(allow_break=True)
                if chunk is _CBOR_BREAK:
                    return b"".join(chunks)
                if not isinstance(chunk, bytes):
                    raise CborDecodeError("Indefinite-length byte string contains a non-bytes chunk.")
                chunks.append(chunk)
        return self._read(length)

    def _decode_text_string(self, additional_info: int) -> str:
        """
        Decode a CBOR text string.

        Args:
            additional_info: Additional-info field from the initial byte.

        Returns:
            Decoded UTF-8 string.

        Raises:
            CborDecodeError: If the text string is malformed.
        """
        length = self._read_length(additional_info)
        if length is None:
            chunks = []
            while True:
                chunk = self._decode_item(allow_break=True)
                if chunk is _CBOR_BREAK:
                    return "".join(chunks)
                if not isinstance(chunk, str):
                    raise CborDecodeError("Indefinite-length text string contains a non-text chunk.")
                chunks.append(chunk)
        try:
            return self._read(length).decode("utf-8")
        except UnicodeDecodeError as e:
            raise CborDecodeError(f"Invalid UTF-8 in CBOR text string: {e}") from e

    def _decode_array(self, additional_info: int) -> Any:
        """
        Decode a CBOR array.

        Args:
            additional_info: Additional-info field from the initial byte.

        Returns:
            List of decoded items.
        """
        length = self._read_length(additional_info)
        items = []
        if length is None:
            while True:
                item = self._decode_item(allow_break=True)
                if item is _CBOR_BREAK:
                    return items
                items.append(item)
        for _ in range(length):
            items.append(self._decode_item(allow_break=False))
        return items

    def _decode_map(self, additional_info: int) -> Dict[Any, Any]:
        """
        Decode a CBOR map.

        Args:
            additional_info: Additional-info field from the initial byte.

        Returns:
            Dictionary of decoded key-value pairs.
        """
        length = self._read_length(additional_info)
        items: Dict[Any, Any] = {}
        if length is None:
            while True:
                key = self._decode_item(allow_break=True)
                if key is _CBOR_BREAK:
                    return items
                items[key] = self._decode_item(allow_break=False)
        for _ in range(length):
            key = self._decode_item(allow_break=False)
            items[key] = self._decode_item(allow_break=False)
        return items

    def _decode_simple_value(self, additional_info: int) -> Any:
        """
        Decode a CBOR simple value or float.

        Args:
            additional_info: Additional-info field from the initial byte.

        Returns:
            Decoded simple value.

        Raises:
            CborDecodeError: If the simple value is unsupported.
        """
        if additional_info < 20:
            return additional_info
        if additional_info == 20:
            return False
        if additional_info == 21:
            return True
        if additional_info in (22, 23):
            return None
        if additional_info == 24:
            return self._read_byte()
        if additional_info == 25:
            return _decode_half_precision_float(self._read(2))
        if additional_info == 26:
            return struct.unpack(">f", self._read(4))[0]
        if additional_info == 27:
            return struct.unpack(">d", self._read(8))[0]
        raise CborDecodeError(f"Unsupported CBOR simple value additional info: {additional_info}")

    def _read_length(self, additional_info: int) -> Optional[int]:
        """
        Decode a CBOR length or integer value.

        Args:
            additional_info: Additional-info field from the initial byte.

        Returns:
            Integer length, or None for indefinite-length values.

        Raises:
            CborDecodeError: If the length encoding is unsupported.
        """
        if additional_info < 24:
            return additional_info
        if additional_info == 24:
            return self._read_byte()
        if additional_info == 25:
            return struct.unpack(">H", self._read(2))[0]
        if additional_info == 26:
            return struct.unpack(">I", self._read(4))[0]
        if additional_info == 27:
            return struct.unpack(">Q", self._read(8))[0]
        if additional_info == 31:
            return None
        raise CborDecodeError(f"Unsupported CBOR length additional info: {additional_info}")

    def _read_byte(self) -> int:
        """
        Read one byte from the CBOR buffer.

        Returns:
            Byte value as an integer.

        Raises:
            CborDecodeError: If the buffer ends unexpectedly.
        """
        return self._read(1)[0]

    def _read(self, length: int) -> bytes:
        """
        Read a fixed number of bytes from the CBOR buffer.

        Args:
            length: Number of bytes to consume.

        Returns:
            Requested bytes.

        Raises:
            CborDecodeError: If the buffer ends unexpectedly.
        """
        if length < 0:
            raise CborDecodeError("CBOR length cannot be negative.")
        end_offset = self._offset + length
        if end_offset > len(self._data):
            raise CborDecodeError("Unexpected end of CBOR payload.")
        chunk = self._data[self._offset:end_offset]
        self._offset = end_offset
        return chunk


class _KiroWebPortalMetaParser(HTMLParser):
    """
    Extract selected ``<meta name=...>`` values from a Kiro Web Portal page.
    """

    def __init__(self) -> None:
        """Initialize the metadata parser."""
        super().__init__()
        self.metadata: Dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        """
        Inspect one HTML start tag for metadata of interest.

        Args:
            tag: HTML tag name.
            attrs: Tag attributes as ``(name, value)`` pairs.
        """
        if tag.lower() != "meta":
            return

        attr_map = {name.lower(): value for name, value in attrs if name}
        meta_name = str(attr_map.get("name") or "").strip().lower()
        normalized_name = KIRO_WEB_PORTAL_METADATA_NAME_MAP.get(meta_name)
        if not normalized_name:
            return

        value = _normalize_optional_text(attr_map.get("content") or attr_map.get("value"))
        if value:
            self.metadata[normalized_name] = value


def _refresh_kiro_desktop_tokens(
    refresh_token: str,
    region: str,
    timeout_seconds: float,
) -> Optional[Dict[str, Any]]:
    """
    Refresh Desktop Auth tokens using the Kiro refresh endpoint.

    Args:
        refresh_token: Desktop Auth refresh token.
        region: Kiro auth region.
        timeout_seconds: Request timeout in seconds.

    Returns:
        Refreshed token material, or None when refresh fails.
    """
    payload = {"refreshToken": refresh_token}
    headers = {
        "Content-Type": "application/json",
        "User-Agent": f"KiroIDE-0.7.45-{get_machine_fingerprint()}",
    }

    try:
        with httpx.Client(timeout=timeout_seconds) as client:
            response = client.post(
                url=get_kiro_refresh_url(region),
                json=payload,
                headers=headers,
            )
            response.raise_for_status()
            data = response.json()
    except (httpx.HTTPError, ValueError) as e:
        logger.debug(f"Kiro Desktop token refresh failed: region={region}, error={e}")
        return None

    access_token = _normalize_optional_text(data.get("accessToken"))
    if not access_token:
        return None

    expires_in = _coerce_positive_int(data.get("expiresIn"), default=3600)
    expires_at = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=max(expires_in - 60, 0))
    return {
        "access_token": access_token,
        "refresh_token": _normalize_optional_text(data.get("refreshToken")) or refresh_token,
        "profile_arn": _normalize_optional_text(data.get("profileArn")),
        "expires_at": expires_at,
    }


def _refresh_aws_sso_oidc_tokens(
    refresh_token: str,
    client_id: str,
    client_secret: str,
    region: str,
    timeout_seconds: float,
) -> Optional[Dict[str, Any]]:
    """
    Refresh AWS SSO OIDC tokens using the CreateToken endpoint.

    Args:
        refresh_token: AWS SSO OIDC refresh token.
        client_id: OIDC client ID.
        client_secret: OIDC client secret.
        region: OIDC region.
        timeout_seconds: Request timeout in seconds.

    Returns:
        Refreshed token material, or None when refresh fails.
    """
    payload = {
        "grantType": "refresh_token",
        "clientId": client_id,
        "clientSecret": client_secret,
        "refreshToken": refresh_token,
    }

    try:
        with httpx.Client(timeout=timeout_seconds) as client:
            response = client.post(
                url=get_aws_sso_oidc_url(region),
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()
            data = response.json()
    except (httpx.HTTPError, ValueError) as e:
        logger.debug(f"AWS SSO OIDC token refresh failed: region={region}, error={e}")
        return None

    access_token = _normalize_optional_text(data.get("accessToken"))
    if not access_token:
        return None

    expires_in = _coerce_positive_int(data.get("expiresIn"), default=3600)
    expires_at = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=max(expires_in - 60, 0))
    return {
        "access_token": access_token,
        "refresh_token": _normalize_optional_text(data.get("refreshToken")) or refresh_token,
        "profile_arn": None,
        "expires_at": expires_at,
    }


def _parse_kiro_token_expiration(token_data: Dict[str, Any]) -> Optional[datetime]:
    """
    Parse a Kiro token expiration timestamp.

    Args:
        token_data: Kiro token payload.

    Returns:
        Parsed UTC timestamp, or None when the value is missing or invalid.
    """
    expires_value = token_data.get("expiresAt") or token_data.get("expires_at")
    normalized_expires_value = _normalize_optional_text(expires_value)
    if not normalized_expires_value:
        return None

    expires_text = normalized_expires_value
    if expires_text.endswith("Z"):
        expires_text = expires_text[:-1] + "+00:00"
    expires_text = re.sub(r"(\.\d{6})\d+", r"\1", expires_text)

    try:
        expires_at = datetime.fromisoformat(expires_text)
    except ValueError:
        return None

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return expires_at.astimezone(timezone.utc)


def _coerce_positive_int(value: Any, default: int) -> int:
    """
    Convert a value to a positive integer fallback.

    Args:
        value: Arbitrary candidate value.
        default: Default integer to use on failure.

    Returns:
        Positive integer value.
    """
    try:
        coerced = int(value)
    except (TypeError, ValueError):
        return default
    return coerced if coerced > 0 else default


def _serialize_log_payload(payload: Dict[str, Any]) -> str:
    """
    Serialize a Web Portal payload for stable logging.

    Args:
        payload: Parsed Kiro Web Portal response payload.

    Returns:
        Compact JSON string for logs.
    """
    try:
        return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        return str(payload)


def _extract_cbor_error_message(payload: Any) -> str:
    """
    Build a short debug string from a CBOR error payload.

    Args:
        payload: Decoded CBOR payload.

    Returns:
        Short textual description.
    """
    if isinstance(payload, dict):
        message = _normalize_optional_text(payload.get("message"))
        error_type = _normalize_optional_text(payload.get("__type"))
        if message and error_type:
            return f"{error_type}: {message}"
        if message:
            return message
        if error_type:
            return error_type
    return f"unexpected {type(payload).__name__} payload"


def _build_visitor_id() -> str:
    """
    Build a browser-like visitor ID for Web Portal requests.

    Returns:
        Short visitor ID string.
    """
    return f"{int(time.time() * 1000)}-{uuid.uuid4().hex[:10]}"


def _normalize_optional_text(value: Any) -> Optional[str]:
    """
    Normalize an optional text value.

    Args:
        value: Arbitrary candidate value.

    Returns:
        Trimmed string, or None when empty.
    """
    if value is None:
        return None
    if isinstance(value, str):
        normalized = value.strip()
        return normalized or None
    if isinstance(value, (int, float)):
        return str(value)
    return None


def _decode_half_precision_float(data: bytes) -> float:
    """
    Decode a CBOR half-precision IEEE 754 float.

    Args:
        data: Two-byte half-float payload.

    Returns:
        Decoded float value.
    """
    value = struct.unpack(">H", data)[0]
    sign = -1.0 if value & 0x8000 else 1.0
    exponent = (value >> 10) & 0x1F
    fraction = value & 0x03FF

    if exponent == 0:
        if fraction == 0:
            return sign * 0.0
        return sign * (fraction / 1024.0) * (2 ** -14)
    if exponent == 31:
        if fraction == 0:
            return sign * float("inf")
        return float("nan")
    return sign * (1.0 + (fraction / 1024.0)) * (2 ** (exponent - 15))
