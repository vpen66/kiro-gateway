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
Request metadata logging for the admin console.

The request log intentionally stores safe operational metadata only. Full user
prompts, API keys, Kiro tokens, and response bodies are not persisted here.
Detailed payload debugging remains handled by debug_logger and DEBUG_MODE.
"""

import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from loguru import logger
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

import kiro.config as config


LOGGED_ENDPOINTS = frozenset({
    "/v1/models",
    "/v1/chat/completions",
    "/v1/messages",
})


class RequestLogStore:
    """
    JSONL-backed request metadata store.

    Args:
        file_path: Path to the JSONL log file.
        max_entries: Maximum number of entries retained.
    """

    def __init__(self, file_path: str, max_entries: int):
        """Initialize the request log store."""
        self.file_path = Path(file_path).expanduser()
        self.max_entries = max(1, max_entries)

    def append(self, entry: Dict[str, Any]) -> None:
        """
        Append a request log entry and enforce retention.

        Args:
            entry: Safe metadata entry to persist.
        """
        self.file_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            with open(self.file_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            self._trim_if_needed()
        except OSError as e:
            logger.error(f"Failed to append request log {self.file_path}: {e}")

    def list_entries(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Return newest request log entries first.

        Args:
            limit: Maximum number of entries to return.

        Returns:
            Newest-first list of request log entries.
        """
        bounded_limit = max(1, min(limit, self.max_entries))
        if not self.file_path.exists():
            return []

        try:
            lines = self.file_path.read_text(encoding="utf-8").splitlines()
        except OSError as e:
            logger.error(f"Failed to read request log {self.file_path}: {e}")
            return []

        entries = []
        for line in reversed(lines[-bounded_limit:]):
            if not line.strip():
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError as e:
                logger.warning(f"Skipping malformed request log line: {e}")
                continue
            if isinstance(parsed, dict):
                entries.append(parsed)

        return entries

    def clear(self) -> None:
        """Delete all request log entries."""
        try:
            if self.file_path.exists():
                self.file_path.unlink()
            logger.info("Request logs cleared")
        except OSError as e:
            logger.error(f"Failed to clear request log {self.file_path}: {e}")
            raise

    def _trim_if_needed(self) -> None:
        """Trim the log file if it exceeds the configured retention."""
        try:
            lines = self.file_path.read_text(encoding="utf-8").splitlines()
        except OSError as e:
            logger.error(f"Failed to inspect request log {self.file_path}: {e}")
            return

        if len(lines) <= self.max_entries:
            return

        retained = lines[-self.max_entries:]
        tmp_path = self.file_path.with_suffix(f"{self.file_path.suffix}.tmp")
        try:
            tmp_path.write_text("\n".join(retained) + "\n", encoding="utf-8")
            tmp_path.replace(self.file_path)
        except OSError as e:
            logger.error(f"Failed to trim request log {self.file_path}: {e}")
            if tmp_path.exists():
                tmp_path.unlink()


class RequestLogMiddleware(BaseHTTPMiddleware):
    """
    Middleware that records safe metadata for gateway API requests.

    The middleware logs OpenAI-compatible, Anthropic-compatible, and model-list
    requests. It does not log admin console requests.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        """
        Process a request and append metadata after the response is created.

        Args:
            request: Incoming request.
            call_next: Next middleware or route handler.

        Returns:
            Response from the downstream application.
        """
        if request.url.path not in LOGGED_ENDPOINTS:
            return await call_next(request)

        started = time.perf_counter()
        request_id = uuid.uuid4().hex
        body_metadata = await self._extract_body_metadata(request)
        error_message: Optional[str] = None
        log_written = False

        def append_log(status_code: int) -> None:
            """Append the request log entry once."""
            nonlocal log_written
            if log_written:
                return
            log_written = True
            duration_ms = round((time.perf_counter() - started) * 1000, 2)
            store = getattr(request.app.state, "request_log_store", get_request_log_store())
            store.append(self._build_entry(
                request=request,
                request_id=request_id,
                status_code=status_code,
                duration_ms=duration_ms,
                body_metadata=body_metadata,
                error_message=error_message,
            ))

        try:
            response = await call_next(request)
        except RuntimeError as e:
            error_message = str(e)
            append_log(500)
            raise
        except ValueError as e:
            error_message = str(e)
            append_log(500)
            raise

        body_iterator = getattr(response, "body_iterator", None)
        if body_iterator is None:
            append_log(response.status_code)
            return response

        async def logging_body_iterator():
            nonlocal error_message
            try:
                async for chunk in body_iterator:
                    yield chunk
            except RuntimeError as e:
                error_message = str(e)
                raise
            except ValueError as e:
                error_message = str(e)
                raise
            finally:
                append_log(response.status_code)

        response.body_iterator = logging_body_iterator()
        return response

    async def _extract_body_metadata(self, request: Request) -> Dict[str, Any]:
        """
        Extract safe metadata from the request body.

        Args:
            request: Incoming request.

        Returns:
            Metadata dictionary containing model, stream flag and body size.
        """
        metadata: Dict[str, Any] = {
            "body_bytes": 0,
            "model": None,
            "stream": None,
        }

        try:
            body = await request.body()
        except RuntimeError as e:
            logger.warning(f"Failed to read request body for request logging: {e}")
            return metadata

        metadata["body_bytes"] = len(body)
        if not body:
            return metadata

        try:
            payload = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return metadata

        if isinstance(payload, dict):
            metadata["model"] = payload.get("model")
            metadata["stream"] = payload.get("stream")

        return metadata

    def _build_entry(
        self,
        request: Request,
        request_id: str,
        status_code: int,
        duration_ms: float,
        body_metadata: Dict[str, Any],
        error_message: Optional[str],
    ) -> Dict[str, Any]:
        """
        Build a safe request log entry.

        Args:
            request: Incoming request.
            request_id: Generated request identifier.
            status_code: Response status code.
            duration_ms: Request handling time.
            body_metadata: Extracted safe body metadata.
            error_message: Exception message for unexpected failures.

        Returns:
            Request log entry.
        """
        client_host = request.client.host if request.client else None
        api_key_id = getattr(request.state, "api_key_id", None)
        api_key_name = getattr(request.state, "api_key_name", None)
        kiro_account_id = getattr(request.state, "kiro_account_id", None)
        kiro_auth_type = getattr(request.state, "kiro_auth_type", None)
        kiro_account_display_name = self._resolve_account_display_name(request, kiro_account_id)
        effective_model = getattr(request.state, "kiro_model", None)
        requested_model = getattr(request.state, "requested_model", body_metadata.get("model"))
        token_usage = self._normalize_token_usage(getattr(request.state, "token_usage", None))

        return {
            "id": request_id,
            "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "method": request.method,
            "path": request.url.path,
            "api_surface": self._classify_api_surface(request.url.path),
            "status_code": status_code,
            "duration_ms": duration_ms,
            "client_host": client_host,
            "api_key_id": api_key_id,
            "api_key_name": api_key_name,
            "model": effective_model or body_metadata.get("model"),
            "requested_model": requested_model,
            "stream": body_metadata.get("stream"),
            "body_bytes": body_metadata.get("body_bytes", 0),
            "kiro_account_id": kiro_account_id,
            "kiro_account_display_name": kiro_account_display_name,
            "kiro_auth_type": kiro_auth_type,
            "token_usage": token_usage,
            "input_tokens": token_usage.get("input_tokens") if token_usage else None,
            "output_tokens": token_usage.get("output_tokens") if token_usage else None,
            "total_tokens": token_usage.get("total_tokens") if token_usage else None,
            "credits_used": token_usage.get("credits_used") if token_usage else None,
            "error": error_message,
        }

    @staticmethod
    def _resolve_account_display_name(request: Request, account_id: Optional[str]) -> Optional[str]:
        """
        Resolve the display name for the upstream Kiro account.

        Args:
            request: Incoming request with state/app references.
            account_id: Raw runtime Kiro account ID.

        Returns:
            Human-readable display name, or None when unavailable.
        """
        state_display_name = getattr(request.state, "kiro_account_display_name", None)
        if state_display_name:
            return state_display_name

        if not account_id:
            return None

        app = getattr(request, "app", None)
        app_state = getattr(app, "state", None)
        account_manager = getattr(app_state, "account_manager", None)
        resolver = getattr(account_manager, "resolve_account_display_name", None)
        if not callable(resolver):
            return None

        try:
            return resolver(account_id)
        except (OSError, RuntimeError, ValueError, AttributeError) as e:
            logger.debug(f"Failed to resolve request log account display name: {e}")
            return None

    @staticmethod
    def _normalize_token_usage(raw_usage: Any) -> Optional[Dict[str, Any]]:
        """
        Normalize OpenAI and Anthropic usage objects for request logs.

        Args:
            raw_usage: Usage dictionary from the response path.

        Returns:
            Normalized token usage dictionary, or None when unavailable.
        """
        if not isinstance(raw_usage, dict):
            return None

        input_tokens = RequestLogMiddleware._coerce_int(
            raw_usage.get("input_tokens", raw_usage.get("prompt_tokens"))
        )
        output_tokens = RequestLogMiddleware._coerce_int(
            raw_usage.get("output_tokens", raw_usage.get("completion_tokens"))
        )
        total_tokens = RequestLogMiddleware._coerce_int(raw_usage.get("total_tokens"))
        if total_tokens is None and input_tokens is not None and output_tokens is not None:
            total_tokens = input_tokens + output_tokens

        normalized: Dict[str, Any] = {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": total_tokens,
        }

        for key in ("credits_used", "cache_read_input_tokens", "cache_creation_input_tokens"):
            if key in raw_usage:
                normalized[key] = raw_usage[key]

        return normalized

    @staticmethod
    def _coerce_int(value: Any) -> Optional[int]:
        """
        Convert a token value to int when possible.

        Args:
            value: Token value from a response usage object.

        Returns:
            Integer token value, or None when unavailable.
        """
        if isinstance(value, bool) or value is None:
            return None
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value)
        if isinstance(value, str) and value.strip().isdigit():
            return int(value.strip())
        return None

    @staticmethod
    def _classify_api_surface(path: str) -> str:
        """
        Classify the gateway API surface by path.

        Args:
            path: Request path.

        Returns:
            API surface label.
        """
        if path == "/v1/chat/completions":
            return "openai"
        if path == "/v1/messages":
            return "anthropic"
        if path == "/v1/models":
            return "models"
        return "unknown"


def get_request_log_store() -> RequestLogStore:
    """
    Create a request log store for the currently configured path.

    Returns:
        RequestLogStore instance.
    """
    return RequestLogStore(
        file_path=config.REQUEST_LOG_FILE,
        max_entries=config.REQUEST_LOG_MAX_ENTRIES,
    )
