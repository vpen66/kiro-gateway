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
        response: Optional[Response] = None
        error_message: Optional[str] = None

        try:
            response = await call_next(request)
            return response
        except RuntimeError as e:
            error_message = str(e)
            raise
        except ValueError as e:
            error_message = str(e)
            raise
        finally:
            status_code = response.status_code if response else 500
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
            "model": body_metadata.get("model"),
            "stream": body_metadata.get("stream"),
            "body_bytes": body_metadata.get("body_bytes", 0),
            "kiro_account_id": kiro_account_id,
            "kiro_auth_type": kiro_auth_type,
            "error": error_message,
        }

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
