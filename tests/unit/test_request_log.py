# -*- coding: utf-8 -*-

"""
Tests for request_log.py.

These tests verify request log persistence, retention, clearing, and
newest-first listing behavior.
"""

import json
from types import SimpleNamespace

from kiro.request_log import RequestLogMiddleware, RequestLogStore


class TestRequestLogStore:
    """Tests for JSONL request log storage."""

    def test_append_and_list_entries_newest_first(self, tmp_path):
        """
        What it does: Appends two request log entries and lists them.
        Purpose: Ensure logs are returned newest first for the admin UI.
        """
        print("\n=== Test: Request logs list newest first ===")

        # Arrange
        store = RequestLogStore(str(tmp_path / "requests.jsonl"), max_entries=10)
        first = {"id": "first", "status_code": 200}
        second = {"id": "second", "status_code": 500}

        # Act
        store.append(first)
        store.append(second)
        entries = store.list_entries(limit=10)

        # Assert
        assert [entry["id"] for entry in entries] == ["second", "first"]

    def test_retention_trims_old_entries(self, tmp_path):
        """
        What it does: Appends more entries than max_entries.
        Purpose: Ensure old logs are trimmed and disk usage stays bounded.
        """
        print("\n=== Test: Request log retention trims old entries ===")

        # Arrange
        log_file = tmp_path / "requests.jsonl"
        store = RequestLogStore(str(log_file), max_entries=2)

        # Act
        store.append({"id": "one"})
        store.append({"id": "two"})
        store.append({"id": "three"})

        # Assert
        lines = log_file.read_text().splitlines()
        assert len(lines) == 2
        assert [json.loads(line)["id"] for line in lines] == ["two", "three"]
        assert [entry["id"] for entry in store.list_entries(limit=10)] == ["three", "two"]

    def test_clear_removes_log_file(self, tmp_path):
        """
        What it does: Clears an existing request log file.
        Purpose: Ensure the admin clear action removes all log entries.
        """
        print("\n=== Test: Clearing request logs removes file ===")

        # Arrange
        log_file = tmp_path / "requests.jsonl"
        store = RequestLogStore(str(log_file), max_entries=10)
        store.append({"id": "entry"})

        # Act
        store.clear()

        # Assert
        assert not log_file.exists()
        assert store.list_entries(limit=10) == []

    def test_malformed_lines_are_skipped(self, tmp_path):
        """
        What it does: Reads a log file containing malformed JSON.
        Purpose: Ensure one bad line does not break log management.
        """
        print("\n=== Test: Malformed request log lines are skipped ===")

        # Arrange
        log_file = tmp_path / "requests.jsonl"
        log_file.write_text('{"id": "ok"}\nnot-json\n', encoding="utf-8")
        store = RequestLogStore(str(log_file), max_entries=10)

        # Act
        entries = store.list_entries(limit=10)

        # Assert
        assert entries == [{"id": "ok"}]


class TestRequestLogMiddleware:
    """Tests for request metadata entry construction."""

    def test_build_entry_includes_client_key_and_upstream_account(self):
        """
        What it does: Builds a request log entry with request state metadata.
        Purpose: Ensure logs show both local proxy key and upstream Kiro account.
        """
        print("\n=== Test: Request log includes upstream account metadata ===")

        # Arrange
        middleware = RequestLogMiddleware(app=SimpleNamespace())
        request = SimpleNamespace(
            client=SimpleNamespace(host="127.0.0.1"),
            state=SimpleNamespace(
                api_key_id="local-key-id",
                api_key_name="Claude workstation",
                kiro_account_id="/tmp/kiro-auth-token.json",
                kiro_auth_type="kiro_desktop",
                kiro_account_display_name="alice@example.com",
                requested_model="claude-opus-4.7",
                kiro_model="auto-kiro",
                token_usage={
                    "input_tokens": 120,
                    "output_tokens": 34,
                    "cache_read_input_tokens": 10,
                },
            ),
            method="POST",
            url=SimpleNamespace(path="/v1/messages"),
        )

        # Act
        entry = middleware._build_entry(
            request=request,
            request_id="request-id",
            status_code=200,
            duration_ms=12.5,
            body_metadata={"model": "claude-sonnet-4.5", "stream": True, "body_bytes": 123},
            error_message=None,
        )

        # Assert
        assert entry["api_key_name"] == "Claude workstation"
        assert entry["kiro_account_id"] == "/tmp/kiro-auth-token.json"
        assert entry["kiro_account_display_name"] == "alice@example.com"
        assert entry["kiro_auth_type"] == "kiro_desktop"
        assert entry["model"] == "auto-kiro"
        assert entry["requested_model"] == "claude-opus-4.7"
        assert entry["input_tokens"] == 120
        assert entry["output_tokens"] == 34
        assert entry["total_tokens"] == 154
        assert entry["token_usage"]["cache_read_input_tokens"] == 10
