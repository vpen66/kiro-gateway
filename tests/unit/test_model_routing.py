# -*- coding: utf-8 -*-

"""
Tests for kiro/model_routing.py.

These tests cover opt-in trigger handling, complexity scoring,
candidate selection, and request model mutation for both API surfaces.
"""

from unittest.mock import patch

from kiro.model_routing import (
    TaskDifficulty,
    apply_anthropic_auto_model_routing,
    apply_openai_auto_model_routing,
    is_auto_kiro_model,
    select_auto_kiro_fallback_model,
    should_auto_route_model,
    should_retry_with_auto_kiro,
)
from kiro.models_anthropic import AnthropicMessage, AnthropicMessagesRequest, AnthropicTool
from kiro.models_openai import ChatCompletionRequest, ChatMessage
from kiro.runtime_settings import AutoModelRoutingSettings


def _routing_settings(
    *,
    enabled: bool,
    trigger_models=None,
    simple_models=None,
    medium_models=None,
    hard_models=None,
) -> AutoModelRoutingSettings:
    """Build test routing settings."""
    return AutoModelRoutingSettings(
        enabled=enabled,
        trigger_models=list(trigger_models or ["auto-kiro"]),
        simple_models=list(simple_models or ["claude-haiku-4.5", "auto-kiro"]),
        medium_models=list(medium_models or ["claude-sonnet-4.5", "claude-haiku-4.5"]),
        hard_models=list(hard_models or ["claude-opus-4.7", "claude-sonnet-4.5"]),
    )


class TestShouldAutoRouteModel:
    """Tests for trigger matching."""

    def test_returns_false_when_feature_is_disabled(self):
        """
        What it does: Checks trigger matching while routing is disabled.
        Purpose: Ensure the feature is opt-in.
        """
        print("\n=== Test: should_auto_route_model returns false when disabled ===")

        with patch(
            "kiro.model_routing.get_auto_model_routing_settings",
            return_value=_routing_settings(enabled=False),
        ):
            assert should_auto_route_model("auto-kiro") is False

    def test_returns_true_for_trigger_model_when_enabled(self):
        """
        What it does: Checks trigger matching for a configured routing alias.
        Purpose: Ensure trigger models activate automatic routing.
        """
        print("\n=== Test: should_auto_route_model returns true for trigger model ===")

        with patch(
            "kiro.model_routing.get_auto_model_routing_settings",
            return_value=_routing_settings(enabled=True, trigger_models=["auto", "auto-kiro"]),
        ):
            assert should_auto_route_model("auto-kiro") is True


class TestAutoKiroFallback:
    """Tests for 503 fallback selection."""

    def test_identifies_public_and_internal_auto_models(self):
        """
        What it does: Checks both public and internal names for Kiro auto.
        Purpose: Prevent fallback loops when a request is already using auto.
        """
        print("\n=== Test: is_auto_kiro_model recognizes aliases ===")

        assert is_auto_kiro_model("auto-kiro") is True
        assert is_auto_kiro_model("auto") is True
        assert is_auto_kiro_model("claude-opus-4.7") is False

    def test_retries_only_once_for_503_concrete_models(self):
        """
        What it does: Validates the status/model guard for auto-kiro fallback.
        Purpose: Ensure only concrete-model 503 errors trigger one fallback attempt.
        """
        print("\n=== Test: should_retry_with_auto_kiro guards fallback ===")

        assert should_retry_with_auto_kiro(503, "claude-opus-4.7", False) is True
        assert should_retry_with_auto_kiro(503, "claude-opus-4.7", True) is False
        assert should_retry_with_auto_kiro(503, "auto-kiro", False) is False
        assert should_retry_with_auto_kiro(500, "claude-opus-4.7", False) is False

    def test_selects_public_alias_before_internal_auto(self):
        """
        What it does: Selects fallback model from available model names.
        Purpose: Prefer the downstream-safe auto-kiro alias over the raw Kiro name.
        """
        print("\n=== Test: select_auto_kiro_fallback_model prefers alias ===")

        assert select_auto_kiro_fallback_model(["auto", "auto-kiro"]) == "auto-kiro"
        assert select_auto_kiro_fallback_model(["auto"]) == "auto"
        assert select_auto_kiro_fallback_model(["claude-sonnet-4.5"]) is None


class TestOpenAIModelRouting:
    """Tests for OpenAI request routing."""

    def test_simple_request_routes_to_simple_candidate(self):
        """
        What it does: Routes a short single-turn request.
        Purpose: Ensure low-complexity tasks pick the fast model tier.
        """
        print("\n=== Test: OpenAI simple request routes to simple candidate ===")

        request_data = ChatCompletionRequest(
            model="auto-kiro",
            messages=[ChatMessage(role="user", content="Say hello in one line.")],
        )

        with patch(
            "kiro.model_routing.get_auto_model_routing_settings",
            return_value=_routing_settings(
                enabled=True,
                trigger_models=["auto-kiro"],
                simple_models=["claude-haiku-4.5", "auto-kiro"],
            ),
        ):
            decision = apply_openai_auto_model_routing(
                request_data,
                ["claude-haiku-4.5", "claude-sonnet-4.5", "auto-kiro"],
            )

        assert decision is not None
        assert decision.difficulty == TaskDifficulty.SIMPLE
        assert decision.selected_model == "claude-haiku-4.5"
        assert request_data.model == "claude-haiku-4.5"

    def test_medium_request_routes_to_medium_candidate(self):
        """
        What it does: Routes a multi-turn request with larger context.
        Purpose: Ensure medium complexity tasks prefer the sonnet tier.
        """
        print("\n=== Test: OpenAI medium request routes to medium candidate ===")

        request_data = ChatCompletionRequest(
            model="auto-kiro",
            messages=[
                ChatMessage(role="user", content="Please review this plan."),
                ChatMessage(role="assistant", content="Share the details."),
                ChatMessage(role="user", content="A" * 1500),
                ChatMessage(role="assistant", content="Noted."),
            ],
        )

        with patch(
            "kiro.model_routing.get_auto_model_routing_settings",
            return_value=_routing_settings(
                enabled=True,
                trigger_models=["auto-kiro"],
                medium_models=["claude-sonnet-4.5", "claude-haiku-4.5"],
            ),
        ):
            decision = apply_openai_auto_model_routing(
                request_data,
                ["claude-haiku-4.5", "claude-sonnet-4.5"],
            )

        assert decision is not None
        assert decision.difficulty == TaskDifficulty.MEDIUM
        assert decision.selected_model == "claude-sonnet-4.5"
        assert request_data.model == "claude-sonnet-4.5"

    def test_falls_back_to_first_available_candidate(self):
        """
        What it does: Routes when the preferred simple candidate is unavailable.
        Purpose: Ensure routing still succeeds with the next configured option.
        """
        print("\n=== Test: OpenAI routing falls back to next available candidate ===")

        request_data = ChatCompletionRequest(
            model="auto-kiro",
            messages=[ChatMessage(role="user", content="Quick summary please.")],
        )

        with patch(
            "kiro.model_routing.get_auto_model_routing_settings",
            return_value=_routing_settings(
                enabled=True,
                trigger_models=["auto-kiro"],
                simple_models=["claude-haiku-4.5", "auto-kiro"],
            ),
        ):
            decision = apply_openai_auto_model_routing(
                request_data,
                ["auto-kiro"],
            )

        assert decision is not None
        assert decision.selected_model == "auto-kiro"
        assert request_data.model == "auto-kiro"

    def test_non_trigger_model_is_left_unchanged(self):
        """
        What it does: Sends an explicit concrete model.
        Purpose: Ensure explicit user model choices are preserved.
        """
        print("\n=== Test: OpenAI explicit model is not auto-routed ===")

        request_data = ChatCompletionRequest(
            model="claude-sonnet-4.5",
            messages=[ChatMessage(role="user", content="Hello")],
        )

        with patch(
            "kiro.model_routing.get_auto_model_routing_settings",
            return_value=_routing_settings(enabled=True, trigger_models=["auto-kiro"]),
        ):
            decision = apply_openai_auto_model_routing(
                request_data,
                ["claude-sonnet-4.5", "auto-kiro"],
            )

        assert decision is None
        assert request_data.model == "claude-sonnet-4.5"


class TestAnthropicModelRouting:
    """Tests for Anthropic request routing."""

    def test_hard_request_routes_to_hard_candidate(self):
        """
        What it does: Routes a request with tools and explicit thinking.
        Purpose: Ensure high-complexity tasks prefer the strongest configured tier.
        """
        print("\n=== Test: Anthropic hard request routes to hard candidate ===")

        request_data = AnthropicMessagesRequest(
            model="auto-kiro",
            max_tokens=1024,
            thinking={"type": "enabled", "budget_tokens": 2048},
            tools=[
                AnthropicTool(
                    name="lookup",
                    description="Search internal data",
                    input_schema={"type": "object", "properties": {"query": {"type": "string"}}},
                )
            ],
            messages=[
                AnthropicMessage(
                    role="user",
                    content=[
                        {"type": "text", "text": "Investigate this service regression."},
                        {"type": "image", "source": {"type": "url", "url": "https://example.com/a.png"}},
                        {"type": "text", "text": "```python\nprint('debug')\n```"},
                    ],
                )
            ],
        )

        with patch(
            "kiro.model_routing.get_auto_model_routing_settings",
            return_value=_routing_settings(
                enabled=True,
                trigger_models=["auto-kiro"],
                hard_models=["claude-opus-4.7", "claude-sonnet-4.5"],
            ),
        ):
            decision = apply_anthropic_auto_model_routing(
                request_data,
                ["claude-opus-4.7", "claude-sonnet-4.5"],
            )

        assert decision is not None
        assert decision.difficulty == TaskDifficulty.HARD
        assert decision.selected_model == "claude-opus-4.7"
        assert request_data.model == "claude-opus-4.7"

    def test_no_available_candidate_returns_none(self):
        """
        What it does: Tries to route when no configured candidate exists.
        Purpose: Ensure the request is left unchanged instead of failing locally.
        """
        print("\n=== Test: Anthropic routing returns none when no candidate matches ===")

        request_data = AnthropicMessagesRequest(
            model="auto-kiro",
            max_tokens=256,
            messages=[AnthropicMessage(role="user", content="Hello")],
        )

        with patch(
            "kiro.model_routing.get_auto_model_routing_settings",
            return_value=_routing_settings(
                enabled=True,
                trigger_models=["auto-kiro"],
                simple_models=["claude-haiku-4.5"],
            ),
        ):
            decision = apply_anthropic_auto_model_routing(request_data, ["deepseek-3.2"])

        assert decision is None
        assert request_data.model == "auto-kiro"
