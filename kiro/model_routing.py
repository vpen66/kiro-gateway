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
Automatic task-based model routing.

This module provides an opt-in routing layer that can map trigger models
(for example ``auto-kiro``) to concrete models based on request complexity.
Explicit user model choices are preserved unless the feature is enabled and the
request model matches the configured trigger set.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, List, Optional, Sequence

from loguru import logger

from kiro.model_resolver import normalize_model_name
from kiro.models_anthropic import AnthropicMessagesRequest
from kiro.models_openai import ChatCompletionRequest
from kiro.runtime_settings import AutoModelRoutingSettings, get_auto_model_routing_settings


class TaskDifficulty(str, Enum):
    """
    Complexity bucket used for automatic model routing.
    """

    SIMPLE = "simple"
    MEDIUM = "medium"
    HARD = "hard"


@dataclass(frozen=True)
class RoutingSignals:
    """
    Signals extracted from a request for complexity scoring.

    Attributes:
        total_text_chars: Total number of extracted text characters.
        system_text_chars: Number of system prompt characters.
        message_count: Number of conversation messages.
        assistant_message_count: Number of assistant turns in the request history.
        tool_count: Number of tool definitions supplied by the client.
        image_count: Number of image content blocks detected.
        code_block_count: Number of fenced code block markers detected.
        reasoning_requested: Whether the client explicitly requested deeper reasoning.
        score: Aggregate complexity score.
    """

    total_text_chars: int
    system_text_chars: int
    message_count: int
    assistant_message_count: int
    tool_count: int
    image_count: int
    code_block_count: int
    reasoning_requested: bool
    score: int


@dataclass(frozen=True)
class ModelRoutingDecision:
    """
    Result of automatic model routing.

    Attributes:
        requested_model: Original model from the client.
        selected_model: Concrete model chosen after complexity analysis.
        difficulty: Derived difficulty bucket.
        signals: Raw signals used for scoring.
        reason: Human-readable summary for logs/debugging.
    """

    requested_model: str
    selected_model: str
    difficulty: TaskDifficulty
    signals: RoutingSignals
    reason: str


def should_auto_route_model(
    requested_model: str,
    settings: Optional[AutoModelRoutingSettings] = None,
) -> bool:
    """
    Determine whether automatic routing should be applied.

    Args:
        requested_model: Model string from the incoming request.
        settings: Optional preloaded runtime routing settings.

    Returns:
        True when routing is enabled and the request model is in the trigger set.
    """
    effective_settings = settings or get_auto_model_routing_settings()
    if not effective_settings.enabled or not requested_model:
        return False

    requested_key = requested_model.strip().lower()
    trigger_keys = {model.strip().lower() for model in effective_settings.trigger_models}
    return requested_key in trigger_keys


def apply_openai_auto_model_routing(
    request_data: ChatCompletionRequest,
    available_models: Sequence[str],
) -> Optional[ModelRoutingDecision]:
    """
    Route an OpenAI-compatible request to a concrete model when enabled.

    Args:
        request_data: OpenAI request object.
        available_models: Models currently available for routing.

    Returns:
        Routing decision when a concrete model was selected, otherwise None.
    """
    settings = get_auto_model_routing_settings()
    if not should_auto_route_model(request_data.model, settings):
        return None

    signals = _build_openai_signals(request_data)
    decision = _route_model(request_data.model, signals, available_models, settings)
    if decision is None:
        logger.warning(
            f"Auto model routing could not find a candidate for OpenAI request model={request_data.model}"
        )
        return None

    request_data.model = decision.selected_model
    logger.info(
        "Auto-routed OpenAI request model: "
        f"requested={decision.requested_model}, selected={decision.selected_model}, "
        f"difficulty={decision.difficulty.value}, score={decision.signals.score}"
    )
    return decision


def apply_anthropic_auto_model_routing(
    request_data: AnthropicMessagesRequest,
    available_models: Sequence[str],
) -> Optional[ModelRoutingDecision]:
    """
    Route an Anthropic-compatible request to a concrete model when enabled.

    Args:
        request_data: Anthropic request object.
        available_models: Models currently available for routing.

    Returns:
        Routing decision when a concrete model was selected, otherwise None.
    """
    settings = get_auto_model_routing_settings()
    if not should_auto_route_model(request_data.model, settings):
        return None

    signals = _build_anthropic_signals(request_data)
    decision = _route_model(request_data.model, signals, available_models, settings)
    if decision is None:
        logger.warning(
            f"Auto model routing could not find a candidate for Anthropic request model={request_data.model}"
        )
        return None

    request_data.model = decision.selected_model
    logger.info(
        "Auto-routed Anthropic request model: "
        f"requested={decision.requested_model}, selected={decision.selected_model}, "
        f"difficulty={decision.difficulty.value}, score={decision.signals.score}"
    )
    return decision


def _route_model(
    requested_model: str,
    signals: RoutingSignals,
    available_models: Sequence[str],
    settings: AutoModelRoutingSettings,
) -> Optional[ModelRoutingDecision]:
    """
    Select a concrete model for the given routing signals.

    Args:
        requested_model: Original client model.
        signals: Extracted complexity signals.
        available_models: Models available in the current runtime.
        settings: Effective automatic routing settings.

    Returns:
        Routing decision, or None when no configured candidate is available.
    """
    difficulty = _classify_difficulty(signals)
    candidate_models = _get_candidate_models_for_difficulty(difficulty, settings)
    selected_model = _select_available_model(candidate_models, available_models)
    if selected_model is None:
        return None

    return ModelRoutingDecision(
        requested_model=requested_model,
        selected_model=selected_model,
        difficulty=difficulty,
        signals=signals,
        reason=(
            f"score={signals.score}, text_chars={signals.total_text_chars}, "
            f"messages={signals.message_count}, tools={signals.tool_count}, "
            f"images={signals.image_count}, code_blocks={signals.code_block_count}, "
            f"reasoning={signals.reasoning_requested}"
        ),
    )


def _build_openai_signals(request_data: ChatCompletionRequest) -> RoutingSignals:
    """
    Build routing signals from an OpenAI request.

    Args:
        request_data: OpenAI request payload.

    Returns:
        Extracted routing signals.
    """
    message_payloads = [message.model_dump() for message in request_data.messages]
    return _build_signals(
        message_payloads=message_payloads,
        system_payload=None,
        tool_count=len(request_data.tools or []),
        reasoning_requested=(request_data.reasoning_effort or "").lower() in {"high", "xhigh"},
    )


def _build_anthropic_signals(request_data: AnthropicMessagesRequest) -> RoutingSignals:
    """
    Build routing signals from an Anthropic request.

    Args:
        request_data: Anthropic request payload.

    Returns:
        Extracted routing signals.
    """
    message_payloads = [message.model_dump() for message in request_data.messages]
    system_payload: Any = request_data.system
    if isinstance(system_payload, list):
        system_payload = [
            block.model_dump() if hasattr(block, "model_dump") else block
            for block in system_payload
        ]

    thinking_payload = request_data.thinking if isinstance(request_data.thinking, dict) else {}
    thinking_enabled = bool(thinking_payload) and thinking_payload.get("type") != "disabled"

    return _build_signals(
        message_payloads=message_payloads,
        system_payload=system_payload,
        tool_count=len(request_data.tools or []),
        reasoning_requested=thinking_enabled,
    )


def _build_signals(
    message_payloads: Sequence[Any],
    system_payload: Any,
    tool_count: int,
    reasoning_requested: bool,
) -> RoutingSignals:
    """
    Convert request payload data into scored routing signals.

    Args:
        message_payloads: Serialized request messages.
        system_payload: Optional system prompt payload.
        tool_count: Number of tool definitions.
        reasoning_requested: Whether the caller explicitly requested deeper reasoning.

    Returns:
        Scored routing signals.
    """
    message_text_fragments = list(_iter_text_fragments(message_payloads))
    system_text_fragments = list(_iter_text_fragments(system_payload))
    total_text_fragments = [*message_text_fragments, *system_text_fragments]

    total_text_chars = sum(len(fragment) for fragment in total_text_fragments)
    system_text_chars = sum(len(fragment) for fragment in system_text_fragments)
    message_count = len(message_payloads)
    assistant_message_count = sum(
        1
        for payload in message_payloads
        if isinstance(payload, dict) and payload.get("role") == "assistant"
    )
    image_count = _count_content_type([*message_payloads, system_payload], "image")
    code_block_count = sum(fragment.count("```") for fragment in total_text_fragments)

    score = 0
    if total_text_chars >= 4000:
        score += 3
    elif total_text_chars >= 1200:
        score += 1

    if message_count >= 8:
        score += 2
    elif message_count >= 4:
        score += 1

    if assistant_message_count >= 3:
        score += 1

    if tool_count >= 3:
        score += 3
    elif tool_count >= 1:
        score += 2

    if image_count >= 1:
        score += 2

    if reasoning_requested:
        score += 2

    if code_block_count >= 1:
        score += 1

    if system_text_chars >= 800:
        score += 1

    return RoutingSignals(
        total_text_chars=total_text_chars,
        system_text_chars=system_text_chars,
        message_count=message_count,
        assistant_message_count=assistant_message_count,
        tool_count=tool_count,
        image_count=image_count,
        code_block_count=code_block_count,
        reasoning_requested=reasoning_requested,
        score=score,
    )


def _classify_difficulty(signals: RoutingSignals) -> TaskDifficulty:
    """
    Map routing signals to a difficulty bucket.

    Args:
        signals: Scored routing signals.

    Returns:
        Difficulty bucket used for candidate model selection.
    """
    if signals.score >= 5:
        return TaskDifficulty.HARD
    if signals.score >= 2:
        return TaskDifficulty.MEDIUM
    return TaskDifficulty.SIMPLE


def _get_candidate_models_for_difficulty(
    difficulty: TaskDifficulty,
    settings: AutoModelRoutingSettings,
) -> List[str]:
    """
    Return configured candidate models for a difficulty bucket.

    Args:
        difficulty: Derived difficulty bucket.
        settings: Effective automatic routing settings.

    Returns:
        Ordered candidate model list.
    """
    if difficulty == TaskDifficulty.HARD:
        return list(settings.hard_models)
    if difficulty == TaskDifficulty.MEDIUM:
        return list(settings.medium_models)
    return list(settings.simple_models)


def _select_available_model(
    candidate_models: Sequence[str],
    available_models: Sequence[str],
) -> Optional[str]:
    """
    Select the first configured candidate that exists in the available model list.

    Args:
        candidate_models: Preferred models for the derived difficulty.
        available_models: Currently available models.

    Returns:
        Selected available model, or None when no candidate is available.
    """
    available_lookup = {
        normalize_model_name(model).lower(): model
        for model in available_models
    }

    for candidate in candidate_models:
        candidate_key = normalize_model_name(candidate).lower()
        if candidate_key in available_lookup:
            return available_lookup[candidate_key]

    return None


def _iter_text_fragments(payload: Any) -> Iterable[str]:
    """
    Recursively extract human text fragments from request payload content.

    Args:
        payload: Arbitrary message or system content payload.

    Yields:
        Text fragments used for routing heuristics.
    """
    if payload is None:
        return

    if isinstance(payload, str):
        yield payload
        return

    if hasattr(payload, "model_dump"):
        yield from _iter_text_fragments(payload.model_dump())
        return

    if isinstance(payload, list):
        for item in payload:
            yield from _iter_text_fragments(item)
        return

    if isinstance(payload, dict):
        payload_type = payload.get("type")
        if payload_type == "text" and isinstance(payload.get("text"), str):
            yield payload["text"]

        content = payload.get("content")
        if isinstance(content, (str, list, dict)):
            yield from _iter_text_fragments(content)

        text = payload.get("text")
        if isinstance(text, str) and payload_type != "text":
            yield text


def _count_content_type(payloads: Sequence[Any], expected_type: str) -> int:
    """
    Count recursively nested content blocks of a specific type.

    Args:
        payloads: Serialized payloads to inspect.
        expected_type: Content block type to count.

    Returns:
        Number of matching content blocks.
    """
    total = 0

    for payload in payloads:
        if payload is None:
            continue

        if hasattr(payload, "model_dump"):
            total += _count_content_type([payload.model_dump()], expected_type)
            continue

        if isinstance(payload, list):
            total += _count_content_type(payload, expected_type)
            continue

        if isinstance(payload, dict):
            if payload.get("type") == expected_type:
                total += 1

            content = payload.get("content")
            if isinstance(content, (list, dict)):
                total += _count_content_type([content], expected_type)

    return total
