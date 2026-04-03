# Copyright (C) 2020-2026 RESCOR LLC. All rights reserved.
#
# This file is part of AccessGuard.
#
# AccessGuard is free software: you can redistribute it and/or modify it
# under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or (at
# your option) any later version.
#
# AccessGuard is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public
# License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with AccessGuard. If not, see <https://www.gnu.org/licenses/>.
#
"""
Abstract model provider and concrete implementations for AI-powered analysis.

The ModelProvider base class defines the interface. Each LLM vendor gets a
concrete subclass. The RoleAnalyzer uses whichever provider is configured
without knowing the underlying API.
"""

import json
import logging
import os
from abc import ABC, abstractmethod

_LOGGER = logging.getLogger(__name__)


class ModelProvider(ABC):
    """
    Abstract base class for LLM providers. Subclass this to add support
    for a new LLM vendor (OpenAI, AWS Bedrock, Google, etc.).
    """

    def __init__(self, model_id: str, max_tokens: int = 4096):
        self.model_id = model_id
        self.max_tokens = max_tokens

    @abstractmethod
    def analyze(self, system_prompt: str, user_prompt: str) -> dict:
        """
        Send a prompt to the model and return the parsed JSON response.
        Raises ValueError if the response is not valid JSON.
        """
        ...

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Human-readable provider name for logging and reports."""
        ...

    def __repr__(self):
        return f"{self.provider_name}({self.model_id})"


class AnthropicProvider(ModelProvider):
    """
    Concrete provider for Anthropic Claude models.
    API key from ANTHROPIC_API_KEY environment variable.
    """

    # Model shortcuts — user can pass a short name or a full model ID
    ALIASES = {
        "opus": "claude-opus-4-6",
        "sonnet": "claude-sonnet-4-6",
        "haiku": "claude-haiku-4-5-20251001",
    }

    def __init__(self, model_id: str = "claude-sonnet-4-6", max_tokens: int = 4096):
        resolved = self.ALIASES.get(model_id, model_id)
        super().__init__(model_id=resolved, max_tokens=max_tokens)

        import anthropic
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise EnvironmentError(
                "ANTHROPIC_API_KEY environment variable is required "
                "for AI-powered analysis. Set it or use --no-ai."
            )
        self.client = anthropic.Anthropic(api_key=api_key)

    @property
    def provider_name(self) -> str:
        return "Anthropic"

    def analyze(self, system_prompt: str, user_prompt: str) -> dict:
        """Send prompt to Claude, return parsed JSON response."""
        _LOGGER.info(f"Sending analysis request to {self.model_id}")

        response = self.client.messages.create(
            model=self.model_id,
            max_tokens=self.max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )

        # Extract text from response
        text = response.content[0].text

        # Parse JSON from response — handle markdown code fences
        text = text.strip()
        if text.startswith("```"):
            # Remove opening fence (with optional language tag)
            first_newline = text.index("\n")
            text = text[first_newline + 1:]
            # Remove closing fence
            if text.endswith("```"):
                text = text[:-3].strip()

        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            _LOGGER.error(f"Model response was not valid JSON: {e}")
            _LOGGER.debug(f"Raw response: {text[:500]}")
            raise ValueError(f"Model returned non-JSON response: {e}")
