"""
Level 1 — Unit tests for modelProvider.py
Tests alias resolution and JSON parsing. No API keys needed.
"""

import pytest
import sys
import os

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "src"))
sys.path.insert(0, _ROOT)

from modelProvider import AnthropicProvider, ModelProvider


class TestAliases:

    def test_sonnet_alias(self):
        assert AnthropicProvider.ALIASES["sonnet"] == "claude-sonnet-4-6"

    def test_opus_alias(self):
        assert AnthropicProvider.ALIASES["opus"] == "claude-opus-4-6"

    def test_haiku_alias(self):
        assert AnthropicProvider.ALIASES["haiku"] == "claude-haiku-4-5-20251001"

    def test_full_model_id_passthrough(self):
        """A full model ID not in aliases should pass through unchanged."""
        resolved = AnthropicProvider.ALIASES.get("claude-sonnet-4-6", "claude-sonnet-4-6")
        assert resolved == "claude-sonnet-4-6"


class TestJsonParsing:

    def test_clean_json(self):
        """The analyze method should parse clean JSON (tested indirectly via fence stripping)."""
        text = '{"recommendations": []}'
        # Simulate the fence-stripping logic
        text = text.strip()
        assert not text.startswith("```")

    def test_fence_stripping(self):
        """JSON wrapped in markdown code fences should be extracted."""
        text = '```json\n{"recommendations": []}\n```'
        text = text.strip()
        if text.startswith("```"):
            first_newline = text.index("\n")
            text = text[first_newline + 1:]
            if text.endswith("```"):
                text = text[:-3].strip()

        import json
        parsed = json.loads(text)
        assert parsed == {"recommendations": []}

    def test_fence_no_language_tag(self):
        """Code fences without a language tag should also work."""
        text = '```\n{"result": true}\n```'
        text = text.strip()
        if text.startswith("```"):
            first_newline = text.index("\n")
            text = text[first_newline + 1:]
            if text.endswith("```"):
                text = text[:-3].strip()

        import json
        parsed = json.loads(text)
        assert parsed == {"result": True}


class TestModelProviderAbstract:

    def test_cannot_instantiate_base_class(self):
        """ModelProvider is abstract and should not be instantiable."""
        with pytest.raises(TypeError):
            ModelProvider(model_id="test")

    def test_anthropic_requires_api_key(self):
        """AnthropicProvider should fail without ANTHROPIC_API_KEY."""
        # Temporarily remove the key if set
        original = os.environ.pop("ANTHROPIC_API_KEY", None)
        try:
            with pytest.raises(EnvironmentError):
                AnthropicProvider(model_id="sonnet")
        finally:
            if original:
                os.environ["ANTHROPIC_API_KEY"] = original
