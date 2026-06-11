"""
LLM client layer for Certior agents.

Supports multiple providers (Anthropic, OpenAI) with automatic detection.
Use ``create_llm_client()`` to get the right client for your configuration.
"""
from .config import LLMConfig
from .client import AnthropicClient, LLMResponse, ToolCallRequest, TokenUsage
from .openai_client import OpenAIClient
from .factory import create_llm_client, detect_provider, PROVIDER_DEFAULTS

__all__ = [
    "LLMConfig",
    "AnthropicClient",
    "OpenAIClient",
    "LLMResponse",
    "ToolCallRequest",
    "TokenUsage",
    "create_llm_client",
    "detect_provider",
    "PROVIDER_DEFAULTS",
]
