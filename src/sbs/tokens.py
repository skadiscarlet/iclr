"""Token counters for shared context budgets. Real runs use the locked tokenizer."""

from __future__ import annotations

from typing import Protocol


class TokenCounter(Protocol):
    def count(self, text: str) -> int: ...

    def truncate(self, text: str, max_tokens: int) -> tuple[str, int, int]:
        """Return (text, start_token, end_token_exclusive)."""
        ...


class CharTokenCounter:
    """Invertible test counter: one character is one token."""

    def count(self, text: str) -> int:
        return len(text)

    def truncate(self, text: str, max_tokens: int) -> tuple[str, int, int]:
        if max_tokens < 0:
            raise ValueError("max_tokens must be >= 0")
        clipped = text[:max_tokens]
        return clipped, 0, len(clipped)


class HuggingFaceTokenCounter:
    def __init__(self, tokenizer: object) -> None:
        self._tokenizer = tokenizer

    def count(self, text: str) -> int:
        encoded = self._tokenizer.encode(text, add_special_tokens=False)
        return len(encoded)

    def truncate(self, text: str, max_tokens: int) -> tuple[str, int, int]:
        encoded = self._tokenizer.encode(text, add_special_tokens=False)
        clipped = encoded[:max_tokens]
        decoded = self._tokenizer.decode(clipped, skip_special_tokens=True)
        return decoded, 0, len(clipped)
