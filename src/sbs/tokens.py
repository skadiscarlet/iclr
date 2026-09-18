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

    def count_chat(
        self,
        messages: list[dict[str, str]],
        *,
        add_generation_prompt: bool = True,
    ) -> tuple[int, list[int], str]:
        return count_chat_tokens(
            self._tokenizer, messages, add_generation_prompt=add_generation_prompt
        )


def count_chat_tokens(
    tokenizer: object,
    messages: list[dict[str, str]],
    *,
    add_generation_prompt: bool = True,
) -> tuple[int, list[int], str]:
    """Count the actual sent chat sequence. Prefer tokenize=True on the template."""

    apply = getattr(tokenizer, "apply_chat_template", None)
    if apply is None:
        raise TypeError("tokenizer must provide apply_chat_template")
    try:
        encoded = apply(
            messages,
            tokenize=True,
            add_generation_prompt=add_generation_prompt,
        )
        ids = _coerce_id_list(encoded)
        return len(ids), ids, "apply_chat_template_tokenize_true"
    except TypeError:
        text = apply(
            messages,
            tokenize=False,
            add_generation_prompt=add_generation_prompt,
        )
        ids = list(tokenizer.encode(text, add_special_tokens=False))
        return len(ids), ids, "template_text_then_encode_no_special"


def _coerce_id_list(encoded: object) -> list[int]:
    if hasattr(encoded, "tolist"):
        encoded = encoded.tolist()
    if isinstance(encoded, list) and encoded and isinstance(encoded[0], list):
        encoded = encoded[0]
    return [int(x) for x in encoded]  # type: ignore[arg-type]


class CharChatTokenCounter(CharTokenCounter):
    """Test counter that still exercises the chat-template counting API."""

    def apply_chat_template(
        self,
        messages: list[dict[str, str]],
        *,
        tokenize: bool = False,
        add_generation_prompt: bool = True,
    ):
        text = "".join(f"<|{m['role']}|>{m['content']}" for m in messages)
        if add_generation_prompt:
            text += "<|assistant|>"
        if tokenize:
            return list(range(len(text)))
        return text

    def encode(self, text: str, add_special_tokens: bool = False) -> list[int]:
        if add_special_tokens:
            raise AssertionError("chat-template path must encode with add_special_tokens=False")
        return list(range(len(text)))

    def decode(self, ids: list[int], skip_special_tokens: bool = True) -> str:
        return "x" * len(ids)

    def count_chat(
        self,
        messages: list[dict[str, str]],
        *,
        add_generation_prompt: bool = True,
    ) -> tuple[int, list[int], str]:
        return count_chat_tokens(
            self, messages, add_generation_prompt=add_generation_prompt
        )
