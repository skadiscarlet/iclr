"""Provider-neutral teacher adapters and disk caching."""

from .anthropic import AnthropicTeacher
from .base import (
    UNREPORTED_PROVIDER_MODEL,
    Teacher,
    TeacherRequest,
    TeacherResponse,
    committed_teacher_response,
    teacher_response_commitment,
)
from .cache import CachedTeacher
from .codex_exec import CodexExecTeacher
from .openai_compatible import OpenAICompatibleTeacher

__all__ = [
    "AnthropicTeacher",
    "CachedTeacher",
    "CodexExecTeacher",
    "OpenAICompatibleTeacher",
    "Teacher",
    "TeacherRequest",
    "TeacherResponse",
    "UNREPORTED_PROVIDER_MODEL",
    "committed_teacher_response",
    "teacher_response_commitment",
]
