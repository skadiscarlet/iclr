"""Strict result contract shared by restartable batch orchestration."""

from pydantic import BaseModel, ConfigDict, Field, StrictStr


class BatchResult(BaseModel):
    """Preserve successful case IDs and every per-case failure message."""

    model_config = ConfigDict(extra="forbid", strict=True)

    processed: list[StrictStr] = Field(default_factory=list)
    failed: dict[StrictStr, StrictStr] = Field(default_factory=dict)
