import pytest
from pydantic import ValidationError

from egsi.generation.batch import BatchResult


def test_batch_result_keeps_failures() -> None:
    result = BatchResult(processed=["a"], failed={"b": "invalid JSON"})

    assert result.processed == ["a"]
    assert result.failed == {"b": "invalid JSON"}


def test_batch_result_defaults_are_empty_and_independent() -> None:
    first = BatchResult()
    second = BatchResult()

    first.processed.append("case-a")
    first.failed["case-b"] = "bad response"

    assert second.processed == []
    assert second.failed == {}


def test_batch_result_rejects_non_json_container_coercion() -> None:
    with pytest.raises(ValidationError):
        BatchResult(processed=("case-a",))


def test_batch_result_forbids_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        BatchResult(processed=[], failed={}, dropped=["case-a"])


def test_batch_result_json_round_trip_keeps_exact_failures() -> None:
    result = BatchResult(
        processed=["case-a"],
        failed={"case-b": "invalid JSON\nprovider response rejected"},
    )

    restored = BatchResult.model_validate_json(result.model_dump_json())

    assert restored == result
