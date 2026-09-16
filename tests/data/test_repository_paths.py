"""Repository blob paths have one byte-exact canonical representation."""

from __future__ import annotations

import pytest

from egsi.data.repository_paths import canonical_repo_blob_path


@pytest.mark.parametrize(
    "value",
    [
        "./A.java",
        "a//b.java",
        "../A.java",
        "a/../A.java",
        "/A.java",
        "a\\b.java",
        "A.java/",
        "",
        ".",
        "A.java\x00suffix",
        "A.java\n",
    ],
)
def test_rejects_noncanonical_repository_blob_paths(value: str) -> None:
    with pytest.raises(ValueError, match="canonical repository-relative POSIX blob path"):
        canonical_repo_blob_path(value)


@pytest.mark.parametrize(
    "value",
    [
        "A.java",
        "src/main/java/example/A.java",
        "src/with space/A.java",
        "src/é/A.java",
    ],
)
def test_accepts_byte_exact_repository_relative_posix_blob_paths(value: str) -> None:
    assert canonical_repo_blob_path(value) == value
