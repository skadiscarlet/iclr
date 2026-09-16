"""One strict representation for repository-relative Git blob paths."""

from __future__ import annotations

from pathlib import PurePosixPath


_ERROR = "path must be a canonical repository-relative POSIX blob path"


def canonical_repo_blob_path(value: str) -> str:
    """Return ``value`` only when it is already byte-exact and canonical.

    This deliberately does not normalize provider-controlled input.  A spelling such
    as ``./src/A.java`` must not become an alias for ``src/A.java`` after validation.
    """

    if type(value) is not str or not value:
        raise ValueError(_ERROR)
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeError:
        raise ValueError(_ERROR) from None
    if (
        "\\" in value
        or ":" in value
        or value.endswith("/")
        or "//" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError(_ERROR)
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.as_posix() != value
        or value == "."
    ):
        raise ValueError(_ERROR)
    return value
