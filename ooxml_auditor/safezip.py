"""Bounds-checked reading of OOXML ZIP containers.

All member names and relationship targets are normalized and verified to
stay inside the package root so that ``..`` segments, absolute paths or
hostile sizes cannot cause out-of-bounds reads or decompression bombs.
"""

from __future__ import annotations

import posixpath
import zipfile


MAX_MEMBERS = 10_000
MAX_MEMBER_UNCOMPRESSED = 64 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED = 256 * 1024 * 1024
MAX_COMPRESSION_RATIO = 100


class ContainerError(Exception):
    """The ZIP container is corrupt or violates safety limits."""


class PathTraversalError(ContainerError):
    """A part name or relationship target escapes the package root."""


def normalize_part_name(name: str) -> str:
    """Normalize a ZIP member / part name and confine it to the package root."""
    if not name or "\x00" in name:
        raise PathTraversalError(f"invalid part name: {name!r}")
    name = name.replace("\\", "/")
    if name.startswith("/") or (len(name) > 1 and name[1] == ":"):
        raise PathTraversalError(f"absolute part name not allowed: {name!r}")
    normalized = posixpath.normpath(name)
    if normalized in (".", "..") or normalized.startswith("../"):
        raise PathTraversalError(f"part name escapes package root: {name!r}")
    return normalized


def resolve_target(source_part: str, target: str) -> str:
    """Resolve an internal relationship target against its source part.

    The result is guaranteed to stay inside the package root; anything
    else raises :class:`PathTraversalError`.
    """
    if not target or "\x00" in target:
        raise PathTraversalError(f"invalid relationship target: {target!r}")
    cleaned = target.replace("\\", "/")
    if cleaned.startswith("/") or (len(cleaned) > 1 and cleaned[1] == ":"):
        raise PathTraversalError(f"absolute relationship target not allowed: {target!r}")
    base = posixpath.dirname(source_part)
    resolved = posixpath.normpath(posixpath.join(base, cleaned))
    if resolved in (".", "..") or resolved.startswith("../"):
        raise PathTraversalError(
            f"relationship target escapes package root: {target!r} (from {source_part!r})"
        )
    return resolved


class SafeZip:
    """A zipfile wrapper enforcing member, size and ratio limits."""

    def __init__(self, source):
        try:
            self._zip = zipfile.ZipFile(source)
        except zipfile.BadZipFile as exc:
            raise ContainerError(f"not a valid ZIP/OOXML container: {exc}") from exc
        self._names: dict[str, zipfile.ZipInfo] = {}
        self._validate()

    def _validate(self) -> None:
        infos = self._zip.infolist()
        if len(infos) > MAX_MEMBERS:
            raise ContainerError(f"too many members: {len(infos)} > {MAX_MEMBERS}")
        total = 0
        for info in infos:
            name = normalize_part_name(info.filename)
            if info.is_dir():
                continue
            if info.file_size > MAX_MEMBER_UNCOMPRESSED:
                raise ContainerError(
                    f"member {name!r} too large: {info.file_size} bytes"
                )
            if info.compress_size > 0 and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO:
                raise ContainerError(
                    f"member {name!r} exceeds compression ratio limit"
                )
            total += info.file_size
            if total > MAX_TOTAL_UNCOMPRESSED:
                raise ContainerError("aggregate uncompressed size exceeds limit")
            self._names[name] = info

    def names(self) -> list:
        return sorted(self._names)

    def __contains__(self, name: str) -> bool:
        return name in self._names

    def read(self, name: str) -> bytes:
        if name not in self._names:
            raise ContainerError(f"part not present in container: {name!r}")
        return self._zip.read(self._names[name])

    def close(self) -> None:
        self._zip.close()

    def __enter__(self) -> "SafeZip":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
