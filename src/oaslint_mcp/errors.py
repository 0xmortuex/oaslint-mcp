"""Exception types. Everything here is an expected, user-actionable failure."""

from __future__ import annotations


class SpecError(Exception):
    """A problem with the input (bad file, bad path, unsupported version, ...)."""


class RefError(SpecError):
    """A $ref that cannot be resolved (missing target, remote, outside the sandbox)."""
