"""
DefendKing exception hierarchy.

Convention used across the whole package:
    - Programmer errors (wrong type, malformed value, missing required
      argument) raise `InvalidInputError` immediately - these are bugs in
      the calling code and should never be silently swallowed.
    - External-world failures (network unreachable, DNS lookup failed,
      file not found, third-party API error) are caught and reported back
      as a `{"success": False, "error": ..., "error_type": ...}`-shaped
      dict instead of raising, since these are expected/recoverable
      conditions in normal operation, not bugs. Functions that document
      this behavior wrap the underlying failure in `ExternalServiceError`
      internally so the `error_type` field is informative, then return it
      inside the result dict rather than letting it propagate.

Both derive from `DefendKingError` so callers who want to catch "anything
that went wrong in DefendKing" can do `except DefendKingError:` once,
instead of enumerating every subclass.
"""

from __future__ import annotations


class DefendKingError(Exception):
    """Base class for every exception raised by DefendKing."""


class InvalidInputError(DefendKingError, ValueError):
    """
    Raised when a caller passes an argument of the wrong type, an empty
    value where content is required, or a value outside the function's
    valid range/format. Inherits from `ValueError` too, so existing code
    written against plain `ValueError`/`TypeError` handling still works
    without changes.
    """


class ExternalServiceError(DefendKingError):
    """
    Represents a failure talking to something outside the process - a
    network call, DNS resolution, or filesystem operation. DefendKing
    functions generally do NOT raise this directly to the caller; instead
    they catch the underlying `OSError`/`requests` exception, wrap it in
    an `ExternalServiceError` for a consistent message, and return it as
    part of an error dict (see each function's docstring for the exact
    shape). It's exposed here so advanced callers can still choose to
    construct/inspect it, and so internal helper code has one exception
    type to standardize around instead of leaking raw `requests`/`socket`
    exception types.
    """
