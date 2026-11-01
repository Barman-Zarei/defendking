"""Explicit check coverage for reports; never retain raw operational errors."""

from __future__ import annotations

import re
import socket
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Optional

from .exceptions import ExternalServiceError, InvalidInputError


@dataclass(frozen=True)
class SecurityCheckResult:
    """Outcome of one declared check, separate from its security findings.

    IDs are public labels, not targets or paths. Every declared check counts
    toward coverage. A completed check may still produce security findings.
    """

    check_id: str
    status: str
    reason: Optional[str] = None

    def __post_init__(self):
        if not isinstance(self.check_id, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", self.check_id):
            raise InvalidInputError("check_id must be a short public identifier")
        allowed = {
            "completed": (None,),
            "failed": ("missing-file", "network-error", "external-service-error"),
            "skipped": ("disabled", "not-run"),
        }
        if not isinstance(self.status, str) or self.status not in allowed or self.reason not in allowed[self.status]:
            raise InvalidInputError("invalid check status or reason code")

    @classmethod
    def from_exception(cls, check_id: str, error: Exception) -> SecurityCheckResult:
        """Classify operational failures without copying their messages.

        Programmer errors remain errors in the caller and are never converted
        into a successful report or an operational failure.
        """
        if not isinstance(error, (OSError, ExternalServiceError)):
            raise InvalidInputError("expected an operational exception")
        reason = "external-service-error"
        current: Optional[BaseException] = error
        seen: set[int] = set()
        while current is not None and id(current) not in seen:
            seen.add(id(current))
            if isinstance(current, FileNotFoundError):
                reason = "missing-file"
                break
            if isinstance(current, (TimeoutError, ConnectionError, socket.gaierror)):
                reason = "network-error"
                break
            current = current.__cause__
        return cls(check_id, "failed", reason)

    @classmethod
    def from_result(cls, check_id: str, result: Mapping[str, Any]) -> SecurityCheckResult:
        """Accept a returned check dictionary, discarding raw error details.

        An ordinary negative security result (for example valid=False) is a
        completed check. Only an explicit operational error marks it failed.
        """
        if not isinstance(result, Mapping):
            raise InvalidInputError("result must be a check result dictionary")
        if result.get("success") is False or result.get("error") is not None or result.get("error_type") is not None:
            return cls(check_id, "failed", "external-service-error")
        return cls(check_id, "completed")

    def to_dict(self) -> dict[str, Any]:
        """Return only the public identifier, status and optional reason code."""
        return {"check_id": self.check_id, "status": self.status, **({"reason": self.reason} if self.reason else {})}


def coverage_summary(checks: list[SecurityCheckResult]) -> dict[str, Any]:
    """Coverage of the caller's declared checks, not all possible checks."""
    if not isinstance(checks, list) or any(not isinstance(check, SecurityCheckResult) for check in checks):
        raise InvalidInputError("checks must be a list of SecurityCheckResult objects")
    if len({check.check_id for check in checks}) != len(checks):
        raise InvalidInputError("check identifiers must be unique")
    counts = {status: sum(check.status == status for check in checks) for status in ("completed", "failed", "skipped")}
    return {
        "status": "complete" if checks and counts["completed"] == len(checks) else "incomplete",
        "total": len(checks),
        **counts,
    }
