"""
air-openai-agents-trust — Custom Exceptions

The OpenAI Agents SDK hooks are async observation points.
To block execution, we raise custom exceptions that propagate
up to the Runner, halting the agent run.
"""

from __future__ import annotations


class AirTrustError(Exception):
    """Base exception for all AIR Trust Layer errors."""

    def __init__(self, message: str, details: dict | None = None) -> None:
        super().__init__(message)
        self.details = details or {}


class ConsentDeniedError(AirTrustError):
    """Raised when a tool call is blocked because the user denied consent."""

    def __init__(
        self,
        tool_name: str,
        risk_level: str,
        message: str | None = None,
    ) -> None:
        msg = message or f"Consent denied for tool '{tool_name}' (risk: {risk_level})"
        super().__init__(msg, {"tool_name": tool_name, "risk_level": risk_level})
        self.tool_name = tool_name
        self.risk_level = risk_level


class InjectionBlockedError(AirTrustError):
    """Raised when a prompt injection is detected above threshold."""

    def __init__(
        self,
        score: float,
        patterns: list[str],
        message: str | None = None,
    ) -> None:
        msg = message or (
            f"Prompt injection blocked (score: {score:.2f}, "
            f"patterns: {', '.join(patterns)})"
        )
        super().__init__(msg, {"score": score, "patterns": patterns})
        self.score = score
        self.patterns = patterns
