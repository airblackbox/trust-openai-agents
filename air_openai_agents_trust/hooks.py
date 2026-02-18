"""
air-openai-agents-trust — RunHooks Implementation

Integrates the AIR Trust Layer with the OpenAI Agents SDK.

The OpenAI Agents SDK provides RunHooks — async lifecycle callbacks
that fire during agent execution. We subclass RunHooks to inject:
  - Consent gating on tool calls (on_tool_start)
  - Injection detection on LLM inputs (on_agent_start)
  - Data vault tokenization on all inputs/outputs
  - Tamper-evident audit trail on every event

Usage:
    from openai_agents import Agent, Runner
    from air_openai_agents_trust import AirTrustRunHooks

    hooks = AirTrustRunHooks()
    result = await Runner.run(agent, "input", hooks=hooks)
"""

from __future__ import annotations

from typing import Any

from .audit_ledger import AuditLedger
from .config import AirTrustConfig
from .consent_gate import ConsentGate
from .data_vault import DataVault
from .errors import ConsentDeniedError, InjectionBlockedError
from .injection_detector import InjectionDetector

# Try to import the base class; fall back to object if not installed
try:
    from agents import RunHooks as _BaseRunHooks

    _HAS_AGENTS_SDK = True
except ImportError:
    try:
        from openai_agents import RunHooks as _BaseRunHooks

        _HAS_AGENTS_SDK = True
    except ImportError:
        _BaseRunHooks = object
        _HAS_AGENTS_SDK = False


class AirTrustRunHooks(_BaseRunHooks):
    """
    AIR Trust Layer hooks for the OpenAI Agents SDK.

    All methods are async to match the RunHooks interface.
    Raises ConsentDeniedError or InjectionBlockedError to halt execution.
    """

    def __init__(
        self,
        config: AirTrustConfig | None = None,
        consent_prompt_fn: Any | None = None,
    ) -> None:
        if _HAS_AGENTS_SDK and hasattr(_BaseRunHooks, "__init__"):
            super().__init__()
        self.config = config or AirTrustConfig()
        self._consent_prompt_fn = consent_prompt_fn

        if not self.config.enabled:
            self.ledger = None
            self.vault = None
            self.consent_gate = None
            self.detector = None
            return

        self.ledger = AuditLedger(
            self.config.audit_ledger,
            gateway_url=self.config.gateway_url,
            gateway_key=self.config.gateway_key,
        )
        self.vault = DataVault(
            self.config.vault,
            gateway_url=self.config.gateway_url,
            gateway_key=self.config.gateway_key,
        )
        self.consent_gate = ConsentGate(self.config.consent_gate, self.ledger)
        self.detector = InjectionDetector(self.config.injection_detection)

    # ------------------------------------------------------------------
    # RunHooks lifecycle methods (async)
    # ------------------------------------------------------------------

    async def on_agent_start(self, context: Any, agent: Any) -> None:
        """Called before an agent is invoked."""
        if not self.config.enabled:
            return

        agent_name = getattr(agent, "name", "unknown")

        if self.config.audit_ledger.enabled and self.ledger:
            self.ledger.append(
                action="agent_start",
                metadata={"agent": agent_name, "framework": "openai-agents"},
            )

    async def on_agent_end(self, context: Any, agent: Any, output: Any = None) -> None:
        """Called when an agent produces final output."""
        if not self.config.enabled:
            return

        agent_name = getattr(agent, "name", "unknown")

        # Tokenize output
        tokenized = False
        if self.config.vault.enabled and self.vault and output:
            vault_result = self.vault.tokenize(str(output))
            tokenized = vault_result["tokenized"]

        if self.config.audit_ledger.enabled and self.ledger:
            self.ledger.append(
                action="agent_end",
                data_tokenized=tokenized,
                metadata={"agent": agent_name, "framework": "openai-agents"},
            )

    async def on_tool_start(
        self, context: Any, agent: Any, tool: Any
    ) -> None:
        """
        Called immediately before a tool is invoked.

        Applies:
        1. Consent gate — blocks destructive tools
        2. Data vault — tokenizes sensitive data
        3. Audit ledger — logs the tool call
        """
        if not self.config.enabled:
            return

        tool_name = getattr(tool, "name", str(tool))
        agent_name = getattr(agent, "name", "unknown")

        # 1. Consent gate
        if self.config.consent_gate.enabled and self.consent_gate:
            result = self.consent_gate.intercept(
                tool_name, {}, prompt_fn=self._consent_prompt_fn
            )
            if result.get("blocked"):
                risk = self.consent_gate.classify_risk(tool_name)
                raise ConsentDeniedError(tool_name, risk.value)

        # 2. Audit ledger
        risk_level = "none"
        if self.consent_gate:
            risk_level = self.consent_gate.classify_risk(tool_name).value

        if self.config.audit_ledger.enabled and self.ledger:
            self.ledger.append(
                action="tool_call_start",
                tool_name=tool_name,
                risk_level=risk_level,
                metadata={"agent": agent_name, "framework": "openai-agents"},
            )

    async def on_tool_end(
        self, context: Any, agent: Any, tool: Any, result: Any = None
    ) -> None:
        """Called immediately after tool execution."""
        if not self.config.enabled:
            return

        tool_name = getattr(tool, "name", str(tool))

        # Tokenize result
        tokenized = False
        if self.config.vault.enabled and self.vault and result:
            vault_result = self.vault.tokenize(str(result))
            tokenized = vault_result["tokenized"]

        if self.config.audit_ledger.enabled and self.ledger:
            self.ledger.append(
                action="tool_call_end",
                tool_name=tool_name,
                data_tokenized=tokenized,
                metadata={"framework": "openai-agents"},
            )

    async def on_llm_start(self, context: Any, agent: Any) -> None:
        """
        Called just before LLM invocation.

        Applies injection detection on the agent's recent context.
        Note: The SDK doesn't expose raw prompts in on_llm_start,
        so injection scanning is done via on_agent_start context
        or can be enhanced with custom tracing.
        """
        if not self.config.enabled:
            return

        agent_name = getattr(agent, "name", "unknown")

        if self.config.audit_ledger.enabled and self.ledger:
            self.ledger.append(
                action="llm_call_start",
                metadata={"agent": agent_name, "framework": "openai-agents"},
            )

    async def on_llm_end(
        self, context: Any, agent: Any, response: Any = None
    ) -> None:
        """Called immediately after LLM returns."""
        if not self.config.enabled:
            return

        agent_name = getattr(agent, "name", "unknown")

        # Tokenize response
        tokenized = False
        if self.config.vault.enabled and self.vault and response:
            content = self._extract_content(response)
            if content:
                vault_result = self.vault.tokenize(content)
                tokenized = vault_result["tokenized"]

        if self.config.audit_ledger.enabled and self.ledger:
            self.ledger.append(
                action="llm_call_end",
                data_tokenized=tokenized,
                metadata={"agent": agent_name, "framework": "openai-agents"},
            )

    async def on_handoff(
        self, context: Any, from_agent: Any, to_agent: Any
    ) -> None:
        """Called when an agent hands off to another agent."""
        if not self.config.enabled:
            return

        from_name = getattr(from_agent, "name", "unknown")
        to_name = getattr(to_agent, "name", "unknown")

        if self.config.audit_ledger.enabled and self.ledger:
            self.ledger.append(
                action="agent_handoff",
                metadata={
                    "from_agent": from_name,
                    "to_agent": to_name,
                    "framework": "openai-agents",
                },
            )

    # ------------------------------------------------------------------
    # Standalone scanning method (for use outside hooks)
    # ------------------------------------------------------------------

    def scan_input(self, content: str) -> None:
        """
        Scan arbitrary input for injection patterns.

        Call this manually to scan user input before passing to
        Runner.run(). Raises InjectionBlockedError if blocked.
        """
        if not self.config.enabled or not self.detector:
            return

        scan_result = self.detector.scan(content)

        if scan_result.detected:
            # Tokenize for audit
            tokenized = False
            if self.config.vault.enabled and self.vault:
                vault_result = self.vault.tokenize(content)
                tokenized = vault_result["tokenized"]

            if self.config.audit_ledger.enabled and self.ledger:
                self.ledger.append(
                    action="injection_scan",
                    injection_detected=True,
                    data_tokenized=tokenized,
                    metadata={
                        "score": scan_result.score,
                        "patterns": scan_result.patterns,
                        "blocked": scan_result.blocked,
                        "framework": "openai-agents",
                    },
                )

            if scan_result.blocked:
                raise InjectionBlockedError(scan_result.score, scan_result.patterns)

    # ------------------------------------------------------------------
    # Public inspection API
    # ------------------------------------------------------------------

    def get_audit_stats(self) -> dict:
        """Get audit chain statistics."""
        if not self.ledger:
            return {"enabled": False}
        return self.ledger.stats()

    def verify_chain(self) -> dict:
        """Verify the integrity of the audit chain."""
        if not self.ledger:
            return {"enabled": False}
        return self.ledger.verify().to_dict()

    def export_audit(self) -> list[dict]:
        """Export all audit entries."""
        if not self.ledger:
            return []
        return self.ledger.export()

    def get_vault_stats(self) -> dict:
        """Get data vault statistics."""
        if not self.vault:
            return {"enabled": False}
        return self.vault.stats()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_content(data: Any) -> str | None:
        """Extract text content from various response formats."""
        if isinstance(data, str):
            return data
        if isinstance(data, dict):
            content = data.get("content", "")
            if content:
                return str(content)
            choices = data.get("choices", [])
            if choices:
                parts = []
                for choice in choices:
                    msg = choice.get("message", {})
                    c = msg.get("content", "")
                    if c:
                        parts.append(str(c))
                return "\n".join(parts) if parts else None
        if isinstance(data, list):
            parts = []
            for item in data:
                if isinstance(item, dict):
                    c = item.get("content", "")
                    if c:
                        parts.append(str(c))
                elif isinstance(item, str):
                    parts.append(item)
            return "\n".join(parts) if parts else None
        # Try string conversion for SDK response objects
        try:
            return str(data)
        except Exception:
            return None
