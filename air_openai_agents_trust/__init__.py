"""
air-openai-agents-trust — AIR Trust Layer for OpenAI Agents SDK

Drop-in security, audit, and compliance for OpenAI agent workflows.
"""

from .config import (
    RISK_ORDER,
    AirTrustConfig,
    AuditLedgerConfig,
    ConsentGateConfig,
    InjectionDetectionConfig,
    RiskLevel,
    VaultConfig,
)
from .errors import AirTrustError, ConsentDeniedError, InjectionBlockedError
from .hooks import AirTrustRunHooks

__all__ = [
    "AirTrustRunHooks",
    "AirTrustConfig",
    "AirTrustError",
    "AuditLedgerConfig",
    "ConsentDeniedError",
    "ConsentGateConfig",
    "InjectionBlockedError",
    "InjectionDetectionConfig",
    "RISK_ORDER",
    "RiskLevel",
    "VaultConfig",
]
