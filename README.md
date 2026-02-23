# air-openai-agents-trust

[![CI](https://github.com/airblackbox/trust-openai-agents/actions/workflows/ci.yml/badge.svg)](https://github.com/airblackbox/trust-openai-agents/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://github.com/airblackbox/trust-openai-agents/blob/main/LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-3776AB.svg?logo=python&logoColor=white)](https://python.org)


**AIR Trust Layer for OpenAI Agents SDK** — Drop-in security, audit, and compliance for OpenAI agent workflows.

Part of the [AIR Blackbox](https://airblackbox.com) ecosystem. Adds tamper-proof audit trails, sensitive data tokenization, consent gates for destructive tools, and prompt injection detection.

## Quick Start

```bash
pip install air-openai-agents-trust
```

```python
from agents import Agent, Runner
from air_openai_agents_trust import AirTrustRunHooks

# Create the trust hooks
hooks = AirTrustRunHooks()

# Scan user input before running (optional but recommended)
user_input = "Search for AI safety research papers"
hooks.scan_input(user_input)

# Run with hooks — all events are now audited
result = await Runner.run(agent, user_input, hooks=hooks)

# Check what happened
print(hooks.get_audit_stats())
print(hooks.verify_chain())
```

## What It Does

### Tamper-Proof Audit Trail
Every tool call, LLM invocation, agent start/end, and handoff is logged to an HMAC-SHA256 signed chain.

### Sensitive Data Tokenization
API keys, credentials, PII automatically detected and tokenized. **14 built-in patterns**.

### Consent Gate
Destructive tools blocked until approved. Raises `ConsentDeniedError`:

```python
from air_openai_agents_trust import ConsentDeniedError, InjectionBlockedError

try:
    hooks.scan_input(user_input)
    result = await Runner.run(agent, user_input, hooks=hooks)
except ConsentDeniedError as e:
    print(f"Tool '{e.tool_name}' blocked (risk: {e.risk_level})")
except InjectionBlockedError as e:
    print(f"Injection detected (score: {e.score})")
```

### Prompt Injection Detection
15+ weighted patterns. Use `hooks.scan_input()` before running agents.

## Hook Mapping

| OpenAI Agents Hook | Trust Components |
|-------------------|-----------------|
| `on_agent_start` | AuditLedger |
| `on_agent_end` | DataVault → AuditLedger |
| `on_tool_start` | ConsentGate → AuditLedger |
| `on_tool_end` | DataVault → AuditLedger |
| `on_llm_start` | AuditLedger |
| `on_llm_end` | DataVault → AuditLedger |
| `on_handoff` | AuditLedger |
| `scan_input()` | InjectionDetector → DataVault → AuditLedger |

## Configuration

```python
from air_openai_agents_trust import AirTrustRunHooks, AirTrustConfig

config = AirTrustConfig(
    consent_gate={"enabled": True, "risk_threshold": "high"},
    vault={"enabled": True, "categories": ["api_key", "credential", "pii"]},
    injection_detection={"enabled": True, "sensitivity": "medium"},
    audit_ledger={"enabled": True, "max_entries": 10000},
)

hooks = AirTrustRunHooks(config=config)
```

## Works with Handoffs

```python
triage = Agent(name="triage", handoffs=[billing_agent, support_agent])

hooks = AirTrustRunHooks()
result = await Runner.run(triage, "I need help with billing", hooks=hooks)
# Handoff from triage → billing_agent is audited
```

## API Reference

```python
hooks.get_audit_stats()   # Chain statistics
hooks.verify_chain()      # Verify chain integrity
hooks.export_audit()      # Export all entries
hooks.get_vault_stats()   # Vault statistics
hooks.scan_input(text)    # Scan for injection (sync)
```

## AIR Blackbox Ecosystem

| Repository | Purpose |
|-----------|---------|
| [trust-crewai](https://github.com/airblackbox/trust-crewai) | Trust layer for CrewAI |
| [trust-langchain](https://github.com/airblackbox/trust-langchain) | Trust layer for LangChain |
| [trust-autogen](https://github.com/airblackbox/trust-autogen) | Trust layer for AutoGen |
| **trust-openai-agents** | **Trust layer for OpenAI Agents SDK** (this repo) |

## Development

```bash
git clone https://github.com/airblackbox/trust-openai-agents.git
cd trust-openai-agents
pip install -e ".[dev]"
pytest tests/ -v
```

## License

MIT
