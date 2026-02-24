# air-openai-agents-trust

[![CI](https://github.com/airblackbox/trust-openai-agents/actions/workflows/ci.yml/badge.svg)](https://github.com/airblackbox/trust-openai-agents/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://github.com/airblackbox/trust-openai-agents/blob/main/LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-3776AB.svg?logo=python&logoColor=white)](https://python.org)


**EU AI Act compliance infrastructure for OpenAI Agents SDK.** Drop-in trust layer that adds tamper-evident audit logging, PII tokenization, consent-based tool gating, and prompt injection detection — making your OpenAI agent stack compliant with Articles 9, 10, 11, 12, 14, and 15 of the EU AI Act.

Part of the [AIR Blackbox](https://github.com/airblackbox) ecosystem — the compliance layer for autonomous AI agents.

> The EU AI Act enforcement date for high-risk AI systems is **August 2, 2026**. See the [full compliance mapping](./docs/eu-ai-act-compliance.md) for article-by-article coverage.

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

## EU AI Act Compliance

| EU AI Act Article | Requirement | AIR Feature |
|---|---|---|
| Art. 9 | Risk management | ConsentGate risk classification |
| Art. 10 | Data governance | DataVault PII tokenization |
| Art. 11 | Technical documentation | Full call graph audit logging |
| Art. 12 | Record-keeping | HMAC-SHA256 tamper-evident chain |
| Art. 14 | Human oversight | Consent-based tool blocking |
| Art. 15 | Robustness & security | InjectionDetector + multi-layer defense |

See [docs/eu-ai-act-compliance.md](./docs/eu-ai-act-compliance.md) for the full article-by-article mapping.

## AIR Blackbox Ecosystem

| Package | Framework | Install |
|---|---|---|
| `air-langchain-trust` | LangChain / LangGraph | `pip install air-langchain-trust` |
| `air-crewai-trust` | CrewAI | `pip install air-crewai-trust` |
| `air-openai-agents-trust` | OpenAI Agents SDK | `pip install air-openai-agents-trust` |
| `air-autogen-trust` | Microsoft AutoGen | `pip install air-autogen-trust` |
| `openclaw-air-trust` | TypeScript / Node.js | `npm install openclaw-air-trust` |
| `air-compliance` | Compliance checker CLI | `pip install air-compliance` |
| Gateway | Any HTTP agent | `docker pull ghcr.io/airblackbox/gateway:main` |

## Development

```bash
git clone https://github.com/airblackbox/trust-openai-agents.git
cd trust-openai-agents
pip install -e ".[dev]"
pytest tests/ -v
```

## License

Apache-2.0
