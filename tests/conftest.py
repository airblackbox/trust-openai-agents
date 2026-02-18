"""Shared test fixtures for air-openai-agents-trust."""

import os
import tempfile

import pytest

from air_openai_agents_trust.audit_ledger import AuditLedger
from air_openai_agents_trust.config import (
    AuditLedgerConfig,
    ConsentGateConfig,
    InjectionDetectionConfig,
    VaultConfig,
)
from air_openai_agents_trust.consent_gate import ConsentGate
from air_openai_agents_trust.data_vault import DataVault
from air_openai_agents_trust.injection_detector import InjectionDetector


@pytest.fixture
def tmp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.fixture
def ledger_config(tmp_dir):
    return AuditLedgerConfig(
        enabled=True,
        local_path=os.path.join(tmp_dir, "audit-ledger.json"),
        forward_to_gateway=False,
        max_entries=10_000,
    )


@pytest.fixture
def ledger(ledger_config):
    return AuditLedger(ledger_config)


@pytest.fixture
def vault_config():
    return VaultConfig()


@pytest.fixture
def vault(vault_config):
    return DataVault(vault_config)


@pytest.fixture
def consent_config():
    return ConsentGateConfig()


@pytest.fixture
def consent_gate(consent_config, ledger):
    return ConsentGate(consent_config, ledger)


@pytest.fixture
def injection_config():
    return InjectionDetectionConfig()


@pytest.fixture
def detector(injection_config):
    return InjectionDetector(injection_config)
