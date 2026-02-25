"""Tests for new GODRECON advanced features."""

from __future__ import annotations

import pytest

from godrecon.core.config import (
    Config,
    AuthConfig,
    NucleiConfig,
    OOBConfig,
    JSSecretsConfig,
    GitDorkConfig,
    WAFConfig,
    FuzzingConfig,
    ParamDiscoveryConfig,
    SupplyChainConfig,
)
from godrecon.modules.base import Finding
from godrecon.reporting.bug_report import BugReport, BugReportGenerator


# ---------------------------------------------------------------------------
# Config tests
# ---------------------------------------------------------------------------

def test_auth_config_defaults():
    cfg = AuthConfig()
    assert cfg.enabled is False
    assert cfg.bearer_token == ""
    assert cfg.cookies == {}
    assert cfg.headers == {}


def test_nuclei_config_defaults():
    cfg = NucleiConfig()
    assert cfg.enabled is True
    assert "critical" in cfg.severity
    assert "high" in cfg.severity


def test_oob_config_defaults():
    cfg = OOBConfig()
    assert cfg.enabled is False
    assert cfg.use_interactsh is False


def test_js_secrets_config_defaults():
    cfg = JSSecretsConfig()
    assert cfg.enabled is True
    assert cfg.entropy_threshold > 0


def test_waf_config_defaults():
    cfg = WAFConfig()
    assert cfg.enabled is True
    assert cfg.apply_bypass is True


def test_fuzzing_config_defaults():
    cfg = FuzzingConfig()
    assert cfg.enabled is False
    assert cfg.max_mutations > 0


def test_param_discovery_config_defaults():
    cfg = ParamDiscoveryConfig()
    assert cfg.enabled is True
    assert cfg.brute_force is True
    assert cfg.mine_js is True


def test_supply_chain_config_defaults():
    cfg = SupplyChainConfig()
    assert cfg.enabled is True
    assert cfg.check_sri is True


def test_config_has_new_fields():
    cfg = Config()
    assert hasattr(cfg, "auth")
    assert hasattr(cfg, "nuclei")
    assert hasattr(cfg, "oob")
    assert hasattr(cfg, "js_secrets")
    assert hasattr(cfg, "git_dork")
    assert hasattr(cfg, "waf")
    assert hasattr(cfg, "fuzzing")
    assert hasattr(cfg, "param_discovery")
    assert hasattr(cfg, "supply_chain")


def test_modules_config_has_new_modules():
    cfg = Config()
    modules = cfg.modules.model_dump()
    assert "js_secrets" in modules
    assert "param_discovery" in modules
    assert "waf" in modules
    assert "fuzzing" in modules
    assert "supply_chain" in modules
    assert "git_dorking" in modules
    assert "oob" in modules
    assert "nuclei" in modules


# ---------------------------------------------------------------------------
# New module instantiation tests
# ---------------------------------------------------------------------------

def test_js_secrets_module_instantiates():
    from godrecon.modules.js_secrets import JSSecretsModule
    m = JSSecretsModule()
    assert m.name == "js_secrets"


def test_param_discovery_module_instantiates():
    from godrecon.modules.param_discovery import ParamDiscoveryModule
    m = ParamDiscoveryModule()
    assert m.name == "param_discovery"


def test_waf_module_instantiates():
    from godrecon.modules.waf import WAFModule
    m = WAFModule()
    assert m.name == "waf"


def test_fuzzing_module_instantiates():
    from godrecon.modules.fuzzing import FuzzingModule
    m = FuzzingModule()
    assert m.name == "fuzzing"


def test_supply_chain_module_instantiates():
    from godrecon.modules.supply_chain import SupplyChainModule
    m = SupplyChainModule()
    assert m.name == "supply_chain"


def test_git_dorking_module_instantiates():
    from godrecon.modules.git_dorking import GitDorkingModule
    m = GitDorkingModule()
    assert m.name == "git_dorking"


def test_oob_module_instantiates():
    from godrecon.modules.oob import OOBModule
    m = OOBModule()
    assert m.name == "oob"


def test_nuclei_module_instantiates():
    from godrecon.modules.nuclei import NucleiModule
    m = NucleiModule()
    assert m.name == "nuclei"


# ---------------------------------------------------------------------------
# New detector instantiation tests
# ---------------------------------------------------------------------------

def test_rce_detector_instantiates():
    from godrecon.modules.vulns.detectors.rce_detector import RCEDetector
    d = RCEDetector(http_client=None)
    assert d is not None


def test_lfi_detector_instantiates():
    from godrecon.modules.vulns.detectors.lfi_detector import LFIDetector
    d = LFIDetector(http_client=None)
    assert d is not None


def test_ssti_detector_instantiates():
    from godrecon.modules.vulns.detectors.ssti_detector import SSTIDetector
    d = SSTIDetector(http_client=None)
    assert d is not None


def test_xxe_detector_instantiates():
    from godrecon.modules.vulns.detectors.xxe_detector import XXEDetector
    d = XXEDetector(http_client=None)
    assert d is not None


def test_command_injection_detector_instantiates():
    from godrecon.modules.vulns.detectors.command_injection import CommandInjectionDetector
    d = CommandInjectionDetector(http_client=None)
    assert d is not None


def test_path_traversal_detector_instantiates():
    from godrecon.modules.vulns.detectors.path_traversal import PathTraversalDetector
    d = PathTraversalDetector(http_client=None)
    assert d is not None


def test_jwt_detector_instantiates():
    from godrecon.modules.vulns.detectors.jwt_detector import JWTDetector
    d = JWTDetector(http_client=None)
    assert d is not None


def test_auth_bypass_detector_instantiates():
    from godrecon.modules.vulns.detectors.auth_bypass import AuthBypassDetector
    d = AuthBypassDetector(http_client=None)
    assert d is not None


def test_graphql_injection_detector_instantiates():
    from godrecon.modules.vulns.detectors.graphql_injection import GraphQLInjectionDetector
    d = GraphQLInjectionDetector(http_client=None)
    assert d is not None


def test_host_header_injection_detector_instantiates():
    from godrecon.modules.vulns.detectors.host_header_injection import HostHeaderInjectionDetector
    d = HostHeaderInjectionDetector(http_client=None)
    assert d is not None


def test_http_smuggling_detector_instantiates():
    from godrecon.modules.vulns.detectors.http_smuggling import HTTPSmugglingDetector
    d = HTTPSmugglingDetector(http_client=None)
    assert d is not None


def test_prototype_pollution_detector_instantiates():
    from godrecon.modules.vulns.detectors.prototype_pollution import PrototypePollutionDetector
    d = PrototypePollutionDetector(http_client=None)
    assert d is not None


def test_deserialization_detector_instantiates():
    from godrecon.modules.vulns.detectors.deserialization import DeserializationDetector
    d = DeserializationDetector(http_client=None)
    assert d is not None


def test_http_verb_tampering_detector_instantiates():
    from godrecon.modules.vulns.detectors.http_verb_tampering import HTTPVerbTamperingDetector
    d = HTTPVerbTamperingDetector(http_client=None)
    assert d is not None


def test_websocket_hijacking_detector_instantiates():
    from godrecon.modules.vulns.detectors.websocket_hijacking import WebSocketHijackingDetector
    d = WebSocketHijackingDetector(http_client=None)
    assert d is not None


def test_race_condition_detector_instantiates():
    from godrecon.modules.vulns.detectors.race_condition import RaceConditionDetector
    d = RaceConditionDetector(http_client=None)
    assert d is not None


def test_broken_access_control_detector_instantiates():
    from godrecon.modules.vulns.detectors.broken_access_control import BrokenAccessControlDetector
    d = BrokenAccessControlDetector(http_client=None)
    assert d is not None


def test_idor_detector_instantiates():
    from godrecon.modules.vulns.detectors.idor_detector import IDORDetector
    d = IDORDetector(http_client=None)
    assert d is not None


# ---------------------------------------------------------------------------
# Bug report generator tests
# ---------------------------------------------------------------------------

def test_bug_report_generator_from_finding():
    gen = BugReportGenerator()
    finding = Finding(
        title="SQL Injection found",
        severity="critical",
        description="Parameter id is injectable",
        evidence="SQL error in response",
        data={"url": "https://example.com/api", "param": "id", "payload": "' OR 1=1--", "method": "GET"},
        tags=["sqli", "p1", "critical"],
    )
    report = gen.generate_from_finding(finding, "example.com")
    assert report.title == "SQL Injection found"
    assert report.severity == "critical"
    assert report.cvss_score == 9.8
    assert "example.com" in report.curl_command
    assert report.remediation != ""


def test_bug_report_to_markdown():
    report = BugReport(
        title="XSS Found",
        vulnerability_type="xss",
        severity="high",
        target="example.com",
        description="Reflected XSS in search parameter",
        impact="Attacker can execute scripts in victim browser",
        steps_to_reproduce=["Navigate to /search?q=<script>alert(1)</script>"],
        proof_of_concept="<script>alert(1)</script> reflected unescaped",
        curl_command='curl "https://example.com/search?q=<script>alert(1)</script>"',
        cvss_score=7.5,
        remediation="Encode output",
    )
    md = report.to_markdown()
    assert "# XSS Found" in md
    assert "high" in md.upper() or "HIGH" in md
    assert "Steps to Reproduce" in md
    assert "Proof of Concept" in md
    assert "Remediation" in md


def test_bug_report_hackerone_format():
    report = BugReport(
        title="SSRF",
        vulnerability_type="ssrf",
        severity="critical",
        target="example.com",
        description="SSRF via url parameter",
        impact="Internal network access",
    )
    h1 = report.to_hackerone_format()
    assert "title" in h1
    assert h1["title"] == "SSRF"


def test_bug_report_bugcrowd_format():
    report = BugReport(
        title="SSRF",
        vulnerability_type="ssrf",
        severity="critical",
        target="example.com",
        description="SSRF via url parameter",
        impact="Internal network access",
    )
    bc = report.to_bugcrowd_format()
    assert "title" in bc
    assert bc["severity"] == "P1"


def test_bug_report_generator_batch():
    gen = BugReportGenerator()
    findings = [
        Finding(title="SQLi", severity="critical", description="SQL injection"),
        Finding(title="XSS", severity="high", description="Cross-site scripting"),
    ]
    reports = gen.generate_batch(findings, "example.com")
    assert len(reports) == 2


def test_bug_report_json_export():
    gen = BugReportGenerator()
    finding = Finding(title="Test Vuln", severity="medium", description="Test")
    reports = gen.generate_batch([finding], "example.com")
    json_str = gen.export_json(reports)
    import json
    data = json.loads(json_str)
    assert len(data) == 1
    assert data[0]["title"] == "Test Vuln"


# ---------------------------------------------------------------------------
# Auth client tests
# ---------------------------------------------------------------------------

def test_auth_client_instantiates():
    from godrecon.utils.auth_client import AuthenticatedClient
    client = AuthenticatedClient(http=None, auth_config=None)
    assert client is not None


def test_auth_client_builds_headers_bearer():
    from godrecon.utils.auth_client import AuthenticatedClient
    auth = AuthConfig(enabled=True, bearer_token="mytoken123")
    client = AuthenticatedClient(http=None, auth_config=auth)
    headers = client._build_headers()
    assert headers.get("Authorization") == "Bearer mytoken123"


def test_auth_client_builds_headers_api_key():
    from godrecon.utils.auth_client import AuthenticatedClient
    auth = AuthConfig(enabled=True, api_key="myapikey", api_key_header="X-API-Key")
    client = AuthenticatedClient(http=None, auth_config=auth)
    headers = client._build_headers()
    assert headers.get("X-API-Key") == "myapikey"


def test_auth_client_merges_cookies():
    from godrecon.utils.auth_client import AuthenticatedClient
    auth = AuthConfig(enabled=True, cookies={"session": "abc123"})
    client = AuthenticatedClient(http=None, auth_config=auth)
    assert client._session_cookies.get("session") == "abc123"


# ---------------------------------------------------------------------------
# Monitoring notifications tests
# ---------------------------------------------------------------------------

def test_monitoring_notifier_instantiates():
    from godrecon.monitoring.notifications import MonitoringNotifier
    from godrecon.core.config import NotificationsConfig
    notifier = MonitoringNotifier(NotificationsConfig())
    assert notifier is not None


def test_slack_notifier_instantiates():
    from godrecon.monitoring.notifications import SlackNotifier
    from godrecon.core.config import SlackConfig
    notifier = SlackNotifier(SlackConfig(enabled=True, webhook_url="https://hooks.slack.com/test"))
    assert notifier is not None


def test_discord_notifier_instantiates():
    from godrecon.monitoring.notifications import DiscordNotifier
    from godrecon.core.config import DiscordConfig
    notifier = DiscordNotifier(DiscordConfig(enabled=True, webhook_url="https://discord.com/api/webhooks/test"))
    assert notifier is not None
