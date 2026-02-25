"""Tests for the 15 advanced features added to GODRECON."""

from __future__ import annotations

import asyncio

import pytest

from godrecon.modules.base import Finding
from godrecon.core.config import Config


# ---------------------------------------------------------------------------
# Feature 1: AI Validator
# ---------------------------------------------------------------------------

def test_ai_validator_pattern_based():
    from godrecon.ai.validator import AIValidator
    validator = AIValidator()
    finding = Finding(title="SQL Injection", severity="critical", description="SQL injection found in login form")
    result = validator.validate_finding(finding)
    assert "is_real" in result
    assert "confidence" in result
    assert "explanation" in result
    assert "poc" in result
    assert isinstance(result["confidence"], float)
    assert 0.0 <= result["confidence"] <= 1.0


def test_ai_validator_xss():
    from godrecon.ai.validator import AIValidator
    validator = AIValidator()
    finding = Finding(title="XSS Reflected", severity="high", description="Cross-site scripting via parameter")
    result = validator.validate_finding(finding, provider="pattern")
    assert result["is_real"] is True
    assert result["confidence"] > 0.5


def test_ai_validator_fallback_to_pattern_openai():
    from godrecon.ai.validator import AIValidator
    validator = AIValidator(provider="openai")
    finding = Finding(title="RCE via deserialization", severity="critical", description="Remote code execution")
    result = validator.validate_finding(finding, provider="openai")
    assert "is_real" in result
    assert "confidence" in result


def test_ai_validator_fallback_to_pattern_anthropic():
    from godrecon.ai.validator import AIValidator
    validator = AIValidator()
    finding = Finding(title="SSRF Internal", severity="high", description="Server-side request forgery")
    result = validator.validate_finding(finding, provider="anthropic")
    assert "is_real" in result


def test_ai_validator_generic_title_penalty():
    from godrecon.ai.validator import AIValidator
    validator = AIValidator()
    finding = Finding(title="finding", severity="info", description="generic issue")
    result = validator.validate_finding(finding)
    assert result["confidence"] < 0.6


# ---------------------------------------------------------------------------
# Feature 2: Passive Recon
# ---------------------------------------------------------------------------

def test_passive_recon_module_instantiates():
    from godrecon.modules.passive_recon import PassiveReconModule
    m = PassiveReconModule()
    assert m.name == "passive_recon"


def test_passive_recon_module_execute_no_keys():
    from godrecon.modules.passive_recon import PassiveReconModule
    m = PassiveReconModule()
    cfg = Config()
    result = asyncio.run(m.run("example.com", cfg))
    assert result.module_name == "passive_recon"
    assert isinstance(result.findings, list)
    assert len(result.findings) >= 1


# ---------------------------------------------------------------------------
# Feature 3: Mobile API
# ---------------------------------------------------------------------------

def test_mobile_api_module_instantiates():
    from godrecon.modules.mobile_api import MobileAPIModule
    m = MobileAPIModule()
    assert m.name == "mobile_api"


def test_mobile_api_no_apk_configured():
    from godrecon.modules.mobile_api import MobileAPIModule
    m = MobileAPIModule()
    cfg = Config()
    result = asyncio.run(m.run("example.com", cfg))
    assert result.module_name == "mobile_api"
    assert any("No APK" in f.title for f in result.findings)


# ---------------------------------------------------------------------------
# Feature 4: Vuln Chaining
# ---------------------------------------------------------------------------

def test_vuln_chaining_module_instantiates():
    from godrecon.modules.vuln_chaining import VulnChainingModule
    m = VulnChainingModule()
    assert m.name == "vuln_chaining"


def test_vuln_chaining_detects_chain():
    from godrecon.modules.vuln_chaining import VulnChainingModule
    m = VulnChainingModule()
    findings = [
        Finding(title="Open Redirect", severity="medium", tags=["open_redirect"]),
        Finding(title="OAuth Misconfiguration", severity="high", tags=["oauth"]),
    ]
    chains = m.analyze_findings(findings)
    assert len(chains) >= 1
    assert any("OAuth" in c.title or "Account Takeover" in c.title for c in chains)


def test_vuln_chaining_ssrf_cloud():
    from godrecon.modules.vuln_chaining import VulnChainingModule
    m = VulnChainingModule()
    findings = [
        Finding(title="SSRF Found", severity="high", tags=["ssrf"]),
        Finding(title="Cloud Metadata", severity="medium", tags=["cloud"]),
    ]
    chains = m.analyze_findings(findings)
    assert len(chains) >= 1


# ---------------------------------------------------------------------------
# Feature 5: Cloud Misconfig
# ---------------------------------------------------------------------------

def test_cloud_misconfig_module_instantiates():
    from godrecon.modules.cloud_misconfig import CloudMisconfigModule
    m = CloudMisconfigModule()
    assert m.name == "cloud_misconfig"


def test_cloud_misconfig_run():
    from godrecon.modules.cloud_misconfig import CloudMisconfigModule
    m = CloudMisconfigModule()
    cfg = Config()
    result = asyncio.run(m.run("example.com", cfg))
    assert result.module_name == "cloud_misconfig"
    assert isinstance(result.findings, list)


# ---------------------------------------------------------------------------
# Feature 6: Subdomain Permutation
# ---------------------------------------------------------------------------

def test_subdomain_permutation_module_instantiates():
    from godrecon.modules.subdomain_permutation import SubdomainPermutationModule
    m = SubdomainPermutationModule()
    assert m.name == "subdomain_permutation"


def test_subdomain_permutation_generates():
    from godrecon.modules.subdomain_permutation.engine import _generate_permutations
    results = _generate_permutations("example.com", ["dev", "staging"], 1)
    assert len(results) > 0
    assert any("dev" in s for s in results)


# ---------------------------------------------------------------------------
# Feature 7: Broken Auth
# ---------------------------------------------------------------------------

def test_broken_auth_module_instantiates():
    from godrecon.modules.broken_auth import BrokenAuthModule
    m = BrokenAuthModule()
    assert m.name == "broken_auth"


def test_broken_auth_jwt_test():
    from godrecon.modules.broken_auth import BrokenAuthModule
    m = BrokenAuthModule()
    cfg = Config()
    result = asyncio.run(m.run("example.com", cfg))
    assert result.module_name == "broken_auth"
    assert isinstance(result.findings, list)
    jwt_findings = [f for f in result.findings if "JWT" in f.title or "jwt" in " ".join(f.tags)]
    assert len(jwt_findings) >= 1


# ---------------------------------------------------------------------------
# Feature 8: Collaboration
# ---------------------------------------------------------------------------

def test_collaboration_module_instantiates():
    from godrecon.modules.collaboration import CollaborationModule
    m = CollaborationModule()
    assert m.name == "collaboration"


def test_collaboration_disabled_by_default():
    from godrecon.modules.collaboration import CollaborationModule
    m = CollaborationModule()
    cfg = Config()
    result = asyncio.run(m.run("example.com", cfg))
    assert result.module_name == "collaboration"
    assert any("Disabled" in f.title or "collaboration" in " ".join(f.tags).lower() for f in result.findings)


def test_collaboration_claim_finding():
    from godrecon.modules.collaboration import CollaborationModule
    m = CollaborationModule()
    assert m.claim_finding("finding-001", "alice") is True
    assert m.claim_finding("finding-001", "bob") is False


# ---------------------------------------------------------------------------
# Feature 9: Bug Bounty
# ---------------------------------------------------------------------------

def test_bug_bounty_module_instantiates():
    from godrecon.modules.bug_bounty import BugBountyModule
    m = BugBountyModule()
    assert m.name == "bug_bounty"


def test_bug_bounty_matches_google():
    from godrecon.modules.bug_bounty import BugBountyModule
    m = BugBountyModule()
    cfg = Config()
    result = asyncio.run(m.run("google.com", cfg))
    assert any("Google" in f.title for f in result.findings)


def test_bug_bounty_no_match():
    from godrecon.modules.bug_bounty import BugBountyModule
    m = BugBountyModule()
    matches = m._match_programs("unknown-target-xyz123.io")
    assert matches == []


def test_bug_bounty_estimate_payout():
    from godrecon.modules.bug_bounty import BugBountyModule
    m = BugBountyModule()
    program = {"name": "Test", "max_payout": 10000}
    assert m.estimate_payout(program, "critical") == 10000
    assert m.estimate_payout(program, "low") == 200


# ---------------------------------------------------------------------------
# Feature 10: Browser Extension
# ---------------------------------------------------------------------------

def test_browser_extension_module_instantiates():
    from godrecon.modules.browser_extension import BrowserExtensionModule
    m = BrowserExtensionModule()
    assert m.name == "browser_extension"


def test_browser_extension_analyze_content():
    from godrecon.modules.browser_extension import BrowserExtensionModule
    m = BrowserExtensionModule()
    content = 'chrome-extension://cfhdojbkjhnklbpkdaibdccddilifddb/content.js'
    findings = m._analyze_content(content, "https://example.com")
    assert len(findings) >= 1
    assert any("Adblock" in f.title or "cfhdojbkjhnklbpkdaibdccddilifddb" in f.title for f in findings)


def test_browser_extension_no_extensions():
    from godrecon.modules.browser_extension import BrowserExtensionModule
    m = BrowserExtensionModule()
    findings = m._analyze_content("<html><body>Hello</body></html>", "https://example.com")
    assert findings == []


# ---------------------------------------------------------------------------
# Feature 11: Wayback Mining
# ---------------------------------------------------------------------------

def test_wayback_mining_module_instantiates():
    from godrecon.modules.wayback_mining import WaybackMiningModule
    m = WaybackMiningModule()
    assert m.name == "wayback_mining"


def test_wayback_mining_sensitive_pattern():
    import re
    from godrecon.modules.wayback_mining.miner import _SENSITIVE_PATTERNS
    assert _SENSITIVE_PATTERNS.search("/api/v1/admin")
    assert _SENSITIVE_PATTERNS.search("/backup/db.sql")
    assert not _SENSITIVE_PATTERNS.search("/about-us")


# ---------------------------------------------------------------------------
# Feature 12: Business Logic
# ---------------------------------------------------------------------------

def test_business_logic_module_instantiates():
    from godrecon.modules.business_logic import BusinessLogicModule
    m = BusinessLogicModule()
    assert m.name == "business_logic"


def test_business_logic_run():
    from godrecon.modules.business_logic import BusinessLogicModule
    m = BusinessLogicModule()
    cfg = Config()
    result = asyncio.run(m.run("example.com", cfg))
    assert result.module_name == "business_logic"
    assert isinstance(result.findings, list)


# ---------------------------------------------------------------------------
# Feature 13: Multi-Region
# ---------------------------------------------------------------------------

def test_multi_region_module_instantiates():
    from godrecon.modules.multi_region import MultiRegionModule
    m = MultiRegionModule()
    assert m.name == "multi_region"


def test_multi_region_compare_regions():
    from godrecon.modules.multi_region import MultiRegionModule
    m = MultiRegionModule()
    responses = {
        "us-east": {"status": 200, "length": 1000, "body_sample": "welcome"},
        "eu-west": {"status": 451, "length": 200, "body_sample": "not available in your country"},
    }
    findings = m._compare_regions(responses, "https://example.com")
    assert len(findings) >= 1
    assert any("Geo" in f.title or "geo" in " ".join(f.tags) for f in findings)


# ---------------------------------------------------------------------------
# Feature 14: Smart Priority Scoring
# ---------------------------------------------------------------------------

def test_smart_priority_scorer_instantiates():
    from godrecon.ai.scorer import SmartPriorityScorer
    scorer = SmartPriorityScorer()
    assert scorer is not None


def test_smart_priority_scorer_critical():
    from godrecon.ai.scorer import SmartPriorityScorer
    scorer = SmartPriorityScorer()
    finding = Finding(title="RCE via deserialization", severity="critical", tags=["rce"])
    score = scorer.priority_score(finding)
    assert 0 <= score <= 100
    assert score > 70


def test_smart_priority_scorer_info():
    from godrecon.ai.scorer import SmartPriorityScorer
    scorer = SmartPriorityScorer()
    finding = Finding(title="Banner disclosure", severity="info", tags=["info"])
    score = scorer.priority_score(finding)
    assert score < 50


def test_smart_priority_scorer_color():
    from godrecon.ai.scorer import SmartPriorityScorer
    scorer = SmartPriorityScorer()
    assert scorer.color(90) == "red"
    assert scorer.color(65) == "orange"
    assert scorer.color(10) == "green"


def test_smart_priority_scorer_rank_findings():
    from godrecon.ai.scorer import SmartPriorityScorer
    scorer = SmartPriorityScorer()
    findings = [
        Finding(title="Info banner", severity="info"),
        Finding(title="Critical RCE", severity="critical", tags=["rce"]),
        Finding(title="Medium XSS", severity="medium", tags=["xss"]),
    ]
    ranked = scorer.rank_findings(findings)
    assert len(ranked) == 3
    assert ranked[0]["priority_score"] >= ranked[1]["priority_score"]
    assert ranked[0]["title"] == "Critical RCE"


# ---------------------------------------------------------------------------
# Feature 15: Cache Poisoning
# ---------------------------------------------------------------------------

def test_cache_poisoning_module_instantiates():
    from godrecon.modules.cache_poisoning import CachePoisoningModule
    m = CachePoisoningModule()
    assert m.name == "cache_poisoning"


def test_cache_poisoning_run():
    from godrecon.modules.cache_poisoning import CachePoisoningModule
    m = CachePoisoningModule()
    cfg = Config()
    result = asyncio.run(m.run("example.com", cfg))
    assert result.module_name == "cache_poisoning"
    assert isinstance(result.findings, list)


# ---------------------------------------------------------------------------
# Config tests
# ---------------------------------------------------------------------------

def test_config_new_fields():
    cfg = Config()
    assert hasattr(cfg, "ai_validator")
    assert hasattr(cfg, "passive_recon")
    assert hasattr(cfg, "mobile_api")
    assert hasattr(cfg, "vuln_chaining")
    assert hasattr(cfg, "cloud_misconfig")
    assert hasattr(cfg, "subdomain_permutation_config")
    assert hasattr(cfg, "broken_auth")
    assert hasattr(cfg, "collaboration_config")
    assert hasattr(cfg, "bug_bounty_config")
    assert hasattr(cfg, "browser_extension_config")
    assert hasattr(cfg, "wayback_mining_config")
    assert hasattr(cfg, "business_logic_config")
    assert hasattr(cfg, "multi_region_config")
    assert hasattr(cfg, "smart_scoring")
    assert hasattr(cfg, "cache_poisoning_config")
    assert hasattr(cfg, "scan_mode")


def test_config_modules_new_flags():
    from godrecon.core.config import ModulesConfig
    m = ModulesConfig()
    assert m.passive_recon is True
    assert m.mobile_api is False
    assert m.vuln_chaining is True
    assert m.cloud_misconfig is True
    assert m.subdomain_permutation is True
    assert m.broken_auth is True
    assert m.collaboration is False
    assert m.bug_bounty is True
    assert m.browser_extension is True
    assert m.wayback_mining is True
    assert m.business_logic is True
    assert m.multi_region is False
    assert m.cache_poisoning is True


def test_config_ai_validator_config():
    from godrecon.core.config import AIValidatorConfig
    c = AIValidatorConfig()
    assert c.provider == "pattern"
    assert c.confidence_threshold == 0.7


def test_config_api_keys_ai_fields():
    from godrecon.core.config import APIKeysConfig
    k = APIKeysConfig()
    assert hasattr(k, "openai")
    assert hasattr(k, "anthropic")
    assert hasattr(k, "gemini")


def test_scan_mode_config():
    from godrecon.core.config import ScanModeConfig
    c = ScanModeConfig()
    assert c.mode == "standard"
    assert c.continuous_interval == 3600
