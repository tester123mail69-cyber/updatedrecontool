"""Tests for the subdomain supercharger new sources and configuration."""

from __future__ import annotations

import pytest

from godrecon.core.config import (
    Config,
    APIKeysConfig,
    SubdomainSuperchargerConfig,
    SubdomainSuperchargerSourcesConfig,
    SubdomainSuperchargerTechniquesConfig,
)


# ---------------------------------------------------------------------------
# Config tests
# ---------------------------------------------------------------------------


def test_api_keys_has_chaos():
    """APIKeysConfig should include a chaos field."""
    cfg = APIKeysConfig()
    assert hasattr(cfg, "chaos")
    assert cfg.chaos == ""


def test_config_has_subdomain_supercharger():
    """Config should include subdomain_supercharger field."""
    cfg = Config()
    assert hasattr(cfg, "subdomain_supercharger")
    assert isinstance(cfg.subdomain_supercharger, SubdomainSuperchargerConfig)


def test_subdomain_supercharger_defaults():
    """SubdomainSuperchargerConfig should have sensible defaults."""
    cfg = SubdomainSuperchargerConfig()
    assert cfg.recursive_depth == 3
    assert cfg.threads == 50
    assert cfg.timeout == 10
    assert cfg.wildcard_detection is True
    assert cfg.bruteforce_wordlist == "wordlists/subdomains-large.txt"
    assert cfg.permutation_wordlist == "wordlists/permutations.txt"


def test_subdomain_supercharger_sources_defaults():
    """All passive sources should be enabled by default."""
    sources = SubdomainSuperchargerSourcesConfig()
    assert sources.subfinder is True
    assert sources.amass is True
    assert sources.assetfinder is True
    assert sources.findomain is True
    assert sources.chaos is True
    assert sources.crtsh is True
    assert sources.securitytrails is True
    assert sources.shodan is True
    assert sources.censys is True
    assert sources.virustotal is True
    assert sources.bufferover is True
    assert sources.alienvault is True
    assert sources.wayback is True
    assert sources.commoncrawl is True
    assert sources.rapiddns is True
    assert sources.riddler is True
    assert sources.threatcrowd is True
    assert sources.hackertarget is True
    assert sources.dnsdumpster is True
    assert sources.github is True


def test_subdomain_supercharger_techniques_defaults():
    """All active techniques should be enabled by default."""
    techniques = SubdomainSuperchargerTechniquesConfig()
    assert techniques.dns_bruteforce is True
    assert techniques.permutations is True
    assert techniques.recursive is True
    assert techniques.zone_transfer is True
    assert techniques.tls_scraping is True
    assert techniques.reverse_dns is True
    assert techniques.google_dorking is True
    assert techniques.noerror_enum is True
    assert techniques.favicon_hash is True
    assert techniques.spf_mining is True


# ---------------------------------------------------------------------------
# New source instantiation tests
# ---------------------------------------------------------------------------


def test_chaos_source_instantiates():
    """ChaosSource should instantiate with an API key."""
    from godrecon.modules.subdomains.sources.chaos import ChaosSource
    src = ChaosSource(api_key="testkey123")
    assert src.name == "chaos"
    assert src.requires_api_key is True
    assert src.api_key_name == "chaos"


def test_chaos_source_empty_key():
    """ChaosSource should instantiate with empty key (fetch will return empty)."""
    from godrecon.modules.subdomains.sources.chaos import ChaosSource
    src = ChaosSource(api_key="")
    assert src.api_key == ""


def test_subfinder_source_instantiates():
    """SubfinderSource should instantiate without any API key."""
    from godrecon.modules.subdomains.sources.subfinder import SubfinderSource
    src = SubfinderSource()
    assert src.name == "subfinder"
    assert src.requires_api_key is False


def test_amass_source_instantiates():
    """AmassSource should instantiate without any API key."""
    from godrecon.modules.subdomains.sources.amass import AmassSource
    src = AmassSource()
    assert src.name == "amass"
    assert src.requires_api_key is False


def test_assetfinder_source_instantiates():
    """AssetfinderSource should instantiate without any API key."""
    from godrecon.modules.subdomains.sources.assetfinder import AssetfinderSource
    src = AssetfinderSource()
    assert src.name == "assetfinder"
    assert src.requires_api_key is False


def test_findomain_source_instantiates():
    """FindomainSource should instantiate without any API key."""
    from godrecon.modules.subdomains.sources.findomain import FindomainSource
    src = FindomainSource()
    assert src.name == "findomain"
    assert src.requires_api_key is False


def test_tls_scrape_source_instantiates():
    """TLSScrapeSource should instantiate without any API key."""
    from godrecon.modules.subdomains.sources.tls_scrape import TLSScrapeSource
    src = TLSScrapeSource()
    assert src.name == "tls_scrape"
    assert src.requires_api_key is False


def test_noerror_enum_source_instantiates():
    """NoErrorEnumSource should instantiate without any API key."""
    from godrecon.modules.subdomains.sources.noerror_enum import NoErrorEnumSource
    src = NoErrorEnumSource()
    assert src.name == "noerror_enum"
    assert src.requires_api_key is False


def test_favicon_shodan_source_instantiates():
    """FaviconShodanSource should instantiate with a Shodan API key."""
    from godrecon.modules.subdomains.sources.favicon_shodan import FaviconShodanSource
    src = FaviconShodanSource(api_key="testkey456")
    assert src.name == "favicon_shodan"
    assert src.requires_api_key is True
    assert src.api_key_name == "shodan"


def test_favicon_shodan_mmh3_hash():
    """The MurmurHash3 function should return a signed 32-bit integer."""
    from godrecon.modules.subdomains.sources.favicon_shodan import _mmh3_hash
    result = _mmh3_hash(b"hello world")
    assert isinstance(result, int)
    assert -(2**31) <= result <= (2**31 - 1)


def test_all_new_sources_are_subdomain_sources():
    """All new source classes must subclass SubdomainSource."""
    from godrecon.modules.subdomains.sources.base import SubdomainSource
    from godrecon.modules.subdomains.sources.chaos import ChaosSource
    from godrecon.modules.subdomains.sources.subfinder import SubfinderSource
    from godrecon.modules.subdomains.sources.amass import AmassSource
    from godrecon.modules.subdomains.sources.assetfinder import AssetfinderSource
    from godrecon.modules.subdomains.sources.findomain import FindomainSource
    from godrecon.modules.subdomains.sources.tls_scrape import TLSScrapeSource
    from godrecon.modules.subdomains.sources.noerror_enum import NoErrorEnumSource
    from godrecon.modules.subdomains.sources.favicon_shodan import FaviconShodanSource

    for cls in (
        ChaosSource,
        SubfinderSource,
        AmassSource,
        AssetfinderSource,
        FindomainSource,
        TLSScrapeSource,
        NoErrorEnumSource,
        FaviconShodanSource,
    ):
        assert issubclass(cls, SubdomainSource), f"{cls.__name__} must subclass SubdomainSource"


def test_permutations_wordlist_exists():
    """The permutations wordlist should exist in the wordlists directory."""
    from pathlib import Path
    wordlist = Path("wordlists/permutations.txt")
    assert wordlist.exists(), "wordlists/permutations.txt must exist"
    words = [
        line.strip()
        for line in wordlist.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]
    assert len(words) >= 50, "permutations wordlist should have at least 50 entries"
    assert "dev" in words
    assert "staging" in words
    assert "api" in words


def test_aggregator_builds_sources_with_chaos_key():
    """The aggregator should include ChaosSource when chaos API key is set."""
    from godrecon.modules.subdomains.aggregator import _build_sources
    from godrecon.core.config import Config

    cfg = Config()
    cfg.api_keys.chaos = "fake-chaos-key-12345"
    sources = _build_sources(cfg)
    source_names = [s.name for s in sources]
    assert "chaos" in source_names, "ChaosSource should be included when chaos API key is set"


def test_aggregator_skips_chaos_without_key():
    """The aggregator should skip ChaosSource when chaos API key is empty."""
    from godrecon.modules.subdomains.aggregator import _build_sources
    from godrecon.core.config import Config

    cfg = Config()
    cfg.api_keys.chaos = ""
    sources = _build_sources(cfg)
    source_names = [s.name for s in sources]
    assert "chaos" not in source_names, "ChaosSource should be skipped when chaos API key is absent"
