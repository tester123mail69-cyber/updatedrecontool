"""Configuration management for GODRECON.

Loads configuration from config.yaml, with support for CLI overrides
and environment variables.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, Field

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


class DNSConfig(BaseModel):
    """DNS resolver configuration."""

    resolvers: List[str] = ["8.8.8.8", "8.8.4.4", "1.1.1.1"]
    timeout: int = 5


class SubdomainBruteforceConfig(BaseModel):
    """Brute-force configuration for subdomain enumeration."""

    enabled: bool = True
    wordlist: str = "wordlists/subdomains-large.txt"
    concurrency: int = 500


class SubdomainPermutationConfig(BaseModel):
    """Permutation scanner configuration."""

    enabled: bool = True
    depth: int = 2
    patterns: List[str] = Field(default_factory=lambda: ["dev", "staging", "test", "api", "admin", "internal"])


class SubdomainRecursiveConfig(BaseModel):
    """Recursive enumeration configuration."""

    enabled: bool = False
    depth: int = 2


class SubdomainModuleConfig(BaseModel):
    """Detailed configuration for the subdomain enumeration module."""

    enabled: bool = True
    sources: List[str] = Field(default_factory=lambda: ["all"])
    bruteforce: SubdomainBruteforceConfig = Field(
        default_factory=SubdomainBruteforceConfig
    )
    permutation: SubdomainPermutationConfig = Field(
        default_factory=SubdomainPermutationConfig
    )
    recursive: SubdomainRecursiveConfig = Field(
        default_factory=SubdomainRecursiveConfig
    )
    timeout_per_source: int = 30


class DNSModuleConfig(BaseModel):
    """Configuration for the DNS intelligence module."""

    enabled: bool = True
    resolve_all_types: bool = True
    check_dnssec: bool = True
    attempt_zone_transfer: bool = True
    check_security: bool = True
    email_security: bool = True
    passive_dns: bool = True
    dkim_selectors: List[str] = Field(
        default_factory=lambda: [
            "default", "google", "selector1", "selector2", "k1", "k2",
            "dkim", "mail", "email", "s1", "s2", "mandrill", "amazonses",
            "cm", "protonmail", "zoho",
        ]
    )
    doh_enabled: bool = False
    doh_server: str = "https://cloudflare-dns.com/dns-query"


class ModulesConfig(BaseModel):
    """Enable/disable individual scan modules."""

    subdomains: bool = True
    dns: bool = True
    http_probe: bool = True
    ports: bool = True
    tech: bool = True
    osint: bool = True
    takeover: bool = True
    cloud: bool = True
    vulns: bool = True
    crawl: bool = True
    ssl: bool = True
    email_sec: bool = True
    screenshots: bool = True
    api_intel: bool = True
    content_discovery: bool = True
    network: bool = True
    visual: bool = True
    js_secrets: bool = True
    param_discovery: bool = True
    waf: bool = True
    fuzzing: bool = False  # disabled by default as it's active/noisy
    supply_chain: bool = True
    git_dorking: bool = True
    oob: bool = False  # disabled by default (needs external server)
    nuclei: bool = True
    passive_recon: bool = True
    mobile_api: bool = False
    vuln_chaining: bool = True
    cloud_misconfig: bool = True
    subdomain_permutation: bool = True
    broken_auth: bool = True
    collaboration: bool = False
    bug_bounty: bool = True
    browser_extension: bool = True
    wayback_mining: bool = True
    business_logic: bool = True
    multi_region: bool = False
    cache_poisoning: bool = True


class HttpProbeConfig(BaseModel):
    """HTTP probing configuration."""

    enabled: bool = True
    ports: List[int] = Field(default_factory=lambda: [80, 443, 8080, 8443, 8000, 8888, 3000, 5000])
    concurrency: int = 100
    timeout: int = 10
    follow_redirects: bool = True
    max_redirects: int = 5
    check_security_headers: bool = True
    check_cors: bool = True


class TechDetectionConfig(BaseModel):
    """Technology detection configuration."""

    enabled: bool = True
    detect_cms: bool = True
    detect_waf: bool = True
    detect_cdn: bool = True
    detect_frameworks: bool = True
    favicon_hash: bool = True
    jarm: bool = True


class SSLAnalysisConfig(BaseModel):
    """SSL/TLS analysis configuration."""

    enabled: bool = True
    check_ciphers: bool = True
    check_vulnerabilities: bool = True
    check_certificate: bool = True
    check_protocols: bool = True
    grade: bool = True


class PortScanConfig(BaseModel):
    """Port scanning configuration."""

    enabled: bool = True
    scan_type: str = "top100"  # top100, top1000, custom, full
    custom_ports: List[int] = Field(default_factory=list)
    concurrency: int = 500
    timeout: float = 3.0
    banner_grab: bool = True
    service_detection: bool = True


class ContentDiscoveryConfig(BaseModel):
    """Content and directory discovery configuration."""

    enabled: bool = True
    wordlist: str = "wordlists/directories.txt"
    concurrency: int = 50
    status_codes: List[int] = Field(default_factory=lambda: [200, 201, 301, 302, 307, 401, 403])
    recursive: bool = False
    recursive_depth: int = 2
    check_sensitive_files: bool = True
    check_backups: bool = True
    timeout: float = 10.0


class TakeoverConfig(BaseModel):
    """Subdomain takeover detection configuration."""

    enabled: bool = True
    verify: bool = True
    check_all_subdomains: bool = True


class APIKeysConfig(BaseModel):
    """API key configuration for external services."""

    shodan: str = ""
    censys_id: str = ""
    censys_secret: str = ""
    virustotal: str = ""
    securitytrails: str = ""
    binaryedge: str = ""
    hunter: str = ""
    github: str = ""
    fullhunt: str = ""
    nvd: str = ""
    gitlab: str = ""
    shodan_facets: str = ""
    openai: str = ""
    anthropic: str = ""
    gemini: str = ""
    chaos: str = ""


class ReportingConfig(BaseModel):
    """Reporting output configuration."""

    auto_report: bool = True
    format: str = "html"
    include_screenshots: bool = True


class DeepScanConfig(BaseModel):
    """Deep scan mode configuration overrides."""

    port_scan_type: str = "full"
    subdomain_recursive_depth: int = 5
    crawl_max_depth: int = 10
    crawl_max_pages: int = 5000
    content_discovery_recursive: bool = True
    content_discovery_depth: int = 5
    bruteforce_wordlist: str = "wordlists/subdomains-large.txt"
    directory_wordlist: str = "wordlists/directories-large.txt"
    module_timeout: int = 0


class GeneralConfig(BaseModel):
    """General scan configuration."""

    threads: int = 50
    timeout: int = 10
    retries: int = 3
    module_timeout: int = 300
    cross_validate: bool = False
    deep_scan: bool = False
    safe_mode: bool = True
    rate_limit: int = 0
    delay_between_requests: float = 0.0
    max_payload_tests: int = 10
    min_confidence: float = 0.5
    user_agents: List[str] = Field(
        default_factory=lambda: [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
        ]
    )
    proxy: Optional[str] = None
    output_dir: str = "./output"
    output_format: str = "json"


class OSINTConfig(BaseModel):
    """Configuration for the OSINT module."""

    enabled: bool = True
    whois: bool = True
    social_media: bool = True
    google_dorks: bool = True
    metadata_extraction: bool = True


class CloudConfig(BaseModel):
    """Configuration for the cloud asset enumeration module."""

    enabled: bool = True
    check_aws: bool = True
    check_azure: bool = True
    check_gcp: bool = True
    bucket_bruteforce: bool = True
    bucket_permutations: int = 10


class CrawlConfig(BaseModel):
    """Configuration for the web crawl module."""

    enabled: bool = True
    max_depth: int = 3
    max_pages: int = 100
    respect_robots: bool = True
    extract_forms: bool = True
    analyze_js: bool = True
    follow_redirects: bool = True


class APIIntelConfig(BaseModel):
    """Configuration for the API intelligence module."""

    enabled: bool = True
    discover_endpoints: bool = True
    check_security: bool = True
    check_graphql: bool = True


class VulnsConfig(BaseModel):
    """Configuration for the vulnerability detection module."""

    enabled: bool = True
    cve_lookup: bool = True
    pattern_matching: bool = True
    posture_scoring: bool = True
    max_cve_results: int = 20
    safe_mode: bool = True
    severity_threshold: str = "info"


class NetworkConfig(BaseModel):
    """Configuration for the network intelligence module."""

    enabled: bool = True
    traceroute: bool = True
    cdn_bypass: bool = True
    geolocation: bool = True
    asn_lookup: bool = True
    topology: bool = True
    max_traceroute_hops: int = 30
    origin_subdomain_check: bool = True


class VisualConfig(BaseModel):
    """Configuration for the visual reconnaissance module."""

    enabled: bool = True
    screenshots: bool = True
    similarity: bool = True
    concurrency: int = 5
    timeout: int = 15
    viewport_width: int = 1280
    viewport_height: int = 720
    output_dir: str = "output/screenshots"


class APIConfig(BaseModel):
    """Configuration for the REST API server."""

    enabled: bool = True
    host: str = "127.0.0.1"
    port: int = 8000
    api_key: str = ""
    cors_origins: List[str] = Field(default_factory=lambda: ["http://127.0.0.1:8000", "http://localhost:8000"])
    max_concurrent_scans: int = 3


class SlackConfig(BaseModel):
    """Slack notification configuration."""

    enabled: bool = False
    webhook_url: str = ""


class DiscordConfig(BaseModel):
    """Discord notification configuration."""

    enabled: bool = False
    webhook_url: str = ""


class TelegramConfig(BaseModel):
    """Telegram notification configuration."""

    enabled: bool = False
    bot_token: str = ""
    chat_id: str = ""


class EmailConfig(BaseModel):
    """Email (SMTP) notification configuration."""

    enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_pass: str = ""
    from_addr: str = ""
    to_addrs: List[str] = Field(default_factory=list)


class WebhookNotifConfig(BaseModel):
    """Generic webhook notification configuration."""

    enabled: bool = False
    url: str = ""
    headers: Dict[str, Any] = Field(default_factory=dict)


class NotificationsConfig(BaseModel):
    """Configuration for all notification backends."""

    slack: SlackConfig = Field(default_factory=SlackConfig)
    discord: DiscordConfig = Field(default_factory=DiscordConfig)
    telegram: TelegramConfig = Field(default_factory=TelegramConfig)
    email: EmailConfig = Field(default_factory=EmailConfig)
    webhook: WebhookNotifConfig = Field(default_factory=WebhookNotifConfig)


class MonitoringConfig(BaseModel):
    """Continuous monitoring configuration."""

    enabled: bool = True
    storage_dir: str = "./output/monitoring"
    max_history: int = 100


class DashboardConfig(BaseModel):
    """Web dashboard configuration."""

    enabled: bool = True
    host: str = "127.0.0.1"
    port: int = 8000


class AuthConfig(BaseModel):
    """Authenticated scanning configuration."""
    enabled: bool = False
    cookies: Dict[str, str] = Field(default_factory=dict)
    headers: Dict[str, str] = Field(default_factory=dict)
    bearer_token: str = ""
    api_key: str = ""
    api_key_header: str = "X-API-Key"
    login_url: str = ""
    login_data: Dict[str, str] = Field(default_factory=dict)
    session_renewal_url: str = ""


class NucleiConfig(BaseModel):
    """Nuclei template integration configuration."""
    enabled: bool = True
    binary_path: str = "nuclei"
    templates_dir: str = ""
    auto_update: bool = True
    severity: List[str] = Field(default_factory=lambda: ["critical", "high", "medium", "low"])
    concurrency: int = 25
    timeout: int = 30


class OOBConfig(BaseModel):
    """Out-of-band detection configuration."""
    enabled: bool = False
    server_url: str = ""
    interactsh_server: str = "https://oast.pro"
    use_interactsh: bool = False
    callback_timeout: int = 30


class JSSecretsConfig(BaseModel):
    """JavaScript secrets scanner configuration."""
    enabled: bool = True
    entropy_threshold: float = 4.0
    max_js_files: int = 100
    check_active: bool = False


class GitDorkConfig(BaseModel):
    """GitHub/GitLab dorking configuration."""
    enabled: bool = True
    max_results: int = 50
    search_gitlab: bool = False
    gitlab_url: str = "https://gitlab.com"


class WAFConfig(BaseModel):
    """WAF detection and bypass configuration."""
    enabled: bool = True
    apply_bypass: bool = True


class FuzzingConfig(BaseModel):
    """Fuzzing engine configuration."""
    enabled: bool = False
    max_mutations: int = 50
    timeout: float = 10.0
    detect_anomalies: bool = True


class ParamDiscoveryConfig(BaseModel):
    """Smart parameter discovery configuration."""
    enabled: bool = True
    brute_force: bool = True
    mine_js: bool = True
    extract_forms: bool = True
    max_params: int = 100


class SupplyChainConfig(BaseModel):
    """Supply chain analysis configuration."""
    enabled: bool = True
    check_sri: bool = True
    check_vulnerable_versions: bool = True


class SubdomainSuperchargerSourcesConfig(BaseModel):
    """Toggle individual passive sources for the subdomain supercharger."""

    subfinder: bool = True
    amass: bool = True
    assetfinder: bool = True
    findomain: bool = True
    chaos: bool = True
    crtsh: bool = True
    securitytrails: bool = True
    shodan: bool = True
    censys: bool = True
    virustotal: bool = True
    bufferover: bool = True
    alienvault: bool = True
    wayback: bool = True
    commoncrawl: bool = True
    rapiddns: bool = True
    riddler: bool = True
    threatcrowd: bool = True
    hackertarget: bool = True
    dnsdumpster: bool = True
    github: bool = True


class SubdomainSuperchargerTechniquesConfig(BaseModel):
    """Toggle active techniques for the subdomain supercharger."""

    dns_bruteforce: bool = True
    permutations: bool = True
    recursive: bool = True
    zone_transfer: bool = True
    tls_scraping: bool = True
    reverse_dns: bool = True
    google_dorking: bool = True
    noerror_enum: bool = True
    favicon_hash: bool = True
    spf_mining: bool = True


class SubdomainSuperchargerConfig(BaseModel):
    """Subdomain supercharger configuration (30+ sources and techniques)."""

    sources: SubdomainSuperchargerSourcesConfig = Field(
        default_factory=SubdomainSuperchargerSourcesConfig
    )
    techniques: SubdomainSuperchargerTechniquesConfig = Field(
        default_factory=SubdomainSuperchargerTechniquesConfig
    )
    bruteforce_wordlist: str = "wordlists/subdomains-large.txt"
    permutation_wordlist: str = "wordlists/permutations.txt"
    recursive_depth: int = 3
    threads: int = 50
    timeout: int = 10
    wildcard_detection: bool = True


class AIValidatorConfig(BaseModel):
    """AI-powered validator configuration."""
    provider: str = "pattern"  # pattern, openai, anthropic, gemini, ollama
    openai_api_key: str = ""
    anthropic_api_key: str = ""
    gemini_api_key: str = ""
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "llama3"
    confidence_threshold: float = 0.7


class PassiveReconConfig(BaseModel):
    """Passive recon configuration."""
    enabled: bool = True


class MobileAPIConfig(BaseModel):
    """Mobile API extractor configuration."""
    enabled: bool = False
    apk_paths: List[str] = Field(default_factory=list)


class VulnChainingConfig(BaseModel):
    """Vulnerability chaining configuration."""
    enabled: bool = True


class CloudMisconfigConfig(BaseModel):
    """Cloud misconfiguration scanner configuration."""
    enabled: bool = True
    check_s3: bool = True
    check_azure: bool = True
    check_gcp: bool = True
    check_firebase: bool = True
    check_k8s: bool = True
    check_metadata: bool = True


class BrokenAuthConfig(BaseModel):
    """Broken authentication scanner configuration."""
    enabled: bool = True
    test_password_reset: bool = True
    test_2fa_bypass: bool = True
    test_oauth: bool = True
    test_jwt: bool = True


class CollaborationConfig(BaseModel):
    """Real-time collaboration configuration."""
    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 8765


class BugBountyConfig(BaseModel):
    """Bug bounty program matcher configuration."""
    enabled: bool = True


class BrowserExtensionConfig(BaseModel):
    """Browser extension analyzer configuration."""
    enabled: bool = True


class WaybackMiningConfig(BaseModel):
    """Wayback Machine mining configuration."""
    enabled: bool = True
    sources: List[str] = Field(default_factory=lambda: ["wayback", "commoncrawl", "otx"])


class BusinessLogicConfig(BaseModel):
    """Business logic flaw detector configuration."""
    enabled: bool = True


class MultiRegionConfig(BaseModel):
    """Multi-region scanning configuration."""
    enabled: bool = False
    proxies: Dict[str, str] = Field(default_factory=dict)


class SmartScoringConfig(BaseModel):
    """Smart priority scoring configuration."""
    enabled: bool = True


class CachePoisoningConfig(BaseModel):
    """Cache poisoning scanner configuration."""
    enabled: bool = True


class ScanModeConfig(BaseModel):
    """Scan mode configuration."""
    mode: str = "standard"  # quick, standard, deep, continuous
    continuous_interval: int = 3600


class Config(BaseModel):
    """Top-level GODRECON configuration."""

    general: GeneralConfig = Field(default_factory=GeneralConfig)
    deep_scan: DeepScanConfig = Field(default_factory=DeepScanConfig)
    dns: DNSConfig = Field(default_factory=DNSConfig)
    modules: ModulesConfig = Field(default_factory=ModulesConfig)
    subdomains: SubdomainModuleConfig = Field(default_factory=SubdomainModuleConfig)
    dns_module: DNSModuleConfig = Field(default_factory=DNSModuleConfig)
    api_keys: APIKeysConfig = Field(default_factory=APIKeysConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    http_probe: HttpProbeConfig = Field(default_factory=HttpProbeConfig)
    tech_detection: TechDetectionConfig = Field(default_factory=TechDetectionConfig)
    ssl_analysis: SSLAnalysisConfig = Field(default_factory=SSLAnalysisConfig)
    port_scan: PortScanConfig = Field(default_factory=PortScanConfig)
    content_discovery: ContentDiscoveryConfig = Field(default_factory=ContentDiscoveryConfig)
    takeover: TakeoverConfig = Field(default_factory=TakeoverConfig)
    osint: OSINTConfig = Field(default_factory=OSINTConfig)
    cloud_config: CloudConfig = Field(default_factory=CloudConfig)
    crawl: CrawlConfig = Field(default_factory=CrawlConfig)
    api_intel: APIIntelConfig = Field(default_factory=APIIntelConfig)
    vulns: VulnsConfig = Field(default_factory=VulnsConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    visual: VisualConfig = Field(default_factory=VisualConfig)
    api: APIConfig = Field(default_factory=APIConfig)
    monitoring: MonitoringConfig = Field(default_factory=MonitoringConfig)
    notifications: NotificationsConfig = Field(default_factory=NotificationsConfig)
    dashboard: DashboardConfig = Field(default_factory=DashboardConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    nuclei: NucleiConfig = Field(default_factory=NucleiConfig)
    oob: OOBConfig = Field(default_factory=OOBConfig)
    js_secrets: JSSecretsConfig = Field(default_factory=JSSecretsConfig)
    git_dork: GitDorkConfig = Field(default_factory=GitDorkConfig)
    waf: WAFConfig = Field(default_factory=WAFConfig)
    fuzzing: FuzzingConfig = Field(default_factory=FuzzingConfig)
    param_discovery: ParamDiscoveryConfig = Field(default_factory=ParamDiscoveryConfig)
    supply_chain: SupplyChainConfig = Field(default_factory=SupplyChainConfig)
    ai_validator: AIValidatorConfig = Field(default_factory=AIValidatorConfig)
    passive_recon: PassiveReconConfig = Field(default_factory=PassiveReconConfig)
    mobile_api: MobileAPIConfig = Field(default_factory=MobileAPIConfig)
    vuln_chaining: VulnChainingConfig = Field(default_factory=VulnChainingConfig)
    cloud_misconfig: CloudMisconfigConfig = Field(default_factory=CloudMisconfigConfig)
    subdomain_permutation_config: SubdomainPermutationConfig = Field(default_factory=SubdomainPermutationConfig)
    broken_auth: BrokenAuthConfig = Field(default_factory=BrokenAuthConfig)
    collaboration_config: CollaborationConfig = Field(default_factory=CollaborationConfig)
    bug_bounty_config: BugBountyConfig = Field(default_factory=BugBountyConfig)
    browser_extension_config: BrowserExtensionConfig = Field(default_factory=BrowserExtensionConfig)
    wayback_mining_config: WaybackMiningConfig = Field(default_factory=WaybackMiningConfig)
    business_logic_config: BusinessLogicConfig = Field(default_factory=BusinessLogicConfig)
    multi_region_config: MultiRegionConfig = Field(default_factory=MultiRegionConfig)
    smart_scoring: SmartScoringConfig = Field(default_factory=SmartScoringConfig)
    cache_poisoning_config: CachePoisoningConfig = Field(default_factory=CachePoisoningConfig)
    scan_mode: ScanModeConfig = Field(default_factory=ScanModeConfig)
    subdomain_supercharger: SubdomainSuperchargerConfig = Field(
        default_factory=SubdomainSuperchargerConfig
    )


def load_config(config_path: Optional[str] = None) -> Config:
    """Load configuration from a YAML file, applying environment variable overrides.

    Args:
        config_path: Optional path to a YAML configuration file. Defaults to
                     ``config.yaml`` in the current working directory.

    Returns:
        Populated :class:`Config` instance.
    """
    path = Path(config_path) if config_path else Path("config.yaml")

    raw: Dict[str, Any] = {}
    if path.exists():
        with path.open("r") as fh:
            raw = yaml.safe_load(fh) or {}

    # Environment variable overrides (GODRECON__SECTION__KEY=value)
    _apply_env_overrides(raw)

    return Config(**raw)


def _apply_env_overrides(raw: Dict[str, Any]) -> None:
    """Mutate *raw* in-place with values from environment variables.

    Environment variables follow the pattern ``GODRECON__<SECTION>__<KEY>``.
    For example ``GODRECON__GENERAL__THREADS=100``.
    """
    prefix = "GODRECON__"
    for env_key, env_val in os.environ.items():
        if not env_key.startswith(prefix):
            continue
        parts = env_key[len(prefix):].lower().split("__")
        if len(parts) == 2:
            section, key = parts
            raw.setdefault(section, {})[key] = env_val
