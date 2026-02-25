# GODRECON

```
 ██████╗  ██████╗ ██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔════╝ ██╔═══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██║  ███╗██║   ██║██║  ██║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██║   ██║██║   ██║██║  ██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
╚██████╔╝╚██████╔╝██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═════╝  ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
                          by nothingmch69
```

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/tester123mail69-cyber/updatedrecontool?style=social)](https://github.com/tester123mail69-cyber/updatedrecontool/stargazers)
[![GitHub issues](https://img.shields.io/github/issues/tester123mail69-cyber/updatedrecontool)](https://github.com/tester123mail69-cyber/updatedrecontool/issues)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

> **The Ultimate Automated Reconnaissance & Vulnerability Scanner for Bug Bounty Hunters**

---

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Scan Modes](#scan-modes)
- [CLI Reference](#cli-reference)
- [API Keys Setup](#api-keys-setup)
- [Dashboard Guide](#dashboard-guide)
- [Architecture](#architecture)
- [Contributing](#contributing)
- [License](#license)

---

## Features

### Scanner Features (32+)

| Feature | Description |
|---------|-------------|
| **Subdomain Enumeration** | 38+ sources — Subfinder, Amass, Assetfinder, Findomain, Chaos, crt.sh, SecurityTrails, Shodan, Censys, VirusTotal, BufferOver, AlienVault, Wayback, CommonCrawl, RapidDNS, Riddler, ThreatCrowd, HackerTarget, DNSDumpster, GitHub Code Search, and more |
| **Subdomain Supercharger** | DNS brute-force, permutation engine, recursive enumeration, AXFR zone transfer, TLS cert scraping, reverse DNS, NOERROR enumeration, favicon hash matching, SPF/TXT mining |
| **Port Scanning** | Full 65535-port or top-ports scan with banner grabbing |
| **Technology Fingerprinting** | Detect frameworks, servers, CMSs, and libraries |
| **WAF Detection & Bypass** | Cloudflare, Akamai, AWS WAF, Sucuri, Imperva, ModSecurity, F5 |
| **Vulnerability Detection P1–P5** | SQLi, RCE, SSRF, XSS, LFI/RFI, XXE, SSTI, IDOR, CSRF, CORS, Open Redirect, Command Injection, Deserialization, JWT attacks, GraphQL injection, and more |
| **JS Secrets Scanner** | 16 regex patterns + entropy analysis |
| **GitHub/GitLab Dorking** | Automated code search for secrets and sensitive data |
| **Nuclei Integration** | 8000+ community templates |
| **Out-of-Band (OOB) Detection** | Blind SSRF, XSS, SQLi, XXE, RCE |
| **Authenticated Scanning** | Cookie, token, and custom header injection |
| **Smart Parameter Discovery** | Automatic parameter enumeration and fuzzing |
| **Auto Vulnerability Chaining** | Detects and chains multi-step exploits |
| **Cloud Misconfiguration Scanner** | S3, Azure Blob, GCP, Firebase, Kubernetes, Docker |
| **Passive Recon** | Shodan, Censys, SecurityTrails, VirusTotal |
| **Mobile API Endpoint Extractor** | APK decompilation and endpoint extraction |
| **Broken Authentication Scanner** | Session, token, and auth flow testing |
| **Wayback Machine Deep Mining** | Historical URL and parameter extraction |
| **Business Logic Flaw Detection** | Workflow and logic vulnerability testing |
| **Cache Poisoning Scanner** | Web cache poisoning detection |
| **Browser Extension Analyzer** | Extension security analysis |
| **Multi-Region Scanning** | Scan from multiple geographic locations |
| **Supply Chain Analysis** | Dependency and third-party risk analysis |
| **Email Security** | SPF/DKIM/DMARC misconfiguration detection |
| **DNS Analysis** | Full DNS intelligence (A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, CAA) |
| **SSL/TLS Analysis** | Certificate transparency, cipher suites, expiry |
| **Bug Bounty Program Auto-Matcher** | Automatically match findings to bounty programs |
| **AI-Powered Vulnerability Validation** | OpenAI, Claude, Gemini, Ollama, Pattern-based |
| **Smart Priority Scoring** | 0–100 confidence scoring with false-positive filtering |
| **Auto Bug Report Generator** | HackerOne, Bugcrowd, Markdown, PDF formats |
| **Scan Diffing** | Compare two scans to detect new findings |
| **Continuous Monitoring with Alerts** | Slack, Discord, Telegram, Webhook notifications |

### Dashboard Features (70)

<details>
<summary>Click to expand all 70 dashboard features</summary>

**Core Features**
- Live scan progress with real-time updates
- Multi-target management
- Scan history and result storage
- REST API with OpenAPI docs

**Visual & UX**
- Dark/light theme toggle
- Responsive sidebar navigation
- Global search (Ctrl+K)
- Toast notifications
- Rich data tables with sorting/filtering

**Productivity**
- Kanban-style findings board
- Bulk actions on findings
- CSV/JSON/HTML/PDF export
- Report generation wizard
- Scheduled scan management

**Analytics**
- Findings severity breakdown
- Subdomain growth over time
- Vulnerability trend charts
- Module performance metrics
- Leaderboard view

**Security**
- API key authentication
- CORS configuration
- Rate limiting
- Audit log / activity feed

**WOW Factor**
- Attack surface visualization
- Interactive findings timeline
- AI validation panel
- Bug bounty matcher
- Secrets explorer

**Scanner Panels**
- Subdomain enumeration panel
- Vulnerability findings panel
- Port scan results
- Technology fingerprint view
- Cloud misconfiguration panel

**Power Features**
- Scan diffing view
- Continuous monitoring dashboard
- Alert management
- Webhook configuration
- Multi-region scan control

</details>

---

## Quick Start

```bash
# Clone
git clone https://github.com/tester123mail69-cyber/updatedrecontool.git
cd recon1

# Install
pip install -r requirements.txt

# Run your first scan
python main.py scan --target example.com

# Launch dashboard
python main.py api
# Then open http://127.0.0.1:8000/dashboard/
```

---

## Scan Modes

| Mode | Duration | What it does | Command |
|------|----------|-------------|---------|
| **Quick Scan** | 30–45 min | Subdomains + top vulns + secrets | `python main.py scan --target example.com --mode quick` |
| **Standard Scan** | 1.5–2.5 hrs | Everything except fuzzing + OOB + full Nuclei | `python main.py scan --target example.com` |
| **Deep Scan / GOD MODE** | 4–6 hrs | EVERYTHING enabled, no timeouts | `python main.py scan --target example.com --deep` |
| **Continuous Mode** | 24/7 | Rescans on schedule, alerts on new findings | `python main.py monitor example.com --interval daily` |

```bash
# Quick Scan — fast recon
python main.py scan --target example.com --mode quick

# Standard Scan — balanced coverage
python main.py scan --target example.com --format html -o report.html

# Deep Scan — maximum coverage
python main.py scan --target example.com --deep --oob --fuzzing --nuclei

# Continuous Monitoring — daily rescans with Slack alerts
python main.py monitor example.com --interval daily --notify slack
```

---

## CLI Reference

### `godrecon scan`

| Flag | Description | Example |
|------|-------------|---------|
| `--target` | Target domain, IP, or CIDR **(required)** | `--target example.com` |
| `--full` | Run all modules | `--full` |
| `--deep` | Deep scan mode — exhaustive, no timeouts | `--deep` |
| `--mode` | Scan mode: `quick`, `standard`, `deep`, `continuous` | `--mode quick` |
| `--subs-only` | Subdomain enumeration only | `--subs-only` |
| `--ports` | Enable port scanning | `--ports` |
| `--screenshots` | Enable screenshots | `--screenshots` |
| `--nuclei/--no-nuclei` | Run Nuclei templates (default: on) | `--no-nuclei` |
| `--oob` | Enable OOB detection | `--oob` |
| `--fuzzing` | Enable fuzzing engine | `--fuzzing` |
| `--waf-bypass` | Enable WAF bypass techniques | `--waf-bypass` |
| `--auth-cookie` | Session cookie for authenticated scanning | `--auth-cookie session=abc123` |
| `--auth-token` | Bearer token for authenticated scanning | `--auth-token eyJ...` |
| `--auth-header` | Custom auth header | `--auth-header X-API-Key=secret` |
| `--ai-provider` | AI validation provider: `pattern`, `openai`, `anthropic`, `gemini`, `ollama` | `--ai-provider openai` |
| `--passive-recon/--no-passive-recon` | Enable passive recon (default: on) | `--passive-recon` |
| `--wayback/--no-wayback` | Enable Wayback Machine mining (default: on) | `--wayback` |
| `--cache-poisoning/--no-cache-poisoning` | Enable cache poisoning scanner (default: on) | `--cache-poisoning` |
| `--js-secrets/--no-js-secrets` | Enable JS secrets scanning (default: on) | `--js-secrets` |
| `--git-dork` | Enable GitHub/GitLab dorking | `--git-dork` |
| `--output` / `-o` | Output file path | `-o report.html` |
| `--format` / `-f` | Output format: `json`, `csv`, `html`, `pdf`, `md` | `-f html` |
| `--threads` | Concurrency level (default: 50) | `--threads 100` |
| `--min-confidence` | Minimum confidence threshold 0.0–1.0 (default: 0.5) | `--min-confidence 0.7` |
| `--verify/--no-verify` | Cross-validation pass | `--verify` |
| `--resume` | Resume interrupted scan | `--resume` |

### Other Commands

```bash
# Start the API server + dashboard
godrecon api --host 0.0.0.0 --port 8000

# Generate bug bounty report from scan JSON
godrecon report scan.json --format hackerone -o report

# Compare two scans
godrecon diff scan1.json scan2.json

# Manage monitoring schedules
godrecon schedules list
godrecon schedules add --target example.com --interval daily

# Show version
godrecon version
```

---

## API Keys Setup

All API keys are **optional** — GODRECON works without them. Keys unlock additional data sources.

| Key | Where to Get | Free Tier | What it Enables |
|-----|-------------|-----------|-----------------|
| **Shodan** | [shodan.io/register](https://account.shodan.io/register) | 100 queries/month | Port data, banners, CVEs |
| **Censys** | [censys.io/register](https://censys.io/register) | 250 queries/month | Host data, certificates |
| **SecurityTrails** | [securitytrails.com](https://securitytrails.com/app/account) | 50 queries/month | Historical DNS, subdomains |
| **VirusTotal** | [virustotal.com](https://www.virustotal.com/gui/join-us) | 500 req/day | Subdomain data, malware info |
| **OpenAI** | [platform.openai.com](https://platform.openai.com/signup) | $5 free credit | AI vulnerability validation |
| **Anthropic (Claude)** | [console.anthropic.com](https://console.anthropic.com) | $5 free credit | AI vulnerability validation |
| **Google (Gemini)** | [aistudio.google.com](https://aistudio.google.com) | Free tier available | AI vulnerability validation |
| **Chaos (ProjectDiscovery)** | [chaos.projectdiscovery.io](https://chaos.projectdiscovery.io) | Free for researchers | Bug bounty subdomain data |
| **GitHub Token** | [github.com/settings/tokens](https://github.com/settings/tokens) | Free | GitHub dorking, code search |

Add keys to `config.yaml`:

```yaml
api_keys:
  shodan: "your-shodan-key"
  censys_id: "your-censys-app-id"
  censys_secret: "your-censys-secret"
  securitytrails: "your-st-key"
  virustotal: "your-vt-key"
  openai: "sk-..."
  anthropic: "sk-ant-..."
  github_token: "ghp_..."
```

---

## Dashboard Guide

```bash
# Start the server
python main.py api

# Open in browser
# Dashboard: http://127.0.0.1:8000/dashboard/
# API Docs:  http://127.0.0.1:8000/docs
```

The dashboard provides a full web UI with 70 features across:

- **Scans** — Start scans, view progress, browse history
- **Findings** — All vulnerabilities sorted by severity
- **Subdomains** — Complete subdomain enumeration results
- **Vulnerabilities** — P1–P5 vulnerability details
- **Secrets** — JS secrets and leaked credentials
- **Analytics** — Charts, trends, and statistics
- **Reports** — Generate and download reports
- **Targets** — Manage your target list
- **Alerts** — Monitoring alerts and notifications
- **Settings** — API keys, notifications, preferences

See [docs/DASHBOARD_GUIDE.md](docs/DASHBOARD_GUIDE.md) for the full guide.

---

## Architecture

```
godrecon/
├── ai/                  # AI validation (OpenAI, Claude, Gemini, Ollama, Pattern)
├── api/                 # FastAPI server
├── core/                # Engine, config, scheduler, verifier, PoC generator
├── dashboard/           # 70-feature web dashboard
│   ├── templates/       # Jinja2 HTML templates (33+ pages)
│   ├── static/          # CSS, JS, assets
│   └── routes.py        # 75 routes + 30 API endpoints
├── modules/             # All scanner modules
│   ├── subdomains/      # 38+ subdomain sources
│   ├── vulns/           # P1-P5 vulnerability detectors
│   ├── passive_recon/   # Shodan, Censys, SecurityTrails, VirusTotal
│   ├── cloud_misconfig/ # S3, Azure, GCP, Firebase, K8s
│   └── ...              # 20+ more module directories
├── monitoring/          # Slack, Discord, Telegram notifications
├── reporting/           # JSON, HTML, CSV, Markdown, PDF, Bug Reports
├── utils/               # HTTP client, DNS resolver, auth client, helpers
└── cli.py               # Typer + Rich CLI
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full technical overview.

---

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/my-module`)
3. Add your module under `godrecon/modules/`
4. Inherit from `BaseModule` and implement `_execute`
5. Submit a Pull Request

---

## License

MIT License — Copyright © 2026 nothingmch69

See [LICENSE](LICENSE) for full text.

---

<p align="center">Made with ❤️ by <a href="https://github.com/nothingmch69">nothingmch69</a></p>

