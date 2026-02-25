# Frequently Asked Questions

## General

### Is this legal?

**Only scan targets you have explicit permission to test.**

GODRECON is designed for:
- Your own infrastructure
- Bug bounty programs (within their defined scope)
- Authorized penetration testing engagements

**Unauthorized use of this tool against systems you don't own or have permission to test is illegal** under the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act (UK), and equivalent laws worldwide.

The maintainer (nothingmch69) is not responsible for any misuse.

---

### Do I need all API keys?

**No.** All API keys are completely optional.

GODRECON works without any API keys using:
- Free public data sources (crt.sh, Wayback Machine, CommonCrawl, etc.)
- Local scanning (DNS brute-force, HTTP probing, etc.)
- Pattern-based AI validation (no API key needed)

API keys just add more data sources and better AI validation. Start without them and add keys as you need them.

---

### Does it work on Windows?

**Yes.** GODRECON supports Windows 10/11.

- PowerShell is supported
- **WSL2 (Windows Subsystem for Linux) is recommended** for best performance
- All Python features work natively on Windows
- Some external tools (subfinder, amass, nuclei) work best on Linux/macOS

---

### Does it work on macOS?

**Yes.** Full support on macOS 12 Monterey and later.

Install Python via Homebrew:
```bash
brew install python@3.12
```

---

### What Python version do I need?

**Python 3.10 or higher** is required.

Check your version:
```bash
python --version
# or
python3 --version
```

---

## Scanning

### How do I start my first scan?

```bash
git clone https://github.com/tester123mail69-cyber/updatedrecontool.git
cd recon1
pip install -r requirements.txt
python main.py scan --target example.com
```

---

### How long does a scan take?

| Mode | Typical Duration |
|------|-----------------|
| Quick | 30–45 minutes |
| Standard | 1.5–2.5 hours |
| Deep / GOD MODE | 4–6 hours |
| Continuous | Runs 24/7 |

Factors that affect scan time: number of subdomains found, number of live hosts, enabled modules, thread count, and network speed.

---

### Can I scan an IP address or CIDR range?

Yes:
```bash
python main.py scan --target 192.168.1.1
python main.py scan --target 192.168.1.0/24
```

---

### How do I scan a login-protected application?

Use authentication options:
```bash
# Cookie
python main.py scan --target example.com --auth-cookie "session=abc123"

# Bearer token
python main.py scan --target example.com --auth-token "eyJ..."

# Custom header
python main.py scan --target example.com --auth-header "X-API-Key=secret"
```

---

### Can I resume an interrupted scan?

Yes:
```bash
python main.py scan --target example.com --resume
```

---

## Bug Bounty

### How do I get started with bug bounty?

Great resources for beginners:
- [HackerOne's beginner guide](https://www.hackerone.com/hackers/hacker101)
- [Bugcrowd University](https://www.bugcrowd.com/hackers/bugcrowd-university/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) (free)
- [Bug Bounty Hunting Essentials](https://www.amazon.com/Bug-Bounty-Hunting-Essentials-Carlos/dp/1788626893)

Always read the program's scope carefully before scanning.

---

### How do I generate a bug bounty report?

```bash
# Run scan and save JSON
python main.py scan --target example.com --format json -o scan.json

# Generate HackerOne report
python main.py report scan.json --format hackerone -o h1_report

# Generate Bugcrowd report
python main.py report scan.json --format bugcrowd -o bc_report
```

---

## Technical

### Can I add custom modules?

Yes! See [CONTRIBUTING.md](../CONTRIBUTING.md) for how to add new scanner modules.

---

### Where are scan results saved?

By default, results are saved to `./output/`. Change this in `config.yaml`:
```yaml
general:
  output_dir: /path/to/your/output
```

---

### How do I configure notification webhooks?

In `config.yaml`:
```yaml
notifications:
  slack_webhook: "https://hooks.slack.com/services/..."
  discord_webhook: "https://discord.com/api/webhooks/..."
  telegram_bot_token: "..."
  telegram_chat_id: "..."
```

---

### What databases does GODRECON use?

GODRECON stores scan data in SQLite by default (in `./godrecon.db`). No external database setup required.

---

### How do I run GODRECON in Docker?

```bash
docker-compose build
docker-compose run godrecon scan --target example.com
docker-compose run -p 8000:8000 godrecon api --host 0.0.0.0
```
