# Installation Guide

## Requirements

- **Python 3.10+** (required)
- **pip** (comes with Python)
- **git** (to clone the repo)

---

## Step-by-Step Installation

### Linux (Ubuntu / Debian / Kali)

```bash
# 1. Install Python 3.10+ if not already installed
sudo apt update && sudo apt install -y python3 python3-pip python3-venv git

# 2. Clone the repo
git clone https://github.com/tester123mail69-cyber/updatedrecontool.git
cd recon1

# 3. Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Verify installation
python main.py version
```

### macOS

```bash
# 1. Install Python via Homebrew
brew install python@3.12 git

# 2. Clone and setup
git clone https://github.com/tester123mail69-cyber/updatedrecontool.git
cd recon1
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. Verify
python main.py version
```

### Windows

```powershell
# 1. Install Python 3.10+ from python.org (check "Add to PATH")
# 2. Open PowerShell

git clone https://github.com/tester123mail69-cyber/updatedrecontool.git
cd recon1
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Verify
python main.py version
```

---

## Optional External Tools

These tools enhance GODRECON's capabilities but are not required:

| Tool | Purpose | Install |
|------|---------|---------|
| [subfinder](https://github.com/projectdiscovery/subfinder) | Additional subdomain sources | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| [amass](https://github.com/owasp-amass/amass) | Deep subdomain enumeration | `go install -v github.com/owasp-amass/amass/v4/...@master` |
| [nuclei](https://github.com/projectdiscovery/nuclei) | 8000+ vulnerability templates | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| [findomain](https://github.com/findomain/findomain) | Fast subdomain finder | Download from GitHub releases |
| [assetfinder](https://github.com/tomnomnom/assetfinder) | Subdomain discovery | `go install github.com/tomnomnom/assetfinder@latest` |
| [playwright](https://playwright.dev/python/) | Screenshots | `pip install playwright && playwright install chromium` |

---

## Docker Installation

```bash
# Clone the repo
git clone https://github.com/tester123mail69-cyber/updatedrecontool.git
cd recon1

# Build
docker-compose build

# Run a scan
docker-compose run godrecon scan --target example.com

# Start the API server
docker-compose run -p 8000:8000 godrecon api --host 0.0.0.0
```

---

## Troubleshooting

### `ModuleNotFoundError`
```bash
# Make sure you're in the virtual environment
source venv/bin/activate  # Linux/macOS
.\venv\Scripts\Activate.ps1  # Windows

# Reinstall dependencies
pip install -r requirements.txt
```

### `Permission denied` errors
```bash
# Run with sudo if needed (not recommended for venv)
# Or fix permissions:
chmod +x main.py
```

### Playwright / screenshots not working
```bash
pip install playwright
playwright install chromium
```

### DNS resolution issues
Configure custom DNS resolvers in `config.yaml`:
```yaml
dns:
  resolvers:
    - "8.8.8.8"
    - "1.1.1.1"
    - "9.9.9.9"
```
