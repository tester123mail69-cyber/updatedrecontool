# Contributing to GODRECON

Thank you for your interest in contributing to GODRECON! This project is maintained by **nothingmch69**.

---

## How to Contribute

### Fork → Branch → PR

1. **Fork** the repository on GitHub
2. **Clone** your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/recon1.git
   cd recon1
   ```
3. **Create a branch** for your feature or fix:
   ```bash
   git checkout -b feature/my-feature
   # or
   git checkout -b fix/my-bugfix
   ```
4. **Make your changes** (see guidelines below)
5. **Test** your changes:
   ```bash
   pip install -e ".[dev]"
   pytest tests/
   ```
6. **Commit** with a clear message:
   ```bash
   git commit -m "feat: add new subdomain source for xyz"
   ```
7. **Push** and open a Pull Request:
   ```bash
   git push origin feature/my-feature
   ```

---

## Code Style Guidelines

- **Python 3.10+** — use modern Python features (match/case, `|` unions, etc.)
- **Type hints** — all public functions must have type hints
- **Docstrings** — use Google-style docstrings
- **Line length** — 100 characters max
- **Async-first** — all I/O operations must be async
- **Error handling** — never let a module crash the entire scan; catch exceptions and log them

---

## Adding a New Scanner Module

1. Create a directory under `godrecon/modules/your_module/`
2. Create `__init__.py` and `scanner.py`
3. Inherit from `BaseModule`:

```python
from godrecon.modules.base import BaseModule, ModuleResult

class YourScanner(BaseModule):
    name = "your_module"
    description = "What this module does"

    async def _execute(self, target: str, **kwargs) -> ModuleResult:
        findings = []
        # ... your logic here ...
        return ModuleResult(findings=findings)
```

4. Register the module in `godrecon/core/engine.py`
5. Add tests in `tests/`

---

## Reporting Bugs

Open an issue on [GitHub Issues](https://github.com/tester123mail69-cyber/updatedrecontool/issues) with:

- Clear title describing the bug
- Steps to reproduce
- Expected vs actual behavior
- Python version and OS
- Error output / stack trace

---

## Feature Requests

Open a GitHub Issue with the `enhancement` label. Describe:

- The use case / problem you're solving
- How you envision it working
- Any relevant examples from other tools

---

## Project Maintainer

This project is maintained by **[nothingmch69](https://github.com/nothingmch69)**.
