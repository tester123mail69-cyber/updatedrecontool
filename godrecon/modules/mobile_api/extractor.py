"""Mobile API endpoint extractor — analyzes APK files for embedded secrets."""

from __future__ import annotations

import re
import zipfile
from pathlib import Path
from typing import List

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult

_PATTERNS = {
    "api_endpoint": re.compile(
        r'https?://[a-zA-Z0-9._/-]+(?:/v\d+)?(?:/api)?[a-zA-Z0-9/_-]*', re.IGNORECASE
    ),
    "api_key": re.compile(
        r'(?:api[_-]?key|apikey|access[_-]?token|secret[_-]?key)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})',
        re.IGNORECASE,
    ),
    "firebase": re.compile(r'https://[a-z0-9_-]+\.firebaseio\.com', re.IGNORECASE),
    "aws_endpoint": re.compile(r'https://s3[.-][a-z0-9-]+\.amazonaws\.com/[a-zA-Z0-9._/-]*'),
    "aws_key": re.compile(r'AKIA[0-9A-Z]{16}'),
    "google_key": re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
}


class MobileAPIModule(BaseModule):
    """Extracts API endpoints and secrets from APK files."""

    name = "mobile_api"
    description = "Mobile API endpoint extractor for APK analysis"
    version = "1.0.0"
    category = "mobile"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        findings: List[Finding] = []
        apk_paths = config.mobile_api.apk_paths if config.mobile_api.apk_paths else []

        for apk_path in apk_paths:
            path = Path(apk_path)
            if path.exists() and path.suffix.lower() == ".apk":
                findings.extend(self._analyze_apk(apk_path))

        if not apk_paths:
            findings.append(Finding(
                title="Mobile API: No APK configured",
                description="Set mobile_api.apk_paths in config to analyze APK files.",
                severity="info",
                tags=["mobile_api"],
            ))

        return ModuleResult(module_name=self.name, target=target, findings=findings)

    def _analyze_apk(self, apk_path: str) -> List[Finding]:
        findings: List[Finding] = []
        seen: set = set()
        try:
            with zipfile.ZipFile(apk_path, "r") as z:
                for name in z.namelist():
                    if not name.endswith((".xml", ".js", ".json", ".smali", ".properties")):
                        continue
                    try:
                        content = z.read(name).decode("utf-8", errors="ignore")
                    except Exception:  # noqa: BLE001
                        continue
                    for kind, pattern in _PATTERNS.items():
                        for match in pattern.findall(content):
                            val = match if isinstance(match, str) else match[0]
                            key = f"{kind}:{val}"
                            if key in seen:
                                continue
                            seen.add(key)
                            severity = "high" if kind in ("api_key", "aws_key", "google_key") else "medium"
                            findings.append(Finding(
                                title=f"Mobile API: {kind.replace('_', ' ').title()} found",
                                description=f"Found in {name}: {val[:200]}",
                                severity=severity,
                                tags=["mobile_api", kind],
                                data={"file": name, "type": kind, "value": val[:200]},
                            ))
        except Exception:  # noqa: BLE001
            pass
        return findings
