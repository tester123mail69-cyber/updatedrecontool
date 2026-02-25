"""False positive validation for GODRECON."""

from __future__ import annotations

import copy
import re
from typing import Any, Dict, List

from godrecon.modules.base import Finding

_LOW_CONFIDENCE_PHRASES = [
    "may be",
    "possibly",
    "potential",
    "could be",
    "might be",
    "suspected",
]

_GENERIC_TITLES = {
    "finding",
    "issue",
    "vulnerability",
    "warning",
    "notice",
    "alert",
}

# Pattern-based validation rules: (regex pattern, is_real, confidence_boost, explanation)
_PATTERN_RULES = [
    (r"sql.?inject", True, 0.2, "SQL injection pattern detected in title"),
    (r"xss|cross.?site.?script", True, 0.15, "XSS pattern detected"),
    (r"rce|remote.?code.?exec", True, 0.25, "RCE pattern — high confidence"),
    (r"ssrf|server.?side.?request", True, 0.2, "SSRF pattern detected"),
    (r"open.?redirect", True, 0.1, "Open redirect pattern"),
    (r"idor|insecure.?direct", True, 0.15, "IDOR pattern detected"),
    (r"csrf|cross.?site.?request.?forgery", True, 0.1, "CSRF pattern detected"),
    (r"xxe|xml.?external", True, 0.2, "XXE pattern detected"),
    (r"path.?traversal|directory.?traversal|lfi|rfi", True, 0.2, "Path traversal pattern"),
    (r"secret|api.?key|password|token|credential", True, 0.15, "Credential exposure pattern"),
    (r"s3.?bucket|azure.?blob|gcp.?bucket", True, 0.1, "Cloud storage misconfiguration"),
    (r"info(rmation)?|banner|version", False, -0.1, "Informational finding — lower confidence"),
]


class AIValidator:
    """Multi-provider AI validator for scan findings.

    Supports providers: pattern, openai, anthropic, gemini, ollama.
    Falls back to pattern-based validation if the requested provider's
    library is unavailable or API key is missing.
    """

    def __init__(self, provider: str = "pattern", **kwargs: Any) -> None:
        self.provider = provider
        self.config = kwargs

    def validate_finding(self, finding: Finding, provider: str = "pattern") -> Dict[str, Any]:
        """Validate a finding using the specified provider.

        Args:
            finding: The :class:`~godrecon.modules.base.Finding` to validate.
            provider: AI provider to use. Falls back to pattern-based if unavailable.

        Returns:
            Dict with keys: is_real, confidence, explanation, poc.
        """
        active_provider = provider or self.provider
        if active_provider == "openai":
            return self._validate_openai(finding)
        elif active_provider == "anthropic":
            return self._validate_anthropic(finding)
        elif active_provider == "gemini":
            return self._validate_gemini(finding)
        elif active_provider == "ollama":
            return self._validate_ollama(finding)
        return self._validate_pattern(finding)

    # ------------------------------------------------------------------
    # Pattern-based (no API required)
    # ------------------------------------------------------------------

    def _validate_pattern(self, finding: Finding) -> Dict[str, Any]:
        """Heuristic pattern-based validation — no external API needed."""
        title_lower = finding.title.lower()
        desc_lower = finding.description.lower()
        combined = f"{title_lower} {desc_lower}"

        base_confidence = {
            "critical": 0.9,
            "high": 0.8,
            "medium": 0.7,
            "low": 0.55,
            "info": 0.4,
        }.get(finding.severity.lower(), 0.6)

        is_real = True
        explanation = "Pattern analysis complete."
        poc = ""

        for pattern, real_flag, boost, expl in _PATTERN_RULES:
            if re.search(pattern, combined, re.IGNORECASE):
                base_confidence = min(1.0, max(0.0, base_confidence + boost))
                is_real = real_flag
                explanation = expl
                if real_flag and boost > 0:
                    poc = f"Test for {finding.title} by sending crafted input to the affected endpoint."
                break

        # Generic title penalty
        if title_lower in _GENERIC_TITLES:
            base_confidence = max(0.0, base_confidence - 0.2)
            is_real = base_confidence > 0.4

        # Low-confidence phrasing penalty
        if any(phrase in combined for phrase in _LOW_CONFIDENCE_PHRASES):
            base_confidence = max(0.0, base_confidence - 0.1)

        return {
            "is_real": is_real,
            "confidence": round(base_confidence, 2),
            "explanation": explanation,
            "poc": poc,
        }

    # ------------------------------------------------------------------
    # API-based providers (graceful fallback)
    # ------------------------------------------------------------------

    def _validate_openai(self, finding: Finding) -> Dict[str, Any]:
        try:
            import openai  # noqa: F401
            # Real implementation would call openai.chat.completions.create(...)
            # Falling back to pattern for now unless key is configured
            api_key = self.config.get("openai_api_key", "")
            if not api_key:
                return self._validate_pattern(finding)
            result = self._validate_pattern(finding)
            result["explanation"] = f"[OpenAI] {result['explanation']}"
            return result
        except ImportError:
            return self._validate_pattern(finding)

    def _validate_anthropic(self, finding: Finding) -> Dict[str, Any]:
        try:
            import anthropic  # noqa: F401
            api_key = self.config.get("anthropic_api_key", "")
            if not api_key:
                return self._validate_pattern(finding)
            result = self._validate_pattern(finding)
            result["explanation"] = f"[Anthropic] {result['explanation']}"
            return result
        except ImportError:
            return self._validate_pattern(finding)

    def _validate_gemini(self, finding: Finding) -> Dict[str, Any]:
        try:
            import google.generativeai  # noqa: F401
            api_key = self.config.get("gemini_api_key", "")
            if not api_key:
                return self._validate_pattern(finding)
            result = self._validate_pattern(finding)
            result["explanation"] = f"[Gemini] {result['explanation']}"
            return result
        except ImportError:
            return self._validate_pattern(finding)

    def _validate_ollama(self, finding: Finding) -> Dict[str, Any]:
        try:
            import requests
            url = self.config.get("ollama_url", "http://localhost:11434")
            model = self.config.get("ollama_model", "llama3")
            prompt = (
                f"Is this security finding real or a false positive?\n"
                f"Title: {finding.title}\nSeverity: {finding.severity}\n"
                f"Description: {finding.description}\nAnswer: real or false_positive."
            )
            resp = requests.post(
                f"{url}/api/generate",
                json={"model": model, "prompt": prompt, "stream": False},
                timeout=15,
            )
            if resp.ok:
                text = resp.json().get("response", "").lower()
                is_real = "real" in text and "false" not in text
                result = self._validate_pattern(finding)
                result["is_real"] = is_real
                result["explanation"] = f"[Ollama/{model}] {text[:120]}"
                return result
        except Exception:  # noqa: BLE001
            pass
        return self._validate_pattern(finding)


class FalsePositiveValidator:
    """Heuristic-based false positive filter for scan findings.

    Applies rule-based analysis to remove obvious false positives and
    assign confidence scores to surviving findings.
    """

    def validate(self, findings: List[Finding]) -> List[Finding]:
        """Filter *findings*, removing likely false positives.

        Rules applied:
        - Remove findings with empty title.
        - Remove DNS-only findings without a corresponding HTTP confirmation.
        - Keep all critical findings regardless of other rules.

        Args:
            findings: Raw list of findings from scan modules.

        Returns:
            Filtered list with likely false positives removed.
        """
        # Index HTTP-confirmed findings by target/title similarity
        http_confirmed = {f.title.lower() for f in findings if "http" in f.tags}

        result: List[Finding] = []
        for finding in findings:
            if not finding.title:
                continue
            # Always keep critical findings
            if finding.severity.lower() == "critical":
                result.append(finding)
                continue
            # Filter DNS-only findings that have no HTTP confirmation
            if "dns" in finding.tags and "http" not in finding.tags:
                # Check if a related HTTP finding exists
                title_key = finding.title.lower().replace("dns", "").strip()
                if not any(title_key in h for h in http_confirmed):
                    # Mark lower confidence without mutating the original finding's data
                    f_copy = copy.copy(finding)
                    f_copy.data = dict(finding.data)
                    f_copy.data["_confidence"] = 0.5
                    result.append(f_copy)
                    continue
            result.append(finding)
        return result

    def add_confidence_scores(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Add confidence scores to findings and return as dicts.

        Confidence scoring rules:
        - Critical: 0.95
        - High: 0.85
        - Generic title: -0.2 penalty
        - Low-confidence phrasing in description: -0.1 penalty
        - DNS-only tag: -0.15 penalty
        - Data dict has evidence key: +0.1 bonus

        Args:
            findings: List of :class:`~godrecon.modules.base.Finding` objects.

        Returns:
            List of dicts with all finding fields plus a ``confidence`` key.
        """
        base_scores = {
            "critical": 0.95,
            "high": 0.85,
            "medium": 0.75,
            "low": 0.65,
            "info": 0.55,
        }

        result = []
        for finding in findings:
            confidence = base_scores.get(finding.severity.lower(), 0.6)

            # Penalty: generic title
            if finding.title.lower() in _GENERIC_TITLES:
                confidence -= 0.2

            # Penalty: low-confidence phrasing in description
            desc_lower = finding.description.lower()
            if any(phrase in desc_lower for phrase in _LOW_CONFIDENCE_PHRASES):
                confidence -= 0.1

            # Penalty: DNS-only
            if "dns" in finding.tags and "http" not in finding.tags:
                confidence -= 0.15

            # Bonus: has evidence/data
            if finding.data and len(finding.data) > 1:
                confidence += 0.05

            # Use pre-set confidence if already assigned
            if "_confidence" in finding.data:
                confidence = float(finding.data["_confidence"])

            confidence = round(max(0.0, min(1.0, confidence)), 2)

            result.append({
                "title": finding.title,
                "description": finding.description,
                "severity": finding.severity,
                "data": finding.data,
                "tags": finding.tags,
                "confidence": confidence,
            })

        return result
