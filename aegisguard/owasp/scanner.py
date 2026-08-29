"""
OWASP Application & LLM Security Verification Scanner.
Performs passive and active checks against web endpoints, API requests,
and generative AI prompt interactions according to OWASP Top 10 standards.
"""

import re
from typing import Dict, List, Any, Optional
from aegisguard.catalogs.owasp_top10 import OwaspEngine, OwaspCategory, OwaspSeverity


class OwaspSecurityScanner:
    """Security vulnerability evaluator for HTTP headers, API inputs, and LLM prompts."""

    MANDATORY_SECURITY_HEADERS = {
        "Strict-Transport-Security": "Enforces HTTPS connections and prevents SSL stripping.",
        "Content-Security-Policy": "Restricts sources of executable scripts, stylesheets, and frames.",
        "X-Content-Type-Options": "Prevents MIME-sniffing exploits (must be 'nosniff').",
        "X-Frame-Options": "Prevents Clickjacking attacks (must be 'DENY' or 'SAMEORIGIN').",
        "Referrer-Policy": "Controls referrer information leakage in outbound requests."
    }

    SQLI_PATTERNS = [
        r"(?i)\bUNION\s+SELECT\b",
        r"(?i)\bOR\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
        r"(?i)\bWAITFOR\s+DELAY\b",
        r"(?i)\bSLEEP\s*\(\s*\d+\s*\)",
        r"(?i)--\s*$",
        r"(?i)/\*.*?\*/"
    ]

    PROMPT_INJECTION_PATTERNS = [
        r"(?i)ignore\s+(all\s+)?(previous|prior)\s+(instructions|prompts|rules)",
        r"(?i)system\s+override",
        r"(?i)you\s+are\s+now\s+in\s+(developer|unrestricted|god)\s+mode",
        r"(?i)disregard\s+safety\s+guidelines",
        r"(?i)print\s+(your\s+)?(hidden\s+)?system\s+prompt"
    ]

    @classmethod
    def audit_http_headers(cls, headers: Dict[str, str]) -> Dict[str, Any]:
        """Verify presence of security headers according to OWASP A05:2021 Security Misconfiguration."""
        normalized_headers = {k.lower(): v for k, v in headers.items()}
        missing = []
        findings = []

        for header_name, desc in cls.MANDATORY_SECURITY_HEADERS.items():
            if header_name.lower() not in normalized_headers:
                missing.append(header_name)
                findings.append({
                    "header": header_name,
                    "status": "MISSING",
                    "owasp_code": "A05:2021",
                    "description": desc,
                    "severity": "HIGH" if header_name in ["Strict-Transport-Security", "Content-Security-Policy"] else "MEDIUM"
                })

        score = max(0, 100 - (len(missing) * 20))
        return {
            "posture_score": score,
            "missing_headers": missing,
            "findings": findings,
            "total_mandatory": len(cls.MANDATORY_SECURITY_HEADERS),
            "compliant": len(missing) == 0
        }

    @classmethod
    def scan_web_input_for_injection(cls, user_input: str) -> Dict[str, Any]:
        """Detect SQL injection, XSS, and command injection patterns according to OWASP A03:2021."""
        findings = []

        # SQL Injection Check
        for pattern in cls.SQLI_PATTERNS:
            if re.search(pattern, user_input):
                findings.append({
                    "category": "SQL Injection",
                    "owasp_code": "A03:2021",
                    "cwe_id": "CWE-89",
                    "matched_pattern": pattern,
                    "severity": "CRITICAL"
                })
                break

        # XSS Check
        if re.search(r"(?i)<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>|javascript:|onerror=|onload=", user_input):
            findings.append({
                "category": "Cross-Site Scripting",
                "owasp_code": "A03:2021",
                "cwe_id": "CWE-79",
                "severity": "HIGH"
            })

        # Path Traversal Check
        if re.search(r"\.\./|\.\.\\|%2e%2e%2f", user_input):
            findings.append({
                "category": "Path Traversal",
                "owasp_code": "A01:2021",
                "cwe_id": "CWE-22",
                "severity": "HIGH"
            })

        return {
            "is_malicious": len(findings) > 0,
            "findings_count": len(findings),
            "findings": findings
        }

    @classmethod
    def scan_prompt_injection(cls, prompt_text: str) -> Dict[str, Any]:
        """Evaluate GenAI prompt text against OWASP LLM01:2025 Prompt Injection patterns."""
        matched = []
        for pattern in cls.PROMPT_INJECTION_PATTERNS:
            m = re.search(pattern, prompt_text)
            if m:
                matched.append(m.group(0))

        return {
            "prompt_injection_detected": len(matched) > 0,
            "owasp_code": "LLM01:2025",
            "matched_indicators": matched,
            "severity": "CRITICAL" if len(matched) > 1 else ("HIGH" if len(matched) == 1 else "NONE"),
            "recommendation": "Reject prompt execution or sanitize with defensive system prompt wrappers."
        }
