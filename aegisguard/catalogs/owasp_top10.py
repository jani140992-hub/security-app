"""
OWASP Top 10 Security Verification Framework Catalog.
Covers OWASP Top 10 Web (2021), OWASP API Security Top 10 (2023),
and OWASP Generative AI & Large Language Model Top 10 (2025).
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Set


class OwaspCategory(str, Enum):
    WEB_2021 = "OWASP-WEB-2021"
    API_2023 = "OWASP-API-2023"
    LLM_2025 = "OWASP-LLM-2025"


class OwaspSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class OwaspRule:
    code: str
    category: OwaspCategory
    title: str
    description: str
    mapped_cwes: List[str]
    severity: OwaspSeverity
    remediation: str
    domain: str
    rule_type: str


OWASP_CATALOG: Dict[str, OwaspRule] = {
    "A01:2021": OwaspRule(
        code="A01:2021",
        category=OwaspCategory.WEB_2021,
        title="Broken Access Control",
        description="""Access control enforces policy such that users cannot act outside of their intended permissions.""",
        mapped_cwes=['CWE-22', 'CWE-284', 'CWE-285', 'CWE-862'],
        severity=OwaspSeverity.CRITICAL,
        remediation="""Deny by default; implement RBAC/ABAC; disable web server directory listing.""",
        domain="Web Application",
        rule_type="Base Category Rule"
    ),
    "A01:2021.1": OwaspRule(
        code="A01:2021.1",
        category=OwaspCategory.WEB_2021,
        title="Broken Access Control - Verification Check 1",
        description="""Access control enforces policy such that users cannot act outside of their intended permissions. Automated verification check 1 for application security testing and posture validation.""",
        mapped_cwes=['CWE-22', 'CWE-284', 'CWE-285', 'CWE-862'],
        severity=OwaspSeverity.CRITICAL,
        remediation="""Deny by default; implement RBAC/ABAC; disable web server directory listing.""",
        domain="Web Application",
        rule_type="Automated Check 1"
    ),
    "A01:2021.2": OwaspRule(
        code="A01:2021.2",
        category=OwaspCategory.WEB_2021,
        title="Broken Access Control - Verification Check 2",
        description="""Access control enforces policy such that users cannot act outside of their intended permissions. Automated verification check 2 for application security testing and posture validation.""",
        mapped_cwes=['CWE-22', 'CWE-284', 'CWE-285', 'CWE-862'],
        severity=OwaspSeverity.CRITICAL,
        remediation="""Deny by default; implement RBAC/ABAC; disable web server directory listing.""",
        domain="Web Application",
        rule_type="Automated Check 2"
    ),
    "A01:2021.3": OwaspRule(
        code="A01:2021.3",
        category=OwaspCategory.WEB_2021,
        title="Broken Access Control - Verification Check 3",
        description="""Access control enforces policy such that users cannot act outside of their intended permissions. Automated verification check 3 for application security testing and posture validation.""",
        mapped_cwes=['CWE-22', 'CWE-284', 'CWE-285', 'CWE-862'],
        severity=OwaspSeverity.CRITICAL,
        remediation="""Deny by default; implement RBAC/ABAC; disable web server directory listing.""",
        domain="Web Application",
        rule_type="Automated Check 3"
    ),
    "A02:2021": OwaspRule(
        code="A02:2021",
        category=OwaspCategory.WEB_2021,
        title="Cryptographic Failures",
        description="""Failures related to cryptography (or lack thereof) which often leads to sensitive data exposure.""",
        mapped_cwes=['CWE-259', 'CWE-327', 'CWE-331', 'CWE-311'],
        severity=OwaspSeverity.HIGH,
        remediation="""Classify data; encrypt data at rest and in transit using TLS 1.3; discard sensitive data quickly.""",
        domain="Web Application",
        rule_type="Base Category Rule"
    ),
    "A02:2021.1": OwaspRule(
        code="A02:2021.1",
        category=OwaspCategory.WEB_2021,
        title="Cryptographic Failures - Verification Check 1",
        description="""Failures related to cryptography (or lack thereof) which often leads to sensitive data exposure. Automated verification check 1 for application security testing and posture validation.""",
        mapped_cwes=['CWE-259', 'CWE-327', 'CWE-331', 'CWE-311'],
        severity=OwaspSeverity.HIGH,
        remediation="""Classify data; encrypt data at rest and in transit using TLS 1.3; discard sensitive data quickly.""",
        domain="Web Application",
        rule_type="Automated Check 1"
    ),
    "A02:2021.2": OwaspRule(
        code="A02:2021.2",
        category=OwaspCategory.WEB_2021,
        title="Cryptographic Failures - Verification Check 2",
        description="""Failures related to cryptography (or lack thereof) which often leads to sensitive data exposure. Automated verification check 2 for application security testing and posture validation.""",
        mapped_cwes=['CWE-259', 'CWE-327', 'CWE-331', 'CWE-311'],
        severity=OwaspSeverity.HIGH,
        remediation="""Classify data; encrypt data at rest and in transit using TLS 1.3; discard sensitive data quickly.""",
        domain="Web Application",
        rule_type="Automated Check 2"
    ),
    "A02:2021.3": OwaspRule(
        code="A02:2021.3",
        category=OwaspCategory.WEB_2021,
        title="Cryptographic Failures - Verification Check 3",
        description="""Failures related to cryptography (or lack thereof) which often leads to sensitive data exposure. Automated verification check 3 for application security testing and posture validation.""",
        mapped_cwes=['CWE-259', 'CWE-327', 'CWE-331', 'CWE-311'],
        severity=OwaspSeverity.HIGH,
        remediation="""Classify data; encrypt data at rest and in transit using TLS 1.3; discard sensitive data quickly.""",
        domain="Web Application",
        rule_type="Automated Check 3"
    ),
    "A03:2021": OwaspRule(
        code="A03:2021",
        category=OwaspCategory.WEB_2021,
        title="Injection",
        description="""Application is vulnerable to injection when user-supplied data is not validated, filtered, or sanitized.""",
        mapped_cwes=['CWE-79', 'CWE-89', 'CWE-78', 'CWE-94'],
        severity=OwaspSeverity.CRITICAL,
        remediation="""Use parameterized queries; use positive server-side input validation; limit query results.""",
        domain="Web Application",
        rule_type="Base Category Rule"
    ),
    "A03:2021.1": OwaspRule(
        code="A03:2021.1",
        category=OwaspCategory.WEB_2021,
        title="Injection - Verification Check 1",
        description="""Application is vulnerable to injection when user-supplied data is not validated, filtered, or sanitized. Automated verification check 1 for application security testing and posture validation.""",
        mapped_cwes=['CWE-79', 'CWE-89', 'CWE-78', 'CWE-94'],
        severity=OwaspSeverity.CRITICAL,
        remediation="""Use parameterized queries; use positive server-side input validation; limit query results.""",
        domain="Web Application",
        rule_type="Automated Check 1"
    ),
    "A03:2021.2": OwaspRule(
        code="A03:2021.2",
        category=OwaspCategory.WEB_2021,
        title="Injection - Verification Check 2",
        description="""Application is vulnerable to injection when user-supplied data is not validated, filtered, or sanitized. Automated verification check 2 for application security testing and posture validation.""",
        mapped_cwes=['CWE-79', 'CWE-89', 'CWE-78', 'CWE-94'],
        severity=OwaspSeverity.CRITICAL,
        remediation="""Use parameterized queries; use positive server-side input validation; limit query results.""",
        domain="Web Application",
        rule_type="Automated Check 2"
    ),
    "A03:2021.3": OwaspRule(
        code="A03:2021.3",
        category=OwaspCategory.WEB_2021,
        title="Injection - Verification Check 3",
        description="""Application is vulnerable to injection when user-supplied data is not validated, filtered, or sanitized. Automated verification check 3 for application security testing and posture validation.""",
        mapped_cwes=['CWE-79', 'CWE-89', 'CWE-78', 'CWE-94'],
        severity=OwaspSeverity.CRITICAL,
        remediation="""Use parameterized queries; use positive server-side input validation; limit query results.""",
        domain="Web Application",
        rule_type="Automated Check 3"
    ),
    "A04:2021": OwaspRule(
        code="A04:2021",
        category=OwaspCategory.WEB_2021,
        title="Insecure Design",
        description="""Focuses on risks related to design and architectural flaws, calling for threat modeling and secure design patterns.""",
        mapped_cwes=['CWE-209', 'CWE-256', 'CWE-522'],
        severity=OwaspSeverity.HIGH,
        remediation="""Establish secure development lifecycle (SDLC); perform threat modeling; integrate security tests.""",
        domain="Web Application",
        rule_type="Base Category Rule"
    ),
    "A04:2021.1": OwaspRule(
        code="A04:2021.1",
        category=OwaspCategory.WEB_2021,
        title="Insecure Design - Verification Check 1",
        description="""Focuses on risks related to design and architectural flaws, calling for threat modeling and secure design patterns. Automated verification check 1 for application security testing and posture validation.""",
        mapped_cwes=['CWE-209', 'CWE-256', 'CWE-522'],
        severity=OwaspSeverity.HIGH,
        remediation="""Establish secure development lifecycle (SDLC); perform threat modeling; integrate security tests.""",
        domain="Web Application",
        rule_type="Automated Check 1"
    ),
    "A04:2021.2": OwaspRule(
        code="A04:2021.2",
        category=OwaspCategory.WEB_2021,
        title="Insecure Design - Verification Check 2",
        description="""Focuses on risks related to design and architectural flaws, calling for threat modeling and secure design patterns. Automated verification check 2 for application security testing and posture validation.""",
        mapped_cwes=['CWE-209', 'CWE-256', 'CWE-522'],
        severity=OwaspSeverity.HIGH,
        remediation="""Establish secure development lifecycle (SDLC); perform threat modeling; integrate security tests.""",
        domain="Web Application",
        rule_type="Automated Check 2"
    ),
    "A04:2021.3": OwaspRule(
        code="A04:2021.3",
        category=OwaspCategory.WEB_2021,
        title="Insecure Design - Verification Check 3",
        description="""Focuses on risks related to design and architectural flaws, calling for threat modeling and secure design patterns. Automated verification check 3 for application security testing and posture validation.""",
        mapped_cwes=['CWE-209', 'CWE-256', 'CWE-522'],
        severity=OwaspSeverity.HIGH,
        remediation="""Establish secure development lifecycle (SDLC); perform threat modeling; integrate security tests.""",
        domain="Web Application",
        rule_type="Automated Check 3"
    ),
    "A05:2021": OwaspRule(
        code="A05:2021",
        category=OwaspCategory.WEB_2021,
        title="Security Misconfiguration",
        description="""Occurs when security settings are defined, implemented, and maintained with default values or gaps.""",
        mapped_cwes=['CWE-16', 'CWE-2', 'CWE-11'],
        severity=OwaspSeverity.MEDIUM,
        remediation="""Automate hardening scripts; remove unused features/frameworks; send security headers.""",
        domain="Web Application",
        rule_type="Base Category Rule"
    ),
    "A05:2021.1": OwaspRule(
        code="A05:2021.1",
        category=OwaspCategory.WEB_2021,
        title="Security Misconfiguration - Verification Check 1",
        description="""Occurs when security settings are defined, implemented, and maintained with default values or gaps. Automated verification check 1 for application security testing and posture validation.""",
        mapped_cwes=['CWE-16', 'CWE-2', 'CWE-11'],
        severity=OwaspSeverity.MEDIUM,
        remediation="""Automate hardening scripts; remove unused features/frameworks; send security headers.""",
        domain="Web Application",
        rule_type="Automated Check 1"
    ),
    "A05:2021.2": OwaspRule(
        code="A05:2021.2",
        category=OwaspCategory.WEB_2021,
        title="Security Misconfiguration - Verification Check 2",
        description="""Occurs when security settings are defined, implemented, and maintained with default values or gaps. Automated verification check 2 for application security testing and posture validation.""",
        mapped_cwes=['CWE-16', 'CWE-2', 'CWE-11'],
        severity=OwaspSeverity.MEDIUM,
        remediation="""Automate hardening scripts; remove unused features/frameworks; send security headers.""",
        domain="Web Application",
        rule_type="Automated Check 2"
    ),
    "A05:2021.3": OwaspRule(
        code="A05:2021.3",
        category=OwaspCategory.WEB_2021,
        title="Security Misconfiguration - Verification Check 3",
        description="""Occurs when security settings are defined, implemented, and maintained with default values or gaps. Automated verification check 3 for application security testing and posture validation.""",
        mapped_cwes=['CWE-16', 'CWE-2', 'CWE-11'],
        severity=OwaspSeverity.MEDIUM,
        remediation="""Automate hardening scripts; remove unused features/frameworks; send security headers.""",
        domain="Web Application",
        rule_type="Automated Check 3"
    ),
    "A06:2021": OwaspRule(
        code="A06:2021",
        category=OwaspCategory.WEB_2021,
        title="Vulnerable and Outdated Components",
        description="""Components with known vulnerabilities are used, which undermines application defenses.""",
        mapped_cwes=['CWE-1104', 'CWE-1035'],
        severity=OwaspSeverity.HIGH,
        remediation="""Maintain Software Bill of Materials (SBOM); continuously monitor CVE databases; subscribe to advisories.""",
        domain="Web Application",
        rule_type="Base Category Rule"
    ),
    "A06:2021.1": OwaspRule(
        code="A06:2021.1",
        category=OwaspCategory.WEB_2021,
        title="Vulnerable and Outdated Components - Verification Check 1",
        description="""Components with known vulnerabilities are used, which undermines application defenses. Automated verification check 1 for application security testing and posture validation.""",
        mapped_cwes=['CWE-1104', 'CWE-1035'],
        severity=OwaspSeverity.HIGH,
        remediation="""Maintain Software Bill of Materials (SBOM); continuously monitor CVE databases; subscribe to advisories.""",
        domain="Web Application",
        rule_type="Automated Check 1"
    ),
    "A06:2021.2": OwaspRule(
        code="A06:2021.2",
        category=OwaspCategory.WEB_2021,
        title="Vulnerable and Outdated Components - Verification Check 2",
        description="""Components with known vulnerabilities are used, which undermines application defenses. Automated verification check 2 for application security testing and posture validation.""",
        mapped_cwes=['CWE-1104', 'CWE-1035'],
        severity=OwaspSeverity.HIGH,
        remediation="""Maintain Software Bill of Materials (SBOM); continuously monitor CVE databases; subscribe to advisories.""",
        domain="Web Application",
        rule_type="Automated Check 2"
    ),
    "A06:2021.3": OwaspRule(
        code="A06:2021.3",
        category=OwaspCategory.WEB_2021,
        title="Vulnerable and Outdated Components - Verification Check 3",
        description="""Components with known vulnerabilities are used, which undermines application defenses. Automated verification check 3 for application security testing and posture validation.""",
        mapped_cwes=['CWE-1104', 'CWE-1035'],
        severity=OwaspSeverity.HIGH,
        remediation="""Maintain Software Bill of Materials (SBOM); continuously monitor CVE databases; subscribe to advisories.""",
        domain="Web Application",
        rule_type="Automated Check 3"
    ),
    "A07:2021": OwaspRule(
        code="A07:2021",
        category=OwaspCategory.WEB_2021,
        title="Identification and Authentication Failures",
        description="""Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks.""",
        mapped_cwes=['CWE-287', 'CWE-384', 'CWE-798'],
        severity=OwaspSeverity.CRITICAL,
        remediation="""Implement multi-factor authentication (MFA); do not ship default credentials; rate limit logins.""",
        domain="Web Application",
        rule_type="Base Category Rule"
    ),
    "A07:2021.1": OwaspRule(
        code="A07:2021.1",
        category=OwaspCategory.WEB_2021,
        title="Identification and Authentication Failures - Verification Check 1",
        description="""Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks. Automated verification check 1 for application security testing and posture validation.""",
        mapped_cwes=['CWE-287', 'CWE-384', 'CWE-798'],
        severity=OwaspSeverity.CRITICAL,
        remediation="""Implement multi-factor authentication (MFA); do not ship default credentials; rate limit logins.""",
        domain="Web Application",
        rule_type="Automated Check 1"
    ),
    "A07:2021.2": OwaspRule(
        code="A07:2021.2",
        category=OwaspCategory.WEB_2021,
        title="Identification and Authentication Failures - Verification Check 2",
        description="""Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks. Automated verification check 2 for application security testing and posture validation.""",
        mapped_cwes=['CWE-287', 'CWE-384', 'CWE-798'],
        severity=OwaspSeverity.CRITICAL,
        remediation="""Implement multi-factor authentication (MFA); do not ship default credentials; rate limit logins.""",
        domain="Web Application",
        rule_type="Automated Check 2"
    ),
    "A07:2021.3": OwaspRule(
        code="A07:2021.3",
        category=OwaspCategory.WEB_2021,
        title="Identification and Authentication Failures - Verification Check 3",
        description="""Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks. Automated verification check 3 for application security testing and posture validation.""",
        mapped_cwes=['CWE-287', 'CWE-384', 'CWE-798'],
        severity=OwaspSeverity.CRITICAL,
        remediation="""Implement multi-factor authentication (MFA); do not ship default credentials; rate limit logins.""",
        domain="Web Application",
        rule_type="Automated Check 3"
    ),
    "A08:2021": OwaspRule(
        code="A08:2021",
        category=OwaspCategory.WEB_2021,
        title="Software and Data Integrity Failures",
        description="""Relates to code and infrastructure that does not protect against integrity violations, including CI/CD pipelines.""",
        mapped_cwes=['CWE-494', 'CWE-502', 'CWE-565'],
        severity=OwaspSeverity.HIGH,
        remediation="""Use digital signatures for updates; review code changes; use signed container images.""",
        domain="Web Application",
        rule_type="Base Category Rule"
    ),
    "A08:2021.1": OwaspRule(
        code="A08:2021.1",
        category=OwaspCategory.WEB_2021,
        title="Software and Data Integrity Failures - Verification Check 1",
        description="""Relates to code and infrastructure that does not protect against integrity violations, including CI/CD pipelines. Automated verification check 1 for application security testing and posture validation.""",
        mapped_cwes=['CWE-494', 'CWE-502', 'CWE-565'],
        severity=OwaspSeverity.HIGH,
        remediation="""Use digital signatures for updates; review code changes; use signed container images.""",
        domain="Web Application",
        rule_type="Automated Check 1"
    ),
    "A08:2021.2": OwaspRule(
        code="A08:2021.2",
        category=OwaspCategory.WEB_2021,
        title="Software and Data Integrity Failures - Verification Check 2",
        description="""Relates to code and infrastructure that does not protect against integrity violations, including CI/CD pipelines. Automated verification check 2 for application security testing and posture validation.""",
        mapped_cwes=['CWE-494', 'CWE-502', 'CWE-565'],
        severity=OwaspSeverity.HIGH,
        remediation="""Use digital signatures for updates; review code changes; use signed container images.""",
        domain="Web Application",
        rule_type="Automated Check 2"
    ),
    "A08:2021.3": OwaspRule(
        code="A08:2021.3",
        category=OwaspCategory.WEB_2021,
        title="Software and Data Integrity Failures - Verification Check 3",
        description="""Relates to code and infrastructure that does not protect against integrity violations, including CI/CD pipelines. Automated verification check 3 for application security testing and posture validation.""",
        mapped_cwes=['CWE-494', 'CWE-502', 'CWE-565'],
        severity=OwaspSeverity.HIGH,
        remediation="""Use digital signatures for updates; review code changes; use signed container images.""",
        domain="Web Application",
        rule_type="Automated Check 3"
    ),
    "A09:2021": OwaspRule(
        code="A09:2021",
        category=OwaspCategory.WEB_2021,
        title="Security Logging and Monitoring Failures",
        description="""Insufficient logging, detection, monitoring, and active response enables attackers to achieve persistent compromise.""",
        mapped_cwes=['CWE-778', 'CWE-117'],
        severity=OwaspSeverity.MEDIUM,
        remediation="""Log all login, access control, and server-side input validation failures; ingest into SIEM.""",
        domain="Web Application",
        rule_type="Base Category Rule"
    ),
    "A09:2021.1": OwaspRule(
        code="A09:2021.1",
        category=OwaspCategory.WEB_2021,
        title="Security Logging and Monitoring Failures - Verification Check 1",
        description="""Insufficient logging, detection, monitoring, and active response enables attackers to achieve persistent compromise. Automated verification check 1 for application security testing and posture validation.""",
        mapped_cwes=['CWE-778', 'CWE-117'],
        severity=OwaspSeverity.MEDIUM,
        remediation="""Log all login, access control, and server-side input validation failures; ingest into SIEM.""",
        domain="Web Application",
        rule_type="Automated Check 1"
    ),
    "A09:2021.2": OwaspRule(
        code="A09:2021.2",
        category=OwaspCategory.WEB_2021,
        title="Security Logging and Monitoring Failures - Verification Check 2",
        description="""Insufficient logging, detection, monitoring, and active response enables attackers to achieve persistent compromise. Automated verification check 2 for application security testing and posture validation.""",
        mapped_cwes=['CWE-778', 'CWE-117'],
        severity=OwaspSeverity.MEDIUM,
        remediation="""Log all login, access control, and server-side input validation failures; ingest into SIEM.""",
        domain="Web Application",
        rule_type="Automated Check 2"
    ),
    "A09:2021.3": OwaspRule(
        code="A09:2021.3",
        category=OwaspCategory.WEB_2021,
        title="Security Logging and Monitoring Failures - Verification Check 3",
        description="""Insufficient logging, detection, monitoring, and active response enables attackers to achieve persistent compromise. Automated verification check 3 for application security testing and posture validation.""",
        mapped_cwes=['CWE-778', 'CWE-117'],
        severity=OwaspSeverity.MEDIUM,
        remediation="""Log all login, access control, and server-side input validation failures; ingest into SIEM.""",
        domain="Web Application",
        rule_type="Automated Check 3"
    ),
    "A10:2021": OwaspRule(
        code="A10:2021",
        category=OwaspCategory.WEB_2021,
        title="Server-Side Request Forgery (SSRF)",
        description="""Occurs when a web application fetches a remote resource without validating the user-supplied URL.""",
        mapped_cwes=['CWE-918'],
        severity=OwaspSeverity.HIGH,
        remediation="""Sanitize and validate all client-supplied input data; enforce URL allowlists; disable HTTP redirections.""",
        domain="Web Application",
        rule_type="Base Category Rule"
    ),
    "A10:2021.1": OwaspRule(
        code="A10:2021.1",
        category=OwaspCategory.WEB_2021,
        title="Server-Side Request Forgery (SSRF) - Verification Check 1",
        description="""Occurs when a web application fetches a remote resource without validating the user-supplied URL. Automated verification check 1 for application security testing and posture validation.""",
        mapped_cwes=['CWE-918'],
        severity=OwaspSeverity.HIGH,
        remediation="""Sanitize and validate all client-supplied input data; enforce URL allowlists; disable HTTP redirections.""",
        domain="Web Application",
        rule_type="Automated Check 1"
    ),
    "A10:2021.2": OwaspRule(
        code="A10:2021.2",
        category=OwaspCategory.WEB_2021,
        title="Server-Side Request Forgery (SSRF) - Verification Check 2",
        description="""Occurs when a web application fetches a remote resource without validating the user-supplied URL. Automated verification check 2 for application security testing and posture validation.""",
        mapped_cwes=['CWE-918'],
        severity=OwaspSeverity.HIGH,
        remediation="""Sanitize and validate all client-supplied input data; enforce URL allowlists; disable HTTP redirections.""",
        domain="Web Application",
        rule_type="Automated Check 2"
    ),
    "A10:2021.3": OwaspRule(
        code="A10:2021.3",
        category=OwaspCategory.WEB_2021,
        title="Server-Side Request Forgery (SSRF) - Verification Check 3",
        description="""Occurs when a web application fetches a remote resource without validating the user-supplied URL. Automated verification check 3 for application security testing and posture validation.""",
        mapped_cwes=['CWE-918'],
        severity=OwaspSeverity.HIGH,
        remediation="""Sanitize and validate all client-supplied input data; enforce URL allowlists; disable HTTP redirections.""",
        domain="Web Application",
        rule_type="Automated Check 3"
    ),
    "API1:2023": OwaspRule(
        code="API1:2023",
        category=OwaspCategory.API_2023,
        title="Broken Object Level Authorization (BOLA)",
        description="""Attackers manipulate object identifiers to access unauthorized resources belonging to other tenants.""",
        mapped_cwes=['CWE-284', 'CWE-639'],
        severity=OwaspSeverity.CRITICAL,
        remediation="""Implement authorization checks based on user identity for every object request.""",
        domain="API Security",
        rule_type="Base Category Rule"
    ),
    "API1:2023.1": OwaspRule(
        code="API1:2023.1",
        category=OwaspCategory.API_2023,
        title="Broken Object Level Authorization (BOLA) - Verification Check 1",
        description="""Attackers manipulate object identifiers to access unauthorized resources belonging to other tenants. Automated verification check 1 for application security testing and posture validation.""",
        mapped_cwes=['CWE-284', 'CWE-639'],
        severity=OwaspSeverity.CRITICAL,
        remediation="""Implement authorization checks based on user identity for every object request.""",
        domain="API Security",
        rule_type="Automated Check 1"
    ),
    "API1:2023.2": OwaspRule(
        code="API1:2023.2",
        category=OwaspCategory.API_2023,
        title="Broken Object Level Authorization (BOLA) - Verification Check 2",
        description="""Attackers manipulate object identifiers to access unauthorized resources belonging to other tenants. Automated verification check 2 for application security testing and posture validation.""",
        mapped_cwes=['CWE-284', 'CWE-639'],
        severity=OwaspSeverity.CRITICAL,
        remediation="""Implement authorization checks based on user identity for every object request.""",
        domain="API Security",
        rule_type="Automated Check 2"
    ),
    "API1:2023.3": OwaspRule(
        code="API1:2023.3",
        category=OwaspCategory.API_2023,
        title="Broken Object Level Authorization (BOLA) - Verification Check 3",
        description="""Attackers manipulate object identifiers to access unauthorized resources belonging to other tenants. Automated verification check 3 for application security testing and posture validation.""",
        mapped_cwes=['CWE-284', 'CWE-639'],
        severity=OwaspSeverity.CRITICAL,
        remediation="""Implement authorization checks based on user identity for every object request.""",
        domain="API Security",
        rule_type="Automated Check 3"
    ),
    "API2:2023": OwaspRule(
        code="API2:2023",
        category=OwaspCategory.API_2023,
        title="Broken Authentication",
        description="""Poorly implemented authentication endpoints allow attackers to compromise tokens or exploit implementation flaws.""",
        mapped_cwes=['CWE-287', 'CWE-384'],
        severity=OwaspSeverity.CRITICAL,
        remediation="""Apply OAuth 2.0 / OpenID Connect; implement token expiration; secure password recovery.""",
        domain="API Security",
        rule_type="Base Category Rule"
    ),
    "API2:2023.1": OwaspRule(
        code="API2:2023.1",
        category=OwaspCategory.API_2023,
        title="Broken Authentication - Verification Check 1",
        description="""Poorly implemented authentication endpoints allow attackers to compromise tokens or exploit implementation flaws. Automated verification check 1 for application security testing and posture validation.""",
        mapped_cwes=['CWE-287', 'CWE-384'],
        severity=OwaspSeverity.CRITICAL,
        remediation="""Apply OAuth 2.0 / OpenID Connect; implement token expiration; secure password recovery.""",
        domain="API Security",
        rule_type="Automated Check 1"
    ),
    "API2:2023.2": OwaspRule(
        code="API2:2023.2",
        category=OwaspCategory.API_2023,
        title="Broken Authentication - Verification Check 2",
        description="""Poorly implemented authentication endpoints allow attackers to compromise tokens or exploit implementation flaws. Automated verification check 2 for application security testing and posture validation.""",
        mapped_cwes=['CWE-287', 'CWE-384'],
        severity=OwaspSeverity.CRITICAL,
        remediation="""Apply OAuth 2.0 / OpenID Connect; implement token expiration; secure password recovery.""",
        domain="API Security",
        rule_type="Automated Check 2"
    ),
    "API2:2023.3": OwaspRule(
        code="API2:2023.3",
        category=OwaspCategory.API_2023,
        title="Broken Authentication - Verification Check 3",
        description="""Poorly implemented authentication endpoints allow attackers to compromise tokens or exploit implementation flaws. Automated verification check 3 for application security testing and posture validation.""",
        mapped_cwes=['CWE-287', 'CWE-384'],
        severity=OwaspSeverity.CRITICAL,
        remediation="""Apply OAuth 2.0 / OpenID Connect; implement token expiration; secure password recovery.""",
        domain="API Security",
        rule_type="Automated Check 3"
    ),
    "API3:2023": OwaspRule(
        code="API3:2023",
        category=OwaspCategory.API_2023,
        title="Broken Object Property Level Authorization",
        description="""Exposing internal object properties leads to unauthorized data access or privilege manipulation.""",
        mapped_cwes=['CWE-213', 'CWE-915'],
        severity=OwaspSeverity.HIGH,
        remediation="""Validate user access to specific object properties; do not expose full database models.""",
        domain="API Security",
        rule_type="Base Category Rule"
    ),
    "API3:2023.1": OwaspRule(
        code="API3:2023.1",
        category=OwaspCategory.API_2023,
        title="Broken Object Property Level Authorization - Verification Check 1",
        description="""Exposing internal object properties leads to unauthorized data access or privilege manipulation. Automated verification check 1 for application security testing and posture validation.""",
        mapped_cwes=['CWE-213', 'CWE-915'],
        severity=OwaspSeverity.HIGH,
        remediation="""Validate user access to specific object properties; do not expose full database models.""",
        domain="API Security",
        rule_type="Automated Check 1"
    ),
    "API3:2023.2": OwaspRule(
        code="API3:2023.2",
        category=OwaspCategory.API_2023,
        title="Broken Object Property Level Authorization - Verification Check 2",
        description="""Exposing internal object properties leads to unauthorized data access or privilege manipulation. Automated verification check 2 for application security testing and posture validation.""",
        mapped_cwes=['CWE-213', 'CWE-915'],
        severity=OwaspSeverity.HIGH,
        remediation="""Validate user access to specific object properties; do not expose full database models.""",
        domain="API Security",
        rule_type="Automated Check 2"
    ),
    "API3:2023.3": OwaspRule(
        code="API3:2023.3",
        category=OwaspCategory.API_2023,
        title="Broken Object Property Level Authorization - Verification Check 3",
        description="""Exposing internal object properties leads to unauthorized data access or privilege manipulation. Automated verification check 3 for application security testing and posture validation.""",
        mapped_cwes=['CWE-213', 'CWE-915'],
        severity=OwaspSeverity.HIGH,
        remediation="""Validate user access to specific object properties; do not expose full database models.""",
        domain="API Security",
        rule_type="Automated Check 3"
    ),
    "API4:2023": OwaspRule(
        code="API4:2023",
        category=OwaspCategory.API_2023,
        title="Unrestricted Resource Consumption",
        description="""APIs that do not restrict client requests are susceptible to Denial of Service (DoS) and unexpected bills.""",
        mapped_cwes=['CWE-400', 'CWE-770'],
        severity=OwaspSeverity.MEDIUM,
        remediation="""Enforce rate limiting; set execution timeouts; limit memory allocation and payload sizes.""",
        domain="API Security",
        rule_type="Base Category Rule"
    ),
    "API4:2023.1": OwaspRule(
        code="API4:2023.1",
        category=OwaspCategory.API_2023,
        title="Unrestricted Resource Consumption - Verification Check 1",
        description="""APIs that do not restrict client requests are susceptible to Denial of Service (DoS) and unexpected bills. Automated verification check 1 for application security testing and posture validation.""",
        mapped_cwes=['CWE-400', 'CWE-770'],
        severity=OwaspSeverity.MEDIUM,
        remediation="""Enforce rate limiting; set execution timeouts; limit memory allocation and payload sizes.""",
        domain="API Security",
        rule_type="Automated Check 1"
    ),
    "API4:2023.2": OwaspRule(
        code="API4:2023.2",
        category=OwaspCategory.API_2023,
        title="Unrestricted Resource Consumption - Verification Check 2",
        description="""APIs that do not restrict client requests are susceptible to Denial of Service (DoS) and unexpected bills. Automated verification check 2 for application security testing and posture validation.""",
        mapped_cwes=['CWE-400', 'CWE-770'],
        severity=OwaspSeverity.MEDIUM,
        remediation="""Enforce rate limiting; set execution timeouts; limit memory allocation and payload sizes.""",
        domain="API Security",
        rule_type="Automated Check 2"
    ),
    "API4:2023.3": OwaspRule(
        code="API4:2023.3",
        category=OwaspCategory.API_2023,
        title="Unrestricted Resource Consumption - Verification Check 3",
        description="""APIs that do not restrict client requests are susceptible to Denial of Service (DoS) and unexpected bills. Automated verification check 3 for application security testing and posture validation.""",
        mapped_cwes=['CWE-400', 'CWE-770'],
        severity=OwaspSeverity.MEDIUM,
        remediation="""Enforce rate limiting; set execution timeouts; limit memory allocation and payload sizes.""",
        domain="API Security",
        rule_type="Automated Check 3"
    ),
    "API5:2023": OwaspRule(
        code="API5:2023",
        category=OwaspCategory.API_2023,
        title="Broken Function Level Authorization",
        description="""Flaws in authorization allows unprivileged users to execute administrative API endpoints.""",
        mapped_cwes=['CWE-285', 'CWE-862'],
        severity=OwaspSeverity.HIGH,
        remediation="""Implement strict role-based access checks at the controller/route level; deny by default.""",
        domain="API Security",
        rule_type="Base Category Rule"
    ),
    "API5:2023.1": OwaspRule(
        code="API5:2023.1",
        category=OwaspCategory.API_2023,
        title="Broken Function Level Authorization - Verification Check 1",
        description="""Flaws in authorization allows unprivileged users to execute administrative API endpoints. Automated verification check 1 for application security testing and posture validation.""",
        mapped_cwes=['CWE-285', 'CWE-862'],
        severity=OwaspSeverity.HIGH,
        remediation="""Implement strict role-based access checks at the controller/route level; deny by default.""",
        domain="API Security",
        rule_type="Automated Check 1"
    ),
    "API5:2023.2": OwaspRule(
        code="API5:2023.2",
        category=OwaspCategory.API_2023,
        title="Broken Function Level Authorization - Verification Check 2",
        description="""Flaws in authorization allows unprivileged users to execute administrative API endpoints. Automated verification check 2 for application security testing and posture validation.""",
        mapped_cwes=['CWE-285', 'CWE-862'],
        severity=OwaspSeverity.HIGH,
        remediation="""Implement strict role-based access checks at the controller/route level; deny by default.""",
        domain="API Security",
        rule_type="Automated Check 2"
    ),
    "API5:2023.3": OwaspRule(
        code="API5:2023.3",
        category=OwaspCategory.API_2023,
        title="Broken Function Level Authorization - Verification Check 3",
        description="""Flaws in authorization allows unprivileged users to execute administrative API endpoints. Automated verification check 3 for application security testing and posture validation.""",
        mapped_cwes=['CWE-285', 'CWE-862'],
        severity=OwaspSeverity.HIGH,
        remediation="""Implement strict role-based access checks at the controller/route level; deny by default.""",
        domain="API Security",
        rule_type="Automated Check 3"
    ),
    "API6:2023": OwaspRule(
        code="API6:2023",
        category=OwaspCategory.API_2023,
        title="Unrestricted Access to Sensitive Business Flows",
        description="""Automated bots exploit legitimate API business flows without triggering traditional technical exploits.""",
        mapped_cwes=['CWE-799', 'CWE-837'],
        severity=OwaspSeverity.MEDIUM,
        remediation="""Implement CAPTCHA; analyze request patterns; device fingerprinting.""",
        domain="API Security",
        rule_type="Base Category Rule"
    ),
    "API6:2023.1": OwaspRule(
        code="API6:2023.1",
        category=OwaspCategory.API_2023,
        title="Unrestricted Access to Sensitive Business Flows - Verification Check 1",
        description="""Automated bots exploit legitimate API business flows without triggering traditional technical exploits. Automated verification check 1 for application security testing and posture validation.""",
        mapped_cwes=['CWE-799', 'CWE-837'],
        severity=OwaspSeverity.MEDIUM,
        remediation="""Implement CAPTCHA; analyze request patterns; device fingerprinting.""",
        domain="API Security",
        rule_type="Automated Check 1"
    ),
    "API6:2023.2": OwaspRule(
        code="API6:2023.2",
        category=OwaspCategory.API_2023,
        title="Unrestricted Access to Sensitive Business Flows - Verification Check 2",
        description="""Automated bots exploit legitimate API business flows without triggering traditional technical exploits. Automated verification check 2 for application security testing and posture validation.""",
        mapped_cwes=['CWE-799', 'CWE-837'],
        severity=OwaspSeverity.MEDIUM,
        remediation="""Implement CAPTCHA; analyze request patterns; device fingerprinting.""",
        domain="API Security",
        rule_type="Automated Check 2"
    ),
    "API6:2023.3": OwaspRule(
        code="API6:2023.3",
        category=OwaspCategory.API_2023,
        title="Unrestricted Access to Sensitive Business Flows - Verification Check 3",
        description="""Automated bots exploit legitimate API business flows without triggering traditional technical exploits. Automated verification check 3 for application security testing and posture validation.""",
        mapped_cwes=['CWE-799', 'CWE-837'],
        severity=OwaspSeverity.MEDIUM,
        remediation="""Implement CAPTCHA; analyze request patterns; device fingerprinting.""",
        domain="API Security",
        rule_type="Automated Check 3"
    ),
    "API7:2023": OwaspRule(
        code="API7:2023",
        category=OwaspCategory.API_2023,
        title="Server Side Request Forgery",
        description="""API endpoints accepting external URIs enable attackers to interact with internal backend services.""",
        mapped_cwes=['CWE-918'],
        severity=OwaspSeverity.HIGH,
        remediation="""Isolate network segment for outbound requests; validate target domains against allowlist.""",
        domain="API Security",
        rule_type="Base Category Rule"
    ),
    "API7:2023.1": OwaspRule(
        code="API7:2023.1",
        category=OwaspCategory.API_2023,
        title="Server Side Request Forgery - Verification Check 1",
        description="""API endpoints accepting external URIs enable attackers to interact with internal backend services. Automated verification check 1 for application security testing and posture validation.""",
        mapped_cwes=['CWE-918'],
        severity=OwaspSeverity.HIGH,
        remediation="""Isolate network segment for outbound requests; validate target domains against allowlist.""",
        domain="API Security",
        rule_type="Automated Check 1"
    ),
    "API7:2023.2": OwaspRule(
        code="API7:2023.2",
        category=OwaspCategory.API_2023,
        title="Server Side Request Forgery - Verification Check 2",
        description="""API endpoints accepting external URIs enable attackers to interact with internal backend services. Automated verification check 2 for application security testing and posture validation.""",
        mapped_cwes=['CWE-918'],
        severity=OwaspSeverity.HIGH,
        remediation="""Isolate network segment for outbound requests; validate target domains against allowlist.""",
        domain="API Security",
        rule_type="Automated Check 2"
    ),
    "API7:2023.3": OwaspRule(
        code="API7:2023.3",
        category=OwaspCategory.API_2023,
        title="Server Side Request Forgery - Verification Check 3",
        description="""API endpoints accepting external URIs enable attackers to interact with internal backend services. Automated verification check 3 for application security testing and posture validation.""",
        mapped_cwes=['CWE-918'],
        severity=OwaspSeverity.HIGH,
        remediation="""Isolate network segment for outbound requests; validate target domains against allowlist.""",
        domain="API Security",
        rule_type="Automated Check 3"
    ),
    "API8:2023": OwaspRule(
        code="API8:2023",
        category=OwaspCategory.API_2023,
        title="Security Misconfiguration",
        description="""APIs commonly expose debug interfaces, unencrypted endpoints, or verbose stack traces.""",
        mapped_cwes=['CWE-16', 'CWE-209'],
        severity=OwaspSeverity.MEDIUM,
        remediation="""Standardize API gateway configurations; disable verbose error messages; enforce TLS 1.3.""",
        domain="API Security",
        rule_type="Base Category Rule"
    ),
    "API8:2023.1": OwaspRule(
        code="API8:2023.1",
        category=OwaspCategory.API_2023,
        title="Security Misconfiguration - Verification Check 1",
        description="""APIs commonly expose debug interfaces, unencrypted endpoints, or verbose stack traces. Automated verification check 1 for application security testing and posture validation.""",
        mapped_cwes=['CWE-16', 'CWE-209'],
        severity=OwaspSeverity.MEDIUM,
        remediation="""Standardize API gateway configurations; disable verbose error messages; enforce TLS 1.3.""",
        domain="API Security",
        rule_type="Automated Check 1"
    ),
    "API8:2023.2": OwaspRule(
        code="API8:2023.2",
        category=OwaspCategory.API_2023,
        title="Security Misconfiguration - Verification Check 2",
        description="""APIs commonly expose debug interfaces, unencrypted endpoints, or verbose stack traces. Automated verification check 2 for application security testing and posture validation.""",
        mapped_cwes=['CWE-16', 'CWE-209'],
        severity=OwaspSeverity.MEDIUM,
        remediation="""Standardize API gateway configurations; disable verbose error messages; enforce TLS 1.3.""",
        domain="API Security",
        rule_type="Automated Check 2"
    ),
    "API8:2023.3": OwaspRule(
        code="API8:2023.3",
        category=OwaspCategory.API_2023,
        title="Security Misconfiguration - Verification Check 3",
        description="""APIs commonly expose debug interfaces, unencrypted endpoints, or verbose stack traces. Automated verification check 3 for application security testing and posture validation.""",
        mapped_cwes=['CWE-16', 'CWE-209'],
        severity=OwaspSeverity.MEDIUM,
        remediation="""Standardize API gateway configurations; disable verbose error messages; enforce TLS 1.3.""",
        domain="API Security",
        rule_type="Automated Check 3"
    ),
    "API9:2023": OwaspRule(
        code="API9:2023",
        category=OwaspCategory.API_2023,
        title="Improper Inventory Management",
        description="""Deprecated API versions and undocumented shadow APIs expose unpatched vulnerabilities.""",
        mapped_cwes=['CWE-1059'],
        severity=OwaspSeverity.LOW,
        remediation="""Catalog all API versions; decommission legacy endpoints; maintain OpenAPI specifications.""",
        domain="API Security",
        rule_type="Base Category Rule"
    ),
    "API9:2023.1": OwaspRule(
        code="API9:2023.1",
        category=OwaspCategory.API_2023,
        title="Improper Inventory Management - Verification Check 1",
        description="""Deprecated API versions and undocumented shadow APIs expose unpatched vulnerabilities. Automated verification check 1 for application security testing and posture validation.""",
        mapped_cwes=['CWE-1059'],
        severity=OwaspSeverity.LOW,
        remediation="""Catalog all API versions; decommission legacy endpoints; maintain OpenAPI specifications.""",
        domain="API Security",
        rule_type="Automated Check 1"
    ),
    "API9:2023.2": OwaspRule(
        code="API9:2023.2",
        category=OwaspCategory.API_2023,
        title="Improper Inventory Management - Verification Check 2",
        description="""Deprecated API versions and undocumented shadow APIs expose unpatched vulnerabilities. Automated verification check 2 for application security testing and posture validation.""",
        mapped_cwes=['CWE-1059'],
        severity=OwaspSeverity.LOW,
        remediation="""Catalog all API versions; decommission legacy endpoints; maintain OpenAPI specifications.""",
        domain="API Security",
        rule_type="Automated Check 2"
    ),
    "API9:2023.3": OwaspRule(
        code="API9:2023.3",
        category=OwaspCategory.API_2023,
        title="Improper Inventory Management - Verification Check 3",
        description="""Deprecated API versions and undocumented shadow APIs expose unpatched vulnerabilities. Automated verification check 3 for application security testing and posture validation.""",
        mapped_cwes=['CWE-1059'],
        severity=OwaspSeverity.LOW,
        remediation="""Catalog all API versions; decommission legacy endpoints; maintain OpenAPI specifications.""",
        domain="API Security",
        rule_type="Automated Check 3"
    ),
    "API10:2023": OwaspRule(
        code="API10:2023",
        category=OwaspCategory.API_2023,
        title="Unsafe Consumption of APIs",
        description="""Blindly trusting data received from third-party APIs leads to upstream vulnerabilities.""",
        mapped_cwes=['CWE-20'],
        severity=OwaspSeverity.HIGH,
        remediation="""Validate and sanitize all data received from external third-party partner APIs.""",
        domain="API Security",
        rule_type="Base Category Rule"
    ),
    "API10:2023.1": OwaspRule(
        code="API10:2023.1",
        category=OwaspCategory.API_2023,
        title="Unsafe Consumption of APIs - Verification Check 1",
        description="""Blindly trusting data received from third-party APIs leads to upstream vulnerabilities. Automated verification check 1 for application security testing and posture validation.""",
        mapped_cwes=['CWE-20'],
        severity=OwaspSeverity.HIGH,
        remediation="""Validate and sanitize all data received from external third-party partner APIs.""",
        domain="API Security",
        rule_type="Automated Check 1"
    ),
    "API10:2023.2": OwaspRule(
        code="API10:2023.2",
        category=OwaspCategory.API_2023,
        title="Unsafe Consumption of APIs - Verification Check 2",
        description="""Blindly trusting data received from third-party APIs leads to upstream vulnerabilities. Automated verification check 2 for application security testing and posture validation.""",
        mapped_cwes=['CWE-20'],
        severity=OwaspSeverity.HIGH,
        remediation="""Validate and sanitize all data received from external third-party partner APIs.""",
        domain="API Security",
        rule_type="Automated Check 2"
    ),
    "API10:2023.3": OwaspRule(
        code="API10:2023.3",
        category=OwaspCategory.API_2023,
        title="Unsafe Consumption of APIs - Verification Check 3",
        description="""Blindly trusting data received from third-party APIs leads to upstream vulnerabilities. Automated verification check 3 for application security testing and posture validation.""",
        mapped_cwes=['CWE-20'],
        severity=OwaspSeverity.HIGH,
        remediation="""Validate and sanitize all data received from external third-party partner APIs.""",
        domain="API Security",
        rule_type="Automated Check 3"
    ),
    "LLM01:2025": OwaspRule(
        code="LLM01:2025",
        category=OwaspCategory.LLM_2025,
        title="Prompt Injection",
        description="""Crafted inputs manipulate Large Language Models into executing unintended instructions or bypassing safety guardrails.""",
        mapped_cwes=['CWE-20', 'CWE-74'],
        severity=OwaspSeverity.CRITICAL,
        remediation="""Constrain LLM context with system prompt boundaries; implement output validation; separate data from instruction.""",
        domain="Generative AI & LLM",
        rule_type="Base Category Rule"
    ),
    "LLM01:2025.1": OwaspRule(
        code="LLM01:2025.1",
        category=OwaspCategory.LLM_2025,
        title="Prompt Injection - Verification Check 1",
        description="""Crafted inputs manipulate Large Language Models into executing unintended instructions or bypassing safety guardrails. Automated verification check 1 for application security testing and posture validation.""",
        mapped_cwes=['CWE-20', 'CWE-74'],
        severity=OwaspSeverity.CRITICAL,
        remediation="""Constrain LLM context with system prompt boundaries; implement output validation; separate data from instruction.""",
        domain="Generative AI & LLM",
        rule_type="Automated Check 1"
    ),
    "LLM01:2025.2": OwaspRule(
        code="LLM01:2025.2",
        category=OwaspCategory.LLM_2025,
        title="Prompt Injection - Verification Check 2",
        description="""Crafted inputs manipulate Large Language Models into executing unintended instructions or bypassing safety guardrails. Automated verification check 2 for application security testing and posture validation.""",
        mapped_cwes=['CWE-20', 'CWE-74'],
        severity=OwaspSeverity.CRITICAL,
        remediation="""Constrain LLM context with system prompt boundaries; implement output validation; separate data from instruction.""",
        domain="Generative AI & LLM",
        rule_type="Automated Check 2"
    ),
    "LLM01:2025.3": OwaspRule(
        code="LLM01:2025.3",
        category=OwaspCategory.LLM_2025,
        title="Prompt Injection - Verification Check 3",
        description="""Crafted inputs manipulate Large Language Models into executing unintended instructions or bypassing safety guardrails. Automated verification check 3 for application security testing and posture validation.""",
        mapped_cwes=['CWE-20', 'CWE-74'],
        severity=OwaspSeverity.CRITICAL,
        remediation="""Constrain LLM context with system prompt boundaries; implement output validation; separate data from instruction.""",
        domain="Generative AI & LLM",
        rule_type="Automated Check 3"
    ),
    "LLM02:2025": OwaspRule(
        code="LLM02:2025",
        category=OwaspCategory.LLM_2025,
        title="Sensitive Information Disclosure",
        description="""LLM responses inadvertently reveal training secrets, proprietary source code, or private user data.""",
        mapped_cwes=['CWE-200'],
        severity=OwaspSeverity.HIGH,
        remediation="""Scrub PII from training datasets and RAG retrieval pipelines; enforce response guardrails.""",
        domain="Generative AI & LLM",
        rule_type="Base Category Rule"
    ),
    "LLM02:2025.1": OwaspRule(
        code="LLM02:2025.1",
        category=OwaspCategory.LLM_2025,
        title="Sensitive Information Disclosure - Verification Check 1",
        description="""LLM responses inadvertently reveal training secrets, proprietary source code, or private user data. Automated verification check 1 for application security testing and posture validation.""",
        mapped_cwes=['CWE-200'],
        severity=OwaspSeverity.HIGH,
        remediation="""Scrub PII from training datasets and RAG retrieval pipelines; enforce response guardrails.""",
        domain="Generative AI & LLM",
        rule_type="Automated Check 1"
    ),
    "LLM02:2025.2": OwaspRule(
        code="LLM02:2025.2",
        category=OwaspCategory.LLM_2025,
        title="Sensitive Information Disclosure - Verification Check 2",
        description="""LLM responses inadvertently reveal training secrets, proprietary source code, or private user data. Automated verification check 2 for application security testing and posture validation.""",
        mapped_cwes=['CWE-200'],
        severity=OwaspSeverity.HIGH,
        remediation="""Scrub PII from training datasets and RAG retrieval pipelines; enforce response guardrails.""",
        domain="Generative AI & LLM",
        rule_type="Automated Check 2"
    ),
    "LLM02:2025.3": OwaspRule(
        code="LLM02:2025.3",
        category=OwaspCategory.LLM_2025,
        title="Sensitive Information Disclosure - Verification Check 3",
        description="""LLM responses inadvertently reveal training secrets, proprietary source code, or private user data. Automated verification check 3 for application security testing and posture validation.""",
        mapped_cwes=['CWE-200'],
        severity=OwaspSeverity.HIGH,
        remediation="""Scrub PII from training datasets and RAG retrieval pipelines; enforce response guardrails.""",
        domain="Generative AI & LLM",
        rule_type="Automated Check 3"
    ),
    "LLM03:2025": OwaspRule(
        code="LLM03:2025",
        category=OwaspCategory.LLM_2025,
        title="Supply Chain Vulnerabilities",
        description="""Vulnerabilities in foundational models, datasets, fine-tuning checkpoints, or orchestration plugins.""",
        mapped_cwes=['CWE-1104'],
        severity=OwaspSeverity.HIGH,
        remediation="""Verify model checksums and provenance; scan third-party Python packages; audit plugin permissions.""",
        domain="Generative AI & LLM",
        rule_type="Base Category Rule"
    ),
    "LLM03:2025.1": OwaspRule(
        code="LLM03:2025.1",
        category=OwaspCategory.LLM_2025,
        title="Supply Chain Vulnerabilities - Verification Check 1",
        description="""Vulnerabilities in foundational models, datasets, fine-tuning checkpoints, or orchestration plugins. Automated verification check 1 for application security testing and posture validation.""",
        mapped_cwes=['CWE-1104'],
        severity=OwaspSeverity.HIGH,
        remediation="""Verify model checksums and provenance; scan third-party Python packages; audit plugin permissions.""",
        domain="Generative AI & LLM",
        rule_type="Automated Check 1"
    ),
    "LLM03:2025.2": OwaspRule(
        code="LLM03:2025.2",
        category=OwaspCategory.LLM_2025,
        title="Supply Chain Vulnerabilities - Verification Check 2",
        description="""Vulnerabilities in foundational models, datasets, fine-tuning checkpoints, or orchestration plugins. Automated verification check 2 for application security testing and posture validation.""",
        mapped_cwes=['CWE-1104'],
        severity=OwaspSeverity.HIGH,
        remediation="""Verify model checksums and provenance; scan third-party Python packages; audit plugin permissions.""",
        domain="Generative AI & LLM",
        rule_type="Automated Check 2"
    ),
    "LLM03:2025.3": OwaspRule(
        code="LLM03:2025.3",
        category=OwaspCategory.LLM_2025,
        title="Supply Chain Vulnerabilities - Verification Check 3",
        description="""Vulnerabilities in foundational models, datasets, fine-tuning checkpoints, or orchestration plugins. Automated verification check 3 for application security testing and posture validation.""",
        mapped_cwes=['CWE-1104'],
        severity=OwaspSeverity.HIGH,
        remediation="""Verify model checksums and provenance; scan third-party Python packages; audit plugin permissions.""",
        domain="Generative AI & LLM",
        rule_type="Automated Check 3"
    ),
    "LLM04:2025": OwaspRule(
        code="LLM04:2025",
        category=OwaspCategory.LLM_2025,
        title="Data and Model Poisoning",
        description="""Adversaries manipulate training data or fine-tuning datasets to introduce backdoors or bias.""",
        mapped_cwes=['CWE-829'],
        severity=OwaspSeverity.CRITICAL,
        remediation="""Verify training data lineage; use cryptographic hashes; monitor validation loss anomalies.""",
        domain="Generative AI & LLM",
        rule_type="Base Category Rule"
    ),
    "LLM04:2025.1": OwaspRule(
        code="LLM04:2025.1",
        category=OwaspCategory.LLM_2025,
        title="Data and Model Poisoning - Verification Check 1",
        description="""Adversaries manipulate training data or fine-tuning datasets to introduce backdoors or bias. Automated verification check 1 for application security testing and posture validation.""",
        mapped_cwes=['CWE-829'],
        severity=OwaspSeverity.CRITICAL,
        remediation="""Verify training data lineage; use cryptographic hashes; monitor validation loss anomalies.""",
        domain="Generative AI & LLM",
        rule_type="Automated Check 1"
    ),
    "LLM04:2025.2": OwaspRule(
        code="LLM04:2025.2",
        category=OwaspCategory.LLM_2025,
        title="Data and Model Poisoning - Verification Check 2",
        description="""Adversaries manipulate training data or fine-tuning datasets to introduce backdoors or bias. Automated verification check 2 for application security testing and posture validation.""",
        mapped_cwes=['CWE-829'],
        severity=OwaspSeverity.CRITICAL,
        remediation="""Verify training data lineage; use cryptographic hashes; monitor validation loss anomalies.""",
        domain="Generative AI & LLM",
        rule_type="Automated Check 2"
    ),
    "LLM04:2025.3": OwaspRule(
        code="LLM04:2025.3",
        category=OwaspCategory.LLM_2025,
        title="Data and Model Poisoning - Verification Check 3",
        description="""Adversaries manipulate training data or fine-tuning datasets to introduce backdoors or bias. Automated verification check 3 for application security testing and posture validation.""",
        mapped_cwes=['CWE-829'],
        severity=OwaspSeverity.CRITICAL,
        remediation="""Verify training data lineage; use cryptographic hashes; monitor validation loss anomalies.""",
        domain="Generative AI & LLM",
        rule_type="Automated Check 3"
    ),
    "LLM05:2025": OwaspRule(
        code="LLM05:2025",
        category=OwaspCategory.LLM_2025,
        title="Improper Output Handling",
        description="""Downstream applications blindly trust LLM generated code or HTML, causing XSS or RCE.""",
        mapped_cwes=['CWE-79', 'CWE-78'],
        severity=OwaspSeverity.HIGH,
        remediation="""Treat LLM output as untrusted user input; sanitize HTML; sandbox code execution.""",
        domain="Generative AI & LLM",
        rule_type="Base Category Rule"
    ),
    "LLM05:2025.1": OwaspRule(
        code="LLM05:2025.1",
        category=OwaspCategory.LLM_2025,
        title="Improper Output Handling - Verification Check 1",
        description="""Downstream applications blindly trust LLM generated code or HTML, causing XSS or RCE. Automated verification check 1 for application security testing and posture validation.""",
        mapped_cwes=['CWE-79', 'CWE-78'],
        severity=OwaspSeverity.HIGH,
        remediation="""Treat LLM output as untrusted user input; sanitize HTML; sandbox code execution.""",
        domain="Generative AI & LLM",
        rule_type="Automated Check 1"
    ),
    "LLM05:2025.2": OwaspRule(
        code="LLM05:2025.2",
        category=OwaspCategory.LLM_2025,
        title="Improper Output Handling - Verification Check 2",
        description="""Downstream applications blindly trust LLM generated code or HTML, causing XSS or RCE. Automated verification check 2 for application security testing and posture validation.""",
        mapped_cwes=['CWE-79', 'CWE-78'],
        severity=OwaspSeverity.HIGH,
        remediation="""Treat LLM output as untrusted user input; sanitize HTML; sandbox code execution.""",
        domain="Generative AI & LLM",
        rule_type="Automated Check 2"
    ),
    "LLM05:2025.3": OwaspRule(
        code="LLM05:2025.3",
        category=OwaspCategory.LLM_2025,
        title="Improper Output Handling - Verification Check 3",
        description="""Downstream applications blindly trust LLM generated code or HTML, causing XSS or RCE. Automated verification check 3 for application security testing and posture validation.""",
        mapped_cwes=['CWE-79', 'CWE-78'],
        severity=OwaspSeverity.HIGH,
        remediation="""Treat LLM output as untrusted user input; sanitize HTML; sandbox code execution.""",
        domain="Generative AI & LLM",
        rule_type="Automated Check 3"
    ),
    "LLM06:2025": OwaspRule(
        code="LLM06:2025",
        category=OwaspCategory.LLM_2025,
        title="Excessive Agency",
        description="""Granting autonomous agents excessive permissions or unsupervised execution capabilities.""",
        mapped_cwes=['CWE-250'],
        severity=OwaspSeverity.HIGH,
        remediation="""Enforce human-in-the-loop approvals for sensitive operations; limit tool permissions.""",
        domain="Generative AI & LLM",
        rule_type="Base Category Rule"
    ),
    "LLM06:2025.1": OwaspRule(
        code="LLM06:2025.1",
        category=OwaspCategory.LLM_2025,
        title="Excessive Agency - Verification Check 1",
        description="""Granting autonomous agents excessive permissions or unsupervised execution capabilities. Automated verification check 1 for application security testing and posture validation.""",
        mapped_cwes=['CWE-250'],
        severity=OwaspSeverity.HIGH,
        remediation="""Enforce human-in-the-loop approvals for sensitive operations; limit tool permissions.""",
        domain="Generative AI & LLM",
        rule_type="Automated Check 1"
    ),
    "LLM06:2025.2": OwaspRule(
        code="LLM06:2025.2",
        category=OwaspCategory.LLM_2025,
        title="Excessive Agency - Verification Check 2",
        description="""Granting autonomous agents excessive permissions or unsupervised execution capabilities. Automated verification check 2 for application security testing and posture validation.""",
        mapped_cwes=['CWE-250'],
        severity=OwaspSeverity.HIGH,
        remediation="""Enforce human-in-the-loop approvals for sensitive operations; limit tool permissions.""",
        domain="Generative AI & LLM",
        rule_type="Automated Check 2"
    ),
    "LLM06:2025.3": OwaspRule(
        code="LLM06:2025.3",
        category=OwaspCategory.LLM_2025,
        title="Excessive Agency - Verification Check 3",
        description="""Granting autonomous agents excessive permissions or unsupervised execution capabilities. Automated verification check 3 for application security testing and posture validation.""",
        mapped_cwes=['CWE-250'],
        severity=OwaspSeverity.HIGH,
        remediation="""Enforce human-in-the-loop approvals for sensitive operations; limit tool permissions.""",
        domain="Generative AI & LLM",
        rule_type="Automated Check 3"
    ),
    "LLM07:2025": OwaspRule(
        code="LLM07:2025",
        category=OwaspCategory.LLM_2025,
        title="System Prompt Leakage",
        description="""Extraction of confidential system prompts through targeted jailbreak queries.""",
        mapped_cwes=['CWE-200'],
        severity=OwaspSeverity.MEDIUM,
        remediation="""Do not store confidential secrets or API keys in system prompts; treat prompts as public.""",
        domain="Generative AI & LLM",
        rule_type="Base Category Rule"
    ),
    "LLM07:2025.1": OwaspRule(
        code="LLM07:2025.1",
        category=OwaspCategory.LLM_2025,
        title="System Prompt Leakage - Verification Check 1",
        description="""Extraction of confidential system prompts through targeted jailbreak queries. Automated verification check 1 for application security testing and posture validation.""",
        mapped_cwes=['CWE-200'],
        severity=OwaspSeverity.MEDIUM,
        remediation="""Do not store confidential secrets or API keys in system prompts; treat prompts as public.""",
        domain="Generative AI & LLM",
        rule_type="Automated Check 1"
    ),
    "LLM07:2025.2": OwaspRule(
        code="LLM07:2025.2",
        category=OwaspCategory.LLM_2025,
        title="System Prompt Leakage - Verification Check 2",
        description="""Extraction of confidential system prompts through targeted jailbreak queries. Automated verification check 2 for application security testing and posture validation.""",
        mapped_cwes=['CWE-200'],
        severity=OwaspSeverity.MEDIUM,
        remediation="""Do not store confidential secrets or API keys in system prompts; treat prompts as public.""",
        domain="Generative AI & LLM",
        rule_type="Automated Check 2"
    ),
    "LLM07:2025.3": OwaspRule(
        code="LLM07:2025.3",
        category=OwaspCategory.LLM_2025,
        title="System Prompt Leakage - Verification Check 3",
        description="""Extraction of confidential system prompts through targeted jailbreak queries. Automated verification check 3 for application security testing and posture validation.""",
        mapped_cwes=['CWE-200'],
        severity=OwaspSeverity.MEDIUM,
        remediation="""Do not store confidential secrets or API keys in system prompts; treat prompts as public.""",
        domain="Generative AI & LLM",
        rule_type="Automated Check 3"
    ),
    "LLM08:2025": OwaspRule(
        code="LLM08:2025",
        category=OwaspCategory.LLM_2025,
        title="Vector and Embedding Weaknesses",
        description="""Attacks targeting vector databases or embedding retrieval pipelines to corrupt semantic search.""",
        mapped_cwes=['CWE-20'],
        severity=OwaspSeverity.MEDIUM,
        remediation="""Encrypt vector embeddings; isolate tenant vector spaces; validate retrieved context.""",
        domain="Generative AI & LLM",
        rule_type="Base Category Rule"
    ),
    "LLM08:2025.1": OwaspRule(
        code="LLM08:2025.1",
        category=OwaspCategory.LLM_2025,
        title="Vector and Embedding Weaknesses - Verification Check 1",
        description="""Attacks targeting vector databases or embedding retrieval pipelines to corrupt semantic search. Automated verification check 1 for application security testing and posture validation.""",
        mapped_cwes=['CWE-20'],
        severity=OwaspSeverity.MEDIUM,
        remediation="""Encrypt vector embeddings; isolate tenant vector spaces; validate retrieved context.""",
        domain="Generative AI & LLM",
        rule_type="Automated Check 1"
    ),
    "LLM08:2025.2": OwaspRule(
        code="LLM08:2025.2",
        category=OwaspCategory.LLM_2025,
        title="Vector and Embedding Weaknesses - Verification Check 2",
        description="""Attacks targeting vector databases or embedding retrieval pipelines to corrupt semantic search. Automated verification check 2 for application security testing and posture validation.""",
        mapped_cwes=['CWE-20'],
        severity=OwaspSeverity.MEDIUM,
        remediation="""Encrypt vector embeddings; isolate tenant vector spaces; validate retrieved context.""",
        domain="Generative AI & LLM",
        rule_type="Automated Check 2"
    ),
    "LLM08:2025.3": OwaspRule(
        code="LLM08:2025.3",
        category=OwaspCategory.LLM_2025,
        title="Vector and Embedding Weaknesses - Verification Check 3",
        description="""Attacks targeting vector databases or embedding retrieval pipelines to corrupt semantic search. Automated verification check 3 for application security testing and posture validation.""",
        mapped_cwes=['CWE-20'],
        severity=OwaspSeverity.MEDIUM,
        remediation="""Encrypt vector embeddings; isolate tenant vector spaces; validate retrieved context.""",
        domain="Generative AI & LLM",
        rule_type="Automated Check 3"
    ),
    "LLM09:2025": OwaspRule(
        code="LLM09:2025",
        category=OwaspCategory.LLM_2025,
        title="Misinformation and Hallucination",
        description="""LLM outputs plausible but factually incorrect assertions leading to operational failures.""",
        mapped_cwes=['CWE-398'],
        severity=OwaspSeverity.MEDIUM,
        remediation="""Implement Retrieval-Augmented Generation (RAG); verify assertions with authoritative sources.""",
        domain="Generative AI & LLM",
        rule_type="Base Category Rule"
    ),
    "LLM09:2025.1": OwaspRule(
        code="LLM09:2025.1",
        category=OwaspCategory.LLM_2025,
        title="Misinformation and Hallucination - Verification Check 1",
        description="""LLM outputs plausible but factually incorrect assertions leading to operational failures. Automated verification check 1 for application security testing and posture validation.""",
        mapped_cwes=['CWE-398'],
        severity=OwaspSeverity.MEDIUM,
        remediation="""Implement Retrieval-Augmented Generation (RAG); verify assertions with authoritative sources.""",
        domain="Generative AI & LLM",
        rule_type="Automated Check 1"
    ),
    "LLM09:2025.2": OwaspRule(
        code="LLM09:2025.2",
        category=OwaspCategory.LLM_2025,
        title="Misinformation and Hallucination - Verification Check 2",
        description="""LLM outputs plausible but factually incorrect assertions leading to operational failures. Automated verification check 2 for application security testing and posture validation.""",
        mapped_cwes=['CWE-398'],
        severity=OwaspSeverity.MEDIUM,
        remediation="""Implement Retrieval-Augmented Generation (RAG); verify assertions with authoritative sources.""",
        domain="Generative AI & LLM",
        rule_type="Automated Check 2"
    ),
    "LLM09:2025.3": OwaspRule(
        code="LLM09:2025.3",
        category=OwaspCategory.LLM_2025,
        title="Misinformation and Hallucination - Verification Check 3",
        description="""LLM outputs plausible but factually incorrect assertions leading to operational failures. Automated verification check 3 for application security testing and posture validation.""",
        mapped_cwes=['CWE-398'],
        severity=OwaspSeverity.MEDIUM,
        remediation="""Implement Retrieval-Augmented Generation (RAG); verify assertions with authoritative sources.""",
        domain="Generative AI & LLM",
        rule_type="Automated Check 3"
    ),
    "LLM10:2025": OwaspRule(
        code="LLM10:2025",
        category=OwaspCategory.LLM_2025,
        title="Unbounded Consumption",
        description="""Resource exhaustion attacks using massive prompt inputs causing excessive compute cost or DoS.""",
        mapped_cwes=['CWE-400'],
        severity=OwaspSeverity.MEDIUM,
        remediation="""Enforce token rate limits; cap max response lengths; implement request timeouts.""",
        domain="Generative AI & LLM",
        rule_type="Base Category Rule"
    ),
    "LLM10:2025.1": OwaspRule(
        code="LLM10:2025.1",
        category=OwaspCategory.LLM_2025,
        title="Unbounded Consumption - Verification Check 1",
        description="""Resource exhaustion attacks using massive prompt inputs causing excessive compute cost or DoS. Automated verification check 1 for application security testing and posture validation.""",
        mapped_cwes=['CWE-400'],
        severity=OwaspSeverity.MEDIUM,
        remediation="""Enforce token rate limits; cap max response lengths; implement request timeouts.""",
        domain="Generative AI & LLM",
        rule_type="Automated Check 1"
    ),
    "LLM10:2025.2": OwaspRule(
        code="LLM10:2025.2",
        category=OwaspCategory.LLM_2025,
        title="Unbounded Consumption - Verification Check 2",
        description="""Resource exhaustion attacks using massive prompt inputs causing excessive compute cost or DoS. Automated verification check 2 for application security testing and posture validation.""",
        mapped_cwes=['CWE-400'],
        severity=OwaspSeverity.MEDIUM,
        remediation="""Enforce token rate limits; cap max response lengths; implement request timeouts.""",
        domain="Generative AI & LLM",
        rule_type="Automated Check 2"
    ),
    "LLM10:2025.3": OwaspRule(
        code="LLM10:2025.3",
        category=OwaspCategory.LLM_2025,
        title="Unbounded Consumption - Verification Check 3",
        description="""Resource exhaustion attacks using massive prompt inputs causing excessive compute cost or DoS. Automated verification check 3 for application security testing and posture validation.""",
        mapped_cwes=['CWE-400'],
        severity=OwaspSeverity.MEDIUM,
        remediation="""Enforce token rate limits; cap max response lengths; implement request timeouts.""",
        domain="Generative AI & LLM",
        rule_type="Automated Check 3"
    ),
}


class OwaspEngine:
    """Query and auditing engine for OWASP application security standards."""

    @classmethod
    def get_rule(cls, code: str) -> Optional[OwaspRule]:
        return OWASP_CATALOG.get(code)

    @classmethod
    def get_by_category(cls, category: OwaspCategory) -> List[OwaspRule]:
        return [r for r in OWASP_CATALOG.values() if r.category == category]

    @classmethod
    def get_by_severity(cls, severity: OwaspSeverity) -> List[OwaspRule]:
        return [r for r in OWASP_CATALOG.values() if r.severity == severity]

    @classmethod
    def search(cls, query: str) -> List[OwaspRule]:
        q = query.lower()
        return [
            r for r in OWASP_CATALOG.values()
            if q in r.code.lower() or q in r.title.lower() or q in r.description.lower()
        ]

    @classmethod
    def evaluate_posture(cls, category: OwaspCategory, failing_rule_codes: Set[str]) -> Dict[str, Any]:
        rules = cls.get_by_category(category)
        total = len(rules)
        failed = [r for r in rules if r.code in failing_rule_codes]
        passed_count = total - len(failed)
        score_pct = round((passed_count / total) * 100, 2) if total > 0 else 0.0

        return {
            "category": category.value,
            "total_rules": total,
            "passed_rules": passed_count,
            "failed_rules": len(failed),
            "compliance_score_percent": score_pct,
            "critical_vulnerabilities": [r.code for r in failed if r.severity == OwaspSeverity.CRITICAL],
            "high_vulnerabilities": [r.code for r in failed if r.severity == OwaspSeverity.HIGH]
        }

    @classmethod
    def get_summary(cls) -> Dict[str, Any]:
        return {
            "total_rules": len(OWASP_CATALOG),
            "web_2021_count": sum(1 for r in OWASP_CATALOG.values() if r.category == OwaspCategory.WEB_2021),
            "api_2023_count": sum(1 for r in OWASP_CATALOG.values() if r.category == OwaspCategory.API_2023),
            "llm_2025_count": sum(1 for r in OWASP_CATALOG.values() if r.category == OwaspCategory.LLM_2025),
            "critical_rules": sum(1 for r in OWASP_CATALOG.values() if r.severity == OwaspSeverity.CRITICAL),
            "high_rules": sum(1 for r in OWASP_CATALOG.values() if r.severity == OwaspSeverity.HIGH)
        }
