# AegisGuard Enterprise Cyber Defense & SecOps Platform

[![CI Pipeline](https://github.com/jani140992-hub/security-app/actions/workflows/ci.yml/badge.svg)](https://github.com/jani140992-hub/security-app/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![MIT License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14.1%20Enterprise-orange.svg)](https://attack.mitre.org/)
[![NIST SP 800-53](https://img.shields.io/badge/NIST-SP%20800--53%20Rev%205-blue.svg)](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
[![CIS Benchmarks](https://img.shields.io/badge/CIS-Benchmarks%20v3.0-purple.svg)](https://www.cisecurity.org/cis-benchmarks)
[![LOC](https://img.shields.io/badge/lines%20of%20code-50k+-brightgreen.svg)](https://github.com/jani140992-hub/security-app)

AegisGuard is an enterprise-grade cyber defense and SecOps operations platform unifying SIEM log normalization, SOAR automated incident response playbooks, Cloud Security Posture Management (CSPM), OWASP Top 10 verification, Zero-Trust PKI, and high-fidelity STIX 2.1 Threat Intelligence.

Designed for Fortune 500 security operations centers (SOC), managed detection and response (MDR) providers, and DevSecOps engineering teams, AegisGuard bridges the gap between static compliance mandates and active dynamic adversarial threat containment.

## Architecture & Subsystems
- SIEM Multi-format log normalization (Syslog RFC 3164/5424, EVTX, CloudTrail, Suricata, Nginx)
- Real-time stream correlation engine with sliding time windows
- 14 MITRE ATT&CK Tactics & 360 Techniques
- 360+ CVE advisories with native FIRST CVSS v3.1 mathematical scoring engine
- NIST SP 800-53 Rev 5 (168 controls across 19 families)
- CIS Benchmarks (139 recommendations across 5 benchmark profiles)
- 240 Sigma detection rules compiled across Windows, Linux, and Cloud
- 613 STIX 2.1 IOCs tracked across 10 major threat actors
- 379 Suricata network intrusion detection signatures
- Automated SOAR containment playbooks (Host isolation, firewall block, IAM credential revocation)
- Zero-Trust Cryptography & internal PKI Certificate Authority

## Quickstart
```bash
# Run CLI overview
python -m aegisguard.cli.main overview

# Run automated tests
python -m unittest discover -s tests -p "test_*.py" -v

# Launch REST API server
python -m aegisguard.api.app 8443
```
