# AegisGuard Enterprise Cyber Defense & SecOps Platform

[![CI Pipeline](https://github.com/jani140992-hub/security-app/actions/workflows/ci.yml/badge.svg)](https://github.com/jani140992-hub/security-app/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![MIT License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14.1%20Enterprise-orange.svg)](https://attack.mitre.org/)
[![NIST SP 800-53](https://img.shields.io/badge/NIST-SP%20800--53%20Rev%205-blue.svg)](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
[![CIS Benchmarks](https://img.shields.io/badge/CIS-Benchmarks%20v3.0-purple.svg)](https://www.cisecurity.org/cis-benchmarks)
[![LOC](https://img.shields.io/badge/lines%20of%20code-50k+-brightgreen.svg)](https://github.com/jani140992-hub/security-app)

**AegisGuard** is an enterprise-grade cyber defense and SecOps operations platform unifying **SIEM log normalization & correlation**, **SOAR automated incident response playbooks**, **Cloud Security Posture Management (CSPM)**, **OWASP Top 10 verification**, **Zero-Trust PKI**, and high-fidelity **STIX 2.1 Threat Intelligence**.

---

## Dependencies

AegisGuard requires the following foundational environments and packages:

- **Runtime Environment**: Python >= 3.10, Node.js >= 18 (for dashboard asset tooling)
- **Containerization**: Docker >= 24.0, Docker Compose >= 2.20
- **Python Libraries**:
  - `fastapi >= 0.104.0`: Asynchronous REST API framework
  - `uvicorn >= 0.24.0`: Lightning-fast ASGI production server
  - `pydantic >= 2.5.0`: Data schema validation and typing
  - `cryptography >= 41.0.0`: Low-level cryptographic primitives
  - `requests >= 2.31.0`: Synchronous HTTP client for external threat feed ingestion

---

## Installation

Clone the repository and prepare the virtual environment:

```bash
# 1. Clone the repository
git clone git@github.com:jani140992-hub/security-app.git
cd security-app

# 2. Create and activate isolated Python virtual environment
python -m venv venv

# On Linux / macOS:
source venv/bin/activate

# On Windows PowerShell:
.\venv\Scripts\Activate.ps1

# 3. Install required production dependencies
pip install -r requirements.txt

# 4. Install AegisGuard package in editable mode
pip install -e .
```

---

## Build

### Container Image Build
Build the containerized production image:

```bash
docker build -t aegisguard:latest .
```

### Python Package Distribution Build
To build wheel and source distributions:

```bash
pip install build
python -m build
```

---

## Run

### Run Local CLI Operations
Once installed, the `aegis` command-line utility is available globally:

```bash
# Display enterprise platform telemetry overview
aegis overview

# Ingest and scan raw syslog event
aegis scan-log --type syslog --log "<34>Oct 11 22:14:15 srv01 sshd[1234]: Failed password for invalid user root from 198.51.100.42 port 50232 ssh2"

# Query the vulnerability database
aegis check-cve Log4j

# Query threat intelligence feeds
aegis threat-lookup 198.51.100.42

# Perform continuous compliance audit against NIST SP 800-53
aegis audit-compliance --framework NIST-800-53 --baseline MODERATE
```

### Run REST API Server
Start the standalone AegisGuard HTTP/REST API service on port 8443:

```bash
python -m aegisguard.api.app 8443
```

### Run with Docker Compose
To launch the complete SecOps stack in the background:

```bash
docker-compose up -d
```

### Run Automated Tests
Run the complete unit and integration test suite:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

---

## Usage

### 1. Unified SIEM Ingestion & Correlation
AegisGuard ingests multiple log formats and converts them to OCSF schemas:
```python
from aegisguard.siem.parser import LogParser
from aegisguard.siem.engine import CorrelationEngine

# Parse Syslog
evt = LogParser.parse_syslog("<34>Oct 11 22:14:15 srv01 sshd[1234]: Failed password for invalid user root from 198.51.100.42 port 50232 ssh2")

# Correlate
engine = CorrelationEngine()
alerts = engine.process_event(evt)
for alert in alerts:
    print(f"[{alert.severity.value}] {alert.title} ({alert.rule_id})")
```

### 2. SOAR Automated Containment Playbooks
Trigger immediate automated response actions:
```python
from aegisguard.soar.playbooks import SoarPlaybookEngine

# Quarantine host
record = SoarPlaybookEngine.execute_host_isolation_playbook("10.0.10.25", "srv-finance-01", "alert-101")
print(f"Playbook {record.playbook_name}: {record.status.value}")
```

### 3. Threat Intelligence IOC Lookup & STIX 2.1 Export
Query IOC database or export STIX bundles:
```python
from aegisguard.catalogs.stix_threat_intel import ThreatIntelligenceEngine

ioc = ThreatIntelligenceEngine.lookup_ioc("198.51.100.42")
print(f"IOC Hit: {ioc.value} | Actor: {ioc.associated_actor} | Confidence: {ioc.confidence}%")

bundle = ThreatIntelligenceEngine.export_stix_bundle()
print(f"Exported STIX Bundle with {len(bundle['objects'])} objects")
```

---

## License

This project is licensed under the MIT License - see the LICENSE file for details.
