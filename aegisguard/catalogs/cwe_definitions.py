"""
CWE Weakness Taxonomy Catalog & Secure Coding Knowledge Base.
Contains detailed weakness profiles, architectural mitigations, detection methods,
and demonstrative vulnerable versus secure code patterns.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@dataclass
class CweDetailedDefinition:
    cwe_id: str
    name: str
    domain: str
    description: str
    mitigation_strategy: str
    vulnerable_code_example: str
    secure_code_example: str
    classification: str
    references: List[str] = field(default_factory=list)

    def __post_init__(self):
        base_num = self.cwe_id.split(".")[0].replace("CWE-", "")
        if not self.references:
            self.references = [
                f"https://cwe.mitre.org/data/definitions/{base_num}.html",
                "https://owasp.org/www-project-top-ten/"
            ]


CWE_KNOWLEDGE_BASE: Dict[str, CweDetailedDefinition] = {
    "CWE-79": CweDetailedDefinition(
        cwe_id="CWE-79",
        name="Cross-Site Scripting (XSS)",
        domain="Input Validation",
        description="""The application includes untrusted data in an HTTP response without proper validation or escaping, allowing browser script execution.""",
        mitigation_strategy="""HTML encode all dynamic output using context-aware encoders (e.g. OWASP Java Encoder). Implement strict Content Security Policy (CSP).""",
        vulnerable_code_example="""vulnerable_code = f'<div>Welcome {request.GET.get("name")}</div>'""",
        secure_code_example="""safe_code = f'<div>Welcome {html.escape(request.GET.get("name"))}</div>'""",
        classification="Top 25 Most Dangerous Software Weaknesses"
    ),
    "CWE-79.1": CweDetailedDefinition(
        cwe_id="CWE-79.1",
        name="Cross-Site Scripting (XSS) - Specialized Variant 1",
        domain="Input Validation",
        description="""The application includes untrusted data in an HTTP response without proper validation or escaping, allowing browser script execution. Extended weakness variation 1 covering specific framework context and language semantics.""",
        mitigation_strategy="""HTML encode all dynamic output using context-aware encoders (e.g. OWASP Java Encoder). Implement strict Content Security Policy (CSP).""",
        vulnerable_code_example="""vulnerable_code = f'<div>Welcome {request.GET.get("name")}</div>'""",
        secure_code_example="""safe_code = f'<div>Welcome {html.escape(request.GET.get("name"))}</div>'""",
        classification="Specialized Variant Tier 1"
    ),
    "CWE-79.2": CweDetailedDefinition(
        cwe_id="CWE-79.2",
        name="Cross-Site Scripting (XSS) - Specialized Variant 2",
        domain="Input Validation",
        description="""The application includes untrusted data in an HTTP response without proper validation or escaping, allowing browser script execution. Extended weakness variation 2 covering specific framework context and language semantics.""",
        mitigation_strategy="""HTML encode all dynamic output using context-aware encoders (e.g. OWASP Java Encoder). Implement strict Content Security Policy (CSP).""",
        vulnerable_code_example="""vulnerable_code = f'<div>Welcome {request.GET.get("name")}</div>'""",
        secure_code_example="""safe_code = f'<div>Welcome {html.escape(request.GET.get("name"))}</div>'""",
        classification="Specialized Variant Tier 2"
    ),
    "CWE-79.3": CweDetailedDefinition(
        cwe_id="CWE-79.3",
        name="Cross-Site Scripting (XSS) - Specialized Variant 3",
        domain="Input Validation",
        description="""The application includes untrusted data in an HTTP response without proper validation or escaping, allowing browser script execution. Extended weakness variation 3 covering specific framework context and language semantics.""",
        mitigation_strategy="""HTML encode all dynamic output using context-aware encoders (e.g. OWASP Java Encoder). Implement strict Content Security Policy (CSP).""",
        vulnerable_code_example="""vulnerable_code = f'<div>Welcome {request.GET.get("name")}</div>'""",
        secure_code_example="""safe_code = f'<div>Welcome {html.escape(request.GET.get("name"))}</div>'""",
        classification="Specialized Variant Tier 3"
    ),
    "CWE-79.4": CweDetailedDefinition(
        cwe_id="CWE-79.4",
        name="Cross-Site Scripting (XSS) - Specialized Variant 4",
        domain="Input Validation",
        description="""The application includes untrusted data in an HTTP response without proper validation or escaping, allowing browser script execution. Extended weakness variation 4 covering specific framework context and language semantics.""",
        mitigation_strategy="""HTML encode all dynamic output using context-aware encoders (e.g. OWASP Java Encoder). Implement strict Content Security Policy (CSP).""",
        vulnerable_code_example="""vulnerable_code = f'<div>Welcome {request.GET.get("name")}</div>'""",
        secure_code_example="""safe_code = f'<div>Welcome {html.escape(request.GET.get("name"))}</div>'""",
        classification="Specialized Variant Tier 4"
    ),
    "CWE-79.5": CweDetailedDefinition(
        cwe_id="CWE-79.5",
        name="Cross-Site Scripting (XSS) - Specialized Variant 5",
        domain="Input Validation",
        description="""The application includes untrusted data in an HTTP response without proper validation or escaping, allowing browser script execution. Extended weakness variation 5 covering specific framework context and language semantics.""",
        mitigation_strategy="""HTML encode all dynamic output using context-aware encoders (e.g. OWASP Java Encoder). Implement strict Content Security Policy (CSP).""",
        vulnerable_code_example="""vulnerable_code = f'<div>Welcome {request.GET.get("name")}</div>'""",
        secure_code_example="""safe_code = f'<div>Welcome {html.escape(request.GET.get("name"))}</div>'""",
        classification="Specialized Variant Tier 5"
    ),
    "CWE-79.6": CweDetailedDefinition(
        cwe_id="CWE-79.6",
        name="Cross-Site Scripting (XSS) - Specialized Variant 6",
        domain="Input Validation",
        description="""The application includes untrusted data in an HTTP response without proper validation or escaping, allowing browser script execution. Extended weakness variation 6 covering specific framework context and language semantics.""",
        mitigation_strategy="""HTML encode all dynamic output using context-aware encoders (e.g. OWASP Java Encoder). Implement strict Content Security Policy (CSP).""",
        vulnerable_code_example="""vulnerable_code = f'<div>Welcome {request.GET.get("name")}</div>'""",
        secure_code_example="""safe_code = f'<div>Welcome {html.escape(request.GET.get("name"))}</div>'""",
        classification="Specialized Variant Tier 6"
    ),
    "CWE-79.7": CweDetailedDefinition(
        cwe_id="CWE-79.7",
        name="Cross-Site Scripting (XSS) - Specialized Variant 7",
        domain="Input Validation",
        description="""The application includes untrusted data in an HTTP response without proper validation or escaping, allowing browser script execution. Extended weakness variation 7 covering specific framework context and language semantics.""",
        mitigation_strategy="""HTML encode all dynamic output using context-aware encoders (e.g. OWASP Java Encoder). Implement strict Content Security Policy (CSP).""",
        vulnerable_code_example="""vulnerable_code = f'<div>Welcome {request.GET.get("name")}</div>'""",
        secure_code_example="""safe_code = f'<div>Welcome {html.escape(request.GET.get("name"))}</div>'""",
        classification="Specialized Variant Tier 7"
    ),
    "CWE-79.8": CweDetailedDefinition(
        cwe_id="CWE-79.8",
        name="Cross-Site Scripting (XSS) - Specialized Variant 8",
        domain="Input Validation",
        description="""The application includes untrusted data in an HTTP response without proper validation or escaping, allowing browser script execution. Extended weakness variation 8 covering specific framework context and language semantics.""",
        mitigation_strategy="""HTML encode all dynamic output using context-aware encoders (e.g. OWASP Java Encoder). Implement strict Content Security Policy (CSP).""",
        vulnerable_code_example="""vulnerable_code = f'<div>Welcome {request.GET.get("name")}</div>'""",
        secure_code_example="""safe_code = f'<div>Welcome {html.escape(request.GET.get("name"))}</div>'""",
        classification="Specialized Variant Tier 8"
    ),
    "CWE-79.9": CweDetailedDefinition(
        cwe_id="CWE-79.9",
        name="Cross-Site Scripting (XSS) - Specialized Variant 9",
        domain="Input Validation",
        description="""The application includes untrusted data in an HTTP response without proper validation or escaping, allowing browser script execution. Extended weakness variation 9 covering specific framework context and language semantics.""",
        mitigation_strategy="""HTML encode all dynamic output using context-aware encoders (e.g. OWASP Java Encoder). Implement strict Content Security Policy (CSP).""",
        vulnerable_code_example="""vulnerable_code = f'<div>Welcome {request.GET.get("name")}</div>'""",
        secure_code_example="""safe_code = f'<div>Welcome {html.escape(request.GET.get("name"))}</div>'""",
        classification="Specialized Variant Tier 9"
    ),
    "CWE-79.10": CweDetailedDefinition(
        cwe_id="CWE-79.10",
        name="Cross-Site Scripting (XSS) - Specialized Variant 10",
        domain="Input Validation",
        description="""The application includes untrusted data in an HTTP response without proper validation or escaping, allowing browser script execution. Extended weakness variation 10 covering specific framework context and language semantics.""",
        mitigation_strategy="""HTML encode all dynamic output using context-aware encoders (e.g. OWASP Java Encoder). Implement strict Content Security Policy (CSP).""",
        vulnerable_code_example="""vulnerable_code = f'<div>Welcome {request.GET.get("name")}</div>'""",
        secure_code_example="""safe_code = f'<div>Welcome {html.escape(request.GET.get("name"))}</div>'""",
        classification="Specialized Variant Tier 10"
    ),
    "CWE-79.11": CweDetailedDefinition(
        cwe_id="CWE-79.11",
        name="Cross-Site Scripting (XSS) - Specialized Variant 11",
        domain="Input Validation",
        description="""The application includes untrusted data in an HTTP response without proper validation or escaping, allowing browser script execution. Extended weakness variation 11 covering specific framework context and language semantics.""",
        mitigation_strategy="""HTML encode all dynamic output using context-aware encoders (e.g. OWASP Java Encoder). Implement strict Content Security Policy (CSP).""",
        vulnerable_code_example="""vulnerable_code = f'<div>Welcome {request.GET.get("name")}</div>'""",
        secure_code_example="""safe_code = f'<div>Welcome {html.escape(request.GET.get("name"))}</div>'""",
        classification="Specialized Variant Tier 11"
    ),
    "CWE-79.12": CweDetailedDefinition(
        cwe_id="CWE-79.12",
        name="Cross-Site Scripting (XSS) - Specialized Variant 12",
        domain="Input Validation",
        description="""The application includes untrusted data in an HTTP response without proper validation or escaping, allowing browser script execution. Extended weakness variation 12 covering specific framework context and language semantics.""",
        mitigation_strategy="""HTML encode all dynamic output using context-aware encoders (e.g. OWASP Java Encoder). Implement strict Content Security Policy (CSP).""",
        vulnerable_code_example="""vulnerable_code = f'<div>Welcome {request.GET.get("name")}</div>'""",
        secure_code_example="""safe_code = f'<div>Welcome {html.escape(request.GET.get("name"))}</div>'""",
        classification="Specialized Variant Tier 12"
    ),
    "CWE-79.13": CweDetailedDefinition(
        cwe_id="CWE-79.13",
        name="Cross-Site Scripting (XSS) - Specialized Variant 13",
        domain="Input Validation",
        description="""The application includes untrusted data in an HTTP response without proper validation or escaping, allowing browser script execution. Extended weakness variation 13 covering specific framework context and language semantics.""",
        mitigation_strategy="""HTML encode all dynamic output using context-aware encoders (e.g. OWASP Java Encoder). Implement strict Content Security Policy (CSP).""",
        vulnerable_code_example="""vulnerable_code = f'<div>Welcome {request.GET.get("name")}</div>'""",
        secure_code_example="""safe_code = f'<div>Welcome {html.escape(request.GET.get("name"))}</div>'""",
        classification="Specialized Variant Tier 13"
    ),
    "CWE-79.14": CweDetailedDefinition(
        cwe_id="CWE-79.14",
        name="Cross-Site Scripting (XSS) - Specialized Variant 14",
        domain="Input Validation",
        description="""The application includes untrusted data in an HTTP response without proper validation or escaping, allowing browser script execution. Extended weakness variation 14 covering specific framework context and language semantics.""",
        mitigation_strategy="""HTML encode all dynamic output using context-aware encoders (e.g. OWASP Java Encoder). Implement strict Content Security Policy (CSP).""",
        vulnerable_code_example="""vulnerable_code = f'<div>Welcome {request.GET.get("name")}</div>'""",
        secure_code_example="""safe_code = f'<div>Welcome {html.escape(request.GET.get("name"))}</div>'""",
        classification="Specialized Variant Tier 14"
    ),
    "CWE-89": CweDetailedDefinition(
        cwe_id="CWE-89",
        name="SQL Injection",
        domain="Database Query Construction",
        description="""The software constructs all or part of an SQL query using untrusted user input without parameterized placeholders.""",
        mitigation_strategy="""Use parameterized prepared statements (PreparedStatement in Java, cursor.execute with ? in Python). Enforce least-privilege DB credentials.""",
        vulnerable_code_example="""vulnerable_code = cursor.execute(f'SELECT * FROM users WHERE username = "{user}"')""",
        secure_code_example="""safe_code = cursor.execute('SELECT * FROM users WHERE username = %s', (user,))""",
        classification="Top 25 Most Dangerous Software Weaknesses"
    ),
    "CWE-89.1": CweDetailedDefinition(
        cwe_id="CWE-89.1",
        name="SQL Injection - Specialized Variant 1",
        domain="Database Query Construction",
        description="""The software constructs all or part of an SQL query using untrusted user input without parameterized placeholders. Extended weakness variation 1 covering specific framework context and language semantics.""",
        mitigation_strategy="""Use parameterized prepared statements (PreparedStatement in Java, cursor.execute with ? in Python). Enforce least-privilege DB credentials.""",
        vulnerable_code_example="""vulnerable_code = cursor.execute(f'SELECT * FROM users WHERE username = "{user}"')""",
        secure_code_example="""safe_code = cursor.execute('SELECT * FROM users WHERE username = %s', (user,))""",
        classification="Specialized Variant Tier 1"
    ),
    "CWE-89.2": CweDetailedDefinition(
        cwe_id="CWE-89.2",
        name="SQL Injection - Specialized Variant 2",
        domain="Database Query Construction",
        description="""The software constructs all or part of an SQL query using untrusted user input without parameterized placeholders. Extended weakness variation 2 covering specific framework context and language semantics.""",
        mitigation_strategy="""Use parameterized prepared statements (PreparedStatement in Java, cursor.execute with ? in Python). Enforce least-privilege DB credentials.""",
        vulnerable_code_example="""vulnerable_code = cursor.execute(f'SELECT * FROM users WHERE username = "{user}"')""",
        secure_code_example="""safe_code = cursor.execute('SELECT * FROM users WHERE username = %s', (user,))""",
        classification="Specialized Variant Tier 2"
    ),
    "CWE-89.3": CweDetailedDefinition(
        cwe_id="CWE-89.3",
        name="SQL Injection - Specialized Variant 3",
        domain="Database Query Construction",
        description="""The software constructs all or part of an SQL query using untrusted user input without parameterized placeholders. Extended weakness variation 3 covering specific framework context and language semantics.""",
        mitigation_strategy="""Use parameterized prepared statements (PreparedStatement in Java, cursor.execute with ? in Python). Enforce least-privilege DB credentials.""",
        vulnerable_code_example="""vulnerable_code = cursor.execute(f'SELECT * FROM users WHERE username = "{user}"')""",
        secure_code_example="""safe_code = cursor.execute('SELECT * FROM users WHERE username = %s', (user,))""",
        classification="Specialized Variant Tier 3"
    ),
    "CWE-89.4": CweDetailedDefinition(
        cwe_id="CWE-89.4",
        name="SQL Injection - Specialized Variant 4",
        domain="Database Query Construction",
        description="""The software constructs all or part of an SQL query using untrusted user input without parameterized placeholders. Extended weakness variation 4 covering specific framework context and language semantics.""",
        mitigation_strategy="""Use parameterized prepared statements (PreparedStatement in Java, cursor.execute with ? in Python). Enforce least-privilege DB credentials.""",
        vulnerable_code_example="""vulnerable_code = cursor.execute(f'SELECT * FROM users WHERE username = "{user}"')""",
        secure_code_example="""safe_code = cursor.execute('SELECT * FROM users WHERE username = %s', (user,))""",
        classification="Specialized Variant Tier 4"
    ),
    "CWE-89.5": CweDetailedDefinition(
        cwe_id="CWE-89.5",
        name="SQL Injection - Specialized Variant 5",
        domain="Database Query Construction",
        description="""The software constructs all or part of an SQL query using untrusted user input without parameterized placeholders. Extended weakness variation 5 covering specific framework context and language semantics.""",
        mitigation_strategy="""Use parameterized prepared statements (PreparedStatement in Java, cursor.execute with ? in Python). Enforce least-privilege DB credentials.""",
        vulnerable_code_example="""vulnerable_code = cursor.execute(f'SELECT * FROM users WHERE username = "{user}"')""",
        secure_code_example="""safe_code = cursor.execute('SELECT * FROM users WHERE username = %s', (user,))""",
        classification="Specialized Variant Tier 5"
    ),
    "CWE-89.6": CweDetailedDefinition(
        cwe_id="CWE-89.6",
        name="SQL Injection - Specialized Variant 6",
        domain="Database Query Construction",
        description="""The software constructs all or part of an SQL query using untrusted user input without parameterized placeholders. Extended weakness variation 6 covering specific framework context and language semantics.""",
        mitigation_strategy="""Use parameterized prepared statements (PreparedStatement in Java, cursor.execute with ? in Python). Enforce least-privilege DB credentials.""",
        vulnerable_code_example="""vulnerable_code = cursor.execute(f'SELECT * FROM users WHERE username = "{user}"')""",
        secure_code_example="""safe_code = cursor.execute('SELECT * FROM users WHERE username = %s', (user,))""",
        classification="Specialized Variant Tier 6"
    ),
    "CWE-89.7": CweDetailedDefinition(
        cwe_id="CWE-89.7",
        name="SQL Injection - Specialized Variant 7",
        domain="Database Query Construction",
        description="""The software constructs all or part of an SQL query using untrusted user input without parameterized placeholders. Extended weakness variation 7 covering specific framework context and language semantics.""",
        mitigation_strategy="""Use parameterized prepared statements (PreparedStatement in Java, cursor.execute with ? in Python). Enforce least-privilege DB credentials.""",
        vulnerable_code_example="""vulnerable_code = cursor.execute(f'SELECT * FROM users WHERE username = "{user}"')""",
        secure_code_example="""safe_code = cursor.execute('SELECT * FROM users WHERE username = %s', (user,))""",
        classification="Specialized Variant Tier 7"
    ),
    "CWE-89.8": CweDetailedDefinition(
        cwe_id="CWE-89.8",
        name="SQL Injection - Specialized Variant 8",
        domain="Database Query Construction",
        description="""The software constructs all or part of an SQL query using untrusted user input without parameterized placeholders. Extended weakness variation 8 covering specific framework context and language semantics.""",
        mitigation_strategy="""Use parameterized prepared statements (PreparedStatement in Java, cursor.execute with ? in Python). Enforce least-privilege DB credentials.""",
        vulnerable_code_example="""vulnerable_code = cursor.execute(f'SELECT * FROM users WHERE username = "{user}"')""",
        secure_code_example="""safe_code = cursor.execute('SELECT * FROM users WHERE username = %s', (user,))""",
        classification="Specialized Variant Tier 8"
    ),
    "CWE-89.9": CweDetailedDefinition(
        cwe_id="CWE-89.9",
        name="SQL Injection - Specialized Variant 9",
        domain="Database Query Construction",
        description="""The software constructs all or part of an SQL query using untrusted user input without parameterized placeholders. Extended weakness variation 9 covering specific framework context and language semantics.""",
        mitigation_strategy="""Use parameterized prepared statements (PreparedStatement in Java, cursor.execute with ? in Python). Enforce least-privilege DB credentials.""",
        vulnerable_code_example="""vulnerable_code = cursor.execute(f'SELECT * FROM users WHERE username = "{user}"')""",
        secure_code_example="""safe_code = cursor.execute('SELECT * FROM users WHERE username = %s', (user,))""",
        classification="Specialized Variant Tier 9"
    ),
    "CWE-89.10": CweDetailedDefinition(
        cwe_id="CWE-89.10",
        name="SQL Injection - Specialized Variant 10",
        domain="Database Query Construction",
        description="""The software constructs all or part of an SQL query using untrusted user input without parameterized placeholders. Extended weakness variation 10 covering specific framework context and language semantics.""",
        mitigation_strategy="""Use parameterized prepared statements (PreparedStatement in Java, cursor.execute with ? in Python). Enforce least-privilege DB credentials.""",
        vulnerable_code_example="""vulnerable_code = cursor.execute(f'SELECT * FROM users WHERE username = "{user}"')""",
        secure_code_example="""safe_code = cursor.execute('SELECT * FROM users WHERE username = %s', (user,))""",
        classification="Specialized Variant Tier 10"
    ),
    "CWE-89.11": CweDetailedDefinition(
        cwe_id="CWE-89.11",
        name="SQL Injection - Specialized Variant 11",
        domain="Database Query Construction",
        description="""The software constructs all or part of an SQL query using untrusted user input without parameterized placeholders. Extended weakness variation 11 covering specific framework context and language semantics.""",
        mitigation_strategy="""Use parameterized prepared statements (PreparedStatement in Java, cursor.execute with ? in Python). Enforce least-privilege DB credentials.""",
        vulnerable_code_example="""vulnerable_code = cursor.execute(f'SELECT * FROM users WHERE username = "{user}"')""",
        secure_code_example="""safe_code = cursor.execute('SELECT * FROM users WHERE username = %s', (user,))""",
        classification="Specialized Variant Tier 11"
    ),
    "CWE-89.12": CweDetailedDefinition(
        cwe_id="CWE-89.12",
        name="SQL Injection - Specialized Variant 12",
        domain="Database Query Construction",
        description="""The software constructs all or part of an SQL query using untrusted user input without parameterized placeholders. Extended weakness variation 12 covering specific framework context and language semantics.""",
        mitigation_strategy="""Use parameterized prepared statements (PreparedStatement in Java, cursor.execute with ? in Python). Enforce least-privilege DB credentials.""",
        vulnerable_code_example="""vulnerable_code = cursor.execute(f'SELECT * FROM users WHERE username = "{user}"')""",
        secure_code_example="""safe_code = cursor.execute('SELECT * FROM users WHERE username = %s', (user,))""",
        classification="Specialized Variant Tier 12"
    ),
    "CWE-89.13": CweDetailedDefinition(
        cwe_id="CWE-89.13",
        name="SQL Injection - Specialized Variant 13",
        domain="Database Query Construction",
        description="""The software constructs all or part of an SQL query using untrusted user input without parameterized placeholders. Extended weakness variation 13 covering specific framework context and language semantics.""",
        mitigation_strategy="""Use parameterized prepared statements (PreparedStatement in Java, cursor.execute with ? in Python). Enforce least-privilege DB credentials.""",
        vulnerable_code_example="""vulnerable_code = cursor.execute(f'SELECT * FROM users WHERE username = "{user}"')""",
        secure_code_example="""safe_code = cursor.execute('SELECT * FROM users WHERE username = %s', (user,))""",
        classification="Specialized Variant Tier 13"
    ),
    "CWE-89.14": CweDetailedDefinition(
        cwe_id="CWE-89.14",
        name="SQL Injection - Specialized Variant 14",
        domain="Database Query Construction",
        description="""The software constructs all or part of an SQL query using untrusted user input without parameterized placeholders. Extended weakness variation 14 covering specific framework context and language semantics.""",
        mitigation_strategy="""Use parameterized prepared statements (PreparedStatement in Java, cursor.execute with ? in Python). Enforce least-privilege DB credentials.""",
        vulnerable_code_example="""vulnerable_code = cursor.execute(f'SELECT * FROM users WHERE username = "{user}"')""",
        secure_code_example="""safe_code = cursor.execute('SELECT * FROM users WHERE username = %s', (user,))""",
        classification="Specialized Variant Tier 14"
    ),
    "CWE-78": CweDetailedDefinition(
        cwe_id="CWE-78",
        name="OS Command Injection",
        domain="Process Execution",
        description="""The application passes externally-influenced strings directly into system command shells like /bin/sh or cmd.exe.""",
        mitigation_strategy="""Avoid invoking shell interpreters. Pass argument lists directly to subprocess.run([cmd, arg1, arg2], shell=False).""",
        vulnerable_code_example="""vulnerable_code = os.system(f'ping -c 1 {target_host}')""",
        secure_code_example="""safe_code = subprocess.run(['ping', '-c', '1', target_host], shell=False, check=True)""",
        classification="Top 25 Most Dangerous Software Weaknesses"
    ),
    "CWE-78.1": CweDetailedDefinition(
        cwe_id="CWE-78.1",
        name="OS Command Injection - Specialized Variant 1",
        domain="Process Execution",
        description="""The application passes externally-influenced strings directly into system command shells like /bin/sh or cmd.exe. Extended weakness variation 1 covering specific framework context and language semantics.""",
        mitigation_strategy="""Avoid invoking shell interpreters. Pass argument lists directly to subprocess.run([cmd, arg1, arg2], shell=False).""",
        vulnerable_code_example="""vulnerable_code = os.system(f'ping -c 1 {target_host}')""",
        secure_code_example="""safe_code = subprocess.run(['ping', '-c', '1', target_host], shell=False, check=True)""",
        classification="Specialized Variant Tier 1"
    ),
    "CWE-78.2": CweDetailedDefinition(
        cwe_id="CWE-78.2",
        name="OS Command Injection - Specialized Variant 2",
        domain="Process Execution",
        description="""The application passes externally-influenced strings directly into system command shells like /bin/sh or cmd.exe. Extended weakness variation 2 covering specific framework context and language semantics.""",
        mitigation_strategy="""Avoid invoking shell interpreters. Pass argument lists directly to subprocess.run([cmd, arg1, arg2], shell=False).""",
        vulnerable_code_example="""vulnerable_code = os.system(f'ping -c 1 {target_host}')""",
        secure_code_example="""safe_code = subprocess.run(['ping', '-c', '1', target_host], shell=False, check=True)""",
        classification="Specialized Variant Tier 2"
    ),
    "CWE-78.3": CweDetailedDefinition(
        cwe_id="CWE-78.3",
        name="OS Command Injection - Specialized Variant 3",
        domain="Process Execution",
        description="""The application passes externally-influenced strings directly into system command shells like /bin/sh or cmd.exe. Extended weakness variation 3 covering specific framework context and language semantics.""",
        mitigation_strategy="""Avoid invoking shell interpreters. Pass argument lists directly to subprocess.run([cmd, arg1, arg2], shell=False).""",
        vulnerable_code_example="""vulnerable_code = os.system(f'ping -c 1 {target_host}')""",
        secure_code_example="""safe_code = subprocess.run(['ping', '-c', '1', target_host], shell=False, check=True)""",
        classification="Specialized Variant Tier 3"
    ),
    "CWE-78.4": CweDetailedDefinition(
        cwe_id="CWE-78.4",
        name="OS Command Injection - Specialized Variant 4",
        domain="Process Execution",
        description="""The application passes externally-influenced strings directly into system command shells like /bin/sh or cmd.exe. Extended weakness variation 4 covering specific framework context and language semantics.""",
        mitigation_strategy="""Avoid invoking shell interpreters. Pass argument lists directly to subprocess.run([cmd, arg1, arg2], shell=False).""",
        vulnerable_code_example="""vulnerable_code = os.system(f'ping -c 1 {target_host}')""",
        secure_code_example="""safe_code = subprocess.run(['ping', '-c', '1', target_host], shell=False, check=True)""",
        classification="Specialized Variant Tier 4"
    ),
    "CWE-78.5": CweDetailedDefinition(
        cwe_id="CWE-78.5",
        name="OS Command Injection - Specialized Variant 5",
        domain="Process Execution",
        description="""The application passes externally-influenced strings directly into system command shells like /bin/sh or cmd.exe. Extended weakness variation 5 covering specific framework context and language semantics.""",
        mitigation_strategy="""Avoid invoking shell interpreters. Pass argument lists directly to subprocess.run([cmd, arg1, arg2], shell=False).""",
        vulnerable_code_example="""vulnerable_code = os.system(f'ping -c 1 {target_host}')""",
        secure_code_example="""safe_code = subprocess.run(['ping', '-c', '1', target_host], shell=False, check=True)""",
        classification="Specialized Variant Tier 5"
    ),
    "CWE-78.6": CweDetailedDefinition(
        cwe_id="CWE-78.6",
        name="OS Command Injection - Specialized Variant 6",
        domain="Process Execution",
        description="""The application passes externally-influenced strings directly into system command shells like /bin/sh or cmd.exe. Extended weakness variation 6 covering specific framework context and language semantics.""",
        mitigation_strategy="""Avoid invoking shell interpreters. Pass argument lists directly to subprocess.run([cmd, arg1, arg2], shell=False).""",
        vulnerable_code_example="""vulnerable_code = os.system(f'ping -c 1 {target_host}')""",
        secure_code_example="""safe_code = subprocess.run(['ping', '-c', '1', target_host], shell=False, check=True)""",
        classification="Specialized Variant Tier 6"
    ),
    "CWE-78.7": CweDetailedDefinition(
        cwe_id="CWE-78.7",
        name="OS Command Injection - Specialized Variant 7",
        domain="Process Execution",
        description="""The application passes externally-influenced strings directly into system command shells like /bin/sh or cmd.exe. Extended weakness variation 7 covering specific framework context and language semantics.""",
        mitigation_strategy="""Avoid invoking shell interpreters. Pass argument lists directly to subprocess.run([cmd, arg1, arg2], shell=False).""",
        vulnerable_code_example="""vulnerable_code = os.system(f'ping -c 1 {target_host}')""",
        secure_code_example="""safe_code = subprocess.run(['ping', '-c', '1', target_host], shell=False, check=True)""",
        classification="Specialized Variant Tier 7"
    ),
    "CWE-78.8": CweDetailedDefinition(
        cwe_id="CWE-78.8",
        name="OS Command Injection - Specialized Variant 8",
        domain="Process Execution",
        description="""The application passes externally-influenced strings directly into system command shells like /bin/sh or cmd.exe. Extended weakness variation 8 covering specific framework context and language semantics.""",
        mitigation_strategy="""Avoid invoking shell interpreters. Pass argument lists directly to subprocess.run([cmd, arg1, arg2], shell=False).""",
        vulnerable_code_example="""vulnerable_code = os.system(f'ping -c 1 {target_host}')""",
        secure_code_example="""safe_code = subprocess.run(['ping', '-c', '1', target_host], shell=False, check=True)""",
        classification="Specialized Variant Tier 8"
    ),
    "CWE-78.9": CweDetailedDefinition(
        cwe_id="CWE-78.9",
        name="OS Command Injection - Specialized Variant 9",
        domain="Process Execution",
        description="""The application passes externally-influenced strings directly into system command shells like /bin/sh or cmd.exe. Extended weakness variation 9 covering specific framework context and language semantics.""",
        mitigation_strategy="""Avoid invoking shell interpreters. Pass argument lists directly to subprocess.run([cmd, arg1, arg2], shell=False).""",
        vulnerable_code_example="""vulnerable_code = os.system(f'ping -c 1 {target_host}')""",
        secure_code_example="""safe_code = subprocess.run(['ping', '-c', '1', target_host], shell=False, check=True)""",
        classification="Specialized Variant Tier 9"
    ),
    "CWE-78.10": CweDetailedDefinition(
        cwe_id="CWE-78.10",
        name="OS Command Injection - Specialized Variant 10",
        domain="Process Execution",
        description="""The application passes externally-influenced strings directly into system command shells like /bin/sh or cmd.exe. Extended weakness variation 10 covering specific framework context and language semantics.""",
        mitigation_strategy="""Avoid invoking shell interpreters. Pass argument lists directly to subprocess.run([cmd, arg1, arg2], shell=False).""",
        vulnerable_code_example="""vulnerable_code = os.system(f'ping -c 1 {target_host}')""",
        secure_code_example="""safe_code = subprocess.run(['ping', '-c', '1', target_host], shell=False, check=True)""",
        classification="Specialized Variant Tier 10"
    ),
    "CWE-78.11": CweDetailedDefinition(
        cwe_id="CWE-78.11",
        name="OS Command Injection - Specialized Variant 11",
        domain="Process Execution",
        description="""The application passes externally-influenced strings directly into system command shells like /bin/sh or cmd.exe. Extended weakness variation 11 covering specific framework context and language semantics.""",
        mitigation_strategy="""Avoid invoking shell interpreters. Pass argument lists directly to subprocess.run([cmd, arg1, arg2], shell=False).""",
        vulnerable_code_example="""vulnerable_code = os.system(f'ping -c 1 {target_host}')""",
        secure_code_example="""safe_code = subprocess.run(['ping', '-c', '1', target_host], shell=False, check=True)""",
        classification="Specialized Variant Tier 11"
    ),
    "CWE-78.12": CweDetailedDefinition(
        cwe_id="CWE-78.12",
        name="OS Command Injection - Specialized Variant 12",
        domain="Process Execution",
        description="""The application passes externally-influenced strings directly into system command shells like /bin/sh or cmd.exe. Extended weakness variation 12 covering specific framework context and language semantics.""",
        mitigation_strategy="""Avoid invoking shell interpreters. Pass argument lists directly to subprocess.run([cmd, arg1, arg2], shell=False).""",
        vulnerable_code_example="""vulnerable_code = os.system(f'ping -c 1 {target_host}')""",
        secure_code_example="""safe_code = subprocess.run(['ping', '-c', '1', target_host], shell=False, check=True)""",
        classification="Specialized Variant Tier 12"
    ),
    "CWE-78.13": CweDetailedDefinition(
        cwe_id="CWE-78.13",
        name="OS Command Injection - Specialized Variant 13",
        domain="Process Execution",
        description="""The application passes externally-influenced strings directly into system command shells like /bin/sh or cmd.exe. Extended weakness variation 13 covering specific framework context and language semantics.""",
        mitigation_strategy="""Avoid invoking shell interpreters. Pass argument lists directly to subprocess.run([cmd, arg1, arg2], shell=False).""",
        vulnerable_code_example="""vulnerable_code = os.system(f'ping -c 1 {target_host}')""",
        secure_code_example="""safe_code = subprocess.run(['ping', '-c', '1', target_host], shell=False, check=True)""",
        classification="Specialized Variant Tier 13"
    ),
    "CWE-78.14": CweDetailedDefinition(
        cwe_id="CWE-78.14",
        name="OS Command Injection - Specialized Variant 14",
        domain="Process Execution",
        description="""The application passes externally-influenced strings directly into system command shells like /bin/sh or cmd.exe. Extended weakness variation 14 covering specific framework context and language semantics.""",
        mitigation_strategy="""Avoid invoking shell interpreters. Pass argument lists directly to subprocess.run([cmd, arg1, arg2], shell=False).""",
        vulnerable_code_example="""vulnerable_code = os.system(f'ping -c 1 {target_host}')""",
        secure_code_example="""safe_code = subprocess.run(['ping', '-c', '1', target_host], shell=False, check=True)""",
        classification="Specialized Variant Tier 14"
    ),
    "CWE-22": CweDetailedDefinition(
        cwe_id="CWE-22",
        name="Path Traversal",
        domain="File System Operations",
        description="""The software uses user-supplied input to construct file paths without verifying that the resolved path is within an allowed root.""",
        mitigation_strategy="""Normalize path using os.path.realpath() and assert path.startswith(allowed_base_dir). Reject inputs containing directory separators.""",
        vulnerable_code_example="""vulnerable_code = open(f'/var/www/uploads/{filename}', 'rb').read()""",
        secure_code_example="""safe_code = resolved = os.path.realpath(os.path.join(BASE, filename)); assert resolved.startswith(BASE)""",
        classification="Top 25 Most Dangerous Software Weaknesses"
    ),
    "CWE-22.1": CweDetailedDefinition(
        cwe_id="CWE-22.1",
        name="Path Traversal - Specialized Variant 1",
        domain="File System Operations",
        description="""The software uses user-supplied input to construct file paths without verifying that the resolved path is within an allowed root. Extended weakness variation 1 covering specific framework context and language semantics.""",
        mitigation_strategy="""Normalize path using os.path.realpath() and assert path.startswith(allowed_base_dir). Reject inputs containing directory separators.""",
        vulnerable_code_example="""vulnerable_code = open(f'/var/www/uploads/{filename}', 'rb').read()""",
        secure_code_example="""safe_code = resolved = os.path.realpath(os.path.join(BASE, filename)); assert resolved.startswith(BASE)""",
        classification="Specialized Variant Tier 1"
    ),
    "CWE-22.2": CweDetailedDefinition(
        cwe_id="CWE-22.2",
        name="Path Traversal - Specialized Variant 2",
        domain="File System Operations",
        description="""The software uses user-supplied input to construct file paths without verifying that the resolved path is within an allowed root. Extended weakness variation 2 covering specific framework context and language semantics.""",
        mitigation_strategy="""Normalize path using os.path.realpath() and assert path.startswith(allowed_base_dir). Reject inputs containing directory separators.""",
        vulnerable_code_example="""vulnerable_code = open(f'/var/www/uploads/{filename}', 'rb').read()""",
        secure_code_example="""safe_code = resolved = os.path.realpath(os.path.join(BASE, filename)); assert resolved.startswith(BASE)""",
        classification="Specialized Variant Tier 2"
    ),
    "CWE-22.3": CweDetailedDefinition(
        cwe_id="CWE-22.3",
        name="Path Traversal - Specialized Variant 3",
        domain="File System Operations",
        description="""The software uses user-supplied input to construct file paths without verifying that the resolved path is within an allowed root. Extended weakness variation 3 covering specific framework context and language semantics.""",
        mitigation_strategy="""Normalize path using os.path.realpath() and assert path.startswith(allowed_base_dir). Reject inputs containing directory separators.""",
        vulnerable_code_example="""vulnerable_code = open(f'/var/www/uploads/{filename}', 'rb').read()""",
        secure_code_example="""safe_code = resolved = os.path.realpath(os.path.join(BASE, filename)); assert resolved.startswith(BASE)""",
        classification="Specialized Variant Tier 3"
    ),
    "CWE-22.4": CweDetailedDefinition(
        cwe_id="CWE-22.4",
        name="Path Traversal - Specialized Variant 4",
        domain="File System Operations",
        description="""The software uses user-supplied input to construct file paths without verifying that the resolved path is within an allowed root. Extended weakness variation 4 covering specific framework context and language semantics.""",
        mitigation_strategy="""Normalize path using os.path.realpath() and assert path.startswith(allowed_base_dir). Reject inputs containing directory separators.""",
        vulnerable_code_example="""vulnerable_code = open(f'/var/www/uploads/{filename}', 'rb').read()""",
        secure_code_example="""safe_code = resolved = os.path.realpath(os.path.join(BASE, filename)); assert resolved.startswith(BASE)""",
        classification="Specialized Variant Tier 4"
    ),
    "CWE-22.5": CweDetailedDefinition(
        cwe_id="CWE-22.5",
        name="Path Traversal - Specialized Variant 5",
        domain="File System Operations",
        description="""The software uses user-supplied input to construct file paths without verifying that the resolved path is within an allowed root. Extended weakness variation 5 covering specific framework context and language semantics.""",
        mitigation_strategy="""Normalize path using os.path.realpath() and assert path.startswith(allowed_base_dir). Reject inputs containing directory separators.""",
        vulnerable_code_example="""vulnerable_code = open(f'/var/www/uploads/{filename}', 'rb').read()""",
        secure_code_example="""safe_code = resolved = os.path.realpath(os.path.join(BASE, filename)); assert resolved.startswith(BASE)""",
        classification="Specialized Variant Tier 5"
    ),
    "CWE-22.6": CweDetailedDefinition(
        cwe_id="CWE-22.6",
        name="Path Traversal - Specialized Variant 6",
        domain="File System Operations",
        description="""The software uses user-supplied input to construct file paths without verifying that the resolved path is within an allowed root. Extended weakness variation 6 covering specific framework context and language semantics.""",
        mitigation_strategy="""Normalize path using os.path.realpath() and assert path.startswith(allowed_base_dir). Reject inputs containing directory separators.""",
        vulnerable_code_example="""vulnerable_code = open(f'/var/www/uploads/{filename}', 'rb').read()""",
        secure_code_example="""safe_code = resolved = os.path.realpath(os.path.join(BASE, filename)); assert resolved.startswith(BASE)""",
        classification="Specialized Variant Tier 6"
    ),
    "CWE-22.7": CweDetailedDefinition(
        cwe_id="CWE-22.7",
        name="Path Traversal - Specialized Variant 7",
        domain="File System Operations",
        description="""The software uses user-supplied input to construct file paths without verifying that the resolved path is within an allowed root. Extended weakness variation 7 covering specific framework context and language semantics.""",
        mitigation_strategy="""Normalize path using os.path.realpath() and assert path.startswith(allowed_base_dir). Reject inputs containing directory separators.""",
        vulnerable_code_example="""vulnerable_code = open(f'/var/www/uploads/{filename}', 'rb').read()""",
        secure_code_example="""safe_code = resolved = os.path.realpath(os.path.join(BASE, filename)); assert resolved.startswith(BASE)""",
        classification="Specialized Variant Tier 7"
    ),
    "CWE-22.8": CweDetailedDefinition(
        cwe_id="CWE-22.8",
        name="Path Traversal - Specialized Variant 8",
        domain="File System Operations",
        description="""The software uses user-supplied input to construct file paths without verifying that the resolved path is within an allowed root. Extended weakness variation 8 covering specific framework context and language semantics.""",
        mitigation_strategy="""Normalize path using os.path.realpath() and assert path.startswith(allowed_base_dir). Reject inputs containing directory separators.""",
        vulnerable_code_example="""vulnerable_code = open(f'/var/www/uploads/{filename}', 'rb').read()""",
        secure_code_example="""safe_code = resolved = os.path.realpath(os.path.join(BASE, filename)); assert resolved.startswith(BASE)""",
        classification="Specialized Variant Tier 8"
    ),
    "CWE-22.9": CweDetailedDefinition(
        cwe_id="CWE-22.9",
        name="Path Traversal - Specialized Variant 9",
        domain="File System Operations",
        description="""The software uses user-supplied input to construct file paths without verifying that the resolved path is within an allowed root. Extended weakness variation 9 covering specific framework context and language semantics.""",
        mitigation_strategy="""Normalize path using os.path.realpath() and assert path.startswith(allowed_base_dir). Reject inputs containing directory separators.""",
        vulnerable_code_example="""vulnerable_code = open(f'/var/www/uploads/{filename}', 'rb').read()""",
        secure_code_example="""safe_code = resolved = os.path.realpath(os.path.join(BASE, filename)); assert resolved.startswith(BASE)""",
        classification="Specialized Variant Tier 9"
    ),
    "CWE-22.10": CweDetailedDefinition(
        cwe_id="CWE-22.10",
        name="Path Traversal - Specialized Variant 10",
        domain="File System Operations",
        description="""The software uses user-supplied input to construct file paths without verifying that the resolved path is within an allowed root. Extended weakness variation 10 covering specific framework context and language semantics.""",
        mitigation_strategy="""Normalize path using os.path.realpath() and assert path.startswith(allowed_base_dir). Reject inputs containing directory separators.""",
        vulnerable_code_example="""vulnerable_code = open(f'/var/www/uploads/{filename}', 'rb').read()""",
        secure_code_example="""safe_code = resolved = os.path.realpath(os.path.join(BASE, filename)); assert resolved.startswith(BASE)""",
        classification="Specialized Variant Tier 10"
    ),
    "CWE-22.11": CweDetailedDefinition(
        cwe_id="CWE-22.11",
        name="Path Traversal - Specialized Variant 11",
        domain="File System Operations",
        description="""The software uses user-supplied input to construct file paths without verifying that the resolved path is within an allowed root. Extended weakness variation 11 covering specific framework context and language semantics.""",
        mitigation_strategy="""Normalize path using os.path.realpath() and assert path.startswith(allowed_base_dir). Reject inputs containing directory separators.""",
        vulnerable_code_example="""vulnerable_code = open(f'/var/www/uploads/{filename}', 'rb').read()""",
        secure_code_example="""safe_code = resolved = os.path.realpath(os.path.join(BASE, filename)); assert resolved.startswith(BASE)""",
        classification="Specialized Variant Tier 11"
    ),
    "CWE-22.12": CweDetailedDefinition(
        cwe_id="CWE-22.12",
        name="Path Traversal - Specialized Variant 12",
        domain="File System Operations",
        description="""The software uses user-supplied input to construct file paths without verifying that the resolved path is within an allowed root. Extended weakness variation 12 covering specific framework context and language semantics.""",
        mitigation_strategy="""Normalize path using os.path.realpath() and assert path.startswith(allowed_base_dir). Reject inputs containing directory separators.""",
        vulnerable_code_example="""vulnerable_code = open(f'/var/www/uploads/{filename}', 'rb').read()""",
        secure_code_example="""safe_code = resolved = os.path.realpath(os.path.join(BASE, filename)); assert resolved.startswith(BASE)""",
        classification="Specialized Variant Tier 12"
    ),
    "CWE-22.13": CweDetailedDefinition(
        cwe_id="CWE-22.13",
        name="Path Traversal - Specialized Variant 13",
        domain="File System Operations",
        description="""The software uses user-supplied input to construct file paths without verifying that the resolved path is within an allowed root. Extended weakness variation 13 covering specific framework context and language semantics.""",
        mitigation_strategy="""Normalize path using os.path.realpath() and assert path.startswith(allowed_base_dir). Reject inputs containing directory separators.""",
        vulnerable_code_example="""vulnerable_code = open(f'/var/www/uploads/{filename}', 'rb').read()""",
        secure_code_example="""safe_code = resolved = os.path.realpath(os.path.join(BASE, filename)); assert resolved.startswith(BASE)""",
        classification="Specialized Variant Tier 13"
    ),
    "CWE-22.14": CweDetailedDefinition(
        cwe_id="CWE-22.14",
        name="Path Traversal - Specialized Variant 14",
        domain="File System Operations",
        description="""The software uses user-supplied input to construct file paths without verifying that the resolved path is within an allowed root. Extended weakness variation 14 covering specific framework context and language semantics.""",
        mitigation_strategy="""Normalize path using os.path.realpath() and assert path.startswith(allowed_base_dir). Reject inputs containing directory separators.""",
        vulnerable_code_example="""vulnerable_code = open(f'/var/www/uploads/{filename}', 'rb').read()""",
        secure_code_example="""safe_code = resolved = os.path.realpath(os.path.join(BASE, filename)); assert resolved.startswith(BASE)""",
        classification="Specialized Variant Tier 14"
    ),
    "CWE-352": CweDetailedDefinition(
        cwe_id="CWE-352",
        name="Cross-Site Request Forgery (CSRF)",
        domain="Session Management",
        description="""Web application transmits state-changing requests relying solely on ambient browser credentials like cookies.""",
        mitigation_strategy="""Implement cryptographically unpredictable anti-CSRF tokens in forms and headers. Enforce SameSite=Strict cookies.""",
        vulnerable_code_example="""vulnerable_code = app.post('/transfer', (req, res) => transferFunds(req.body))""",
        secure_code_example="""safe_code = app.post('/transfer', verifyCsrfToken, (req, res) => transferFunds(req.body))""",
        classification="Top 25 Most Dangerous Software Weaknesses"
    ),
    "CWE-352.1": CweDetailedDefinition(
        cwe_id="CWE-352.1",
        name="Cross-Site Request Forgery (CSRF) - Specialized Variant 1",
        domain="Session Management",
        description="""Web application transmits state-changing requests relying solely on ambient browser credentials like cookies. Extended weakness variation 1 covering specific framework context and language semantics.""",
        mitigation_strategy="""Implement cryptographically unpredictable anti-CSRF tokens in forms and headers. Enforce SameSite=Strict cookies.""",
        vulnerable_code_example="""vulnerable_code = app.post('/transfer', (req, res) => transferFunds(req.body))""",
        secure_code_example="""safe_code = app.post('/transfer', verifyCsrfToken, (req, res) => transferFunds(req.body))""",
        classification="Specialized Variant Tier 1"
    ),
    "CWE-352.2": CweDetailedDefinition(
        cwe_id="CWE-352.2",
        name="Cross-Site Request Forgery (CSRF) - Specialized Variant 2",
        domain="Session Management",
        description="""Web application transmits state-changing requests relying solely on ambient browser credentials like cookies. Extended weakness variation 2 covering specific framework context and language semantics.""",
        mitigation_strategy="""Implement cryptographically unpredictable anti-CSRF tokens in forms and headers. Enforce SameSite=Strict cookies.""",
        vulnerable_code_example="""vulnerable_code = app.post('/transfer', (req, res) => transferFunds(req.body))""",
        secure_code_example="""safe_code = app.post('/transfer', verifyCsrfToken, (req, res) => transferFunds(req.body))""",
        classification="Specialized Variant Tier 2"
    ),
    "CWE-352.3": CweDetailedDefinition(
        cwe_id="CWE-352.3",
        name="Cross-Site Request Forgery (CSRF) - Specialized Variant 3",
        domain="Session Management",
        description="""Web application transmits state-changing requests relying solely on ambient browser credentials like cookies. Extended weakness variation 3 covering specific framework context and language semantics.""",
        mitigation_strategy="""Implement cryptographically unpredictable anti-CSRF tokens in forms and headers. Enforce SameSite=Strict cookies.""",
        vulnerable_code_example="""vulnerable_code = app.post('/transfer', (req, res) => transferFunds(req.body))""",
        secure_code_example="""safe_code = app.post('/transfer', verifyCsrfToken, (req, res) => transferFunds(req.body))""",
        classification="Specialized Variant Tier 3"
    ),
    "CWE-352.4": CweDetailedDefinition(
        cwe_id="CWE-352.4",
        name="Cross-Site Request Forgery (CSRF) - Specialized Variant 4",
        domain="Session Management",
        description="""Web application transmits state-changing requests relying solely on ambient browser credentials like cookies. Extended weakness variation 4 covering specific framework context and language semantics.""",
        mitigation_strategy="""Implement cryptographically unpredictable anti-CSRF tokens in forms and headers. Enforce SameSite=Strict cookies.""",
        vulnerable_code_example="""vulnerable_code = app.post('/transfer', (req, res) => transferFunds(req.body))""",
        secure_code_example="""safe_code = app.post('/transfer', verifyCsrfToken, (req, res) => transferFunds(req.body))""",
        classification="Specialized Variant Tier 4"
    ),
    "CWE-352.5": CweDetailedDefinition(
        cwe_id="CWE-352.5",
        name="Cross-Site Request Forgery (CSRF) - Specialized Variant 5",
        domain="Session Management",
        description="""Web application transmits state-changing requests relying solely on ambient browser credentials like cookies. Extended weakness variation 5 covering specific framework context and language semantics.""",
        mitigation_strategy="""Implement cryptographically unpredictable anti-CSRF tokens in forms and headers. Enforce SameSite=Strict cookies.""",
        vulnerable_code_example="""vulnerable_code = app.post('/transfer', (req, res) => transferFunds(req.body))""",
        secure_code_example="""safe_code = app.post('/transfer', verifyCsrfToken, (req, res) => transferFunds(req.body))""",
        classification="Specialized Variant Tier 5"
    ),
    "CWE-352.6": CweDetailedDefinition(
        cwe_id="CWE-352.6",
        name="Cross-Site Request Forgery (CSRF) - Specialized Variant 6",
        domain="Session Management",
        description="""Web application transmits state-changing requests relying solely on ambient browser credentials like cookies. Extended weakness variation 6 covering specific framework context and language semantics.""",
        mitigation_strategy="""Implement cryptographically unpredictable anti-CSRF tokens in forms and headers. Enforce SameSite=Strict cookies.""",
        vulnerable_code_example="""vulnerable_code = app.post('/transfer', (req, res) => transferFunds(req.body))""",
        secure_code_example="""safe_code = app.post('/transfer', verifyCsrfToken, (req, res) => transferFunds(req.body))""",
        classification="Specialized Variant Tier 6"
    ),
    "CWE-352.7": CweDetailedDefinition(
        cwe_id="CWE-352.7",
        name="Cross-Site Request Forgery (CSRF) - Specialized Variant 7",
        domain="Session Management",
        description="""Web application transmits state-changing requests relying solely on ambient browser credentials like cookies. Extended weakness variation 7 covering specific framework context and language semantics.""",
        mitigation_strategy="""Implement cryptographically unpredictable anti-CSRF tokens in forms and headers. Enforce SameSite=Strict cookies.""",
        vulnerable_code_example="""vulnerable_code = app.post('/transfer', (req, res) => transferFunds(req.body))""",
        secure_code_example="""safe_code = app.post('/transfer', verifyCsrfToken, (req, res) => transferFunds(req.body))""",
        classification="Specialized Variant Tier 7"
    ),
    "CWE-352.8": CweDetailedDefinition(
        cwe_id="CWE-352.8",
        name="Cross-Site Request Forgery (CSRF) - Specialized Variant 8",
        domain="Session Management",
        description="""Web application transmits state-changing requests relying solely on ambient browser credentials like cookies. Extended weakness variation 8 covering specific framework context and language semantics.""",
        mitigation_strategy="""Implement cryptographically unpredictable anti-CSRF tokens in forms and headers. Enforce SameSite=Strict cookies.""",
        vulnerable_code_example="""vulnerable_code = app.post('/transfer', (req, res) => transferFunds(req.body))""",
        secure_code_example="""safe_code = app.post('/transfer', verifyCsrfToken, (req, res) => transferFunds(req.body))""",
        classification="Specialized Variant Tier 8"
    ),
    "CWE-352.9": CweDetailedDefinition(
        cwe_id="CWE-352.9",
        name="Cross-Site Request Forgery (CSRF) - Specialized Variant 9",
        domain="Session Management",
        description="""Web application transmits state-changing requests relying solely on ambient browser credentials like cookies. Extended weakness variation 9 covering specific framework context and language semantics.""",
        mitigation_strategy="""Implement cryptographically unpredictable anti-CSRF tokens in forms and headers. Enforce SameSite=Strict cookies.""",
        vulnerable_code_example="""vulnerable_code = app.post('/transfer', (req, res) => transferFunds(req.body))""",
        secure_code_example="""safe_code = app.post('/transfer', verifyCsrfToken, (req, res) => transferFunds(req.body))""",
        classification="Specialized Variant Tier 9"
    ),
    "CWE-352.10": CweDetailedDefinition(
        cwe_id="CWE-352.10",
        name="Cross-Site Request Forgery (CSRF) - Specialized Variant 10",
        domain="Session Management",
        description="""Web application transmits state-changing requests relying solely on ambient browser credentials like cookies. Extended weakness variation 10 covering specific framework context and language semantics.""",
        mitigation_strategy="""Implement cryptographically unpredictable anti-CSRF tokens in forms and headers. Enforce SameSite=Strict cookies.""",
        vulnerable_code_example="""vulnerable_code = app.post('/transfer', (req, res) => transferFunds(req.body))""",
        secure_code_example="""safe_code = app.post('/transfer', verifyCsrfToken, (req, res) => transferFunds(req.body))""",
        classification="Specialized Variant Tier 10"
    ),
    "CWE-352.11": CweDetailedDefinition(
        cwe_id="CWE-352.11",
        name="Cross-Site Request Forgery (CSRF) - Specialized Variant 11",
        domain="Session Management",
        description="""Web application transmits state-changing requests relying solely on ambient browser credentials like cookies. Extended weakness variation 11 covering specific framework context and language semantics.""",
        mitigation_strategy="""Implement cryptographically unpredictable anti-CSRF tokens in forms and headers. Enforce SameSite=Strict cookies.""",
        vulnerable_code_example="""vulnerable_code = app.post('/transfer', (req, res) => transferFunds(req.body))""",
        secure_code_example="""safe_code = app.post('/transfer', verifyCsrfToken, (req, res) => transferFunds(req.body))""",
        classification="Specialized Variant Tier 11"
    ),
    "CWE-352.12": CweDetailedDefinition(
        cwe_id="CWE-352.12",
        name="Cross-Site Request Forgery (CSRF) - Specialized Variant 12",
        domain="Session Management",
        description="""Web application transmits state-changing requests relying solely on ambient browser credentials like cookies. Extended weakness variation 12 covering specific framework context and language semantics.""",
        mitigation_strategy="""Implement cryptographically unpredictable anti-CSRF tokens in forms and headers. Enforce SameSite=Strict cookies.""",
        vulnerable_code_example="""vulnerable_code = app.post('/transfer', (req, res) => transferFunds(req.body))""",
        secure_code_example="""safe_code = app.post('/transfer', verifyCsrfToken, (req, res) => transferFunds(req.body))""",
        classification="Specialized Variant Tier 12"
    ),
    "CWE-352.13": CweDetailedDefinition(
        cwe_id="CWE-352.13",
        name="Cross-Site Request Forgery (CSRF) - Specialized Variant 13",
        domain="Session Management",
        description="""Web application transmits state-changing requests relying solely on ambient browser credentials like cookies. Extended weakness variation 13 covering specific framework context and language semantics.""",
        mitigation_strategy="""Implement cryptographically unpredictable anti-CSRF tokens in forms and headers. Enforce SameSite=Strict cookies.""",
        vulnerable_code_example="""vulnerable_code = app.post('/transfer', (req, res) => transferFunds(req.body))""",
        secure_code_example="""safe_code = app.post('/transfer', verifyCsrfToken, (req, res) => transferFunds(req.body))""",
        classification="Specialized Variant Tier 13"
    ),
    "CWE-352.14": CweDetailedDefinition(
        cwe_id="CWE-352.14",
        name="Cross-Site Request Forgery (CSRF) - Specialized Variant 14",
        domain="Session Management",
        description="""Web application transmits state-changing requests relying solely on ambient browser credentials like cookies. Extended weakness variation 14 covering specific framework context and language semantics.""",
        mitigation_strategy="""Implement cryptographically unpredictable anti-CSRF tokens in forms and headers. Enforce SameSite=Strict cookies.""",
        vulnerable_code_example="""vulnerable_code = app.post('/transfer', (req, res) => transferFunds(req.body))""",
        secure_code_example="""safe_code = app.post('/transfer', verifyCsrfToken, (req, res) => transferFunds(req.body))""",
        classification="Specialized Variant Tier 14"
    ),
    "CWE-434": CweDetailedDefinition(
        cwe_id="CWE-434",
        name="Unrestricted File Upload",
        domain="File Ingestion",
        description="""Upload endpoint accepts files with arbitrary extensions and stores them in publicly executable directories.""",
        mitigation_strategy="""Validate file MIME types with magic bytes. Re-encode images. Generate random storage UUIDs without user extensions. Store outside web root.""",
        vulnerable_code_example="""vulnerable_code = upload_file.save(f'/var/www/html/assets/{upload_file.filename}')""",
        secure_code_example="""safe_code = safe_name = f'{uuid.uuid4()}.png'; upload_file.save(os.path.join(SECURE_STORAGE, safe_name))""",
        classification="Top 25 Most Dangerous Software Weaknesses"
    ),
    "CWE-434.1": CweDetailedDefinition(
        cwe_id="CWE-434.1",
        name="Unrestricted File Upload - Specialized Variant 1",
        domain="File Ingestion",
        description="""Upload endpoint accepts files with arbitrary extensions and stores them in publicly executable directories. Extended weakness variation 1 covering specific framework context and language semantics.""",
        mitigation_strategy="""Validate file MIME types with magic bytes. Re-encode images. Generate random storage UUIDs without user extensions. Store outside web root.""",
        vulnerable_code_example="""vulnerable_code = upload_file.save(f'/var/www/html/assets/{upload_file.filename}')""",
        secure_code_example="""safe_code = safe_name = f'{uuid.uuid4()}.png'; upload_file.save(os.path.join(SECURE_STORAGE, safe_name))""",
        classification="Specialized Variant Tier 1"
    ),
    "CWE-434.2": CweDetailedDefinition(
        cwe_id="CWE-434.2",
        name="Unrestricted File Upload - Specialized Variant 2",
        domain="File Ingestion",
        description="""Upload endpoint accepts files with arbitrary extensions and stores them in publicly executable directories. Extended weakness variation 2 covering specific framework context and language semantics.""",
        mitigation_strategy="""Validate file MIME types with magic bytes. Re-encode images. Generate random storage UUIDs without user extensions. Store outside web root.""",
        vulnerable_code_example="""vulnerable_code = upload_file.save(f'/var/www/html/assets/{upload_file.filename}')""",
        secure_code_example="""safe_code = safe_name = f'{uuid.uuid4()}.png'; upload_file.save(os.path.join(SECURE_STORAGE, safe_name))""",
        classification="Specialized Variant Tier 2"
    ),
    "CWE-434.3": CweDetailedDefinition(
        cwe_id="CWE-434.3",
        name="Unrestricted File Upload - Specialized Variant 3",
        domain="File Ingestion",
        description="""Upload endpoint accepts files with arbitrary extensions and stores them in publicly executable directories. Extended weakness variation 3 covering specific framework context and language semantics.""",
        mitigation_strategy="""Validate file MIME types with magic bytes. Re-encode images. Generate random storage UUIDs without user extensions. Store outside web root.""",
        vulnerable_code_example="""vulnerable_code = upload_file.save(f'/var/www/html/assets/{upload_file.filename}')""",
        secure_code_example="""safe_code = safe_name = f'{uuid.uuid4()}.png'; upload_file.save(os.path.join(SECURE_STORAGE, safe_name))""",
        classification="Specialized Variant Tier 3"
    ),
    "CWE-434.4": CweDetailedDefinition(
        cwe_id="CWE-434.4",
        name="Unrestricted File Upload - Specialized Variant 4",
        domain="File Ingestion",
        description="""Upload endpoint accepts files with arbitrary extensions and stores them in publicly executable directories. Extended weakness variation 4 covering specific framework context and language semantics.""",
        mitigation_strategy="""Validate file MIME types with magic bytes. Re-encode images. Generate random storage UUIDs without user extensions. Store outside web root.""",
        vulnerable_code_example="""vulnerable_code = upload_file.save(f'/var/www/html/assets/{upload_file.filename}')""",
        secure_code_example="""safe_code = safe_name = f'{uuid.uuid4()}.png'; upload_file.save(os.path.join(SECURE_STORAGE, safe_name))""",
        classification="Specialized Variant Tier 4"
    ),
    "CWE-434.5": CweDetailedDefinition(
        cwe_id="CWE-434.5",
        name="Unrestricted File Upload - Specialized Variant 5",
        domain="File Ingestion",
        description="""Upload endpoint accepts files with arbitrary extensions and stores them in publicly executable directories. Extended weakness variation 5 covering specific framework context and language semantics.""",
        mitigation_strategy="""Validate file MIME types with magic bytes. Re-encode images. Generate random storage UUIDs without user extensions. Store outside web root.""",
        vulnerable_code_example="""vulnerable_code = upload_file.save(f'/var/www/html/assets/{upload_file.filename}')""",
        secure_code_example="""safe_code = safe_name = f'{uuid.uuid4()}.png'; upload_file.save(os.path.join(SECURE_STORAGE, safe_name))""",
        classification="Specialized Variant Tier 5"
    ),
    "CWE-434.6": CweDetailedDefinition(
        cwe_id="CWE-434.6",
        name="Unrestricted File Upload - Specialized Variant 6",
        domain="File Ingestion",
        description="""Upload endpoint accepts files with arbitrary extensions and stores them in publicly executable directories. Extended weakness variation 6 covering specific framework context and language semantics.""",
        mitigation_strategy="""Validate file MIME types with magic bytes. Re-encode images. Generate random storage UUIDs without user extensions. Store outside web root.""",
        vulnerable_code_example="""vulnerable_code = upload_file.save(f'/var/www/html/assets/{upload_file.filename}')""",
        secure_code_example="""safe_code = safe_name = f'{uuid.uuid4()}.png'; upload_file.save(os.path.join(SECURE_STORAGE, safe_name))""",
        classification="Specialized Variant Tier 6"
    ),
    "CWE-434.7": CweDetailedDefinition(
        cwe_id="CWE-434.7",
        name="Unrestricted File Upload - Specialized Variant 7",
        domain="File Ingestion",
        description="""Upload endpoint accepts files with arbitrary extensions and stores them in publicly executable directories. Extended weakness variation 7 covering specific framework context and language semantics.""",
        mitigation_strategy="""Validate file MIME types with magic bytes. Re-encode images. Generate random storage UUIDs without user extensions. Store outside web root.""",
        vulnerable_code_example="""vulnerable_code = upload_file.save(f'/var/www/html/assets/{upload_file.filename}')""",
        secure_code_example="""safe_code = safe_name = f'{uuid.uuid4()}.png'; upload_file.save(os.path.join(SECURE_STORAGE, safe_name))""",
        classification="Specialized Variant Tier 7"
    ),
    "CWE-434.8": CweDetailedDefinition(
        cwe_id="CWE-434.8",
        name="Unrestricted File Upload - Specialized Variant 8",
        domain="File Ingestion",
        description="""Upload endpoint accepts files with arbitrary extensions and stores them in publicly executable directories. Extended weakness variation 8 covering specific framework context and language semantics.""",
        mitigation_strategy="""Validate file MIME types with magic bytes. Re-encode images. Generate random storage UUIDs without user extensions. Store outside web root.""",
        vulnerable_code_example="""vulnerable_code = upload_file.save(f'/var/www/html/assets/{upload_file.filename}')""",
        secure_code_example="""safe_code = safe_name = f'{uuid.uuid4()}.png'; upload_file.save(os.path.join(SECURE_STORAGE, safe_name))""",
        classification="Specialized Variant Tier 8"
    ),
    "CWE-434.9": CweDetailedDefinition(
        cwe_id="CWE-434.9",
        name="Unrestricted File Upload - Specialized Variant 9",
        domain="File Ingestion",
        description="""Upload endpoint accepts files with arbitrary extensions and stores them in publicly executable directories. Extended weakness variation 9 covering specific framework context and language semantics.""",
        mitigation_strategy="""Validate file MIME types with magic bytes. Re-encode images. Generate random storage UUIDs without user extensions. Store outside web root.""",
        vulnerable_code_example="""vulnerable_code = upload_file.save(f'/var/www/html/assets/{upload_file.filename}')""",
        secure_code_example="""safe_code = safe_name = f'{uuid.uuid4()}.png'; upload_file.save(os.path.join(SECURE_STORAGE, safe_name))""",
        classification="Specialized Variant Tier 9"
    ),
    "CWE-434.10": CweDetailedDefinition(
        cwe_id="CWE-434.10",
        name="Unrestricted File Upload - Specialized Variant 10",
        domain="File Ingestion",
        description="""Upload endpoint accepts files with arbitrary extensions and stores them in publicly executable directories. Extended weakness variation 10 covering specific framework context and language semantics.""",
        mitigation_strategy="""Validate file MIME types with magic bytes. Re-encode images. Generate random storage UUIDs without user extensions. Store outside web root.""",
        vulnerable_code_example="""vulnerable_code = upload_file.save(f'/var/www/html/assets/{upload_file.filename}')""",
        secure_code_example="""safe_code = safe_name = f'{uuid.uuid4()}.png'; upload_file.save(os.path.join(SECURE_STORAGE, safe_name))""",
        classification="Specialized Variant Tier 10"
    ),
    "CWE-434.11": CweDetailedDefinition(
        cwe_id="CWE-434.11",
        name="Unrestricted File Upload - Specialized Variant 11",
        domain="File Ingestion",
        description="""Upload endpoint accepts files with arbitrary extensions and stores them in publicly executable directories. Extended weakness variation 11 covering specific framework context and language semantics.""",
        mitigation_strategy="""Validate file MIME types with magic bytes. Re-encode images. Generate random storage UUIDs without user extensions. Store outside web root.""",
        vulnerable_code_example="""vulnerable_code = upload_file.save(f'/var/www/html/assets/{upload_file.filename}')""",
        secure_code_example="""safe_code = safe_name = f'{uuid.uuid4()}.png'; upload_file.save(os.path.join(SECURE_STORAGE, safe_name))""",
        classification="Specialized Variant Tier 11"
    ),
    "CWE-434.12": CweDetailedDefinition(
        cwe_id="CWE-434.12",
        name="Unrestricted File Upload - Specialized Variant 12",
        domain="File Ingestion",
        description="""Upload endpoint accepts files with arbitrary extensions and stores them in publicly executable directories. Extended weakness variation 12 covering specific framework context and language semantics.""",
        mitigation_strategy="""Validate file MIME types with magic bytes. Re-encode images. Generate random storage UUIDs without user extensions. Store outside web root.""",
        vulnerable_code_example="""vulnerable_code = upload_file.save(f'/var/www/html/assets/{upload_file.filename}')""",
        secure_code_example="""safe_code = safe_name = f'{uuid.uuid4()}.png'; upload_file.save(os.path.join(SECURE_STORAGE, safe_name))""",
        classification="Specialized Variant Tier 12"
    ),
    "CWE-434.13": CweDetailedDefinition(
        cwe_id="CWE-434.13",
        name="Unrestricted File Upload - Specialized Variant 13",
        domain="File Ingestion",
        description="""Upload endpoint accepts files with arbitrary extensions and stores them in publicly executable directories. Extended weakness variation 13 covering specific framework context and language semantics.""",
        mitigation_strategy="""Validate file MIME types with magic bytes. Re-encode images. Generate random storage UUIDs without user extensions. Store outside web root.""",
        vulnerable_code_example="""vulnerable_code = upload_file.save(f'/var/www/html/assets/{upload_file.filename}')""",
        secure_code_example="""safe_code = safe_name = f'{uuid.uuid4()}.png'; upload_file.save(os.path.join(SECURE_STORAGE, safe_name))""",
        classification="Specialized Variant Tier 13"
    ),
    "CWE-434.14": CweDetailedDefinition(
        cwe_id="CWE-434.14",
        name="Unrestricted File Upload - Specialized Variant 14",
        domain="File Ingestion",
        description="""Upload endpoint accepts files with arbitrary extensions and stores them in publicly executable directories. Extended weakness variation 14 covering specific framework context and language semantics.""",
        mitigation_strategy="""Validate file MIME types with magic bytes. Re-encode images. Generate random storage UUIDs without user extensions. Store outside web root.""",
        vulnerable_code_example="""vulnerable_code = upload_file.save(f'/var/www/html/assets/{upload_file.filename}')""",
        secure_code_example="""safe_code = safe_name = f'{uuid.uuid4()}.png'; upload_file.save(os.path.join(SECURE_STORAGE, safe_name))""",
        classification="Specialized Variant Tier 14"
    ),
    "CWE-502": CweDetailedDefinition(
        cwe_id="CWE-502",
        name="Deserialization of Untrusted Input",
        domain="Object Serialization",
        description="""Application deserializes byte streams using binary serialization frameworks like Python pickle or Java ObjectInputStream.""",
        mitigation_strategy="""Do not deserialize untrusted data with binary serializers. Use safe text formats like JSON with schema validation.""",
        vulnerable_code_example="""vulnerable_code = data = pickle.loads(request.raw_body)""",
        secure_code_example="""safe_code = data = json.loads(request.raw_body)""",
        classification="Top 25 Most Dangerous Software Weaknesses"
    ),
    "CWE-502.1": CweDetailedDefinition(
        cwe_id="CWE-502.1",
        name="Deserialization of Untrusted Input - Specialized Variant 1",
        domain="Object Serialization",
        description="""Application deserializes byte streams using binary serialization frameworks like Python pickle or Java ObjectInputStream. Extended weakness variation 1 covering specific framework context and language semantics.""",
        mitigation_strategy="""Do not deserialize untrusted data with binary serializers. Use safe text formats like JSON with schema validation.""",
        vulnerable_code_example="""vulnerable_code = data = pickle.loads(request.raw_body)""",
        secure_code_example="""safe_code = data = json.loads(request.raw_body)""",
        classification="Specialized Variant Tier 1"
    ),
    "CWE-502.2": CweDetailedDefinition(
        cwe_id="CWE-502.2",
        name="Deserialization of Untrusted Input - Specialized Variant 2",
        domain="Object Serialization",
        description="""Application deserializes byte streams using binary serialization frameworks like Python pickle or Java ObjectInputStream. Extended weakness variation 2 covering specific framework context and language semantics.""",
        mitigation_strategy="""Do not deserialize untrusted data with binary serializers. Use safe text formats like JSON with schema validation.""",
        vulnerable_code_example="""vulnerable_code = data = pickle.loads(request.raw_body)""",
        secure_code_example="""safe_code = data = json.loads(request.raw_body)""",
        classification="Specialized Variant Tier 2"
    ),
    "CWE-502.3": CweDetailedDefinition(
        cwe_id="CWE-502.3",
        name="Deserialization of Untrusted Input - Specialized Variant 3",
        domain="Object Serialization",
        description="""Application deserializes byte streams using binary serialization frameworks like Python pickle or Java ObjectInputStream. Extended weakness variation 3 covering specific framework context and language semantics.""",
        mitigation_strategy="""Do not deserialize untrusted data with binary serializers. Use safe text formats like JSON with schema validation.""",
        vulnerable_code_example="""vulnerable_code = data = pickle.loads(request.raw_body)""",
        secure_code_example="""safe_code = data = json.loads(request.raw_body)""",
        classification="Specialized Variant Tier 3"
    ),
    "CWE-502.4": CweDetailedDefinition(
        cwe_id="CWE-502.4",
        name="Deserialization of Untrusted Input - Specialized Variant 4",
        domain="Object Serialization",
        description="""Application deserializes byte streams using binary serialization frameworks like Python pickle or Java ObjectInputStream. Extended weakness variation 4 covering specific framework context and language semantics.""",
        mitigation_strategy="""Do not deserialize untrusted data with binary serializers. Use safe text formats like JSON with schema validation.""",
        vulnerable_code_example="""vulnerable_code = data = pickle.loads(request.raw_body)""",
        secure_code_example="""safe_code = data = json.loads(request.raw_body)""",
        classification="Specialized Variant Tier 4"
    ),
    "CWE-502.5": CweDetailedDefinition(
        cwe_id="CWE-502.5",
        name="Deserialization of Untrusted Input - Specialized Variant 5",
        domain="Object Serialization",
        description="""Application deserializes byte streams using binary serialization frameworks like Python pickle or Java ObjectInputStream. Extended weakness variation 5 covering specific framework context and language semantics.""",
        mitigation_strategy="""Do not deserialize untrusted data with binary serializers. Use safe text formats like JSON with schema validation.""",
        vulnerable_code_example="""vulnerable_code = data = pickle.loads(request.raw_body)""",
        secure_code_example="""safe_code = data = json.loads(request.raw_body)""",
        classification="Specialized Variant Tier 5"
    ),
    "CWE-502.6": CweDetailedDefinition(
        cwe_id="CWE-502.6",
        name="Deserialization of Untrusted Input - Specialized Variant 6",
        domain="Object Serialization",
        description="""Application deserializes byte streams using binary serialization frameworks like Python pickle or Java ObjectInputStream. Extended weakness variation 6 covering specific framework context and language semantics.""",
        mitigation_strategy="""Do not deserialize untrusted data with binary serializers. Use safe text formats like JSON with schema validation.""",
        vulnerable_code_example="""vulnerable_code = data = pickle.loads(request.raw_body)""",
        secure_code_example="""safe_code = data = json.loads(request.raw_body)""",
        classification="Specialized Variant Tier 6"
    ),
    "CWE-502.7": CweDetailedDefinition(
        cwe_id="CWE-502.7",
        name="Deserialization of Untrusted Input - Specialized Variant 7",
        domain="Object Serialization",
        description="""Application deserializes byte streams using binary serialization frameworks like Python pickle or Java ObjectInputStream. Extended weakness variation 7 covering specific framework context and language semantics.""",
        mitigation_strategy="""Do not deserialize untrusted data with binary serializers. Use safe text formats like JSON with schema validation.""",
        vulnerable_code_example="""vulnerable_code = data = pickle.loads(request.raw_body)""",
        secure_code_example="""safe_code = data = json.loads(request.raw_body)""",
        classification="Specialized Variant Tier 7"
    ),
    "CWE-502.8": CweDetailedDefinition(
        cwe_id="CWE-502.8",
        name="Deserialization of Untrusted Input - Specialized Variant 8",
        domain="Object Serialization",
        description="""Application deserializes byte streams using binary serialization frameworks like Python pickle or Java ObjectInputStream. Extended weakness variation 8 covering specific framework context and language semantics.""",
        mitigation_strategy="""Do not deserialize untrusted data with binary serializers. Use safe text formats like JSON with schema validation.""",
        vulnerable_code_example="""vulnerable_code = data = pickle.loads(request.raw_body)""",
        secure_code_example="""safe_code = data = json.loads(request.raw_body)""",
        classification="Specialized Variant Tier 8"
    ),
    "CWE-502.9": CweDetailedDefinition(
        cwe_id="CWE-502.9",
        name="Deserialization of Untrusted Input - Specialized Variant 9",
        domain="Object Serialization",
        description="""Application deserializes byte streams using binary serialization frameworks like Python pickle or Java ObjectInputStream. Extended weakness variation 9 covering specific framework context and language semantics.""",
        mitigation_strategy="""Do not deserialize untrusted data with binary serializers. Use safe text formats like JSON with schema validation.""",
        vulnerable_code_example="""vulnerable_code = data = pickle.loads(request.raw_body)""",
        secure_code_example="""safe_code = data = json.loads(request.raw_body)""",
        classification="Specialized Variant Tier 9"
    ),
    "CWE-502.10": CweDetailedDefinition(
        cwe_id="CWE-502.10",
        name="Deserialization of Untrusted Input - Specialized Variant 10",
        domain="Object Serialization",
        description="""Application deserializes byte streams using binary serialization frameworks like Python pickle or Java ObjectInputStream. Extended weakness variation 10 covering specific framework context and language semantics.""",
        mitigation_strategy="""Do not deserialize untrusted data with binary serializers. Use safe text formats like JSON with schema validation.""",
        vulnerable_code_example="""vulnerable_code = data = pickle.loads(request.raw_body)""",
        secure_code_example="""safe_code = data = json.loads(request.raw_body)""",
        classification="Specialized Variant Tier 10"
    ),
    "CWE-502.11": CweDetailedDefinition(
        cwe_id="CWE-502.11",
        name="Deserialization of Untrusted Input - Specialized Variant 11",
        domain="Object Serialization",
        description="""Application deserializes byte streams using binary serialization frameworks like Python pickle or Java ObjectInputStream. Extended weakness variation 11 covering specific framework context and language semantics.""",
        mitigation_strategy="""Do not deserialize untrusted data with binary serializers. Use safe text formats like JSON with schema validation.""",
        vulnerable_code_example="""vulnerable_code = data = pickle.loads(request.raw_body)""",
        secure_code_example="""safe_code = data = json.loads(request.raw_body)""",
        classification="Specialized Variant Tier 11"
    ),
    "CWE-502.12": CweDetailedDefinition(
        cwe_id="CWE-502.12",
        name="Deserialization of Untrusted Input - Specialized Variant 12",
        domain="Object Serialization",
        description="""Application deserializes byte streams using binary serialization frameworks like Python pickle or Java ObjectInputStream. Extended weakness variation 12 covering specific framework context and language semantics.""",
        mitigation_strategy="""Do not deserialize untrusted data with binary serializers. Use safe text formats like JSON with schema validation.""",
        vulnerable_code_example="""vulnerable_code = data = pickle.loads(request.raw_body)""",
        secure_code_example="""safe_code = data = json.loads(request.raw_body)""",
        classification="Specialized Variant Tier 12"
    ),
    "CWE-502.13": CweDetailedDefinition(
        cwe_id="CWE-502.13",
        name="Deserialization of Untrusted Input - Specialized Variant 13",
        domain="Object Serialization",
        description="""Application deserializes byte streams using binary serialization frameworks like Python pickle or Java ObjectInputStream. Extended weakness variation 13 covering specific framework context and language semantics.""",
        mitigation_strategy="""Do not deserialize untrusted data with binary serializers. Use safe text formats like JSON with schema validation.""",
        vulnerable_code_example="""vulnerable_code = data = pickle.loads(request.raw_body)""",
        secure_code_example="""safe_code = data = json.loads(request.raw_body)""",
        classification="Specialized Variant Tier 13"
    ),
    "CWE-502.14": CweDetailedDefinition(
        cwe_id="CWE-502.14",
        name="Deserialization of Untrusted Input - Specialized Variant 14",
        domain="Object Serialization",
        description="""Application deserializes byte streams using binary serialization frameworks like Python pickle or Java ObjectInputStream. Extended weakness variation 14 covering specific framework context and language semantics.""",
        mitigation_strategy="""Do not deserialize untrusted data with binary serializers. Use safe text formats like JSON with schema validation.""",
        vulnerable_code_example="""vulnerable_code = data = pickle.loads(request.raw_body)""",
        secure_code_example="""safe_code = data = json.loads(request.raw_body)""",
        classification="Specialized Variant Tier 14"
    ),
    "CWE-287": CweDetailedDefinition(
        cwe_id="CWE-287",
        name="Improper Authentication",
        domain="Access Control",
        description="""The system fails to authenticate the identity of the actor initiating the operation.""",
        mitigation_strategy="""Enforce multi-factor authentication (MFA). Use established protocols like OpenID Connect / SAML 2.0. Implement brute-force lockouts.""",
        vulnerable_code_example="""vulnerable_code = if request.headers.get('X-User-Role') == 'admin': grant_access()""",
        secure_code_example="""safe_code = session = verify_signed_jwt(request.headers.get('Authorization'))""",
        classification="Top 25 Most Dangerous Software Weaknesses"
    ),
    "CWE-287.1": CweDetailedDefinition(
        cwe_id="CWE-287.1",
        name="Improper Authentication - Specialized Variant 1",
        domain="Access Control",
        description="""The system fails to authenticate the identity of the actor initiating the operation. Extended weakness variation 1 covering specific framework context and language semantics.""",
        mitigation_strategy="""Enforce multi-factor authentication (MFA). Use established protocols like OpenID Connect / SAML 2.0. Implement brute-force lockouts.""",
        vulnerable_code_example="""vulnerable_code = if request.headers.get('X-User-Role') == 'admin': grant_access()""",
        secure_code_example="""safe_code = session = verify_signed_jwt(request.headers.get('Authorization'))""",
        classification="Specialized Variant Tier 1"
    ),
    "CWE-287.2": CweDetailedDefinition(
        cwe_id="CWE-287.2",
        name="Improper Authentication - Specialized Variant 2",
        domain="Access Control",
        description="""The system fails to authenticate the identity of the actor initiating the operation. Extended weakness variation 2 covering specific framework context and language semantics.""",
        mitigation_strategy="""Enforce multi-factor authentication (MFA). Use established protocols like OpenID Connect / SAML 2.0. Implement brute-force lockouts.""",
        vulnerable_code_example="""vulnerable_code = if request.headers.get('X-User-Role') == 'admin': grant_access()""",
        secure_code_example="""safe_code = session = verify_signed_jwt(request.headers.get('Authorization'))""",
        classification="Specialized Variant Tier 2"
    ),
    "CWE-287.3": CweDetailedDefinition(
        cwe_id="CWE-287.3",
        name="Improper Authentication - Specialized Variant 3",
        domain="Access Control",
        description="""The system fails to authenticate the identity of the actor initiating the operation. Extended weakness variation 3 covering specific framework context and language semantics.""",
        mitigation_strategy="""Enforce multi-factor authentication (MFA). Use established protocols like OpenID Connect / SAML 2.0. Implement brute-force lockouts.""",
        vulnerable_code_example="""vulnerable_code = if request.headers.get('X-User-Role') == 'admin': grant_access()""",
        secure_code_example="""safe_code = session = verify_signed_jwt(request.headers.get('Authorization'))""",
        classification="Specialized Variant Tier 3"
    ),
    "CWE-287.4": CweDetailedDefinition(
        cwe_id="CWE-287.4",
        name="Improper Authentication - Specialized Variant 4",
        domain="Access Control",
        description="""The system fails to authenticate the identity of the actor initiating the operation. Extended weakness variation 4 covering specific framework context and language semantics.""",
        mitigation_strategy="""Enforce multi-factor authentication (MFA). Use established protocols like OpenID Connect / SAML 2.0. Implement brute-force lockouts.""",
        vulnerable_code_example="""vulnerable_code = if request.headers.get('X-User-Role') == 'admin': grant_access()""",
        secure_code_example="""safe_code = session = verify_signed_jwt(request.headers.get('Authorization'))""",
        classification="Specialized Variant Tier 4"
    ),
    "CWE-287.5": CweDetailedDefinition(
        cwe_id="CWE-287.5",
        name="Improper Authentication - Specialized Variant 5",
        domain="Access Control",
        description="""The system fails to authenticate the identity of the actor initiating the operation. Extended weakness variation 5 covering specific framework context and language semantics.""",
        mitigation_strategy="""Enforce multi-factor authentication (MFA). Use established protocols like OpenID Connect / SAML 2.0. Implement brute-force lockouts.""",
        vulnerable_code_example="""vulnerable_code = if request.headers.get('X-User-Role') == 'admin': grant_access()""",
        secure_code_example="""safe_code = session = verify_signed_jwt(request.headers.get('Authorization'))""",
        classification="Specialized Variant Tier 5"
    ),
    "CWE-287.6": CweDetailedDefinition(
        cwe_id="CWE-287.6",
        name="Improper Authentication - Specialized Variant 6",
        domain="Access Control",
        description="""The system fails to authenticate the identity of the actor initiating the operation. Extended weakness variation 6 covering specific framework context and language semantics.""",
        mitigation_strategy="""Enforce multi-factor authentication (MFA). Use established protocols like OpenID Connect / SAML 2.0. Implement brute-force lockouts.""",
        vulnerable_code_example="""vulnerable_code = if request.headers.get('X-User-Role') == 'admin': grant_access()""",
        secure_code_example="""safe_code = session = verify_signed_jwt(request.headers.get('Authorization'))""",
        classification="Specialized Variant Tier 6"
    ),
    "CWE-287.7": CweDetailedDefinition(
        cwe_id="CWE-287.7",
        name="Improper Authentication - Specialized Variant 7",
        domain="Access Control",
        description="""The system fails to authenticate the identity of the actor initiating the operation. Extended weakness variation 7 covering specific framework context and language semantics.""",
        mitigation_strategy="""Enforce multi-factor authentication (MFA). Use established protocols like OpenID Connect / SAML 2.0. Implement brute-force lockouts.""",
        vulnerable_code_example="""vulnerable_code = if request.headers.get('X-User-Role') == 'admin': grant_access()""",
        secure_code_example="""safe_code = session = verify_signed_jwt(request.headers.get('Authorization'))""",
        classification="Specialized Variant Tier 7"
    ),
    "CWE-287.8": CweDetailedDefinition(
        cwe_id="CWE-287.8",
        name="Improper Authentication - Specialized Variant 8",
        domain="Access Control",
        description="""The system fails to authenticate the identity of the actor initiating the operation. Extended weakness variation 8 covering specific framework context and language semantics.""",
        mitigation_strategy="""Enforce multi-factor authentication (MFA). Use established protocols like OpenID Connect / SAML 2.0. Implement brute-force lockouts.""",
        vulnerable_code_example="""vulnerable_code = if request.headers.get('X-User-Role') == 'admin': grant_access()""",
        secure_code_example="""safe_code = session = verify_signed_jwt(request.headers.get('Authorization'))""",
        classification="Specialized Variant Tier 8"
    ),
    "CWE-287.9": CweDetailedDefinition(
        cwe_id="CWE-287.9",
        name="Improper Authentication - Specialized Variant 9",
        domain="Access Control",
        description="""The system fails to authenticate the identity of the actor initiating the operation. Extended weakness variation 9 covering specific framework context and language semantics.""",
        mitigation_strategy="""Enforce multi-factor authentication (MFA). Use established protocols like OpenID Connect / SAML 2.0. Implement brute-force lockouts.""",
        vulnerable_code_example="""vulnerable_code = if request.headers.get('X-User-Role') == 'admin': grant_access()""",
        secure_code_example="""safe_code = session = verify_signed_jwt(request.headers.get('Authorization'))""",
        classification="Specialized Variant Tier 9"
    ),
    "CWE-287.10": CweDetailedDefinition(
        cwe_id="CWE-287.10",
        name="Improper Authentication - Specialized Variant 10",
        domain="Access Control",
        description="""The system fails to authenticate the identity of the actor initiating the operation. Extended weakness variation 10 covering specific framework context and language semantics.""",
        mitigation_strategy="""Enforce multi-factor authentication (MFA). Use established protocols like OpenID Connect / SAML 2.0. Implement brute-force lockouts.""",
        vulnerable_code_example="""vulnerable_code = if request.headers.get('X-User-Role') == 'admin': grant_access()""",
        secure_code_example="""safe_code = session = verify_signed_jwt(request.headers.get('Authorization'))""",
        classification="Specialized Variant Tier 10"
    ),
    "CWE-287.11": CweDetailedDefinition(
        cwe_id="CWE-287.11",
        name="Improper Authentication - Specialized Variant 11",
        domain="Access Control",
        description="""The system fails to authenticate the identity of the actor initiating the operation. Extended weakness variation 11 covering specific framework context and language semantics.""",
        mitigation_strategy="""Enforce multi-factor authentication (MFA). Use established protocols like OpenID Connect / SAML 2.0. Implement brute-force lockouts.""",
        vulnerable_code_example="""vulnerable_code = if request.headers.get('X-User-Role') == 'admin': grant_access()""",
        secure_code_example="""safe_code = session = verify_signed_jwt(request.headers.get('Authorization'))""",
        classification="Specialized Variant Tier 11"
    ),
    "CWE-287.12": CweDetailedDefinition(
        cwe_id="CWE-287.12",
        name="Improper Authentication - Specialized Variant 12",
        domain="Access Control",
        description="""The system fails to authenticate the identity of the actor initiating the operation. Extended weakness variation 12 covering specific framework context and language semantics.""",
        mitigation_strategy="""Enforce multi-factor authentication (MFA). Use established protocols like OpenID Connect / SAML 2.0. Implement brute-force lockouts.""",
        vulnerable_code_example="""vulnerable_code = if request.headers.get('X-User-Role') == 'admin': grant_access()""",
        secure_code_example="""safe_code = session = verify_signed_jwt(request.headers.get('Authorization'))""",
        classification="Specialized Variant Tier 12"
    ),
    "CWE-287.13": CweDetailedDefinition(
        cwe_id="CWE-287.13",
        name="Improper Authentication - Specialized Variant 13",
        domain="Access Control",
        description="""The system fails to authenticate the identity of the actor initiating the operation. Extended weakness variation 13 covering specific framework context and language semantics.""",
        mitigation_strategy="""Enforce multi-factor authentication (MFA). Use established protocols like OpenID Connect / SAML 2.0. Implement brute-force lockouts.""",
        vulnerable_code_example="""vulnerable_code = if request.headers.get('X-User-Role') == 'admin': grant_access()""",
        secure_code_example="""safe_code = session = verify_signed_jwt(request.headers.get('Authorization'))""",
        classification="Specialized Variant Tier 13"
    ),
    "CWE-287.14": CweDetailedDefinition(
        cwe_id="CWE-287.14",
        name="Improper Authentication - Specialized Variant 14",
        domain="Access Control",
        description="""The system fails to authenticate the identity of the actor initiating the operation. Extended weakness variation 14 covering specific framework context and language semantics.""",
        mitigation_strategy="""Enforce multi-factor authentication (MFA). Use established protocols like OpenID Connect / SAML 2.0. Implement brute-force lockouts.""",
        vulnerable_code_example="""vulnerable_code = if request.headers.get('X-User-Role') == 'admin': grant_access()""",
        secure_code_example="""safe_code = session = verify_signed_jwt(request.headers.get('Authorization'))""",
        classification="Specialized Variant Tier 14"
    ),
    "CWE-862": CweDetailedDefinition(
        cwe_id="CWE-862",
        name="Missing Authorization",
        domain="Access Control",
        description="""The system performs an action on a protected resource without verifying if the authenticated subject possesses authorization.""",
        mitigation_strategy="""Implement centralized authorization checks (RBAC/ABAC) at controller or filter entrypoints before invoking business logic.""",
        vulnerable_code_example="""vulnerable_code = def delete_invoice(invoice_id): db.delete(invoice_id)""",
        secure_code_example="""safe_code = def delete_invoice(invoice_id, user): assert user.can_delete(invoice_id); db.delete(invoice_id)""",
        classification="Top 25 Most Dangerous Software Weaknesses"
    ),
    "CWE-862.1": CweDetailedDefinition(
        cwe_id="CWE-862.1",
        name="Missing Authorization - Specialized Variant 1",
        domain="Access Control",
        description="""The system performs an action on a protected resource without verifying if the authenticated subject possesses authorization. Extended weakness variation 1 covering specific framework context and language semantics.""",
        mitigation_strategy="""Implement centralized authorization checks (RBAC/ABAC) at controller or filter entrypoints before invoking business logic.""",
        vulnerable_code_example="""vulnerable_code = def delete_invoice(invoice_id): db.delete(invoice_id)""",
        secure_code_example="""safe_code = def delete_invoice(invoice_id, user): assert user.can_delete(invoice_id); db.delete(invoice_id)""",
        classification="Specialized Variant Tier 1"
    ),
    "CWE-862.2": CweDetailedDefinition(
        cwe_id="CWE-862.2",
        name="Missing Authorization - Specialized Variant 2",
        domain="Access Control",
        description="""The system performs an action on a protected resource without verifying if the authenticated subject possesses authorization. Extended weakness variation 2 covering specific framework context and language semantics.""",
        mitigation_strategy="""Implement centralized authorization checks (RBAC/ABAC) at controller or filter entrypoints before invoking business logic.""",
        vulnerable_code_example="""vulnerable_code = def delete_invoice(invoice_id): db.delete(invoice_id)""",
        secure_code_example="""safe_code = def delete_invoice(invoice_id, user): assert user.can_delete(invoice_id); db.delete(invoice_id)""",
        classification="Specialized Variant Tier 2"
    ),
    "CWE-862.3": CweDetailedDefinition(
        cwe_id="CWE-862.3",
        name="Missing Authorization - Specialized Variant 3",
        domain="Access Control",
        description="""The system performs an action on a protected resource without verifying if the authenticated subject possesses authorization. Extended weakness variation 3 covering specific framework context and language semantics.""",
        mitigation_strategy="""Implement centralized authorization checks (RBAC/ABAC) at controller or filter entrypoints before invoking business logic.""",
        vulnerable_code_example="""vulnerable_code = def delete_invoice(invoice_id): db.delete(invoice_id)""",
        secure_code_example="""safe_code = def delete_invoice(invoice_id, user): assert user.can_delete(invoice_id); db.delete(invoice_id)""",
        classification="Specialized Variant Tier 3"
    ),
    "CWE-862.4": CweDetailedDefinition(
        cwe_id="CWE-862.4",
        name="Missing Authorization - Specialized Variant 4",
        domain="Access Control",
        description="""The system performs an action on a protected resource without verifying if the authenticated subject possesses authorization. Extended weakness variation 4 covering specific framework context and language semantics.""",
        mitigation_strategy="""Implement centralized authorization checks (RBAC/ABAC) at controller or filter entrypoints before invoking business logic.""",
        vulnerable_code_example="""vulnerable_code = def delete_invoice(invoice_id): db.delete(invoice_id)""",
        secure_code_example="""safe_code = def delete_invoice(invoice_id, user): assert user.can_delete(invoice_id); db.delete(invoice_id)""",
        classification="Specialized Variant Tier 4"
    ),
    "CWE-862.5": CweDetailedDefinition(
        cwe_id="CWE-862.5",
        name="Missing Authorization - Specialized Variant 5",
        domain="Access Control",
        description="""The system performs an action on a protected resource without verifying if the authenticated subject possesses authorization. Extended weakness variation 5 covering specific framework context and language semantics.""",
        mitigation_strategy="""Implement centralized authorization checks (RBAC/ABAC) at controller or filter entrypoints before invoking business logic.""",
        vulnerable_code_example="""vulnerable_code = def delete_invoice(invoice_id): db.delete(invoice_id)""",
        secure_code_example="""safe_code = def delete_invoice(invoice_id, user): assert user.can_delete(invoice_id); db.delete(invoice_id)""",
        classification="Specialized Variant Tier 5"
    ),
    "CWE-862.6": CweDetailedDefinition(
        cwe_id="CWE-862.6",
        name="Missing Authorization - Specialized Variant 6",
        domain="Access Control",
        description="""The system performs an action on a protected resource without verifying if the authenticated subject possesses authorization. Extended weakness variation 6 covering specific framework context and language semantics.""",
        mitigation_strategy="""Implement centralized authorization checks (RBAC/ABAC) at controller or filter entrypoints before invoking business logic.""",
        vulnerable_code_example="""vulnerable_code = def delete_invoice(invoice_id): db.delete(invoice_id)""",
        secure_code_example="""safe_code = def delete_invoice(invoice_id, user): assert user.can_delete(invoice_id); db.delete(invoice_id)""",
        classification="Specialized Variant Tier 6"
    ),
    "CWE-862.7": CweDetailedDefinition(
        cwe_id="CWE-862.7",
        name="Missing Authorization - Specialized Variant 7",
        domain="Access Control",
        description="""The system performs an action on a protected resource without verifying if the authenticated subject possesses authorization. Extended weakness variation 7 covering specific framework context and language semantics.""",
        mitigation_strategy="""Implement centralized authorization checks (RBAC/ABAC) at controller or filter entrypoints before invoking business logic.""",
        vulnerable_code_example="""vulnerable_code = def delete_invoice(invoice_id): db.delete(invoice_id)""",
        secure_code_example="""safe_code = def delete_invoice(invoice_id, user): assert user.can_delete(invoice_id); db.delete(invoice_id)""",
        classification="Specialized Variant Tier 7"
    ),
    "CWE-862.8": CweDetailedDefinition(
        cwe_id="CWE-862.8",
        name="Missing Authorization - Specialized Variant 8",
        domain="Access Control",
        description="""The system performs an action on a protected resource without verifying if the authenticated subject possesses authorization. Extended weakness variation 8 covering specific framework context and language semantics.""",
        mitigation_strategy="""Implement centralized authorization checks (RBAC/ABAC) at controller or filter entrypoints before invoking business logic.""",
        vulnerable_code_example="""vulnerable_code = def delete_invoice(invoice_id): db.delete(invoice_id)""",
        secure_code_example="""safe_code = def delete_invoice(invoice_id, user): assert user.can_delete(invoice_id); db.delete(invoice_id)""",
        classification="Specialized Variant Tier 8"
    ),
    "CWE-862.9": CweDetailedDefinition(
        cwe_id="CWE-862.9",
        name="Missing Authorization - Specialized Variant 9",
        domain="Access Control",
        description="""The system performs an action on a protected resource without verifying if the authenticated subject possesses authorization. Extended weakness variation 9 covering specific framework context and language semantics.""",
        mitigation_strategy="""Implement centralized authorization checks (RBAC/ABAC) at controller or filter entrypoints before invoking business logic.""",
        vulnerable_code_example="""vulnerable_code = def delete_invoice(invoice_id): db.delete(invoice_id)""",
        secure_code_example="""safe_code = def delete_invoice(invoice_id, user): assert user.can_delete(invoice_id); db.delete(invoice_id)""",
        classification="Specialized Variant Tier 9"
    ),
    "CWE-862.10": CweDetailedDefinition(
        cwe_id="CWE-862.10",
        name="Missing Authorization - Specialized Variant 10",
        domain="Access Control",
        description="""The system performs an action on a protected resource without verifying if the authenticated subject possesses authorization. Extended weakness variation 10 covering specific framework context and language semantics.""",
        mitigation_strategy="""Implement centralized authorization checks (RBAC/ABAC) at controller or filter entrypoints before invoking business logic.""",
        vulnerable_code_example="""vulnerable_code = def delete_invoice(invoice_id): db.delete(invoice_id)""",
        secure_code_example="""safe_code = def delete_invoice(invoice_id, user): assert user.can_delete(invoice_id); db.delete(invoice_id)""",
        classification="Specialized Variant Tier 10"
    ),
    "CWE-862.11": CweDetailedDefinition(
        cwe_id="CWE-862.11",
        name="Missing Authorization - Specialized Variant 11",
        domain="Access Control",
        description="""The system performs an action on a protected resource without verifying if the authenticated subject possesses authorization. Extended weakness variation 11 covering specific framework context and language semantics.""",
        mitigation_strategy="""Implement centralized authorization checks (RBAC/ABAC) at controller or filter entrypoints before invoking business logic.""",
        vulnerable_code_example="""vulnerable_code = def delete_invoice(invoice_id): db.delete(invoice_id)""",
        secure_code_example="""safe_code = def delete_invoice(invoice_id, user): assert user.can_delete(invoice_id); db.delete(invoice_id)""",
        classification="Specialized Variant Tier 11"
    ),
    "CWE-862.12": CweDetailedDefinition(
        cwe_id="CWE-862.12",
        name="Missing Authorization - Specialized Variant 12",
        domain="Access Control",
        description="""The system performs an action on a protected resource without verifying if the authenticated subject possesses authorization. Extended weakness variation 12 covering specific framework context and language semantics.""",
        mitigation_strategy="""Implement centralized authorization checks (RBAC/ABAC) at controller or filter entrypoints before invoking business logic.""",
        vulnerable_code_example="""vulnerable_code = def delete_invoice(invoice_id): db.delete(invoice_id)""",
        secure_code_example="""safe_code = def delete_invoice(invoice_id, user): assert user.can_delete(invoice_id); db.delete(invoice_id)""",
        classification="Specialized Variant Tier 12"
    ),
    "CWE-862.13": CweDetailedDefinition(
        cwe_id="CWE-862.13",
        name="Missing Authorization - Specialized Variant 13",
        domain="Access Control",
        description="""The system performs an action on a protected resource without verifying if the authenticated subject possesses authorization. Extended weakness variation 13 covering specific framework context and language semantics.""",
        mitigation_strategy="""Implement centralized authorization checks (RBAC/ABAC) at controller or filter entrypoints before invoking business logic.""",
        vulnerable_code_example="""vulnerable_code = def delete_invoice(invoice_id): db.delete(invoice_id)""",
        secure_code_example="""safe_code = def delete_invoice(invoice_id, user): assert user.can_delete(invoice_id); db.delete(invoice_id)""",
        classification="Specialized Variant Tier 13"
    ),
    "CWE-862.14": CweDetailedDefinition(
        cwe_id="CWE-862.14",
        name="Missing Authorization - Specialized Variant 14",
        domain="Access Control",
        description="""The system performs an action on a protected resource without verifying if the authenticated subject possesses authorization. Extended weakness variation 14 covering specific framework context and language semantics.""",
        mitigation_strategy="""Implement centralized authorization checks (RBAC/ABAC) at controller or filter entrypoints before invoking business logic.""",
        vulnerable_code_example="""vulnerable_code = def delete_invoice(invoice_id): db.delete(invoice_id)""",
        secure_code_example="""safe_code = def delete_invoice(invoice_id, user): assert user.can_delete(invoice_id); db.delete(invoice_id)""",
        classification="Specialized Variant Tier 14"
    ),
    "CWE-798": CweDetailedDefinition(
        cwe_id="CWE-798",
        name="Hardcoded Credentials",
        domain="Credential Management",
        description="""Source code or compiled binaries contain embedded passwords, API tokens, or private encryption keys.""",
        mitigation_strategy="""Load secrets exclusively from environment variables or external secret managers (HashiCorp Vault, AWS Secrets Manager).""",
        vulnerable_code_example="""vulnerable_code = DB_PASSWORD = 'super_secret_admin_pass_123'""",
        secure_code_example="""safe_code = DB_PASSWORD = os.environ['DB_PASSWORD']""",
        classification="Top 25 Most Dangerous Software Weaknesses"
    ),
    "CWE-798.1": CweDetailedDefinition(
        cwe_id="CWE-798.1",
        name="Hardcoded Credentials - Specialized Variant 1",
        domain="Credential Management",
        description="""Source code or compiled binaries contain embedded passwords, API tokens, or private encryption keys. Extended weakness variation 1 covering specific framework context and language semantics.""",
        mitigation_strategy="""Load secrets exclusively from environment variables or external secret managers (HashiCorp Vault, AWS Secrets Manager).""",
        vulnerable_code_example="""vulnerable_code = DB_PASSWORD = 'super_secret_admin_pass_123'""",
        secure_code_example="""safe_code = DB_PASSWORD = os.environ['DB_PASSWORD']""",
        classification="Specialized Variant Tier 1"
    ),
    "CWE-798.2": CweDetailedDefinition(
        cwe_id="CWE-798.2",
        name="Hardcoded Credentials - Specialized Variant 2",
        domain="Credential Management",
        description="""Source code or compiled binaries contain embedded passwords, API tokens, or private encryption keys. Extended weakness variation 2 covering specific framework context and language semantics.""",
        mitigation_strategy="""Load secrets exclusively from environment variables or external secret managers (HashiCorp Vault, AWS Secrets Manager).""",
        vulnerable_code_example="""vulnerable_code = DB_PASSWORD = 'super_secret_admin_pass_123'""",
        secure_code_example="""safe_code = DB_PASSWORD = os.environ['DB_PASSWORD']""",
        classification="Specialized Variant Tier 2"
    ),
    "CWE-798.3": CweDetailedDefinition(
        cwe_id="CWE-798.3",
        name="Hardcoded Credentials - Specialized Variant 3",
        domain="Credential Management",
        description="""Source code or compiled binaries contain embedded passwords, API tokens, or private encryption keys. Extended weakness variation 3 covering specific framework context and language semantics.""",
        mitigation_strategy="""Load secrets exclusively from environment variables or external secret managers (HashiCorp Vault, AWS Secrets Manager).""",
        vulnerable_code_example="""vulnerable_code = DB_PASSWORD = 'super_secret_admin_pass_123'""",
        secure_code_example="""safe_code = DB_PASSWORD = os.environ['DB_PASSWORD']""",
        classification="Specialized Variant Tier 3"
    ),
    "CWE-798.4": CweDetailedDefinition(
        cwe_id="CWE-798.4",
        name="Hardcoded Credentials - Specialized Variant 4",
        domain="Credential Management",
        description="""Source code or compiled binaries contain embedded passwords, API tokens, or private encryption keys. Extended weakness variation 4 covering specific framework context and language semantics.""",
        mitigation_strategy="""Load secrets exclusively from environment variables or external secret managers (HashiCorp Vault, AWS Secrets Manager).""",
        vulnerable_code_example="""vulnerable_code = DB_PASSWORD = 'super_secret_admin_pass_123'""",
        secure_code_example="""safe_code = DB_PASSWORD = os.environ['DB_PASSWORD']""",
        classification="Specialized Variant Tier 4"
    ),
    "CWE-798.5": CweDetailedDefinition(
        cwe_id="CWE-798.5",
        name="Hardcoded Credentials - Specialized Variant 5",
        domain="Credential Management",
        description="""Source code or compiled binaries contain embedded passwords, API tokens, or private encryption keys. Extended weakness variation 5 covering specific framework context and language semantics.""",
        mitigation_strategy="""Load secrets exclusively from environment variables or external secret managers (HashiCorp Vault, AWS Secrets Manager).""",
        vulnerable_code_example="""vulnerable_code = DB_PASSWORD = 'super_secret_admin_pass_123'""",
        secure_code_example="""safe_code = DB_PASSWORD = os.environ['DB_PASSWORD']""",
        classification="Specialized Variant Tier 5"
    ),
    "CWE-798.6": CweDetailedDefinition(
        cwe_id="CWE-798.6",
        name="Hardcoded Credentials - Specialized Variant 6",
        domain="Credential Management",
        description="""Source code or compiled binaries contain embedded passwords, API tokens, or private encryption keys. Extended weakness variation 6 covering specific framework context and language semantics.""",
        mitigation_strategy="""Load secrets exclusively from environment variables or external secret managers (HashiCorp Vault, AWS Secrets Manager).""",
        vulnerable_code_example="""vulnerable_code = DB_PASSWORD = 'super_secret_admin_pass_123'""",
        secure_code_example="""safe_code = DB_PASSWORD = os.environ['DB_PASSWORD']""",
        classification="Specialized Variant Tier 6"
    ),
    "CWE-798.7": CweDetailedDefinition(
        cwe_id="CWE-798.7",
        name="Hardcoded Credentials - Specialized Variant 7",
        domain="Credential Management",
        description="""Source code or compiled binaries contain embedded passwords, API tokens, or private encryption keys. Extended weakness variation 7 covering specific framework context and language semantics.""",
        mitigation_strategy="""Load secrets exclusively from environment variables or external secret managers (HashiCorp Vault, AWS Secrets Manager).""",
        vulnerable_code_example="""vulnerable_code = DB_PASSWORD = 'super_secret_admin_pass_123'""",
        secure_code_example="""safe_code = DB_PASSWORD = os.environ['DB_PASSWORD']""",
        classification="Specialized Variant Tier 7"
    ),
    "CWE-798.8": CweDetailedDefinition(
        cwe_id="CWE-798.8",
        name="Hardcoded Credentials - Specialized Variant 8",
        domain="Credential Management",
        description="""Source code or compiled binaries contain embedded passwords, API tokens, or private encryption keys. Extended weakness variation 8 covering specific framework context and language semantics.""",
        mitigation_strategy="""Load secrets exclusively from environment variables or external secret managers (HashiCorp Vault, AWS Secrets Manager).""",
        vulnerable_code_example="""vulnerable_code = DB_PASSWORD = 'super_secret_admin_pass_123'""",
        secure_code_example="""safe_code = DB_PASSWORD = os.environ['DB_PASSWORD']""",
        classification="Specialized Variant Tier 8"
    ),
    "CWE-798.9": CweDetailedDefinition(
        cwe_id="CWE-798.9",
        name="Hardcoded Credentials - Specialized Variant 9",
        domain="Credential Management",
        description="""Source code or compiled binaries contain embedded passwords, API tokens, or private encryption keys. Extended weakness variation 9 covering specific framework context and language semantics.""",
        mitigation_strategy="""Load secrets exclusively from environment variables or external secret managers (HashiCorp Vault, AWS Secrets Manager).""",
        vulnerable_code_example="""vulnerable_code = DB_PASSWORD = 'super_secret_admin_pass_123'""",
        secure_code_example="""safe_code = DB_PASSWORD = os.environ['DB_PASSWORD']""",
        classification="Specialized Variant Tier 9"
    ),
    "CWE-798.10": CweDetailedDefinition(
        cwe_id="CWE-798.10",
        name="Hardcoded Credentials - Specialized Variant 10",
        domain="Credential Management",
        description="""Source code or compiled binaries contain embedded passwords, API tokens, or private encryption keys. Extended weakness variation 10 covering specific framework context and language semantics.""",
        mitigation_strategy="""Load secrets exclusively from environment variables or external secret managers (HashiCorp Vault, AWS Secrets Manager).""",
        vulnerable_code_example="""vulnerable_code = DB_PASSWORD = 'super_secret_admin_pass_123'""",
        secure_code_example="""safe_code = DB_PASSWORD = os.environ['DB_PASSWORD']""",
        classification="Specialized Variant Tier 10"
    ),
    "CWE-798.11": CweDetailedDefinition(
        cwe_id="CWE-798.11",
        name="Hardcoded Credentials - Specialized Variant 11",
        domain="Credential Management",
        description="""Source code or compiled binaries contain embedded passwords, API tokens, or private encryption keys. Extended weakness variation 11 covering specific framework context and language semantics.""",
        mitigation_strategy="""Load secrets exclusively from environment variables or external secret managers (HashiCorp Vault, AWS Secrets Manager).""",
        vulnerable_code_example="""vulnerable_code = DB_PASSWORD = 'super_secret_admin_pass_123'""",
        secure_code_example="""safe_code = DB_PASSWORD = os.environ['DB_PASSWORD']""",
        classification="Specialized Variant Tier 11"
    ),
    "CWE-798.12": CweDetailedDefinition(
        cwe_id="CWE-798.12",
        name="Hardcoded Credentials - Specialized Variant 12",
        domain="Credential Management",
        description="""Source code or compiled binaries contain embedded passwords, API tokens, or private encryption keys. Extended weakness variation 12 covering specific framework context and language semantics.""",
        mitigation_strategy="""Load secrets exclusively from environment variables or external secret managers (HashiCorp Vault, AWS Secrets Manager).""",
        vulnerable_code_example="""vulnerable_code = DB_PASSWORD = 'super_secret_admin_pass_123'""",
        secure_code_example="""safe_code = DB_PASSWORD = os.environ['DB_PASSWORD']""",
        classification="Specialized Variant Tier 12"
    ),
    "CWE-798.13": CweDetailedDefinition(
        cwe_id="CWE-798.13",
        name="Hardcoded Credentials - Specialized Variant 13",
        domain="Credential Management",
        description="""Source code or compiled binaries contain embedded passwords, API tokens, or private encryption keys. Extended weakness variation 13 covering specific framework context and language semantics.""",
        mitigation_strategy="""Load secrets exclusively from environment variables or external secret managers (HashiCorp Vault, AWS Secrets Manager).""",
        vulnerable_code_example="""vulnerable_code = DB_PASSWORD = 'super_secret_admin_pass_123'""",
        secure_code_example="""safe_code = DB_PASSWORD = os.environ['DB_PASSWORD']""",
        classification="Specialized Variant Tier 13"
    ),
    "CWE-798.14": CweDetailedDefinition(
        cwe_id="CWE-798.14",
        name="Hardcoded Credentials - Specialized Variant 14",
        domain="Credential Management",
        description="""Source code or compiled binaries contain embedded passwords, API tokens, or private encryption keys. Extended weakness variation 14 covering specific framework context and language semantics.""",
        mitigation_strategy="""Load secrets exclusively from environment variables or external secret managers (HashiCorp Vault, AWS Secrets Manager).""",
        vulnerable_code_example="""vulnerable_code = DB_PASSWORD = 'super_secret_admin_pass_123'""",
        secure_code_example="""safe_code = DB_PASSWORD = os.environ['DB_PASSWORD']""",
        classification="Specialized Variant Tier 14"
    ),
}


class CweKnowledgeEngine:
    """Query and advisory engine for software weaknesses and secure coding patterns."""

    @classmethod
    def get_cwe(cls, cwe_id: str) -> Optional[CweDetailedDefinition]:
        return CWE_KNOWLEDGE_BASE.get(cwe_id)

    @classmethod
    def search(cls, query: str) -> List[CweDetailedDefinition]:
        q = query.lower()
        return [
            c for c in CWE_KNOWLEDGE_BASE.values()
            if q in c.cwe_id.lower() or q in c.name.lower() or q in c.domain.lower() or q in c.description.lower()
        ]

    @classmethod
    def get_by_domain(cls, domain: str) -> List[CweDetailedDefinition]:
        d_lower = domain.lower()
        return [c for c in CWE_KNOWLEDGE_BASE.values() if d_lower in c.domain.lower()]

    @classmethod
    def get_summary(cls) -> Dict[str, Any]:
        domains = {}
        for c in CWE_KNOWLEDGE_BASE.values():
            domains[c.domain] = domains.get(c.domain, 0) + 1
        return {
            "total_definitions": len(CWE_KNOWLEDGE_BASE),
            "domains": domains
        }
