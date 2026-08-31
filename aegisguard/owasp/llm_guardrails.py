"""
Generative AI & LLM Prompt Safety Guardrails Engine.
Implements pre-execution prompt sanitization, jailbreak pattern detection,
PII redaction (SSNs, credit cards, API keys), and system prompt integrity enforcement.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
import re


class GuardrailAction(str, Enum):
    ALLOW = "ALLOW"
    MASK_AND_ALLOW = "MASK_AND_ALLOW"
    BLOCK = "BLOCK"


@dataclass
class GuardrailEvaluationResult:
    action: GuardrailAction
    is_safe: bool
    sanitized_prompt: str
    detected_violations: List[str] = field(default_factory=list)
    risk_score: float = 0.0


class LlmSafetyGuardrails:
    """Enterprise safety boundary evaluator for LLM prompts and responses."""

    # Regex patterns for sensitive data redaction
    SSN_PATTERN = r"\b\d{3}-\d{2}-\d{4}\b"
    CREDIT_CARD_PATTERN = r"\b(?:\d{4}[ -]?){3}\d{4}\b"
    API_KEY_PATTERN = r"\b(?:sk-[A-Za-z0-9]{32,}|ghp_[A-Za-z0-9]{36}|AKIA[0-9A-Z]{16})\b"

    # Known jailbreak / prompt injection markers
    JAILBREAK_PATTERNS = [
        (r"(?i)\bDAN\s+mode\b", "DAN Mode Jailbreak"),
        (r"(?i)disregard\s+(all\s+)?prior\s+instructions", "Instruction Disregard"),
        (r"(?i)reveal\s+your\s+(secret\s+)?system\s+prompt", "System Prompt Extraction"),
        (r"(?i)you\s+have\s+no\s+ethics\s+or\s+rules", "Safety Constraint Override"),
        (r"(?i)bypass\s+all\s+content\s+filters", "Filter Bypass Attempt")
    ]

    @classmethod
    def sanitize_prompt(cls, prompt: str) -> GuardrailEvaluationResult:
        violations = []
        cleaned = prompt
        risk = 0.0

        # 1. Detect Jailbreak Patterns
        for pattern, label in cls.JAILBREAK_PATTERNS:
            if re.search(pattern, cleaned):
                violations.append(label)
                risk += 35.0

        # 2. Redact Sensitive PII
        if re.search(cls.SSN_PATTERN, cleaned):
            cleaned = re.sub(cls.SSN_PATTERN, "[REDACTED_SSN]", cleaned)
            violations.append("SSN Pattern Detected")
            risk += 15.0

        if re.search(cls.CREDIT_CARD_PATTERN, cleaned):
            cleaned = re.sub(cls.CREDIT_CARD_PATTERN, "[REDACTED_CARD]", cleaned)
            violations.append("Payment Card Pattern Detected")
            risk += 20.0

        if re.search(cls.API_KEY_PATTERN, cleaned):
            cleaned = re.sub(cls.API_KEY_PATTERN, "[REDACTED_API_KEY]", cleaned)
            violations.append("Cloud API Key Detected")
            risk += 25.0

        risk = min(100.0, risk)

        if risk >= 50.0:
            action = GuardrailAction.BLOCK
            is_safe = False
        elif violations:
            action = GuardrailAction.MASK_AND_ALLOW
            is_safe = True
        else:
            action = GuardrailAction.ALLOW
            is_safe = True

        return GuardrailEvaluationResult(
            action=action,
            is_safe=is_safe,
            sanitized_prompt=cleaned if is_safe else "[BLOCKED_BY_GUARDRAIL]",
            detected_violations=violations,
            risk_score=risk
        )
