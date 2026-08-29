"""
System Configuration and Runtime Settings for AegisGuard Platform.
"""

import os
from dataclasses import dataclass, field
from typing import List


@dataclass
class AegisConfig:
    app_name: str = "AegisGuard Enterprise SecOps"
    app_version: str = "1.0.0"
    environment: str = "production"
    api_host: str = "0.0.0.0"
    api_port: int = 8443
    debug_mode: bool = False
    log_level: str = "INFO"
    enable_threat_intel_auto_sync: bool = True
    enable_sigma_rule_engine: bool = True
    enable_stateful_correlation: bool = True
    alert_retention_days: int = 90
    max_batch_event_ingestion: int = 50000
    pki_ca_validity_days: int = 3650
    secret_vault_encryption_algorithm: str = "AES-256-GCM"
    allowed_cors_origins: List[str] = field(default_factory=lambda: ["*"])

    @classmethod
    def load_from_env(cls) -> "AegisConfig":
        return cls(
            environment=os.getenv("AEGIS_ENV", "production"),
            api_host=os.getenv("AEGIS_HOST", "0.0.0.0"),
            api_port=int(os.getenv("AEGIS_PORT", "8443")),
            debug_mode=os.getenv("AEGIS_DEBUG", "false").lower() == "true",
            log_level=os.getenv("AEGIS_LOG_LEVEL", "INFO"),
        )


settings = AegisConfig.load_from_env()
