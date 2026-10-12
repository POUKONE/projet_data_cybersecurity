"""
Modèles communs utilisés par le module d'audit Web.
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class WebCheckResult:
    check_id: str
    name: str
    status: str
    message: str


@dataclass
class WebFinding:
    event_type: str
    classification: str
    severity: str
    confidence: str

    target: str
    url: str

    message: str
    description: str

    parameter: str | None = None
    evidence: str | None = None
    recommendation: str | None = None
    validation_method: str | None = None

    status_code: int | None = None


@dataclass
class WebAuditReport:
    requested_url: str

    audit_status: str = "PENDING"

    final_url: str | None = None
    http_status: int | None = None

    request_count: int = 0

    redirects: list[dict] = field(
        default_factory=list
    )

    pages: list[dict] = field(
        default_factory=list
    )

    checks: list[dict] = field(
        default_factory=list
    )

    findings: list[dict] = field(
        default_factory=list
    )

    alerts: list[dict] = field(
        default_factory=list
    )

    errors: list[dict] = field(
        default_factory=list
    )

    limitations: list[str] = field(
        default_factory=list
    )

    coverage: dict[str, int] = field(
        default_factory=lambda: {
            "executed": 0,
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "indeterminate": 0,
        }
    )

    metadata: dict[str, Any] = field(
        default_factory=dict
    )

    def to_dict(self) -> dict:
        return {
            "requested_url": self.requested_url,
            "audit_status": self.audit_status,
            "final_url": self.final_url,
            "http_status": self.http_status,
            "request_count": self.request_count,
            "redirects": self.redirects,
            "pages": self.pages,
            "checks": self.checks,
            "findings": self.findings,
            "alerts": self.alerts,
            "errors": self.errors,
            "limitations": self.limitations,
            "coverage": self.coverage,
            "metadata": self.metadata,
        }
    