"""Data contracts and schemas for vulnerability patch analysis and safe remediation."""

from datetime import UTC, datetime

from pydantic import BaseModel, Field, field_validator


class EvaluationInput(BaseModel):
    """Enriched evaluation findings received from vuln-evaluator."""

    cve_id: str = Field(..., pattern=r"^CVE-\d{4}-\d{4,}$")
    package_name: str = Field(..., min_length=1)
    installed_version: str = Field(..., min_length=1)
    cvss_base: float = Field(..., ge=0.0, le=10.0)
    epss_score: float = Field(..., ge=0.0, le=1.0)
    epss_percentile: float = Field(..., ge=0.0, le=1.0)
    in_memory: bool
    matching_pids: list[int] = Field(default_factory=list)
    threat_level: str
    verdict_rationale: str

    @field_validator("cve_id", mode="before")
    def force_uppercase_cve(cls, v: str) -> str:
        """Ensure CVE ID is uppercase."""
        if isinstance(v, str):
            return v.strip().upper()
        return v


class PatchCheckResult(BaseModel):
    """Upstream patch availability result."""

    package_name: str
    installed_version: str
    available_version: str | None = None
    is_upgradable: bool = False
    patch_notes: str = ""


class SafePurgeCheckResult(BaseModel):
    """Deterministic 4-stage safety check outcome for package removal."""

    package_name: str
    is_safe_to_purge: bool
    rejection_reason: str = ""
    reverse_dependencies: list[str] = Field(default_factory=list)
    dry_run_affected_packages: list[str] = Field(default_factory=list)
    active_process_pids: list[int] = Field(default_factory=list)
    systemd_dependencies: list[str] = Field(default_factory=list)
    candidate_pruning_branch: list[str] = Field(default_factory=list)


class RemediationVerdict(BaseModel):
    """Final remediation decision and action report."""

    cve_id: str
    package_name: str
    installed_version: str
    status: str = Field(..., description="PATCHED, PURGED, or UNRESOLVED_FORWARD")
    action_summary: str
    patch_details: PatchCheckResult | None = None
    purge_details: SafePurgeCheckResult | None = None
    remediated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
