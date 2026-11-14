"""Remediation workflow coordinator deciding patch, safe purge, or forward."""

import logging
import subprocess

from .apt_checker import AptChecker
from .safety_engine import PackageSafetyEngine
from .schemas import EvaluationInput, RemediationVerdict

logger = logging.getLogger(__name__)


class RemediationManager:
    """Evaluates and coordinates vulnerability remediation actions."""

    def __init__(
        self,
        apt_checker: AptChecker | None = None,
        safety_engine: PackageSafetyEngine | None = None,
        auto_apply: bool = False,
    ):
        self.apt_checker = apt_checker or AptChecker()
        self.safety_engine = safety_engine or PackageSafetyEngine()
        self.auto_apply = auto_apply

    def process_finding(self, finding: EvaluationInput) -> RemediationVerdict:
        """Process a single evaluated vulnerability finding."""
        logger.info("Evaluating remediation for %s (%s)", finding.cve_id, finding.package_name)

        # 1. Check for upstream update
        patch_res = self.apt_checker.check_update_available(finding.package_name, finding.installed_version)

        if patch_res.is_upgradable:
            action = f"Upstream update available: {patch_res.available_version}"
            if self.auto_apply:
                applied = self._apply_package_upgrade(finding.package_name)
                action = (
                    f"Successfully upgraded {finding.package_name} to {patch_res.available_version}"
                    if applied
                    else f"Failed to execute apt upgrade for {finding.package_name}"
                )
            return RemediationVerdict(
                cve_id=finding.cve_id,
                package_name=finding.package_name,
                installed_version=finding.installed_version,
                status="PATCHED",
                action_summary=action,
                patch_details=patch_res,
            )

        # 2. Check if package can be safely purged
        purge_res = self.safety_engine.evaluate_safe_purge(finding.package_name)

        if purge_res.is_safe_to_purge:
            action = "Package is safe to remove (0 active reverse dependencies, 0 process locks)"
            if self.auto_apply:
                applied = self._apply_package_purge(purge_res.candidate_pruning_branch)
                action = (
                    f"Successfully purged package branch: {', '.join(purge_res.candidate_pruning_branch)}"
                    if applied
                    else f"Failed to execute apt purge for {finding.package_name}"
                )
            return RemediationVerdict(
                cve_id=finding.cve_id,
                package_name=finding.package_name,
                installed_version=finding.installed_version,
                status="PURGED",
                action_summary=action,
                purge_details=purge_res,
            )

        # 3. Cannot patch and cannot remove -> Forward to exception requester
        return RemediationVerdict(
            cve_id=finding.cve_id,
            package_name=finding.package_name,
            installed_version=finding.installed_version,
            status="UNRESOLVED_FORWARD",
            action_summary=(
                f"No patch available and removal rejected: {purge_res.rejection_reason}. "
                f"Forwarded for risk exception."
            ),
            patch_details=patch_res,
            purge_details=purge_res,
        )

    def _apply_package_upgrade(self, package_name: str) -> bool:
        """Execute apt-get install --only-upgrade."""
        try:
            res = subprocess.run(
                ["apt-get", "install", "--only-upgrade", "-y", package_name],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            return res.returncode == 0
        except (subprocess.SubprocessError, OSError) as err:
            logger.error("Failed to execute upgrade: %s", err)
            return False

    def _apply_package_purge(self, packages: list[str]) -> bool:
        """Execute apt-get purge -y."""
        try:
            cmd = ["apt-get", "purge", "-y"] + packages
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
            return res.returncode == 0
        except (subprocess.SubprocessError, OSError) as err:
            logger.error("Failed to execute purge: %s", err)
            return False
