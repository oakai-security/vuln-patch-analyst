"""Remediation workflow coordinator deciding patch, safe purge, or forward."""

import json
import logging
import os
import subprocess
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

from .apt_checker import AptChecker
from .safety_engine import PackageSafetyEngine
from .schemas import EvaluationInput, RemediationVerdict

logger = logging.getLogger(__name__)

DEFAULT_REMEDIATION_QUEUE = os.environ.get(
    "OAKAI_REMEDIATION_QUEUE_PATH", "/run/oakai/pending_remediations.json"
)


class RemediationManager:
    """Evaluates and coordinates vulnerability remediation actions."""

    def __init__(
        self,
        apt_checker: AptChecker | None = None,
        safety_engine: PackageSafetyEngine | None = None,
        auto_apply: bool | None = None,
        remediation_queue_path: str | None = None,
    ):
        self.apt_checker = apt_checker or AptChecker()
        self.safety_engine = safety_engine or PackageSafetyEngine()
        if auto_apply is None:
            self.auto_apply = os.environ.get("OAKAI_PATCH_AUTO_APPLY", "false").lower() in (
                "1",
                "true",
                "yes",
            )
        else:
            self.auto_apply = auto_apply
        self.remediation_queue_path = Path(remediation_queue_path or DEFAULT_REMEDIATION_QUEUE)

    def _enqueue_host_remediation(
        self,
        action_type: str,
        cve_id: str,
        package_name: str,
        packages: list[str],
        target_version: str | None = None,
    ) -> bool:
        """Atomically append a verified remediation work item for the host root reconciler."""
        try:
            queue_dir = self.remediation_queue_path.parent
            if not queue_dir.exists() or not os.access(queue_dir, os.W_OK):
                return False

            existing_items: list[dict] = []
            if self.remediation_queue_path.exists():
                try:
                    raw = json.loads(self.remediation_queue_path.read_text(encoding="utf-8"))
                    if isinstance(raw, list):
                        existing_items = raw
                except (OSError, ValueError):
                    existing_items = []

            # Deduplicate by (action_type, tuple(packages))
            pkg_key = sorted(packages)
            for item in existing_items:
                if item.get("action") == action_type and sorted(item.get("packages", [])) == pkg_key:
                    if cve_id not in item.get("cve_ids", []):
                        item.setdefault("cve_ids", []).append(cve_id)
                    break
            else:
                existing_items.append(
                    {
                        "action": action_type,
                        "package_name": package_name,
                        "packages": packages,
                        "target_version": target_version,
                        "cve_ids": [cve_id],
                        "queued_at": datetime.now(UTC).isoformat(),
                        "epoch": time.time(),
                    }
                )

            fd, tmp_path = tempfile.mkstemp(dir=str(queue_dir), prefix=".remediate.")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(existing_items, fh, indent=2)
                os.chmod(tmp_path, 0o664)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
                os.replace(tmp_path, str(self.remediation_queue_path))
            finally:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)

            logger.info(
                "Queued host remediation (%s) for %s -> %s",
                action_type,
                cve_id,
                self.remediation_queue_path,
            )
            return True
        except OSError as err:
            logger.warning("Could not write host remediation queue: %s", err)
            return False

    def process_finding(self, finding: EvaluationInput) -> RemediationVerdict:
        """Process a single evaluated vulnerability finding."""
        logger.info("Evaluating remediation for %s (%s)", finding.cve_id, finding.package_name)

        # 1. Check for upstream update
        patch_res = self.apt_checker.check_update_available(finding.package_name, finding.installed_version)

        if patch_res.is_upgradable:
            action = f"Upstream update available: {patch_res.available_version}"
            if self.auto_apply:
                applied = self._apply_package_upgrade(finding.package_name)
                if applied:
                    action = (
                        f"Successfully upgraded {finding.package_name} to {patch_res.available_version}"
                    )
                else:
                    queued = self._enqueue_host_remediation(
                        action_type="upgrade",
                        cve_id=finding.cve_id,
                        package_name=finding.package_name,
                        packages=[finding.package_name],
                        target_version=patch_res.available_version,
                    )
                    if queued:
                        action = (
                            f"Queued host upgrade of {finding.package_name} to "
                            f"{patch_res.available_version} via oakai-host-reconciler"
                        )
                    else:
                        return RemediationVerdict(
                            cve_id=finding.cve_id,
                            package_name=finding.package_name,
                            installed_version=finding.installed_version,
                            status="UNRESOLVED_FORWARD",
                            action_summary=(
                                f"Upstream update {patch_res.available_version} exists for "
                                f"{finding.package_name}, but container lacks root privileges and "
                                "host remediation queue is unavailable. Forwarded for tracking."
                            ),
                            patch_details=patch_res,
                        )
            else:
                self._enqueue_host_remediation(
                    action_type="upgrade",
                    cve_id=finding.cve_id,
                    package_name=finding.package_name,
                    packages=[finding.package_name],
                    target_version=patch_res.available_version,
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
            branch = purge_res.candidate_pruning_branch or [finding.package_name]
            action = "Package is safe to remove (0 active reverse dependencies, 0 process locks)"
            if self.auto_apply:
                applied = self._apply_package_purge(branch)
                if applied:
                    action = f"Successfully purged package branch: {', '.join(branch)}"
                else:
                    queued = self._enqueue_host_remediation(
                        action_type="purge",
                        cve_id=finding.cve_id,
                        package_name=finding.package_name,
                        packages=branch,
                    )
                    if queued:
                        action = (
                            f"Queued safe package purge ({', '.join(branch)}) "
                            "for execution by host oakai-host-reconciler"
                        )
                    else:
                        return RemediationVerdict(
                            cve_id=finding.cve_id,
                            package_name=finding.package_name,
                            installed_version=finding.installed_version,
                            status="UNRESOLVED_FORWARD",
                            action_summary=(
                                f"Package {finding.package_name} passed 4-stage safe purge check, "
                                "but direct purge failed and host remediation queue is unavailable. "
                                "Forwarded for risk exception."
                            ),
                            patch_details=patch_res,
                            purge_details=purge_res,
                        )
            else:
                self._enqueue_host_remediation(
                    action_type="purge",
                    cve_id=finding.cve_id,
                    package_name=finding.package_name,
                    packages=branch,
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
        """Execute apt-get install --only-upgrade when running as host root."""
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            return False
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
        """Execute apt-get purge -y when running as host root."""
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            return False
        try:
            cmd = ["apt-get", "purge", "-y"] + packages
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
            return res.returncode == 0
        except (subprocess.SubprocessError, OSError) as err:
            logger.error("Failed to execute purge: %s", err)
            return False
