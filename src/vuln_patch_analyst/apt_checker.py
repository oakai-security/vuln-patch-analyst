"""Deterministic APT package manager inspection for available upstream updates."""

import logging
import subprocess

from .schemas import PatchCheckResult

logger = logging.getLogger(__name__)


class AptChecker:
    """Inspects Debian/Ubuntu APT repository state for patched package versions."""

    def __init__(self, timeout_seconds: int = 15):
        self.timeout_seconds = timeout_seconds

    def check_update_available(self, package_name: str, installed_version: str) -> PatchCheckResult:
        """Check if an updated version of package_name exists in configured APT repositories."""
        try:
            result = subprocess.run(
                ["apt-cache", "policy", package_name],
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )

            if result.returncode != 0:
                logger.warning("apt-cache policy failed for %s: %s", package_name, result.stderr)
                return PatchCheckResult(
                    package_name=package_name,
                    installed_version=installed_version,
                    is_upgradable=False,
                    patch_notes="apt-cache returned non-zero exit code",
                )

            installed, candidate = self._parse_policy_output(result.stdout)
            is_upgradable = bool(candidate and candidate != "(none)" and candidate != installed)

            return PatchCheckResult(
                package_name=package_name,
                installed_version=installed or installed_version,
                available_version=candidate if is_upgradable else None,
                is_upgradable=is_upgradable,
                patch_notes=(
                    f"Candidate update available: {candidate}"
                    if is_upgradable
                    else "Package is already at latest available repository version"
                ),
            )

        except (subprocess.SubprocessError, OSError) as err:
            logger.error("Failed to inspect APT policy for %s: %s", package_name, err)
            return PatchCheckResult(
                package_name=package_name,
                installed_version=installed_version,
                is_upgradable=False,
                patch_notes=f"Error executing package query: {err}",
            )

    def _parse_policy_output(self, output: str) -> tuple[str, str]:
        """Parse 'Installed:' and 'Candidate:' lines from apt-cache policy output."""
        installed = ""
        candidate = ""

        for line in output.splitlines():
            line_clean = line.strip()
            if line_clean.startswith("Installed:"):
                parts = line_clean.split(":", 1)
                if len(parts) == 2:
                    installed = parts[1].strip()
            elif line_clean.startswith("Candidate:"):
                parts = line_clean.split(":", 1)
                if len(parts) == 2:
                    candidate = parts[1].strip()

        return installed, candidate
