"""Deterministic 4-stage package safety engine and constrained branch pruning."""

import fnmatch
import logging
import os
import re
import subprocess
from pathlib import Path

from .schemas import SafePurgeCheckResult

logger = logging.getLogger(__name__)

# Essential system packages that must NEVER be removed under any circumstance
PROTECTED_PATTERNS = [
    "linux-image-*",
    "linux-headers-*",
    "systemd*",
    "openssh*",
    "libc*",
    "libsystemd*",
    "coreutils",
    "sudo",
    "falco*",
    "podman*",
    "crun*",
    "conmon*",
    "bash",
    "apt",
    "dpkg",
    "login",
    "init",
]


class PackageSafetyEngine:
    """Evaluates whether a vulnerable package can be safely removed from Linux hosts."""

    def __init__(self, proc_root: str = "/proc", timeout_seconds: int = 15):
        self.proc_root = Path(proc_root)
        self.timeout_seconds = timeout_seconds

    def evaluate_safe_purge(self, package_name: str) -> SafePurgeCheckResult:
        """Execute full 4-stage safety check and return detailed verdict."""
        pkg_clean = package_name.strip().lower()

        # Whitelist Protection Check
        if self._is_protected_package(pkg_clean):
            return SafePurgeCheckResult(
                package_name=pkg_clean,
                is_safe_to_purge=False,
                rejection_reason="Package matches protected core OS pattern and cannot be purged",
            )

        # Stage 1: Check Reverse Dependencies
        rdeps = self._get_installed_reverse_dependencies(pkg_clean)
        candidate_branch = [pkg_clean]

        if rdeps:
            # Evaluate Constrained Branch Pruning (depth = 1)
            # Check if parent reverse dependencies are orphaned/unused
            if len(rdeps) == 1:
                parent_pkg = rdeps[0]
                if self._can_prune_parent_dependency(parent_pkg):
                    candidate_branch.append(parent_pkg)
                else:
                    return SafePurgeCheckResult(
                        package_name=pkg_clean,
                        is_safe_to_purge=False,
                        rejection_reason=f"Active reverse dependency: {parent_pkg}",
                        reverse_dependencies=rdeps,
                    )
            else:
                return SafePurgeCheckResult(
                    package_name=pkg_clean,
                    is_safe_to_purge=False,
                    rejection_reason=f"Multiple active reverse dependencies: {', '.join(rdeps)}",
                    reverse_dependencies=rdeps,
                )

        # Stage 2: Simulated APT Dry-Run Purge
        dry_run_pkgs, dry_run_ok = self._simulate_purge(candidate_branch)
        if not dry_run_ok:
            return SafePurgeCheckResult(
                package_name=pkg_clean,
                is_safe_to_purge=False,
                rejection_reason="APT dry-run simulation affected additional unexpected packages",
                reverse_dependencies=rdeps,
                dry_run_affected_packages=dry_run_pkgs,
                candidate_pruning_branch=candidate_branch,
            )

        # Stage 3: Active Process & Memory Map Lock Check
        active_pids = self._check_process_locks(candidate_branch)
        if active_pids:
            return SafePurgeCheckResult(
                package_name=pkg_clean,
                is_safe_to_purge=False,
                rejection_reason=f"Active running processes hold memory locks (PIDs: {active_pids})",
                reverse_dependencies=rdeps,
                dry_run_affected_packages=dry_run_pkgs,
                active_process_pids=active_pids,
                candidate_pruning_branch=candidate_branch,
            )

        # Stage 4: Systemd Service Unit Audit
        systemd_deps = self._check_systemd_dependencies(candidate_branch)
        if systemd_deps:
            return SafePurgeCheckResult(
                package_name=pkg_clean,
                is_safe_to_purge=False,
                rejection_reason=f"Systemd service units depend on this package: {', '.join(systemd_deps)}",
                reverse_dependencies=rdeps,
                dry_run_affected_packages=dry_run_pkgs,
                systemd_dependencies=systemd_deps,
                candidate_pruning_branch=candidate_branch,
            )

        return SafePurgeCheckResult(
            package_name=pkg_clean,
            is_safe_to_purge=True,
            rejection_reason="",
            reverse_dependencies=rdeps,
            dry_run_affected_packages=dry_run_pkgs,
            active_process_pids=[],
            systemd_dependencies=[],
            candidate_pruning_branch=candidate_branch,
        )

    def _is_protected_package(self, package_name: str) -> bool:
        """Verify package against non-removable OS whitelist patterns."""
        for pattern in PROTECTED_PATTERNS:
            if fnmatch.fnmatch(package_name, pattern):
                return True
        return False

    def _get_installed_reverse_dependencies(self, package_name: str) -> list[str]:
        """Query installed reverse dependencies via apt-cache rdepends --installed."""
        try:
            res = subprocess.run(
                ["apt-cache", "rdepends", "--installed", package_name],
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
            if res.returncode != 0:
                return []

            rdeps = []
            capture = False
            for line in res.stdout.splitlines():
                clean = line.strip()
                if clean.startswith("Reverse Depends:"):
                    capture = True
                    continue
                if capture and clean and clean != package_name and clean not in rdeps:
                    rdeps.append(clean)
            return sorted(rdeps)
        except (subprocess.SubprocessError, OSError):
            return []

    def _can_prune_parent_dependency(self, parent_pkg: str) -> bool:
        """Check if parent dependency was installed automatically and has no other callers."""
        if self._is_protected_package(parent_pkg):
            return False

        # Check if parent is marked as auto-installed
        try:
            res = subprocess.run(
                ["apt-mark", "showauto", parent_pkg],
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
            if res.returncode == 0 and parent_pkg in res.stdout:
                # Check if parent has any other reverse dependencies
                parent_rdeps = self._get_installed_reverse_dependencies(parent_pkg)
                return len(parent_rdeps) == 0
        except (subprocess.SubprocessError, OSError):
            pass

        return False

    def _simulate_purge(self, packages: list[str]) -> tuple[list[str], bool]:
        """Execute apt-get purge --dry-run and verify only target packages are removed."""
        try:
            cmd = ["apt-get", "purge", "--dry-run", "-y"] + packages
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout_seconds, check=False)

            if res.returncode != 0:
                return [], False

            removed_packages: list[str] = []
            capture_removals = False

            for line in res.stdout.splitlines():
                clean = line.strip()
                if "The following packages will be REMOVED:" in clean:
                    capture_removals = True
                    continue
                if capture_removals:
                    if clean.startswith(("0 upgraded", "Need to get")):
                        break
                    # Words in removal list
                    tokens = [t.rstrip("*") for t in clean.split() if t]
                    removed_packages.extend(tokens)

            # Verification rule: Every package to be removed must be in our approved candidate list
            candidate_set = set(packages)
            for pkg in removed_packages:
                if pkg not in candidate_set:
                    logger.warning("Simulated purge would remove unexpected package: %s", pkg)
                    return removed_packages, False

            return removed_packages, True

        except (subprocess.SubprocessError, OSError) as err:
            logger.error("Simulation error: %s", err)
            return [], False

    def _check_process_locks(self, packages: list[str]) -> list[int]:
        """Inspect /proc to check if active PIDs hold open file mappings from candidate packages."""
        if not self.proc_root.exists() or not self.proc_root.is_dir():
            return []

        patterns = [re.compile(rf"\b{re.escape(pkg)}\b", re.IGNORECASE) for pkg in packages]
        active_pids: set[int] = set()

        try:
            for entry in os.listdir(self.proc_root):
                if not entry.isdigit():
                    continue
                pid = int(entry)
                maps_path = self.proc_root / entry / "maps"
                if not maps_path.exists():
                    continue

                try:
                    with open(maps_path, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            parts = line.strip().split(maxsplit=5)
                            if len(parts) >= 6:
                                path_str = parts[5].strip()
                                for pat in patterns:
                                    if pat.search(path_str):
                                        active_pids.add(pid)
                                        break
                except (OSError, PermissionError):
                    continue
        except OSError:
            pass

        return sorted(active_pids)

    def _check_systemd_dependencies(self, packages: list[str]) -> list[str]:
        """Check if any active systemd units depend on or execute candidate package binaries."""
        flagged_units: set[str] = set()

        for pkg in packages:
            # Query files installed by package
            try:
                dpkg_res = subprocess.run(
                    ["dpkg-query", "-L", pkg],
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                    check=False,
                )
                if dpkg_res.returncode == 0:
                    for line in dpkg_res.stdout.splitlines():
                        clean = line.strip()
                        if "/systemd/system/" in clean and clean.endswith(".service"):
                            unit_name = os.path.basename(clean)
                            flagged_units.add(unit_name)
            except (subprocess.SubprocessError, OSError):
                continue

        return sorted(flagged_units)
