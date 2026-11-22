"""Deterministic 4-stage package safety engine and constrained branch pruning."""

import fnmatch
import glob
import json
import logging
import os
import re
import subprocess
import time
from pathlib import Path

from .schemas import SafePurgeCheckResult

logger = logging.getLogger(__name__)

# Essential system packages that must NEVER be removed under any circumstance
PROTECTED_PATTERNS = [
    "linux-image-*",
    "linux-headers-*",
    "linux-libc-dev*",
    "systemd*",
    "openssh*",
    "libc*",
    "libsystemd*",
    "libssl*",
    "zlib1g*",
    "coreutils",
    "sudo",
    "falco*",
    "podman*",
    "crun*",
    "conmon*",
    "buildah*",
    "bash",
    "apt*",
    "dpkg*",
    "login",
    "init",
    "tar",
    "gzip",
    "util-linux*",
    "findutils",
    "grep",
    "sed",
    "base-files",
    "debianutils",
    "git*",
    "curl",
    "ca-certificates",
    "python3*",
]


class PackageSafetyEngine:
    """Evaluates whether a vulnerable package can be safely removed from Linux hosts."""

    def __init__(
        self,
        proc_root: str = "/proc",
        dpkg_info_dir: str = "/var/lib/dpkg/info",
        timeout_seconds: int = 15,
        memmap_path: str | None = None,
        require_full_visibility: bool | None = None,
    ):
        self.proc_root = Path(proc_root)
        self.dpkg_info_dir = Path(dpkg_info_dir)
        self.timeout_seconds = timeout_seconds
        self.memmap_path = Path(memmap_path or os.environ.get("OAKAI_MEMMAP_PATH", "/run/oakai/memmap.json"))
        self.memmap_max_age = int(os.environ.get("OAKAI_MEMMAP_MAX_AGE", "600"))
        # In production (pod.yaml sets OAKAI_REQUIRE_FULL_MEMVIEW=true) a purge is refused unless the
        # root-owned memscan snapshot proves no process, including root-owned ones, maps the package.
        if require_full_visibility is None:
            require_full_visibility = os.environ.get("OAKAI_REQUIRE_FULL_MEMVIEW", "false").lower() in (
                "1",
                "true",
                "yes",
            )
        self.require_full_visibility = require_full_visibility

    def _load_memmap_snapshot(self) -> dict | None:
        """Load the fresh root memscan snapshot, or None when missing, stale, or malformed."""
        try:
            data = json.loads(self.memmap_path.read_text(encoding="utf-8"))
            if time.time() - float(data.get("epoch", 0)) > self.memmap_max_age:
                return None
            return data if isinstance(data.get("files"), dict) else None
        except (OSError, ValueError, TypeError):
            return None

    def evaluate_safe_purge(self, package_name: str) -> SafePurgeCheckResult:
        """Execute full 4-stage safety check and return detailed verdict."""
        pkg_clean = package_name.strip().lower().split(":")[0]

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
                    rejection_reason=f"Multiple active reverse dependencies: {', '.join(rdeps[:8])}",
                    reverse_dependencies=rdeps,
                )

        # Stage 2: Simulated APT Dry-Run Purge
        dry_run_pkgs, dry_run_ok = self._simulate_purge(candidate_branch)
        if not dry_run_ok:
            extra_pkgs = [p for p in dry_run_pkgs if p not in candidate_branch]
            if extra_pkgs:
                reason = (
                    f"APT dry-run simulation affected additional unexpected packages: "
                    f"{', '.join(extra_pkgs[:6])}"
                )
            else:
                reason = "APT dry-run simulation affected additional unexpected packages"
            return SafePurgeCheckResult(
                package_name=pkg_clean,
                is_safe_to_purge=False,
                rejection_reason=reason,
                reverse_dependencies=rdeps,
                dry_run_affected_packages=dry_run_pkgs,
                candidate_pruning_branch=candidate_branch,
            )

        # Stage 3: Active Process & Memory Map Lock Check
        if self.require_full_visibility and self._load_memmap_snapshot() is None:
            return SafePurgeCheckResult(
                package_name=pkg_clean,
                is_safe_to_purge=False,
                rejection_reason=(
                    "Cannot verify no root-owned process maps this package "
                    "(memscan snapshot missing or stale); purge refused"
                ),
                reverse_dependencies=rdeps,
                dry_run_affected_packages=dry_run_pkgs,
                candidate_pruning_branch=candidate_branch,
            )
        active_pids = self._check_process_locks(candidate_branch)
        if active_pids:
            return SafePurgeCheckResult(
                package_name=pkg_clean,
                is_safe_to_purge=False,
                rejection_reason=f"Active running processes hold memory locks (PIDs: {active_pids[:8]})",
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
        """Query strict installed reverse dependencies via apt-cache rdepends."""
        try:
            res = subprocess.run(
                [
                    "apt-cache",
                    "-o",
                    "Dir::Cache::pkgcache=",
                    "-o",
                    "Dir::Cache::srcpkgcache=",
                    "rdepends",
                    "--installed",
                    "--no-recommends",
                    "--no-suggests",
                    "--no-conflicts",
                    "--no-breaks",
                    "--no-replaces",
                    "--no-enhances",
                    package_name,
                ],
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
                clean = line.strip().lstrip("|").strip()
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

        try:
            res = subprocess.run(
                ["apt-mark", "showauto", parent_pkg],
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
            if res.returncode == 0 and parent_pkg in res.stdout:
                parent_rdeps = self._get_installed_reverse_dependencies(parent_pkg)
                return len(parent_rdeps) == 0
        except (subprocess.SubprocessError, OSError):
            pass

        return False

    def _simulate_purge(self, packages: list[str]) -> tuple[list[str], bool]:
        """Execute apt-get purge --dry-run and verify only target packages are removed."""
        try:
            cmd = [
                "apt-get",
                "-o",
                "Dir::Cache::pkgcache=",
                "-o",
                "Dir::Cache::srcpkgcache=",
                "purge",
                "--dry-run",
                "-y",
            ] + packages
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )

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
                    if clean.startswith(("0 upgraded", "Need to get")) or "upgraded," in clean:
                        break
                    tokens = [t.rstrip("*").split(":")[0] for t in clean.split() if t]
                    removed_packages.extend(tokens)

            candidate_set = {p.split(":")[0] for p in packages}
            for pkg in removed_packages:
                if pkg not in candidate_set:
                    logger.warning("Simulated purge would remove unexpected package: %s", pkg)
                    return removed_packages, False

            return removed_packages, True

        except (subprocess.SubprocessError, OSError) as err:
            logger.error("Simulation error: %s", err)
            return [], False

    def _discover_package_files(self, package_name: str) -> list[str]:
        """Resolve actual shared libraries and binaries installed by package from dpkg info."""
        clean_pkg = package_name.strip().lower().split(":")[0]
        discovered: set[str] = set()

        if self.dpkg_info_dir.exists() and self.dpkg_info_dir.is_dir():
            list_files = glob.glob(str(self.dpkg_info_dir / f"{clean_pkg}.list")) + glob.glob(
                str(self.dpkg_info_dir / f"{clean_pkg}:*.list")
            )
            for list_file in list_files:
                try:
                    with open(list_file, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            p = line.strip()
                            if not p or "/gconv/" in p:
                                continue
                            is_bin = p.startswith(("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/"))
                            is_so = p.startswith(("/lib/", "/usr/lib/")) and (
                                ".so." in p or p.endswith(".so")
                            )
                            if is_bin or is_so:
                                bname = os.path.basename(p)
                                if len(bname) >= 2:
                                    discovered.add(bname)
                except OSError:
                    continue

        return sorted(discovered)

    def _check_process_locks(self, packages: list[str]) -> list[int]:
        """Inspect /proc to check if active PIDs hold open file mappings from candidate packages."""
        if not self.proc_root.exists() or not self.proc_root.is_dir():
            return []

        patterns: list[re.Pattern] = []
        for pkg in packages:
            clean_pkg = pkg.split(":")[0]
            patterns.append(re.compile(rf"\b{re.escape(clean_pkg)}\b", re.IGNORECASE))
            for bname in self._discover_package_files(clean_pkg):
                patterns.append(re.compile(rf"(?:^|/){re.escape(bname)}(?:\b|$)", re.IGNORECASE))

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

        # Merge root-visible mappings from the memscan snapshot
        snapshot = self._load_memmap_snapshot()
        if snapshot is not None:
            for pathname, pids in snapshot["files"].items():
                if any(pat.search(pathname) for pat in patterns):
                    active_pids.update(int(p) for p in pids)

        return sorted(active_pids)

    def _check_systemd_dependencies(self, packages: list[str]) -> list[str]:
        """Check if any systemd units belong to candidate packages."""
        flagged_units: set[str] = set()

        for pkg in packages:
            clean_pkg = pkg.split(":")[0]
            # 1. Direct inspection of /var/lib/dpkg/info/*.list
            if self.dpkg_info_dir.exists():
                list_files = glob.glob(str(self.dpkg_info_dir / f"{clean_pkg}.list")) + glob.glob(
                    str(self.dpkg_info_dir / f"{clean_pkg}:*.list")
                )
                for list_file in list_files:
                    try:
                        with open(list_file, "r", encoding="utf-8", errors="ignore") as f:
                            for line in f:
                                clean = line.strip()
                                if "/systemd/system/" in clean and clean.endswith(".service"):
                                    flagged_units.add(os.path.basename(clean))
                    except OSError:
                        continue

            # 2. Fallback to dpkg-query -L
            if not flagged_units:
                try:
                    dpkg_res = subprocess.run(
                        ["dpkg-query", "-L", clean_pkg],
                        capture_output=True,
                        text=True,
                        timeout=self.timeout_seconds,
                        check=False,
                    )
                    if dpkg_res.returncode == 0:
                        for line in dpkg_res.stdout.splitlines():
                            clean = line.strip()
                            if "/systemd/system/" in clean and clean.endswith(".service"):
                                flagged_units.add(os.path.basename(clean))
                except (subprocess.SubprocessError, OSError):
                    continue

        return sorted(flagged_units)
