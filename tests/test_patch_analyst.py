"""Unit test suite for vuln-patch-analyst micro-agent."""

import json
import socket
import tempfile
import threading
from pathlib import Path

from vuln_patch_analyst.apt_checker import AptChecker
from vuln_patch_analyst.remediation_manager import RemediationManager
from vuln_patch_analyst.safety_engine import PackageSafetyEngine
from vuln_patch_analyst.schemas import (
    EvaluationInput,
    PatchCheckResult,
    RemediationVerdict,
    SafePurgeCheckResult,
)
from vuln_patch_analyst.socket_server import UdsPatchServer


def test_protected_whitelist_blocks_system_packages():
    """Verify kernel, libc, systemd, and runtime packages cannot be purged."""
    engine = PackageSafetyEngine()

    assert engine._is_protected_package("libc6") is True
    assert engine._is_protected_package("systemd") is True
    assert engine._is_protected_package("linux-image-6.1.0-arm64") is True
    assert engine._is_protected_package("podman") is True
    assert engine._is_protected_package("falco") is True
    assert engine._is_protected_package("unrelated-pkg") is False

    res = engine.evaluate_safe_purge("systemd")
    assert res.is_safe_to_purge is False
    assert "protected core OS pattern" in res.rejection_reason


def test_safety_engine_blocks_on_reverse_deps(mocker):
    """Verify safety engine fails when active reverse dependencies exist."""
    engine = PackageSafetyEngine()
    mocker.patch.object(engine, "_get_installed_reverse_dependencies", return_value=["active-app", "web-service"])

    res = engine.evaluate_safe_purge("vulnerable-lib")
    assert res.is_safe_to_purge is False
    assert "Multiple active reverse dependencies" in res.rejection_reason


def test_safety_engine_constrained_branch_pruning(mocker):
    """Verify constrained branch pruning allows purging unused parent dependency."""
    engine = PackageSafetyEngine()
    mocker.patch.object(engine, "_get_installed_reverse_dependencies", return_value=["unused-orphan-cli"])
    mocker.patch.object(engine, "_can_prune_parent_dependency", return_value=True)
    mocker.patch.object(engine, "_simulate_purge", return_value=(["vulnerable-lib", "unused-orphan-cli"], True))
    mocker.patch.object(engine, "_check_process_locks", return_value=[])
    mocker.patch.object(engine, "_check_systemd_dependencies", return_value=[])

    res = engine.evaluate_safe_purge("vulnerable-lib")
    assert res.is_safe_to_purge is True
    assert res.candidate_pruning_branch == ["vulnerable-lib", "unused-orphan-cli"]


def test_safety_engine_aborts_on_unexpected_dry_run_packages(mocker):
    """Verify safety engine aborts if dry-run affects unexpected 3rd package."""
    engine = PackageSafetyEngine()
    mocker.patch.object(engine, "_get_installed_reverse_dependencies", return_value=[])
    # Dry-run claims it would also remove unexpected-server
    mocker.patch.object(engine, "_simulate_purge", return_value=(["vulnerable-lib", "unexpected-server"], False))

    res = engine.evaluate_safe_purge("vulnerable-lib")
    assert res.is_safe_to_purge is False
    assert "additional unexpected packages" in res.rejection_reason


def test_remediation_manager_prioritizes_patch(mocker):
    """Verify remediation manager selects upgrade when patch is available."""
    mock_apt = mocker.Mock(spec=AptChecker)
    mock_apt.check_update_available.return_value = PatchCheckResult(
        package_name="curl",
        installed_version="7.88.1",
        available_version="7.88.2-patched",
        is_upgradable=True,
    )

    manager = RemediationManager(apt_checker=mock_apt)
    finding = EvaluationInput(
        cve_id="CVE-2024-0001",
        package_name="curl",
        installed_version="7.88.1",
        cvss_base=8.0,
        epss_score=0.10,
        epss_percentile=0.75,
        in_memory=True,
        threat_level="HIGH",
        verdict_rationale="Active in RAM",
    )

    verdict = manager.process_finding(finding)
    assert verdict.status == "PATCHED"
    assert "7.88.2-patched" in verdict.action_summary


def test_remediation_manager_forwards_unfixable(mocker):
    """Verify unfixable and unremovable packages are marked UNRESOLVED_FORWARD."""
    mock_apt = mocker.Mock(spec=AptChecker)
    mock_apt.check_update_available.return_value = PatchCheckResult(
        package_name="critical-db",
        installed_version="15.0",
        is_upgradable=False,
    )

    mock_safety = mocker.Mock(spec=PackageSafetyEngine)
    mock_safety.evaluate_safe_purge.return_value = SafePurgeCheckResult(
        package_name="critical-db",
        is_safe_to_purge=False,
        rejection_reason="Active process lock detected",
    )

    manager = RemediationManager(apt_checker=mock_apt, safety_engine=mock_safety)
    finding = EvaluationInput(
        cve_id="CVE-2024-9999",
        package_name="critical-db",
        installed_version="15.0",
        cvss_base=9.8,
        epss_score=0.90,
        epss_percentile=0.99,
        in_memory=True,
        threat_level="CRITICAL",
        verdict_rationale="Core DB",
    )

    verdict = manager.process_finding(finding)
    assert verdict.status == "UNRESOLVED_FORWARD"
    assert "Forwarded for risk exception" in verdict.action_summary


def test_uds_socket_roundtrip(mocker):
    """Verify IPC exchange across UDS server."""
    with tempfile.TemporaryDirectory() as temp_dir:
        patch_sock = str(Path(temp_dir) / "test_patch.sock")
        req_sock = str(Path(temp_dir) / "test_req.sock")

        mock_manager = mocker.Mock(spec=RemediationManager)
        mock_manager.process_finding.return_value = RemediationVerdict(
            cve_id="CVE-2024-38077",
            package_name="libtest",
            installed_version="1.0",
            status="UNRESOLVED_FORWARD",
            action_summary="Forwarded for test",
        )

        server = UdsPatchServer(
            socket_path=patch_sock,
            downstream_socket=req_sock,
            remediation_manager=mock_manager,
        )

        server_thread = threading.Thread(target=server.start, daemon=True)
        server_thread.start()

        import time
        time.sleep(0.1)

        client_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client_sock.connect(patch_sock)

        payload = [
            {
                "cve_id": "CVE-2024-38077",
                "package_name": "libtest",
                "installed_version": "1.0",
                "cvss_base": 9.8,
                "epss_score": 0.85,
                "epss_percentile": 0.98,
                "in_memory": True,
                "threat_level": "CRITICAL",
                "verdict_rationale": "High exploit in RAM",
            }
        ]
        client_sock.sendall(json.dumps(payload).encode("utf-8"))
        client_sock.shutdown(socket.SHUT_WR)

        response_raw = client_sock.recv(8192).decode("utf-8")
        client_sock.close()
        server.stop()

        verdicts = json.loads(response_raw)
        assert len(verdicts) == 1
        assert verdicts[0]["status"] == "UNRESOLVED_FORWARD"


def test_purge_refused_without_memscan_snapshot(tmp_path):
    """With full visibility required, a missing snapshot must block any purge."""
    from vuln_patch_analyst.safety_engine import PackageSafetyEngine

    engine = PackageSafetyEngine(
        proc_root=str(tmp_path),
        memmap_path=str(tmp_path / "missing.json"),
        require_full_visibility=True,
    )
    engine._get_installed_reverse_dependencies = lambda pkg: []
    engine._simulate_purge = lambda pkgs: (list(pkgs), True)
    res = engine.evaluate_safe_purge("some-unprotected-pkg")
    assert res.is_safe_to_purge is False
    assert "memscan snapshot" in res.rejection_reason


def test_remediation_manager_queues_host_remediation_when_rootless(tmp_path, mocker):
    """When auto_apply is True inside a rootless container, verified actions queue for the host reconciler."""
    queue_file = tmp_path / "pending_remediations.json"

    mock_apt = mocker.Mock(spec=AptChecker)
    mock_apt.check_update_available.return_value = PatchCheckResult(
        package_name="unused-pkg",
        installed_version="1.0",
        is_upgradable=False,
    )

    mock_safety = mocker.Mock(spec=PackageSafetyEngine)
    mock_safety.evaluate_safe_purge.return_value = SafePurgeCheckResult(
        package_name="unused-pkg",
        is_safe_to_purge=True,
        candidate_pruning_branch=["unused-pkg"],
    )

    manager = RemediationManager(
        apt_checker=mock_apt,
        safety_engine=mock_safety,
        auto_apply=True,
        remediation_queue_path=str(queue_file),
    )
    mocker.patch.object(manager, "_apply_package_purge", return_value=False)

    finding = EvaluationInput(
        cve_id="CVE-2026-1234",
        package_name="unused-pkg",
        installed_version="1.0",
        cvss_base=7.5,
        epss_score=0.01,
        epss_percentile=0.20,
        in_memory=False,
        threat_level="LOW",
        verdict_rationale="Unused package",
    )

    verdict = manager.process_finding(finding)
    assert verdict.status == "PURGED"
    assert "oakai-host-reconciler" in verdict.action_summary
    assert queue_file.exists()
    queued = json.loads(queue_file.read_text(encoding="utf-8"))
    assert len(queued) == 1
    assert queued[0]["action"] == "purge"
    assert queued[0]["packages"] == ["unused-pkg"]

