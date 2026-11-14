"""Command line interface for vuln-patch-analyst."""

import argparse
import json
import logging

from .remediation_manager import RemediationManager
from .schemas import EvaluationInput
from .socket_server import DEFAULT_PATCH_SOCKET, DEFAULT_REQUEST_SOCKET, UdsPatchServer


def main():
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(description="Autonomous Vulnerability Patch & Remediation Analyst")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Server daemon command
    serve_parser = subparsers.add_parser("serve", help="Start UDS remediation server")
    serve_parser.add_argument("--socket", default=DEFAULT_PATCH_SOCKET, help="Path to listen socket")
    serve_parser.add_argument("--downstream", default=DEFAULT_REQUEST_SOCKET, help="Path to requester socket")
    serve_parser.add_argument("--auto-apply", action="store_true", help="Automatically execute apt install/purge")

    # Single check command
    check_parser = subparsers.add_parser("check", help="Evaluate patch or purge feasibility for a package")
    check_parser.add_argument("--package", required=True, help="Package name")
    check_parser.add_argument("--version", default="1.0.0", help="Installed version")
    check_parser.add_argument("--cve", default="CVE-2024-0001", help="Associated CVE ID")

    # File evaluation command
    file_parser = subparsers.add_parser("process-file", help="Process evaluations from JSON file")
    file_parser.add_argument("file_path", help="Path to JSON file of evaluated findings")
    file_parser.add_argument("--auto-apply", action="store_true", help="Execute fixes immediately")

    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    if args.command == "serve":
        manager = RemediationManager(auto_apply=args.auto_apply)
        server = UdsPatchServer(
            socket_path=args.socket,
            downstream_socket=args.downstream,
            remediation_manager=manager,
        )
        try:
            server.start()
        except KeyboardInterrupt:
            server.stop()

    elif args.command == "check":
        finding = EvaluationInput(
            cve_id=args.cve,
            package_name=args.package,
            installed_version=args.version,
            cvss_base=7.5,
            epss_score=0.01,
            epss_percentile=0.40,
            in_memory=False,
            threat_level="MEDIUM",
            verdict_rationale="Manual CLI test",
        )
        manager = RemediationManager()
        verdict = manager.process_finding(finding)
        print(json.dumps(verdict.model_dump(), indent=2))

    elif args.command == "process-file":
        with open(args.file_path, "r", encoding="utf-8") as f:
            raw = json.load(f)

        findings = [EvaluationInput.model_validate(item) for item in (raw if isinstance(raw, list) else [raw])]
        manager = RemediationManager(auto_apply=args.auto_apply)
        results = [manager.process_finding(f).model_dump() for f in findings]
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
