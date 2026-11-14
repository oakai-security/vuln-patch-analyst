"""Unix Domain Socket server accepting evaluated findings and routing unresolved CVEs."""

import json
import logging
import os
import socket
import struct
from pathlib import Path

from pydantic import ValidationError

from .remediation_manager import RemediationManager
from .schemas import EvaluationInput, RemediationVerdict

logger = logging.getLogger(__name__)

DEFAULT_PATCH_SOCKET = os.environ.get("UDS_PATCH_SOCKET", "/run/oakai/patch.sock")
DEFAULT_REQUEST_SOCKET = os.environ.get("UDS_REQUEST_SOCKET", "/run/oakai/request.sock")


class UdsPatchServer:
    """UDS server coordinating remediation and downstream exception routing."""

    def __init__(
        self,
        socket_path: str = DEFAULT_PATCH_SOCKET,
        downstream_socket: str = DEFAULT_REQUEST_SOCKET,
        remediation_manager: RemediationManager | None = None,
    ):
        self.socket_path = socket_path
        self.downstream_socket = downstream_socket
        self.remediation_manager = remediation_manager or RemediationManager()
        self._running = False
        self._server_socket: socket.socket | None = None

    def start(self, max_connections: int = 5):
        """Bind server socket and process incoming finding payloads."""
        sock_file = Path(self.socket_path)
        sock_file.parent.mkdir(parents=True, exist_ok=True)

        if sock_file.exists():
            try:
                sock_file.unlink()
            except OSError as err:
                logger.warning("Failed to unlink stale socket %s: %s", self.socket_path, err)

        self._server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server_socket.bind(self.socket_path)

        try:
            os.chmod(self.socket_path, 0o660)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        except OSError as err:
            logger.warning("Could not set socket permissions to 0660: %s", err)

        self._server_socket.listen(max_connections)
        self._running = True
        logger.info("vuln-patch-analyst UDS server listening on %s", self.socket_path)

        while self._running:
            try:
                conn, _ = self._server_socket.accept()
                self._handle_client(conn)
            except (OSError, KeyboardInterrupt) as err:
                if self._running:
                    logger.error("Socket error: %s", err)
                break

    def stop(self):
        """Stop server and clean up socket inode."""
        self._running = False
        if self._server_socket:
            try:
                self._server_socket.close()
            except OSError:
                pass
        if os.path.exists(self.socket_path):
            try:
                os.unlink(self.socket_path)
            except OSError:
                pass
        logger.info("vuln-patch-analyst UDS server stopped")

    def _handle_client(self, conn: socket.socket):
        """Process incoming findings, remediate or forward, and return response."""
        with conn:
            peer_info = self._get_peer_credentials(conn)
            logger.info("Accepted connection from: %s", peer_info)

            buffer = []
            while True:
                chunk = conn.recv(8192)
                if not chunk:
                    break
                buffer.append(chunk.decode("utf-8", errors="ignore"))

            raw_body = "".join(buffer).strip()
            if not raw_body:
                return

            try:
                parsed = json.loads(raw_body)
                findings: list[EvaluationInput] = []

                if isinstance(parsed, list):
                    findings = [EvaluationInput.model_validate(item) for item in parsed]
                elif isinstance(parsed, dict):
                    findings = [EvaluationInput.model_validate(parsed)]

                verdicts: list[RemediationVerdict] = []
                unresolved_to_forward: list[dict] = []

                for finding in findings:
                    verdict = self.remediation_manager.process_finding(finding)
                    verdicts.append(verdict)

                    if verdict.status == "UNRESOLVED_FORWARD":
                        unresolved_to_forward.append(
                            {
                                "finding": finding.model_dump(),
                                "remediation": verdict.model_dump(),
                            }
                        )

                # Route unfixable CVEs downstream to Exception Requester
                if unresolved_to_forward and os.path.exists(self.downstream_socket):
                    self._forward_to_exception_requester(unresolved_to_forward)

                response_payload = [v.model_dump() for v in verdicts]
                conn.sendall(json.dumps(response_payload, indent=2).encode("utf-8"))

            except (json.JSONDecodeError, ValidationError, KeyError, OSError, TypeError, ValueError) as err:
                logger.error("Error processing remediation request: %s", err)
                conn.sendall(json.dumps({"error": str(err)}).encode("utf-8"))

    def _forward_to_exception_requester(self, payload: list[dict]):
        """Transmit unresolved vulnerabilities over UDS to vuln-exception-requester."""
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(self.downstream_socket)
                client.sendall(json.dumps(payload).encode("utf-8"))
                client.shutdown(socket.SHUT_WR)
                logger.info("Forwarded %d unfixable CVEs to exception requester", len(payload))
        except OSError as err:
            logger.warning("Downstream requester socket %s unreachable: %s", self.downstream_socket, err)

    def _get_peer_credentials(self, conn: socket.socket) -> str:
        """Inspect SO_PEERCRED on Linux."""
        try:
            creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            pid, uid, gid = struct.unpack("3i", creds)
            return f"PID={pid}, UID={uid}, GID={gid}"
        except (AttributeError, OSError):
            return "unknown (SO_PEERCRED unavailable)"
