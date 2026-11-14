# vuln-patch-analyst

Autonomous vulnerability remediation and safe package purge micro-agent developed under the `@oakai-security` organization.

Part of the **Autonomous Vulnerability Remediation, Exception & Governance Pipeline** ([SPEC-020](file:///home/curt/dev/docs/specs/020-vulnerability-exception-and-remediation-governance.md)).

---

## Capabilities & Architecture

Built strictly according to the **Single Responsibility Principle (SRP)**:
1. **Upstream Patch Query**: Evaluates APT repositories for available patched package versions.
2. **4-Stage Safe Purge Evaluation**: Deterministically audits reverse dependencies, simulated dry-run removals, active process memory locks, and systemd service unit dependencies before permitting any package purge.
3. **Constrained Branch Pruning**: Detects and prunes orphaned parent dependencies up to depth 1, eliminating dormant packages safely.
4. **Downstream IPC Routing**: Seamlessly forwards genuinely unfixable vulnerabilities over `/run/oakai/request.sock` to `vuln-exception-requester`.
5. **Unix Domain Socket (UDS) Server**: Exposes `/run/oakai/patch.sock` with `SO_PEERCRED` caller verification.

---

## Installation & Local Development

### Requirements
- Python 3.11+
- `uv` package manager

### Setup
```bash
# Clone and sync virtual environment
uv sync

# Run tests
uv run pytest -v

# Run linter
uv run ruff check .
```

---

## Usage

### 1. Evaluate Package Remediation
```bash
uv run vuln-patch-analyst check --package curl --version 7.88.1 --cve CVE-2024-0001
```

### 2. Batch Remediation from Evaluator Findings
```bash
uv run vuln-patch-analyst process-file evaluated_findings.json
```

### 3. Start UDS Remediation Server Daemon
```bash
uv run vuln-patch-analyst serve --socket /run/oakai/patch.sock --downstream /run/oakai/request.sock
```

---

## Container Deployment
```bash
podman build -t oakai/vuln-patch-analyst:latest .
podman run -d --name vuln-patch-analyst \
  -v /run/oakai:/run/oakai:rw \
  oakai/vuln-patch-analyst:latest
```
