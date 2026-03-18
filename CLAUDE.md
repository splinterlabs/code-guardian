# SecOps Toolkit

Security operations plugin for Claude Code providing SAST scanning, vulnerability tracking, and compliance checking.

## Tools

| Tool | Command | Purpose |
|------|---------|---------|
| Deep Scan | `bun run src/tools/deep-scan.ts` | Full security scan (semgrep, trivy, npm audit) |
| Semgrep | `bun run src/tools/semgrep-scan.ts` | Ad-hoc SAST scanning |
| DevBrain | `bun run src/tools/devbrain.ts` | Security findings memory/tracker |
| GitOps Compliance | `bun run src/tools/gitops-compliance.ts` | IP hardcoding detector |

## Quick Commands

```bash
# Run full scan on current directory
bun run scan

# Check for hardcoded IPs
bun run src/tools/gitops-compliance.ts .

# View security findings status
bun run devbrain status

# Acknowledge false positive
bun run devbrain ack <fingerprint> --reason "..."
```

## Configuration

- `config/semgrep-rules.yaml` — Custom semgrep rules
- `config/compliance-whitelist.yml` — IP compliance exceptions

## Environment Variables

- `SECOPS_CONFIG_PATH` — Path to scan config JSON
- `SECOPS_RULES_PATH` — Path to semgrep rules
- `SECOPS_OUTPUT_DIR` — Scan report output directory
