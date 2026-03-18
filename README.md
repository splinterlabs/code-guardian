# Code Guardian

Reusable security scanning workflows and tools for CI/CD pipelines.

## What This Is

A **generic security toolkit** for any codebase:
- Reusable GitHub Actions workflows (Gitleaks, Semgrep, Trivy, Nuclei)
- Deep scan orchestrator for scheduled security audits
- DevBrain for tracking security findings over time
- GitOps compliance checker for Docker/Compose files
- Custom Semgrep rules for TypeScript, Python, and infrastructure code

## What This Is NOT

- **Not runtime protection** — no WAF, RASP, or live threat blocking
- **Not vulnerability management** — no ticketing, SLAs, or remediation tracking (use DefectDojo, Snyk, etc.)
- **Not secrets management** — no credential storage or rotation (use Vault, 1Password, etc.)
- **Not pentesting** — automated scanning only, no manual exploitation or red team tooling
- **Not compliance certification** — helps with checks but doesn't generate SOC2/ISO reports

## Quick Start

### Using the Reusable Workflows

Add to your repo's `.github/workflows/security.yml`:

```yaml
name: Security

on:
  push:
    branches: [main]
  pull_request:

jobs:
  secrets:
    uses: splinterlabs/code-guardian/.github/workflows/gitleaks.yml@main

  sast:
    uses: splinterlabs/code-guardian/.github/workflows/semgrep.yml@main
    with:
      config: 'p/default'
      severity: 'WARNING'

  dependencies:
    uses: splinterlabs/code-guardian/.github/workflows/dependency-audit.yml@main

  containers:
    uses: splinterlabs/code-guardian/.github/workflows/trivy-scan.yml@main
```

### Available Workflows

| Workflow | Purpose | Key Options |
|----------|---------|-------------|
| `gitleaks.yml` | Secret detection in commits | `scan_depth`, `fail_on_leak` |
| `semgrep.yml` | Static analysis (SAST) | `config`, `severity`, `scan_changed_only` |
| `trivy-scan.yml` | Container & dependency CVEs | `severity`, `ignore_unfixed` |
| `nuclei-scan.yml` | Dynamic testing (DAST) | `target_url`, `severity`, `template_tags` |
| `dependency-audit.yml` | npm/pip vulnerability audit | `fail_on_vulnerabilities` |
| `biome.yml` | Linting & formatting | `paths` |

### Running Deep Scans Locally

```bash
# Install
bun install

# Scan current directory
bun run src/tools/deep-scan.ts

# Scan specific project
bun run src/tools/deep-scan.ts --target /path/to/project

# With webhook notification
bun run src/tools/deep-scan.ts --webhook https://your-endpoint/scan
```

## Tools Included

### deep-scan.ts
Orchestrates multiple security scanners in one run:
- Semgrep (custom + community rules)
- Trivy (filesystem, images, config)
- npm/pip audit
- License compliance
- Test coverage

### devbrain.ts
Tracks security findings over time in SQLite:
- Ingests scan reports
- Detects regressions (new findings on previously-clean files)
- Computes "AI Code Patterns" profile for MEMORY.md
- Surfaces hotspots and trends

### semgrep-scan.ts
Standalone Semgrep wrapper with:
- Custom rules from `config/semgrep-rules.yaml`
- Formatted console output
- Webhook delivery

### gitops-compliance.ts
Validates Docker Compose files against policies:
- Detects hardcoded secrets
- Enforces trusted registries
- Checks for privileged containers

## Configuration

### Custom Semgrep Rules
Edit `config/semgrep-rules.yaml` to add project-specific patterns.

### Compliance Whitelist
Edit `config/compliance-whitelist.yml` to allow specific env vars and registries.

### Deep Scan Config
Create a config file:
```typescript
export default {
  targets: [
    { name: 'api', path: './api', layers: ['semgrep', 'trivy-fs', 'npm-audit'] },
    { name: 'infra', path: './infra', layers: ['trivy-config'] },
  ],
  failThreshold: 'HIGH',
  webhooks: [{ url: 'https://...', minSeverity: 'HIGH' }],
};
```

Run with: `bun run src/tools/deep-scan.ts --config ./scan-config.ts`

## License

MIT
