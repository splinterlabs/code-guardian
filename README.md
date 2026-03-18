# Code Guardian

CI/CD-focused security toolkit that shifts security scanning left in the development pipeline.

## What This Is

A **generic security toolkit** for any codebase:

- **Reusable GitHub Actions Workflows** — Drop-in security workflows you can call from any repo
- **Deep Scan Orchestrator** — Multi-tool scheduled security audits
- **DevBrain** — Security findings memory that tracks issues over time and detects regressions
- **GitOps Compliance Checker** — Policy enforcement for Docker Compose files
- **Custom Semgrep Rules** — AI-aware patterns for TypeScript, Python, and infrastructure

## What This Is NOT

- **Not runtime protection** — No WAF, RASP, or live threat blocking
- **Not vulnerability management** — No ticketing, SLAs, or remediation tracking (use DefectDojo, Snyk, etc.)
- **Not secrets management** — No credential storage or rotation (use Vault, 1Password, etc.)
- **Not pentesting** — Automated scanning only, no manual exploitation or red team tooling
- **Not compliance certification** — Helps with checks but doesn't generate SOC2/ISO reports

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

| Workflow | Scanner | Purpose | Key Options |
|----------|---------|---------|-------------|
| `gitleaks.yml` | Gitleaks | Secret detection in git history | `scan_depth`, `fail_on_leak` |
| `semgrep.yml` | Semgrep | SAST — code security patterns | `config`, `severity`, `scan_changed_only` |
| `trivy-scan.yml` | Trivy | Container/dependency CVEs | `severity`, `ignore_unfixed` |
| `nuclei-scan.yml` | Nuclei | DAST — dynamic endpoint testing | `target_url`, `severity`, `template_tags` |
| `dependency-audit.yml` | npm/pip | Supply chain vulnerabilities | `fail_on_vulnerabilities` |
| `biome.yml` | Biome | Code quality/formatting | `paths` |

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

## Components

### Deep Scan (`deep-scan.ts`)

Orchestrates 8 scan layers in one run:

| Layer | Tool | What It Checks |
|-------|------|----------------|
| `semgrep` | Semgrep | Custom security rules |
| `semgrep-community` | Semgrep | Community rulesets (p/default, etc.) |
| `trivy-fs` | Trivy | Dependency CVEs in filesystem |
| `trivy-image` | Trivy | Container image CVEs |
| `trivy-config` | Trivy | Dockerfile/Compose misconfigurations |
| `npm-audit` | npm | JavaScript supply chain |
| `pip-audit` | pip-audit | Python supply chain |
| `license-check` | license-checker | GPL/AGPL/copyleft detection |
| `test-coverage` | bun/pytest | Test suite health |

Features:
- Configurable per-target layers
- Webhook delivery with severity thresholds
- Exit code based on configurable fail threshold
- Auto-updates MEMORY.md with findings profile

### DevBrain (`devbrain.ts`)

SQLite-backed security findings tracker:

```bash
# Show open findings
bun run src/tools/devbrain.ts status

# Show findings by severity
bun run src/tools/devbrain.ts status --severity HIGH

# AI behavior profile (last 30 days)
bun run src/tools/devbrain.ts profile

# Show recurring issues (regressions)
bun run src/tools/devbrain.ts regressions

# Acknowledge false positive
bun run src/tools/devbrain.ts ack <fingerprint> --reason "Known safe" --expires 90d
```

Finding lifecycle: `new → open → fixed` or `regression`

DevBrain detects when previously-fixed issues reappear and generates an "AI Code Patterns" section for Claude's MEMORY.md showing top recurring rules and hotspots.

### GitOps Compliance (`gitops-compliance.ts`)

Scans Docker Compose files for policy violations:

```bash
# Check a directory
bun run src/tools/gitops-compliance.ts ./stacks

# Strict mode (warnings become errors)
bun run src/tools/gitops-compliance.ts ./stacks --strict
```

**Checks:**
- Hardcoded secrets in environment variables
- Images from non-whitelisted registries
- Node.js containers with <128MB memory (silent OOM risk)
- Traefik middlewares missing `@docker` suffix
- Relative bind mounts (Portainer-incompatible)
- Postgres data directory sub-mounts
- Heredoc quoting that blocks env var expansion

### Custom Semgrep Rules

30+ rules in `config/semgrep-rules.yaml`:

**Security:**
- Hardcoded API keys/secrets
- Unsafe `eval`/`exec` (Python)
- Unsafe deserialization (`pickle`, `yaml.load`)
- Shell injection (`Bun.spawn` with user input)
- Privileged Docker containers
- Ports bound to `0.0.0.0`

**AI Code Quality** (catches common LLM hallucinations):
- Network calls without `try-except`
- Broad `except Exception` handlers
- Deprecated `datetime.utcnow()`
- `fetch()` without `response.ok` check
- String formatting in logging calls

**Infrastructure:**
- `:latest` image tags
- Missing healthchecks
- Containers running as root
- Missing `read_only` rootfs

## Configuration

### Custom Semgrep Rules

Edit `config/semgrep-rules.yaml` to add project-specific patterns.

### Compliance Whitelist

Edit `config/compliance-whitelist.yml` to allow specific env vars and registries.

### Deep Scan Config

Create a config file for multi-target scans:

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

## Architecture

```
code-guardian/
├── .github/workflows/       # Reusable CI workflows
│   ├── gitleaks.yml         # Secret detection
│   ├── semgrep.yml          # SAST scanning
│   ├── trivy-scan.yml       # Container/dependency CVEs
│   ├── nuclei-scan.yml      # DAST scanning
│   └── dependency-audit.yml # Supply chain audit
├── src/tools/
│   ├── deep-scan.ts         # Multi-scanner orchestrator
│   ├── devbrain.ts          # Findings tracker + MEMORY.md
│   ├── semgrep-scan.ts      # Standalone Semgrep wrapper
│   └── gitops-compliance.ts # Compose file policy checker
├── config/
│   ├── semgrep-rules.yaml   # Custom + AI-aware rules
│   └── compliance-whitelist.yml
└── tests/
```

## Design Philosophy

1. **CI-first** — Everything designed to run in GitHub Actions or cron jobs
2. **Modular** — Use individual workflows or the full deep-scan orchestration
3. **AI-aware** — Rules specifically target common LLM-generated code patterns
4. **Memory** — DevBrain tracks findings over time, surfaces regressions
5. **Policy-as-code** — GitOps compliance enforces standards declaratively

## License

MIT
