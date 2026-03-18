#!/usr/bin/env bun

/**
 * deep-scan.ts — Scheduled deep scan orchestrator
 *
 * Runs thorough checks that don't belong in pre-commit:
 *   1. Semgrep (custom + community rules)
 *   2. Trivy filesystem (dependency CVEs)
 *   3. Trivy image (container image CVEs)
 *   4. Trivy config (docker-compose / Dockerfile misconfigurations)
 *   5. npm audit (supply chain)
 *   6. License compliance check
 *   7. Test coverage report
 *   8. Aggregated report + optional webhook delivery
 *
 * Usage:
 *   bun run src/tools/deep-scan.ts
 *   bun run src/tools/deep-scan.ts --target ./my-project
 *   bun run src/tools/deep-scan.ts --config ./scan-config.json
 *   bun run src/tools/deep-scan.ts --webhook https://your-endpoint/scan
 *
 * Environment variables:
 *   SECOPS_CONFIG_PATH — Path to JSON config file (overrides defaults)
 *   SECOPS_RULES_PATH — Path to semgrep rules YAML
 *   SECOPS_OUTPUT_DIR — Directory for scan reports
 *
 * Schedule with cron (nightly at 3am):
 *   0 3 * * * cd /path/to/project && bun run src/tools/deep-scan.ts >> /var/log/deep-scan.log 2>&1
 */

import { parseArgs } from "node:util";
import { computeProfile, ingest as devbrainIngest, openDb, resolveMemoryPath, updateMemoryMd } from "./devbrain.ts";

// ─── Types ──────────────────────────────────────────────────

interface ScanTarget {
	name: string;
	path: string;
	/** Which scan layers to run for this target */
	layers: Layer[];
	/** Docker images to scan (if applicable) */
	images?: string[];
	/** Paths to docker-compose / config files for trivy config scan */
	configFiles?: string[];
}

type Layer =
	| "semgrep"
	| "semgrep-community"
	| "trivy-fs"
	| "trivy-image"
	| "trivy-config"
	| "npm-audit"
	| "pip-audit"
	| "license-check"
	| "test-coverage";

interface Finding {
	layer: string;
	severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
	rule: string;
	file?: string;
	line?: number;
	message: string;
	component: string;
}

// ScanReport — also defined in devbrain.ts (wider types). Keep in sync.
interface ScanReport {
	target: string;
	timestamp: string;
	duration_ms: number;
	findings: Finding[];
	summary: {
		CRITICAL: number;
		HIGH: number;
		MEDIUM: number;
		LOW: number;
		INFO: number;
		total: number;
	};
	layer_status: Record<string, "pass" | "fail" | "skip" | "error">;
}

/**
 * Generic webhook configuration.
 * Works with any endpoint that accepts a JSON POST.
 */
interface WebhookConfig {
	/** URL to POST results to */
	url: string;
	/** Optional auth header value (sent as Authorization: Bearer <token>) */
	token?: string;
	/** Optional custom headers */
	headers?: Record<string, string>;
	/** Only send webhook when findings meet this severity or above.
	 *  Set to "INFO" to always send, "CRITICAL" to only alert on criticals.
	 *  Default: "INFO" (always send) */
	minSeverity?: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
}

interface DeepScanConfig {
	targets: ScanTarget[];
	semgrepRulesPath: string;
	outputDir: string;
	/** Optional webhooks — add as many as you want with different thresholds */
	webhooks?: WebhookConfig[];
	/** Fail the scan (exit code 1) if any finding at this severity or above */
	failThreshold: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
}

// ─── Default config ─────────────────────────────────────────
// Override with SECOPS_CONFIG_PATH env var or --config flag.
// Paths are relative to current working directory.

const DEFAULT_CONFIG: DeepScanConfig = {
	targets: [
		{
			name: "current-project",
			path: ".",
			layers: ["semgrep", "semgrep-community", "trivy-fs", "npm-audit"],
		},
	],
	semgrepRulesPath: process.env.SECOPS_RULES_PATH ?? "./config/semgrep-rules.yaml",
	outputDir: process.env.SECOPS_OUTPUT_DIR ?? "./scan-reports",
	failThreshold: "HIGH",
};

// ─── Severity helpers ────────────────────────────────────────

const SEV_RANK: Record<string, number> = {
	CRITICAL: 4,
	HIGH: 3,
	MEDIUM: 2,
	LOW: 1,
	INFO: 0,
};

const SEV_ICON: Record<string, string> = {
	CRITICAL: "🔴",
	HIGH: "🟠",
	MEDIUM: "🟡",
	LOW: "🔵",
	INFO: "⚪",
};

function mapSemgrepSeverity(sev: string): Finding["severity"] {
	const map: Record<string, Finding["severity"]> = {
		ERROR: "HIGH",
		WARNING: "MEDIUM",
		INFO: "INFO",
	};
	return map[sev] ?? "INFO";
}

function mapTrivySeverity(sev: string): Finding["severity"] {
	const upper = sev.toUpperCase();
	if (upper in SEV_RANK) return upper as Finding["severity"];
	return "INFO";
}

// ─── Shell runner ────────────────────────────────────────────

interface CmdResult {
	stdout: string;
	stderr: string;
	exitCode: number;
}

async function run(args: string[], cwd?: string): Promise<CmdResult> {
	const proc = Bun.spawn(args, {
		stdout: "pipe",
		stderr: "pipe",
		cwd,
	});

	const [stdout, stderr] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()]);

	const exitCode = await proc.exited;
	return { stdout, stderr, exitCode };
}

async function toolExists(name: string): Promise<boolean> {
	const { stdout } = await run(["which", name]);
	return stdout.trim().length > 0;
}

// ─── Layer implementations ───────────────────────────────────

async function runSemgrep(target: ScanTarget, rulesPath: string, community: boolean): Promise<Finding[]> {
	const args = ["semgrep", "--json"];

	if (community) {
		args.push("--config", "auto", "--config", rulesPath);
	} else {
		args.push("--config", rulesPath);
	}

	args.push(target.path);

	const { stdout, exitCode } = await run(args);
	if (exitCode > 1 || !stdout.trim()) return [];

	try {
		const data = JSON.parse(stdout);
		return (data.results ?? []).map(
			(r: {
				check_id: string;
				path: string;
				start: { line: number };
				extra: {
					severity: string;
					message: string;
					metadata?: { component?: string };
				};
			}) => ({
				layer: community ? "semgrep-community" : "semgrep",
				severity: mapSemgrepSeverity(r.extra.severity),
				rule: r.check_id,
				file: r.path,
				line: r.start.line,
				message: r.extra.message.trim(),
				component: r.extra.metadata?.component ?? target.name,
			}),
		);
	} catch {
		return [];
	}
}

async function runTrivyFs(target: ScanTarget): Promise<Finding[]> {
	const { stdout, exitCode } = await run([
		"trivy",
		"fs",
		"--format",
		"json",
		"--severity",
		"LOW,MEDIUM,HIGH,CRITICAL",
		target.path,
	]);

	if (exitCode > 1 || !stdout.trim()) return [];

	try {
		const data = JSON.parse(stdout);
		const findings: Finding[] = [];

		for (const result of data.Results ?? []) {
			for (const vuln of result.Vulnerabilities ?? []) {
				findings.push({
					layer: "trivy-fs",
					severity: mapTrivySeverity(vuln.Severity),
					rule: vuln.VulnerabilityID,
					file: result.Target,
					message: `${vuln.PkgName}@${vuln.InstalledVersion} → ${vuln.Title ?? vuln.VulnerabilityID}${vuln.FixedVersion ? ` (fix: ${vuln.FixedVersion})` : ""}`,
					component: target.name,
				});
			}
		}

		return findings;
	} catch {
		return [];
	}
}

async function runTrivyImage(target: ScanTarget): Promise<Finding[]> {
	const findings: Finding[] = [];

	for (const image of target.images ?? []) {
		const { stdout } = await run([
			"trivy",
			"image",
			"--format",
			"json",
			"--severity",
			"LOW,MEDIUM,HIGH,CRITICAL",
			image,
		]);

		if (!stdout.trim()) continue;

		try {
			const data = JSON.parse(stdout);
			for (const result of data.Results ?? []) {
				for (const vuln of result.Vulnerabilities ?? []) {
					findings.push({
						layer: "trivy-image",
						severity: mapTrivySeverity(vuln.Severity),
						rule: vuln.VulnerabilityID,
						file: image,
						message: `${vuln.PkgName}@${vuln.InstalledVersion} → ${vuln.Title ?? vuln.VulnerabilityID}`,
						component: target.name,
					});
				}
			}
		} catch {
			// continue to next image
		}
	}

	return findings;
}

async function runTrivyConfig(target: ScanTarget): Promise<Finding[]> {
	const findings: Finding[] = [];
	const configFiles = [...(target.configFiles ?? [])];

	// Auto-discover compose files and Dockerfiles if none specified
	if (configFiles.length === 0) {
		const { stdout } = await run([
			"find",
			target.path,
			"-maxdepth",
			"2",
			"-name",
			"docker-compose*.yml",
			"-o",
			"-name",
			"docker-compose*.yaml",
			"-o",
			"-name",
			"compose.yml",
			"-o",
			"-name",
			"Dockerfile",
		]);
		configFiles.push(
			...stdout
				.trim()
				.split("\n")
				.filter((f) => f.length > 0),
		);
	}

	for (const configFile of configFiles) {
		const { stdout } = await run([
			"trivy",
			"config",
			"--format",
			"json",
			"--severity",
			"LOW,MEDIUM,HIGH,CRITICAL",
			configFile,
		]);

		if (!stdout.trim()) continue;

		try {
			const data = JSON.parse(stdout);
			for (const result of data.Results ?? []) {
				for (const misconfig of result.Misconfigurations ?? []) {
					findings.push({
						layer: "trivy-config",
						severity: mapTrivySeverity(misconfig.Severity),
						rule: misconfig.ID ?? misconfig.AVDID ?? "trivy-misconfig",
						file: configFile,
						line: misconfig.CauseMetadata?.StartLine,
						message: `${misconfig.Title}: ${misconfig.Message ?? misconfig.Description ?? ""}`.slice(0, 200),
						component: target.name,
					});
				}
			}
		} catch {
			// continue to next file
		}
	}

	return findings;
}

async function runNpmAudit(target: ScanTarget): Promise<Finding[]> {
	const { stdout } = await run(["npm", "audit", "--json", "--omit=dev"], target.path);

	if (!stdout.trim()) return [];

	try {
		const data = JSON.parse(stdout);
		const findings: Finding[] = [];

		const vulns = data.vulnerabilities ?? {};
		for (const [pkg, info] of Object.entries<{
			severity: string;
			via: Array<{ title?: string; url?: string } | string>;
			fixAvailable?: boolean | { name: string; version: string };
		}>(
			vulns as Record<
				string,
				{
					severity: string;
					via: Array<{ title?: string; url?: string } | string>;
					fixAvailable?: boolean | { name: string; version: string };
				}
			>,
		)) {
			const firstVia = info.via?.[0];
			const title = typeof firstVia === "object" ? (firstVia.title ?? pkg) : pkg;

			findings.push({
				layer: "npm-audit",
				severity: mapTrivySeverity(info.severity),
				rule: `npm-vuln-${pkg}`,
				file: "package.json",
				message: `${pkg}: ${title}${info.fixAvailable ? " (fix available)" : ""}`,
				component: target.name,
			});
		}

		return findings;
	} catch {
		return [];
	}
}

async function runPipAudit(target: ScanTarget): Promise<Finding[]> {
	const { stdout } = await run(["pip-audit", "--format", "json", "--desc"], target.path);

	if (!stdout.trim()) return [];

	try {
		const data = JSON.parse(stdout);
		const findings: Finding[] = [];

		for (const vuln of data.dependencies ?? []) {
			for (const v of vuln.vulns ?? []) {
				findings.push({
					layer: "pip-audit",
					severity: v.fix_versions?.length ? "HIGH" : "MEDIUM",
					rule: v.id,
					file: "requirements.txt",
					message: `${vuln.name}@${vuln.version}: ${v.description?.slice(0, 120) ?? v.id}`,
					component: target.name,
				});
			}
		}

		return findings;
	} catch {
		return [];
	}
}

async function runLicenseCheck(target: ScanTarget): Promise<Finding[]> {
	const findings: Finding[] = [];

	const problematic = [
		"GPL-2.0",
		"GPL-3.0",
		"AGPL-3.0",
		"LGPL-2.1",
		"LGPL-3.0",
		"SSPL-1.0",
		"BSL-1.1",
		"EUPL-1.2",
		"CPAL-1.0",
		"OSL-3.0",
	];

	const hasPackageJson = await Bun.file(`${target.path}/package.json`).exists();
	if (hasPackageJson) {
		const { stdout } = await run(["npx", "license-checker", "--json", "--production"], target.path);

		if (stdout.trim()) {
			try {
				const data = JSON.parse(stdout);
				for (const [pkg, info] of Object.entries<{ licenses?: string }>(
					data as Record<string, { licenses?: string }>,
				)) {
					const license = info.licenses ?? "UNKNOWN";
					if (problematic.some((p) => license.toUpperCase().includes(p)) || license === "UNKNOWN") {
						findings.push({
							layer: "license-check",
							severity: license === "UNKNOWN" ? "MEDIUM" : "LOW",
							rule: `license-${license}`,
							file: "package.json",
							message: `${pkg}: ${license} license detected`,
							component: target.name,
						});
					}
				}
			} catch {
				// skip
			}
		}
	}

	const hasRequirements = await Bun.file(`${target.path}/requirements.txt`).exists();
	if (hasRequirements) {
		const { stdout } = await run(["pip-licenses", "--format=json", "--with-urls"], target.path);

		if (stdout.trim()) {
			try {
				const data = JSON.parse(stdout) as Array<{
					Name: string;
					License: string;
				}>;
				for (const pkg of data) {
					if (problematic.some((p) => pkg.License.toUpperCase().includes(p)) || pkg.License === "UNKNOWN") {
						findings.push({
							layer: "license-check",
							severity: pkg.License === "UNKNOWN" ? "MEDIUM" : "LOW",
							rule: `license-${pkg.License}`,
							file: "requirements.txt",
							message: `${pkg.Name}: ${pkg.License} license detected`,
							component: target.name,
						});
					}
				}
			} catch {
				// skip
			}
		}
	}

	return findings;
}

async function runTestCoverage(target: ScanTarget): Promise<Finding[]> {
	const findings: Finding[] = [];

	const hasPackageJson = await Bun.file(`${target.path}/package.json`).exists();
	const hasPyproject = await Bun.file(`${target.path}/pyproject.toml`).exists();

	if (hasPackageJson) {
		const pkg = await Bun.file(`${target.path}/package.json`).json();
		const testCmd = pkg.scripts?.test;

		if (testCmd) {
			const { exitCode, stderr } = await run(["bun", "run", "test", "--", "--coverage"], target.path);

			if (exitCode !== 0) {
				findings.push({
					layer: "test-coverage",
					severity: "HIGH",
					rule: "tests-failing",
					message: `Tests failed with exit code ${exitCode}: ${stderr.slice(0, 200)}`,
					component: target.name,
				});
			}
		} else {
			findings.push({
				layer: "test-coverage",
				severity: "MEDIUM",
				rule: "no-test-script",
				message: "No test script defined in package.json",
				component: target.name,
			});
		}
	}

	if (hasPyproject) {
		const { exitCode, stderr } = await run(["python", "-m", "pytest", "--tb=short", "-q"], target.path);

		if (exitCode !== 0) {
			findings.push({
				layer: "test-coverage",
				severity: "HIGH",
				rule: "tests-failing",
				message: `pytest failed with exit code ${exitCode}: ${stderr.slice(0, 200)}`,
				component: target.name,
			});
		}
	}

	return findings;
}

// ─── Layer dispatcher ────────────────────────────────────────

const LAYER_RUNNERS: Record<Layer, (target: ScanTarget, config: DeepScanConfig) => Promise<Finding[]>> = {
	semgrep: (t, c) => runSemgrep(t, c.semgrepRulesPath, false),
	"semgrep-community": (t, c) => runSemgrep(t, c.semgrepRulesPath, true),
	"trivy-fs": (t) => runTrivyFs(t),
	"trivy-image": (t) => runTrivyImage(t),
	"trivy-config": (t) => runTrivyConfig(t),
	"npm-audit": (t) => runNpmAudit(t),
	"pip-audit": (t) => runPipAudit(t),
	"license-check": (t) => runLicenseCheck(t),
	"test-coverage": (t, _c) => runTestCoverage(t),
};

const LAYER_TOOLS: Record<string, string> = {
	semgrep: "semgrep",
	"semgrep-community": "semgrep",
	"trivy-fs": "trivy",
	"trivy-image": "trivy",
	"trivy-config": "trivy",
	"npm-audit": "npm",
	"pip-audit": "pip-audit",
	"license-check": "npx",
	"test-coverage": "bun",
};

// ─── Scan executor ───────────────────────────────────────────

async function scanTarget(target: ScanTarget, config: DeepScanConfig): Promise<ScanReport> {
	const start = Date.now();
	const findings: Finding[] = [];
	const layerStatus: Record<string, "pass" | "fail" | "skip" | "error"> = {};

	console.log(`\n${"═".repeat(60)}`);
	console.log(`  Scanning: ${target.name}`);
	console.log(`  Path:     ${target.path}`);
	console.log(`  Layers:   ${target.layers.join(", ")}`);
	console.log(`${"═".repeat(60)}\n`);

	for (const layer of target.layers) {
		const toolName = LAYER_TOOLS[layer];
		const hasIt = toolName ? await toolExists(toolName) : true;

		if (!hasIt) {
			console.log(`  ⏭️  ${layer}: skipped (${toolName} not installed)`);
			layerStatus[layer] = "skip";
			continue;
		}

		process.stdout.write(`  🔄 ${layer}: running...`);

		try {
			const layerFindings = await LAYER_RUNNERS[layer](target, config);
			findings.push(...layerFindings);

			const hasIssues = layerFindings.length > 0;
			layerStatus[layer] = hasIssues ? "fail" : "pass";

			const icon = hasIssues ? "⚠️ " : "✅";
			console.log(`\r  ${icon} ${layer}: ${layerFindings.length} finding(s)`);
		} catch (err) {
			layerStatus[layer] = "error";
			console.log(`\r  ❌ ${layer}: error — ${err}`);
		}
	}

	const summary = {
		CRITICAL: 0,
		HIGH: 0,
		MEDIUM: 0,
		LOW: 0,
		INFO: 0,
		total: 0,
	};
	for (const f of findings) {
		summary[f.severity]++;
		summary.total++;
	}

	return {
		target: target.name,
		timestamp: new Date().toISOString(),
		duration_ms: Date.now() - start,
		findings,
		summary,
		layer_status: layerStatus,
	};
}

// ─── Report formatters ───────────────────────────────────────

function formatReport(reports: ScanReport[]): string {
	const lines: string[] = [];
	const totalFindings = reports.reduce((n, r) => n + r.summary.total, 0);

	lines.push("");
	lines.push("╔══════════════════════════════════════════════════════════╗");
	lines.push("║             CODE GUARDIAN DEEP SCAN                      ║");
	lines.push(`║           ${new Date().toISOString().slice(0, 19).replace("T", " ")}                    ║`);
	lines.push("╚══════════════════════════════════════════════════════════╝");
	lines.push("");

	const agg = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
	for (const r of reports) {
		for (const sev of Object.keys(agg) as Array<keyof typeof agg>) {
			agg[sev] += r.summary[sev];
		}
	}

	lines.push("SUMMARY");
	lines.push("─".repeat(40));
	for (const [sev, count] of Object.entries(agg)) {
		const icon = SEV_ICON[sev] ?? "•";
		const bar = "█".repeat(Math.min(count, 40));
		lines.push(`  ${icon} ${sev.padEnd(10)} ${String(count).padStart(4)}  ${bar}`);
	}
	lines.push(`${"─".repeat(40)}`);
	lines.push(`  Total: ${totalFindings} findings across ${reports.length} target(s)`);
	lines.push("");

	for (const report of reports) {
		lines.push(`┌── ${report.target} (${(report.duration_ms / 1000).toFixed(1)}s) ──`);

		for (const [layer, status] of Object.entries(report.layer_status)) {
			const statusIcon = status === "pass" ? "✅" : status === "fail" ? "⚠️ " : status === "skip" ? "⏭️ " : "❌";
			lines.push(`│  ${statusIcon} ${layer}: ${status}`);
		}

		const sorted = [...report.findings].sort((a, b) => (SEV_RANK[b.severity] ?? 0) - (SEV_RANK[a.severity] ?? 0));
		const top = sorted.slice(0, 15);

		if (top.length > 0) {
			lines.push("│");
			lines.push("│  Findings:");
			for (const f of top) {
				const icon = SEV_ICON[f.severity];
				const loc = f.file ? `${f.file}${f.line ? `:${f.line}` : ""}` : "";
				lines.push(`│    ${icon} [${f.severity}] ${f.rule}`);
				if (loc) lines.push(`│       ${loc}`);
				lines.push(`│       ${f.message.slice(0, 100)}`);
			}

			if (sorted.length > 15) {
				lines.push(`│    ... and ${sorted.length - 15} more`);
			}
		}

		lines.push(`└${"─".repeat(58)}`);
		lines.push("");
	}

	return lines.join("\n");
}

// ─── Generic webhook delivery ────────────────────────────────

function computePriorityScore(reports: ScanReport[]): number {
	let score = 0;
	for (const r of reports) {
		score += r.summary.CRITICAL * 10;
		score += r.summary.HIGH * 5;
		score += r.summary.MEDIUM * 2;
		score += r.summary.LOW * 1;
	}
	return score;
}

function highestSeverity(reports: ScanReport[]): Finding["severity"] {
	for (const sev of ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const) {
		if (reports.some((r) => r.summary[sev] > 0)) return sev;
	}
	return "INFO";
}

async function sendWebhooks(config: DeepScanConfig, reports: ScanReport[]): Promise<void> {
	if (!config.webhooks?.length) return;

	const agg = {
		CRITICAL: 0,
		HIGH: 0,
		MEDIUM: 0,
		LOW: 0,
		INFO: 0,
		total: 0,
	};
	for (const r of reports) {
		for (const sev of ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const) {
			agg[sev] += r.summary[sev];
		}
		agg.total += r.summary.total;
	}

	const highest = highestSeverity(reports);
	const priorityScore = computePriorityScore(reports);

	const payload = {
		scan: "code-guardian-deep-scan",
		timestamp: new Date().toISOString(),
		status: agg.total === 0 ? "clean" : highest === "CRITICAL" ? "critical" : highest === "HIGH" ? "warning" : "info",
		priority_score: priorityScore,
		summary: agg,
		targets: reports.map((r) => ({
			name: r.target,
			duration_ms: r.duration_ms,
			summary: r.summary,
			layer_status: r.layer_status,
			top_findings: r.findings
				.sort((a, b) => (SEV_RANK[b.severity] ?? 0) - (SEV_RANK[a.severity] ?? 0))
				.slice(0, 5)
				.map((f) => ({
					severity: f.severity,
					rule: f.rule,
					file: f.file,
					line: f.line,
					message: f.message.slice(0, 150),
				})),
		})),
	};

	for (const wh of config.webhooks) {
		const minRank = SEV_RANK[wh.minSeverity ?? "INFO"] ?? 0;
		const highestRank = SEV_RANK[highest] ?? 0;

		if (highestRank < minRank) {
			console.log(`📡 ${wh.url}: skipped (highest severity ${highest} below threshold ${wh.minSeverity})`);
			continue;
		}

		const headers: Record<string, string> = {
			"Content-Type": "application/json",
			...(wh.headers ?? {}),
		};
		if (wh.token) {
			headers.Authorization = `Bearer ${wh.token}`;
		}

		try {
			const resp = await fetch(wh.url, {
				method: "POST",
				headers,
				body: JSON.stringify(payload),
			});
			console.log(resp.ok ? `📡 ${wh.url}: delivered (${resp.status})` : `📡 ${wh.url}: failed (${resp.status})`);
		} catch (err) {
			console.error(`📡 ${wh.url}: error —`, err);
		}
	}
}

// ─── Main ────────────────────────────────────────────────────

async function main() {
	const { values } = parseArgs({
		args: Bun.argv.slice(2),
		options: {
			config: { type: "string", short: "c" },
			target: { type: "string", short: "t" },
			webhook: { type: "string", short: "w" },
			"webhook-token": { type: "string" },
			"fail-threshold": { type: "string", default: "HIGH" },
			help: { type: "boolean", short: "h", default: false },
		},
		strict: true,
	});

	if (values.help) {
		console.log(`
deep-scan.ts — Code Guardian deep scan orchestrator

Usage:
  bun run src/tools/deep-scan.ts [options]

Options:
  -c, --config <path>         Path to config file (TypeScript export default)
  -t, --target <dir>          Quick scan a single directory (all layers)
  -w, --webhook <url>         POST results to a webhook URL
      --webhook-token <tok>   Bearer token for webhook auth
      --fail-threshold <sev>  CRITICAL, HIGH, MEDIUM, LOW (default: HIGH)
  -h, --help                  Show this help
`);
		process.exit(0);
	}

	let config = { ...DEFAULT_CONFIG };

	if (values.config) {
		try {
			const loaded = await import(values.config);
			config = { ...DEFAULT_CONFIG, ...loaded.default };
		} catch (err) {
			console.error(`Failed to load config: ${err}`);
			process.exit(1);
		}
	}

	if (values.target) {
		config.targets = [
			{
				name: "cli-target",
				path: values.target,
				layers: [
					"semgrep",
					"semgrep-community",
					"trivy-fs",
					"trivy-config",
					"npm-audit",
					"pip-audit",
					"license-check",
					"test-coverage",
				],
			},
		];
	}

	if (values.webhook) {
		config.webhooks = [
			{
				url: values.webhook,
				token: values["webhook-token"],
				minSeverity: "INFO",
			},
		];
	}

	if (values["fail-threshold"]) {
		config.failThreshold = values["fail-threshold"].toUpperCase() as DeepScanConfig["failThreshold"];
	}

	// Check for required tools
	console.log("🔧 Checking tools...\n");
	const tools = ["semgrep", "trivy", "npm", "bun", "pip-audit"];
	for (const tool of tools) {
		const has = await toolExists(tool);
		console.log(`  ${has ? "✅" : "⚠️ "} ${tool}: ${has ? "found" : "not found (some layers will be skipped)"}`);
	}

	// Run scans
	const reports: ScanReport[] = [];
	for (const target of config.targets) {
		const report = await scanTarget(target, config);
		reports.push(report);
	}

	// Output report
	const reportText = formatReport(reports);
	console.log(reportText);

	// Save reports to disk
	const reportDir = config.outputDir;
	await Bun.spawn(["mkdir", "-p", reportDir]).exited;

	const dateStr = new Date().toISOString().slice(0, 10);
	await Bun.write(`${reportDir}/scan-${dateStr}.json`, JSON.stringify(reports, null, 2));
	await Bun.write(`${reportDir}/scan-${dateStr}.txt`, reportText);

	console.log(`\n📄 Reports saved to ${reportDir}/`);

	// DevBrain: ingest findings, update MEMORY.md.
	// Each report is wrapped in a db.transaction() inside ingest(), so individual
	// report failures are atomic. A failure here is non-fatal — scan results are
	// already saved to disk above.
	try {
		// DB path uses reportDir so it's co-located with scan reports.
		// Use DEVBRAIN_DB env var to override to a stable path if outputDir varies.
		const db = openDb(`${reportDir}/devbrain.db`);
		devbrainIngest(db, reports);
		const profile = computeProfile(db, 30);
		await updateMemoryMd(resolveMemoryPath(), profile);
		console.log("🧠 DevBrain: MEMORY.md updated.");
	} catch (err) {
		console.warn(`⚠️  DevBrain ingest failed (non-fatal): ${err}`);
	}

	await sendWebhooks(config, reports);

	const threshold = SEV_RANK[config.failThreshold] ?? 3;
	const hasBlocking = reports.some((r) => r.findings.some((f) => (SEV_RANK[f.severity] ?? 0) >= threshold));

	if (hasBlocking) {
		console.log(`\n❌ Findings at or above ${config.failThreshold} threshold — exiting with code 1`);
		process.exit(1);
	} else {
		console.log("\n✅ No blocking findings. All clear!");
		process.exit(0);
	}
}

main();
