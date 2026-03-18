#!/usr/bin/env bun

/**
 * semgrep-scan.ts — Ad-hoc Semgrep scan wrapper
 *
 * Runs Semgrep with custom rules + optional auto config, parses
 * JSON output, and formats results for the console or a webhook.
 *
 * Usage:
 *   bun run src/tools/semgrep-scan.ts [target-dir]
 *   bun run src/tools/semgrep-scan.ts --target /path/to/project --severity ERROR
 *   bun run src/tools/semgrep-scan.ts --auto --format json .
 */

import { parseArgs } from "node:util";

// ─── Configuration ──────────────────────────────────────────

interface ScanConfig {
	/** Directory to scan */
	target: string;
	/** Path to custom rules YAML */
	rulesPath: string;
	/** Also run semgrep --config auto (community rules) */
	includeAuto: boolean;
	/** Minimum severity to report: INFO | WARNING | ERROR */
	minSeverity: "INFO" | "WARNING" | "ERROR";
	/** Output format */
	format: "pretty" | "json" | "summary";
	/** Optional webhook URL to POST results to */
	webhookUrl?: string;
	/** Optional webhook bearer token */
	webhookToken?: string;
}

const SEVERITY_RANK: Record<string, number> = {
	INFO: 0,
	WARNING: 1,
	ERROR: 2,
};

const SEVERITY_ICON: Record<string, string> = {
	INFO: "ℹ️ ",
	WARNING: "⚠️ ",
	ERROR: "🚨",
};

// ─── Types for Semgrep JSON output ──────────────────────────

interface SemgrepResult {
	check_id: string;
	path: string;
	start: { line: number; col: number };
	end: { line: number; col: number };
	extra: {
		message: string;
		severity: string;
		metadata?: {
			category?: string;
			component?: string;
			[key: string]: unknown;
		};
		lines?: string;
	};
}

interface SemgrepOutput {
	results: SemgrepResult[];
	errors: Array<{ message: string; level: string }>;
	version?: string;
}

// ─── Argument parsing ───────────────────────────────────────

function parseConfig(): ScanConfig {
	const { values, positionals } = parseArgs({
		args: Bun.argv.slice(2),
		options: {
			target: { type: "string", short: "t" },
			rules: {
				type: "string",
				short: "r",
				default: "./semgrep-rules.yaml",
			},
			auto: { type: "boolean", default: false },
			severity: { type: "string", short: "s", default: "INFO" },
			format: { type: "string", short: "f", default: "pretty" },
			webhook: { type: "string", short: "w" },
			"webhook-token": { type: "string" },
			help: { type: "boolean", short: "h", default: false },
		},
		allowPositionals: true,
		strict: true,
	});

	if (values.help) {
		console.log(`
semgrep-scan.ts — Code Guardian Semgrep wrapper

Usage:
  bun run src/tools/semgrep-scan.ts [options] [target-dir]

Options:
  -t, --target <dir>         Directory to scan (default: current dir)
  -r, --rules <path>         Path to custom rules YAML (default: ./semgrep-rules.yaml)
      --auto                 Also include semgrep community rules (--config auto)
  -s, --severity <level>     Minimum severity: INFO, WARNING, ERROR (default: INFO)
  -f, --format <fmt>         Output: pretty, json, summary (default: pretty)
  -w, --webhook <url>        POST results to a webhook URL
      --webhook-token <tok>  Bearer token for webhook auth
  -h, --help                 Show this help
`);
		process.exit(0);
	}

	const severity = (values.severity?.toUpperCase() ?? "INFO") as ScanConfig["minSeverity"];
	if (!["INFO", "WARNING", "ERROR"].includes(severity)) {
		console.error(`Invalid severity: ${values.severity}`);
		process.exit(1);
	}

	return {
		target: values.target ?? positionals[0] ?? ".",
		rulesPath: values.rules ?? "./semgrep-rules.yaml",
		includeAuto: values.auto ?? false,
		minSeverity: severity,
		format: (values.format ?? "pretty") as ScanConfig["format"],
		webhookUrl: values.webhook,
		webhookToken: values["webhook-token"],
	};
}

// ─── Run Semgrep ────────────────────────────────────────────

async function runSemgrep(config: ScanConfig): Promise<SemgrepOutput> {
	const args = ["semgrep", "--json", "--config", config.rulesPath];

	if (config.includeAuto) {
		args.push("--config", "auto");
	}

	args.push(config.target);

	console.log(`🔍 Running: ${args.join(" ")}\n`);

	const proc = Bun.spawn(args, {
		stdout: "pipe",
		stderr: "pipe",
	});

	const stdout = await new Response(proc.stdout).text();
	const stderr = await new Response(proc.stderr).text();
	const exitCode = await proc.exited;

	// Semgrep exits with 1 when findings exist — that's normal
	if (exitCode > 1) {
		console.error("Semgrep failed:\n", stderr);
		process.exit(exitCode);
	}

	if (!stdout.trim()) {
		return { results: [], errors: [] };
	}

	try {
		return JSON.parse(stdout) as SemgrepOutput;
	} catch {
		console.error("Failed to parse Semgrep JSON output");
		console.error(stdout.slice(0, 500));
		process.exit(1);
	}
}

// ─── Filter & group results ─────────────────────────────────

function filterResults(results: SemgrepResult[], minSeverity: string): SemgrepResult[] {
	const minRank = SEVERITY_RANK[minSeverity] ?? 0;
	return results.filter((r) => (SEVERITY_RANK[r.extra.severity] ?? 0) >= minRank);
}

function groupByComponent(results: SemgrepResult[]): Map<string, SemgrepResult[]> {
	const groups = new Map<string, SemgrepResult[]>();
	for (const r of results) {
		const component = r.extra.metadata?.component ?? "unknown";
		if (!groups.has(component)) groups.set(component, []);
		groups.get(component)?.push(r);
	}
	return groups;
}

// ─── Output formatters ──────────────────────────────────────

function formatPretty(results: SemgrepResult[]): string {
	if (results.length === 0) return "✅ No findings — looking clean!\n";

	const grouped = groupByComponent(results);
	const lines: string[] = [];

	lines.push(`Found ${results.length} finding(s)\n`);

	for (const [component, findings] of grouped) {
		lines.push(`── ${component} (${findings.length}) ──`);

		for (const f of findings) {
			const icon = SEVERITY_ICON[f.extra.severity] ?? "•";
			const loc = `${f.path}:${f.start.line}`;
			lines.push(`  ${icon} [${f.extra.severity}] ${f.check_id}`);
			lines.push(`     ${loc}`);
			lines.push(`     ${f.extra.message.trim()}`);
			if (f.extra.lines) {
				lines.push(`     > ${f.extra.lines.trim()}`);
			}
			lines.push("");
		}
	}

	return lines.join("\n");
}

function formatSummary(results: SemgrepResult[]): string {
	const counts = { ERROR: 0, WARNING: 0, INFO: 0 };
	for (const r of results) {
		const sev = r.extra.severity as keyof typeof counts;
		if (sev in counts) counts[sev]++;
	}

	const components = new Set(results.map((r) => r.extra.metadata?.component ?? "unknown"));

	return [
		`Semgrep scan complete`,
		`  🚨 Errors:   ${counts.ERROR}`,
		`  ⚠️  Warnings: ${counts.WARNING}`,
		`  ℹ️  Info:     ${counts.INFO}`,
		`  Components:  ${[...components].join(", ") || "none"}`,
		results.length === 0 ? "\n✅ All clear!" : "",
	].join("\n");
}

// ─── Webhook delivery ───────────────────────────────────────

async function sendWebhook(config: ScanConfig, results: SemgrepResult[]): Promise<void> {
	if (!config.webhookUrl) return;

	const counts = { ERROR: 0, WARNING: 0, INFO: 0 };
	for (const r of results) {
		const sev = r.extra.severity as keyof typeof counts;
		if (sev in counts) counts[sev]++;
	}

	const payload = {
		title: "Semgrep Scan Results",
		message: `Found ${results.length} finding(s): ${counts.ERROR} errors, ${counts.WARNING} warnings, ${counts.INFO} info`,
		data: {
			total: results.length,
			counts,
			target: config.target,
			timestamp: new Date().toISOString(),
			findings: results.slice(0, 10).map((r) => ({
				rule: r.check_id,
				file: r.path,
				line: r.start.line,
				severity: r.extra.severity,
				message: r.extra.message.trim(),
				component: r.extra.metadata?.component,
			})),
		},
	};

	const headers: Record<string, string> = {
		"Content-Type": "application/json",
	};
	if (config.webhookToken) {
		headers.Authorization = `Bearer ${config.webhookToken}`;
	}

	try {
		const resp = await fetch(config.webhookUrl, {
			method: "POST",
			headers,
			body: JSON.stringify(payload),
		});
		if (resp.ok) {
			console.log(`📡 Webhook delivered to ${config.webhookUrl}`);
		} else {
			console.error(`📡 Webhook failed: ${resp.status} ${resp.statusText}`);
		}
	} catch (err) {
		console.error("📡 Webhook error:", err);
	}
}

// ─── Main ───────────────────────────────────────────────────

async function main() {
	const config = parseConfig();

	// Verify semgrep is installed
	const which = Bun.spawn(["which", "semgrep"], { stdout: "pipe" });
	const whichOut = await new Response(which.stdout).text();
	if (!whichOut.trim()) {
		console.error("❌ semgrep not found. Install it:\n" + "   brew install semgrep\n" + "   # or: pip install semgrep");
		process.exit(1);
	}

	// Verify rules file exists
	const rulesFile = Bun.file(config.rulesPath);
	if (!(await rulesFile.exists())) {
		console.error(`❌ Rules file not found: ${config.rulesPath}`);
		process.exit(1);
	}

	const output = await runSemgrep(config);
	const filtered = filterResults(output.results, config.minSeverity);

	if (output.errors?.length) {
		console.error("Semgrep reported errors:");
		for (const e of output.errors) {
			console.error(`  [${e.level}] ${e.message}`);
		}
		console.error("");
	}

	switch (config.format) {
		case "json":
			console.log(JSON.stringify(filtered, null, 2));
			break;
		case "summary":
			console.log(formatSummary(filtered));
			break;
		default:
			console.log(formatPretty(filtered));
			break;
	}

	await sendWebhook(config, filtered);

	const hasErrors = filtered.some((r) => r.extra.severity === "ERROR");
	process.exit(hasErrors ? 1 : 0);
}

main();
