// src/tools/devbrain.ts

import { Database } from "bun:sqlite";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, resolve } from "node:path";

// ScanReport — matches the type produced by deep-scan.ts.
// Keep in sync if fields are added to either definition.
export interface ScanReport {
	target: string;
	timestamp: string;
	duration_ms: number;
	findings: Array<{
		layer: string;
		severity: string;
		rule: string;
		file?: string;
		line?: number;
		message: string;
		component: string;
	}>;
	summary: {
		CRITICAL: number;
		HIGH: number;
		MEDIUM: number;
		LOW: number;
		INFO: number;
		total: number;
	};
	layer_status: Record<string, string>;
}

export function fingerprint(rule: string, file: string, component: string, target = ""): string {
	return createHash("sha256").update(`${target}::${rule}::${file}::${component}`).digest("hex").slice(0, 16);
}

export function initDb(db: Database): void {
	db.run(`
    CREATE TABLE IF NOT EXISTS scans (
      id        INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT    NOT NULL,
      target    TEXT    NOT NULL,
      duration_ms INTEGER NOT NULL DEFAULT 0,
      total     INTEGER NOT NULL DEFAULT 0,
      critical  INTEGER NOT NULL DEFAULT 0,
      high      INTEGER NOT NULL DEFAULT 0,
      medium    INTEGER NOT NULL DEFAULT 0,
      low       INTEGER NOT NULL DEFAULT 0
    )
  `);

	db.run(`
    CREATE TABLE IF NOT EXISTS findings (
      fingerprint TEXT    PRIMARY KEY,
      rule        TEXT    NOT NULL,
      severity    TEXT    NOT NULL,
      file        TEXT    NOT NULL DEFAULT '',
      component   TEXT    NOT NULL DEFAULT '',
      layer       TEXT    NOT NULL DEFAULT '',
      message     TEXT    NOT NULL DEFAULT '',
      state       TEXT    NOT NULL DEFAULT 'new',
      first_seen  INTEGER NOT NULL,
      last_seen   INTEGER NOT NULL,
      fixed_at    INTEGER,
      ack_reason  TEXT,
      ack_expires TEXT
    )
  `);

	db.run(`
    CREATE TABLE IF NOT EXISTS scan_findings (
      scan_id     INTEGER NOT NULL,
      fingerprint TEXT    NOT NULL,
      line        INTEGER,
      PRIMARY KEY (scan_id, fingerprint)
    )
  `);
}

export function ingest(db: Database, reports: ScanReport[]): void {
	const insertScan = db.prepare(`
    INSERT INTO scans (timestamp, target, duration_ms, total, critical, high, medium, low)
    VALUES ($timestamp, $target, $duration_ms, $total, $critical, $high, $medium, $low)
  `);
	const insertScanFinding = db.prepare(`
    INSERT OR REPLACE INTO scan_findings (scan_id, fingerprint, line) VALUES ($scanId, $fp, $line)
  `);
	const upsertFinding = db.prepare(`
    INSERT INTO findings (fingerprint, rule, severity, file, component, layer, message, state, first_seen, last_seen)
    VALUES ($fp, $rule, $severity, $file, $component, $layer, $message, 'new', $scanId, $scanId)
    ON CONFLICT(fingerprint) DO UPDATE SET
      last_seen = $scanId,
      fixed_at = CASE WHEN state = 'fixed' THEN NULL ELSE fixed_at END,
      state = CASE
        WHEN state = 'ack' AND (ack_expires IS NULL OR ack_expires >= date('now')) THEN 'ack'
        WHEN state = 'ack'        THEN 'open'
        WHEN state = 'fixed'      THEN 'regression'
        WHEN state = 'new'        THEN 'open'
        WHEN state = 'open'       THEN 'open'
        WHEN state = 'regression' THEN 'regression'
        ELSE state
      END
  `);
	const selectOpenForTarget = db.prepare(`
    SELECT DISTINCT f.fingerprint FROM findings f
    JOIN scan_findings sf ON sf.fingerprint = f.fingerprint
    JOIN scans s ON s.id = sf.scan_id
    WHERE s.target = $target
      AND f.state IN ('new', 'open', 'regression')
  `);
	const markFixed = db.prepare("UPDATE findings SET state='fixed', fixed_at=$scanId WHERE fingerprint=$fp");

	const processReport = db.transaction((report: ScanReport) => {
		const result = insertScan.run({
			$timestamp: report.timestamp,
			$target: report.target,
			$duration_ms: report.duration_ms,
			$total: report.summary.total,
			$critical: report.summary.CRITICAL,
			$high: report.summary.HIGH,
			$medium: report.summary.MEDIUM,
			$low: report.summary.LOW,
		});
		const scanId = result.lastInsertRowid as number;

		const seenFps = new Set<string>();
		for (const f of report.findings) {
			const fp = fingerprint(f.rule, f.file ?? "", f.component, report.target);
			seenFps.add(fp);
			upsertFinding.run({
				$fp: fp,
				$rule: f.rule,
				$severity: f.severity,
				$file: f.file ?? "",
				$component: f.component,
				$layer: f.layer,
				$message: f.message,
				$scanId: scanId,
			});
			insertScanFinding.run({ $scanId: scanId, $fp: fp, $line: f.line ?? null });
		}

		// Mark previously-open findings absent from this target's scan as fixed
		const openForTarget = selectOpenForTarget.all({ $target: report.target }) as Array<{
			fingerprint: string;
		}>;

		for (const { fingerprint: fp } of openForTarget) {
			if (!seenFps.has(fp)) {
				markFixed.run({ $scanId: scanId, $fp: fp });
			}
		}
	});

	for (const report of reports) {
		processReport(report);
	}
}

export interface ProfileResult {
	topRules: Array<{ rule: string; count: number; component: string }>;
	hotspots: string[]; // top 2 components by finding density
	openCount: number; // findings in state new|open|regression
	regressionCount: number;
	highCount: number;
	lastScanDate: string | null;
}

export function computeProfile(db: Database, days: number): ProfileResult {
	const since = new Date(Date.now() - days * 86_400_000).toISOString();

	const topRules = db
		.query(
			`
      SELECT f.rule, MAX(f.component) as component, COUNT(DISTINCT sf.fingerprint) as count
      FROM scan_findings sf
      JOIN scans s ON s.id = sf.scan_id
      JOIN findings f ON f.fingerprint = sf.fingerprint
      WHERE s.timestamp >= $since
        AND f.state NOT IN ('ack', 'fixed')
      GROUP BY f.rule
      ORDER BY count DESC
      LIMIT 5
    `,
		)
		.all({ $since: since }) as Array<{ rule: string; count: number; component: string }>;

	// hotspots: all-time density, not windowed — shows accumulated problem areas
	const hotspots = (
		db
			.query(
				`
        SELECT f.component, COUNT(*) as count
        FROM findings f
        WHERE f.state IN ('new', 'open', 'regression')
        GROUP BY f.component
        ORDER BY count DESC
        LIMIT 2
      `,
			)
			.all() as Array<{ component: string }>
	).map((r) => r.component);

	const { open: openCount } = db
		.query("SELECT COUNT(*) as open FROM findings WHERE state IN ('new','open','regression')")
		.get() as { open: number };

	const { reg: regressionCount } = db
		.query("SELECT COUNT(*) as reg FROM findings WHERE state = 'regression'")
		.get() as { reg: number };

	const { high: highCount } = db
		.query("SELECT COUNT(*) as high FROM findings WHERE severity = 'HIGH' AND state IN ('new','open','regression')")
		.get() as { high: number };

	const lastScan = db.query("SELECT timestamp FROM scans ORDER BY id DESC LIMIT 1").get() as {
		timestamp: string;
	} | null;

	return {
		topRules,
		hotspots,
		openCount,
		regressionCount,
		highCount,
		lastScanDate: lastScan?.timestamp.slice(0, 10) ?? null,
	};
}

export function formatProfileSection(profile: ProfileResult): string {
	const date = profile.lastScanDate ?? "unknown";
	const stale = profile.lastScanDate !== null && Date.now() - new Date(profile.lastScanDate).getTime() > 7 * 86_400_000;

	if (stale) {
		return `## AI Code Patterns (updated ${date})\n⚠️  STALE — last scan was >7 days ago. Run deep-scan to refresh.\n`;
	}

	const topStr = profile.topRules
		.slice(0, 5)
		.map((r) => `${r.rule} (${r.count}x)`)
		.join(", ");
	const hotStr = profile.hotspots.slice(0, 2).join(", ");

	return [
		`## AI Code Patterns (updated ${date})`,
		`TOP: ${topStr || "none"}`,
		`HOTSPOT: ${hotStr || "none"}`,
		`OPEN: ${profile.openCount} findings — ${profile.highCount} HIGH | REGRESSIONS: ${profile.regressionCount} active`,
		"",
	].join("\n");
}

export function openDb(dbPath?: string): Database {
	const path = dbPath ?? process.env.DEVBRAIN_DB ?? "./scan-reports/devbrain.db";
	const resolved = resolve(path);
	mkdirSync(dirname(resolved), { recursive: true });
	const db = new Database(resolved);
	initDb(db);
	return db;
}

// Derives the auto-memory path from cwd, matching Claude Code's naming convention.
// e.g. /Users/x/Projects/foo → ~/.claude/projects/-Users-x-Projects-foo/memory/MEMORY.md
export function resolveMemoryPath(): string {
	const encoded = process.cwd().replace(/\//g, "-");
	return resolve(homedir(), ".claude", "projects", encoded, "memory", "MEMORY.md");
}

export async function updateMemoryMd(memoryPath: string, profile: ProfileResult): Promise<void> {
	const section = formatProfileSection(profile);

	if (!existsSync(memoryPath)) {
		// single writer — TOCTOU not a concern
		await writeFile(memoryPath, `# Session Memory\n\n${section}\n`);
		return;
	}

	const content = await readFile(memoryPath, "utf8");
	const lines = content.split("\n");

	// Find the existing section (## AI Code Patterns...)
	const startIdx = lines.findIndex((l) => l.startsWith("## AI Code Patterns"));
	if (startIdx === -1) {
		// Append to end
		const trimmed = content.trimEnd();
		await writeFile(memoryPath, `${trimmed}\n\n${section}\n`);
		return;
	}

	// Find end of section (next ## heading or EOF)
	let endIdx = lines.findIndex((l, i) => i > startIdx && l.startsWith("## "));
	if (endIdx === -1) endIdx = lines.length;

	const newLines = [
		...lines.slice(0, startIdx),
		...section.trimEnd().split("\n"),
		"", // one blank line between sections
		...lines.slice(endIdx),
	];

	await writeFile(memoryPath, newLines.join("\n"));
}

async function main() {
	const [, , command, ...args] = process.argv;

	const db = openDb();

	switch (command) {
		case "ingest": {
			const file = args[0];
			if (!file) {
				console.error("Usage: devbrain ingest <scan-report.json>");
				process.exit(1);
			}
			const raw: unknown = JSON.parse(await Bun.file(file).text());
			const reports: ScanReport[] = Array.isArray(raw) ? (raw as ScanReport[]) : [raw as ScanReport];
			ingest(db, reports);
			const profile = computeProfile(db, 30);
			await updateMemoryMd(resolveMemoryPath(), profile);
			console.log(`✅ Ingested ${reports.length} target(s). MEMORY.md updated.`);
			break;
		}

		case "status": {
			const severityFilter = args.includes("--severity") ? args[args.indexOf("--severity") + 1]?.toUpperCase() : null;

			const rows = db
				.query(
					`SELECT rule, severity, file, component, state, message
           FROM findings
           WHERE state IN ('new','open','regression')
           ${severityFilter ? "AND severity = $sev" : ""}
           ORDER BY
             CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END`,
				)
				.all(severityFilter ? { $sev: severityFilter } : {}) as Array<{
				rule: string;
				severity: string;
				file: string;
				component: string;
				state: string;
				message: string;
			}>;

			if (rows.length === 0) {
				console.log("✅ No open findings.");
				break;
			}
			for (const r of rows) {
				console.log(`[${r.severity}] ${r.rule} (${r.state})`);
				console.log(`  ${r.file} — ${r.component}`);
				console.log(`  ${r.message.slice(0, 100)}`);
				console.log();
			}
			break;
		}

		case "profile": {
			const daysIdx = args.indexOf("--days");
			const daysRaw = daysIdx !== -1 ? Number(args[daysIdx + 1]) : 30;
			const days = Number.isNaN(daysRaw) ? 30 : daysRaw;
			const p = computeProfile(db, days);
			console.log(`\nAI Code Patterns (last ${days} days)\n${"─".repeat(40)}`);
			for (const r of p.topRules) {
				console.log(`  ${r.rule}: ${r.count}x (${r.component})`);
			}
			console.log(`\nHotspots: ${p.hotspots.join(", ") || "none"}`);
			console.log(`Open: ${p.openCount} | HIGH: ${p.highCount} | Regressions: ${p.regressionCount}`);
			break;
		}

		case "regressions": {
			const rows = db
				.query("SELECT rule, severity, file, component, message FROM findings WHERE state='regression'")
				.all() as Array<{
				rule: string;
				severity: string;
				file: string;
				component: string;
				message: string;
			}>;
			if (rows.length === 0) {
				console.log("✅ No regressions.");
				break;
			}
			for (const r of rows) {
				console.log(`[${r.severity}] ${r.rule} — REGRESSION`);
				console.log(`  ${r.file} (${r.component})`);
				console.log();
			}
			break;
		}

		case "ack": {
			const fp = args[0];
			const reasonIdx = args.indexOf("--reason");
			const reason = reasonIdx !== -1 ? args[reasonIdx + 1] : null;
			const expiresIdx = args.indexOf("--expires");
			const expiresRaw = expiresIdx !== -1 ? Number(args[expiresIdx + 1]?.replace("d", "")) : null;
			const expiresDays = expiresRaw !== null && !Number.isNaN(expiresRaw) ? expiresRaw : null;

			if (!fp || !reason) {
				console.error('Usage: devbrain ack <fingerprint> --reason "why" [--expires 90d]');
				process.exit(1);
			}

			const expires = expiresDays ? new Date(Date.now() + expiresDays * 86_400_000).toISOString().slice(0, 10) : null;

			db.run("UPDATE findings SET state='ack', ack_reason=$reason, ack_expires=$expires WHERE fingerprint=$fp", {
				$reason: reason,
				$expires: expires,
				$fp: fp,
			});
			console.log(`✅ Acknowledged. ${expires ? `Expires: ${expires}` : "No expiry."}`);
			break;
		}

		default:
			console.log(`Usage: bun run src/tools/devbrain.ts <command>

Commands:
  ingest <file>                         Ingest a scan report JSON
  status [--severity HIGH]              Show open findings
  profile [--days 30]                   AI behavior profile
  regressions                           Show findings that came back
  ack <fp> --reason "..." [--expires 90d]  Suppress a finding
`);
	}
}

if (import.meta.main) main();
