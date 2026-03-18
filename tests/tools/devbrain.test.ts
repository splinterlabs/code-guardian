// tests/skills/devbrain.test.ts

import { Database } from "bun:sqlite";
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	computeProfile,
	fingerprint,
	formatProfileSection,
	ingest,
	initDb,
	type ProfileResult,
	type ScanReport,
	updateMemoryMd,
} from "../../src/tools/devbrain";

describe("initDb", () => {
	test("creates all three tables", () => {
		const db = new Database(":memory:");
		initDb(db);

		const tables = db
			.query("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
			.all() as Array<{ name: string }>;

		expect(tables.map((t) => t.name)).toEqual(["findings", "scan_findings", "scans"]);
	});

	test("is idempotent — calling twice does not throw", () => {
		const db = new Database(":memory:");
		expect(() => {
			initDb(db);
			initDb(db);
		}).not.toThrow();
	});
});

// Minimal factory helpers
function makeScan(target: string, findings: ScanReport["findings"]): ScanReport {
	return {
		target,
		timestamp: new Date().toISOString(),
		duration_ms: 1000,
		findings,
		summary: {
			CRITICAL: 0,
			HIGH: findings.filter((f) => f.severity === "HIGH").length,
			MEDIUM: 0,
			LOW: 0,
			INFO: 0,
			total: findings.length,
		},
		layer_status: {},
	};
}

function makeFinding(rule: string, file: string, component: string, severity = "HIGH") {
	return { layer: "semgrep", severity, rule, file, line: 10, message: "test", component };
}

describe("ingest state transitions", () => {
	test("new finding gets state=new", () => {
		const db = new Database(":memory:");
		initDb(db);
		const report = makeScan("scripts", [makeFinding("ts-fetch", "src/a.ts", "scripts")]);
		ingest(db, [report]);
		const row = db.query("SELECT state FROM findings").get() as { state: string };
		expect(row.state).toBe("new");
	});

	test("same finding in second scan becomes open", () => {
		const db = new Database(":memory:");
		initDb(db);
		const f = makeFinding("ts-fetch", "src/a.ts", "scripts");
		ingest(db, [makeScan("scripts", [f])]);
		ingest(db, [makeScan("scripts", [f])]);
		const row = db.query("SELECT state FROM findings").get() as { state: string };
		expect(row.state).toBe("open");
	});

	test("finding absent from scan becomes fixed", () => {
		const db = new Database(":memory:");
		initDb(db);
		const f = makeFinding("ts-fetch", "src/a.ts", "scripts");
		ingest(db, [makeScan("scripts", [f])]);
		ingest(db, [makeScan("scripts", [])]);
		const row = db.query("SELECT state FROM findings").get() as { state: string };
		expect(row.state).toBe("fixed");
	});

	test("fixed finding reappearing becomes regression", () => {
		const db = new Database(":memory:");
		initDb(db);
		const f = makeFinding("ts-fetch", "src/a.ts", "scripts");
		ingest(db, [makeScan("scripts", [f])]); // new
		ingest(db, [makeScan("scripts", [])]); // fixed
		ingest(db, [makeScan("scripts", [f])]); // regression
		const row = db.query("SELECT state, fixed_at FROM findings").get() as { state: string; fixed_at: number | null };
		expect(row.state).toBe("regression");
		expect(row.fixed_at).toBeNull(); // cleared when regression occurs
	});

	test("ack'd finding is not re-opened by subsequent scans", () => {
		const db = new Database(":memory:");
		initDb(db);
		const f = makeFinding("ts-fetch", "src/a.ts", "scripts");
		ingest(db, [makeScan("scripts", [f])]);
		db.run("UPDATE findings SET state='ack' WHERE 1=1");
		ingest(db, [makeScan("scripts", [f])]);
		const row = db.query("SELECT state FROM findings").get() as { state: string };
		expect(row.state).toBe("ack");
	});

	test("expired ack transitions back to open on next scan", () => {
		const db = new Database(":memory:");
		initDb(db);

		const f = makeFinding("ts-fetch", "src/a.ts", "scripts");
		ingest(db, [makeScan("scripts", [f])]);

		// Set ack with an already-expired date (yesterday)
		const yesterday = new Date(Date.now() - 86_400_000).toISOString().slice(0, 10);
		db.run("UPDATE findings SET state='ack', ack_expires=$exp WHERE 1=1", { $exp: yesterday });

		// Next scan — expired ack should transition back to open
		ingest(db, [makeScan("scripts", [f])]);

		const row = db.query("SELECT state FROM findings").get() as { state: string };
		expect(row.state).toBe("open");
	});

	test("finding in target B is not fixed when target A scans without it", () => {
		const db = new Database(":memory:");
		initDb(db);

		const f = makeFinding("ts-fetch", "src/lib/utils.ts", "scripts");
		ingest(db, [makeScan("target-a", [f])]);
		ingest(db, [makeScan("target-b", [f])]);

		// target-a scans again without the finding
		ingest(db, [makeScan("target-a", [])]);

		// findings are now per-target; target-b's finding stays open
		const rows = db.query("SELECT state FROM findings").all() as Array<{ state: string }>;
		// Two separate findings (different fingerprints due to different targets)
		expect(rows).toHaveLength(2);
		const states = rows.map((r) => r.state).sort();
		expect(states).toEqual(["fixed", "new"]); // target-a: fixed, target-b: new (seen once)
	});
});

describe("computeProfile", () => {
	test("returns top rules sorted by count descending", () => {
		const db = new Database(":memory:");
		initDb(db);

		// Insert 3 findings for rule-a, 1 for rule-b
		const base = makeScan("scripts", [
			makeFinding("rule-a", "src/a.ts", "c"),
			makeFinding("rule-a", "src/b.ts", "c"),
			makeFinding("rule-a", "src/c.ts", "c"),
			makeFinding("rule-b", "src/d.ts", "c"),
		]);
		ingest(db, [base]);

		const profile = computeProfile(db, 30);
		expect(profile.topRules[0]?.rule).toBe("rule-a");
		expect(profile.topRules[0]?.count).toBe(3);
		expect(profile.topRules[1]?.rule).toBe("rule-b");
	});

	test("returns hotspot components", () => {
		const db = new Database(":memory:");
		initDb(db);

		ingest(db, [
			makeScan("scripts", [
				makeFinding("r1", "a.ts", "comp-x"),
				makeFinding("r2", "b.ts", "comp-x"),
				makeFinding("r3", "c.ts", "comp-y"),
			]),
		]);

		const profile = computeProfile(db, 30);
		expect(profile.hotspots[0]).toBe("comp-x");
	});

	test("open and regression counts are correct", () => {
		const db = new Database(":memory:");
		initDb(db);

		const f = makeFinding("r1", "a.ts", "c");
		ingest(db, [makeScan("s", [f])]); // state = new

		const profile = computeProfile(db, 30);
		expect(profile.openCount).toBe(1); // state=new counts as open
		expect(profile.regressionCount).toBe(0);
		expect(profile.highCount).toBe(1);
	});

	test("topRules excludes findings from scans older than the window", () => {
		const db = new Database(":memory:");
		initDb(db);

		// Manually insert a scan with an old timestamp (100 days ago)
		const oldTs = new Date(Date.now() - 100 * 86_400_000).toISOString();
		db.run(
			"INSERT INTO scans (timestamp, target, duration_ms, total, critical, high, medium, low) VALUES ($ts, 'tgt', 0, 1, 0, 0, 0, 0)",
			{ $ts: oldTs },
		);
		const scanId = (db.query("SELECT last_insert_rowid() as id").get() as { id: number }).id;
		const fp = fingerprint("old-rule", "a.ts", "c", "tgt");
		db.run(
			"INSERT INTO findings (fingerprint, rule, severity, file, component, layer, message, state, first_seen, last_seen) VALUES ($fp, 'old-rule', 'HIGH', 'a.ts', 'c', 'semgrep', 'msg', 'open', $sid, $sid)",
			{ $fp: fp, $sid: scanId },
		);
		db.run("INSERT INTO scan_findings (scan_id, fingerprint, line) VALUES ($sid, $fp, 1)", { $sid: scanId, $fp: fp });

		// Query with 30-day window — old-rule should be excluded
		const profile = computeProfile(db, 30);
		expect(profile.topRules.map((r) => r.rule)).not.toContain("old-rule");
	});
});

describe("fingerprint", () => {
	test("same rule+file+component = same hash", () => {
		expect(fingerprint("rule-a", "src/foo.ts", "comp-x")).toBe(fingerprint("rule-a", "src/foo.ts", "comp-x"));
	});

	test("different rule = different hash", () => {
		expect(fingerprint("rule-a", "src/foo.ts", "comp-x")).not.toBe(fingerprint("rule-b", "src/foo.ts", "comp-x"));
	});

	test("returns 16-char hex string", () => {
		const fp = fingerprint("rule-a", "src/foo.ts", "comp-x");
		expect(typeof fp).toBe("string");
		expect(fp.length).toBe(16);
	});
});

describe("formatProfileSection", () => {
	test("formats profile into block with required content", () => {
		const profile: ProfileResult = {
			topRules: [
				{ rule: "ts-unhandled-fetch", count: 47, component: "typescript-scripts" },
				{ rule: "ai-broad-exception", count: 12, component: "python-scripts" },
			],
			hotspots: ["dev-scripts", "python-scripts"],
			openCount: 23,
			regressionCount: 2,
			highCount: 4,
			lastScanDate: "2026-03-10",
		};

		const section = formatProfileSection(profile);
		expect(section).toContain("## AI Code Patterns");
		expect(section).toContain("ts-unhandled-fetch");
		expect(section).toContain("47x");
		expect(section).toContain("OPEN: 23");
		expect(section).toContain("REGRESSIONS: 2");
	});

	test("emits stale warning when last scan > 7 days ago", () => {
		const profile: ProfileResult = {
			topRules: [],
			hotspots: [],
			openCount: 0,
			regressionCount: 0,
			highCount: 0,
			lastScanDate: "2020-01-01", // definitely stale
		};

		const section = formatProfileSection(profile);
		expect(section).toContain("STALE");
	});

	test("handles null lastScanDate without error", () => {
		const profile: ProfileResult = {
			topRules: [],
			hotspots: [],
			openCount: 0,
			regressionCount: 0,
			highCount: 0,
			lastScanDate: null,
		};

		const section = formatProfileSection(profile);
		expect(section).toContain("## AI Code Patterns");
		expect(section).toContain("unknown");
		expect(section).not.toContain("STALE");
	});
});

describe("updateMemoryMd", () => {
	let tmpDir: string;

	beforeEach(async () => {
		tmpDir = await mkdtemp(join(tmpdir(), "devbrain-test-"));
	});
	afterEach(async () => {
		await rm(tmpDir, { recursive: true });
	});

	test("inserts section when MEMORY.md has no AI Code Patterns section", async () => {
		const memPath = join(tmpDir, "MEMORY.md");
		await writeFile(memPath, "# My Memory\n\n## Other Section\n- some note\n");

		const profile: ProfileResult = {
			topRules: [{ rule: "ts-fetch", count: 5, component: "scripts" }],
			hotspots: ["scripts"],
			openCount: 5,
			regressionCount: 0,
			highCount: 2,
			lastScanDate: "2026-03-10",
		};

		await updateMemoryMd(memPath, profile);
		const content = await readFile(memPath, "utf8");
		expect(content).toContain("## AI Code Patterns");
		expect(content).toContain("ts-fetch");
		expect(content).toContain("## Other Section"); // existing content preserved
	});

	test("replaces existing AI Code Patterns section", async () => {
		const memPath = join(tmpDir, "MEMORY.md");
		await writeFile(
			memPath,
			"# Memory\n\n## AI Code Patterns (updated 2026-03-01)\nOLD: old-rule (1x)\n\n## Other\n- note\n",
		);

		const profile: ProfileResult = {
			topRules: [{ rule: "new-rule", count: 10, component: "scripts" }],
			hotspots: ["scripts"],
			openCount: 10,
			regressionCount: 1,
			highCount: 3,
			lastScanDate: "2026-03-10",
		};

		await updateMemoryMd(memPath, profile);
		const content = await readFile(memPath, "utf8");
		expect(content).not.toContain("old-rule");
		expect(content).toContain("new-rule");
		expect(content).toContain("## Other"); // other sections preserved
	});

	test("creates MEMORY.md if it does not exist", async () => {
		const memPath = join(tmpDir, "nonexistent.md");

		const profile: ProfileResult = {
			topRules: [],
			hotspots: [],
			openCount: 0,
			regressionCount: 0,
			highCount: 0,
			lastScanDate: "2026-03-10",
		};

		await updateMemoryMd(memPath, profile);
		const content = await readFile(memPath, "utf8");
		expect(content).toContain("## AI Code Patterns");
	});
});
