import { appendFile, mkdir, unlink } from "node:fs/promises";
import { dirname, join } from "node:path";

/**
 * Reads JSON from stdin. Returns `{}` on failure or empty input.
 */
export async function readStdinJson(): Promise<Record<string, unknown>> {
	try {
		const text = await Bun.stdin.text();
		if (!text.trim()) return {};
		return JSON.parse(text) as Record<string, unknown>;
	} catch {
		return {};
	}
}

/**
 * Writes a JSON result object to stdout.
 */
export function writeResult(data: Record<string, unknown>): void {
	process.stdout.write(`${JSON.stringify(data)}\n`);
}

/**
 * Writes an error message to stderr and exits with code 2.
 */
export function blockWithError(message: string): never {
	process.stderr.write(`${message}\n`);
	process.exit(2);
}

/**
 * Creates a directory and all parent directories (mkdir -p equivalent).
 */
export async function ensureDir(path: string): Promise<void> {
	await mkdir(path, { recursive: true });
}

/**
 * Appends a JSONL entry to a log file with an auto-generated timestamp.
 * Creates the file and parent directories if they don't exist.
 */
export async function appendLog(path: string, entry: Record<string, unknown>): Promise<void> {
	await ensureDir(dirname(path));
	const line = `${JSON.stringify({ ...entry, timestamp: new Date().toISOString() })}\n`;
	await appendFile(path, line);
}

/**
 * Rotates a log file if it exceeds maxBytes, keeping only the last keepLines lines.
 * No-ops if the file doesn't exist or is under the size threshold.
 */
export async function rotateIfNeeded(
	path: string,
	maxBytes: number = 512 * 1024,
	keepLines: number = 500,
): Promise<void> {
	const file = Bun.file(path);
	if (!(await file.exists())) return;

	const content = await file.text();
	if (Buffer.byteLength(content) <= maxBytes) return;
	const lines = content.trimEnd().split("\n");
	const kept = lines.slice(-keepLines);
	await Bun.write(path, `${kept.join("\n")}\n`);
}

/**
 * Reads a JSON session state file. Returns `{}` if the file is missing or unreadable.
 */
export async function readSessionState(path: string): Promise<Record<string, unknown>> {
	try {
		const file = Bun.file(path);
		if (!(await file.exists())) return {};
		const text = await file.text();
		return JSON.parse(text) as Record<string, unknown>;
	} catch {
		return {};
	}
}

/**
 * Writes a JSON state object to a file, creating parent directories if needed.
 */
export async function writeSessionState(path: string, state: Record<string, unknown>): Promise<void> {
	await ensureDir(dirname(path));
	await Bun.write(path, `${JSON.stringify(state, null, 2)}\n`);
}

/**
 * Deletes a session state file. No-ops if the file doesn't exist.
 */
export async function clearSessionState(path: string): Promise<void> {
	try {
		await unlink(path);
	} catch {
		// File doesn't exist — that's fine
	}
}

/**
 * Standard project paths derived from a base directory.
 */
export interface ProjectPaths {
	logs: string;
	data: string;
	tmp: string;
	sessionState: string;
	currentSession: string;
}

/**
 * Returns the standard `.claude/` paths for a project.
 */
export function getProjectPaths(base: string): ProjectPaths {
	const claudeDir = join(base, ".claude");
	const data = join(claudeDir, "data");
	return {
		logs: join(claudeDir, "logs"),
		data,
		tmp: join(claudeDir, "tmp"),
		sessionState: join(data, "session_state.json"),
		currentSession: join(data, "current_session.json"),
	};
}
