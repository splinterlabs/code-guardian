import { join } from "node:path";
import yaml from "js-yaml";

const DEFAULT_REGISTRY_WHITELIST = [
	"docker.io",
	"ghcr.io",
	"lscr.io",
	"cr.hotio.dev",
	"registry.gitlab.com",
	"mcr.microsoft.com",
	"docker.elastic.co", // Official Elastic registry (Elasticsearch, Kibana, Filebeat)
	"gcr.io", // Google Container Registry (e.g. cadvisor)
	"prometheuscommunity", // Prometheus community exporters (docker.io shorthand)
];

const DEFAULT_ENV_WHITELIST = [
	"PUID",
	"PGID",
	"TZ",
	"UMASK",
	"LOG_LEVEL",
	"LOG_FORMAT",
	"NODE_ENV",
	"DEBUG",
	"PORT",
	"HOST",
	// JVM / runtime tuning — values, not secrets
	"ES_JAVA_OPTS",
	"JAVA_OPTS",
	"NODE_OPTIONS",
	// Notification config — topic names, not secrets
	"NTFY_TOPIC",
	// Network/service config — URLs and hostnames, not secrets
	"ELASTICSEARCH_HOSTS",
	"SEARXNG_BASE_URL",
	"SEARXNG_QUERY_URL",
	// DNS/PKI config — algorithm names and init params, not secrets
	"RFC2136_TSIG_ALGORITHM",
	"DOCKER_STEPCA_INIT_NAME",
	// HTTP client config
	"USER_AGENT",
];

function matchGlob(pattern: string, str: string): boolean {
	if (!pattern.includes("*")) return pattern === str;

	// Safe glob matching without RegExp to avoid ReDoS
	const parts = pattern.split("*");
	let pos = 0;

	for (let i = 0; i < parts.length; i++) {
		const part = parts[i];
		if (part === "") continue;

		if (i === 0) {
			// First part must be at the start
			if (!str.startsWith(part)) return false;
			pos = part.length;
		} else if (i === parts.length - 1) {
			// Last part must be at the end
			if (!str.endsWith(part)) return false;
			// Ensure it doesn't overlap with already matched content
			if (str.length - part.length < pos) return false;
		} else {
			// Middle parts must appear in order
			const idx = str.indexOf(part, pos);
			if (idx === -1) return false;
			pos = idx + part.length;
		}
	}

	return true;
}

export function isWhitelistedEnv(key: string, whitelist: string[]): boolean {
	return whitelist.some((pattern) => matchGlob(pattern, key));
}

export function isWhitelistedRegistry(image: string, whitelist: string[]): boolean {
	const firstSlash = image.indexOf("/");
	const firstSegment = firstSlash === -1 ? image.split(":")[0] : image.slice(0, firstSlash);
	const hasRegistry = firstSegment.includes(".");
	const effectiveImage = hasRegistry ? image : `docker.io/${image}`;
	return whitelist.some((registry) => effectiveImage.startsWith(registry));
}

const PLACEHOLDERS = new Set([
	"changeme",
	"placeholder",
	"replace_me",
	"todo",
	"fixme",
	"example",
	"your_password_here",
	"password",
	"secret",
]);

const COMMON_USERNAMES = new Set(["admin", "root", "postgres", "user", "guest", "anonymous"]);

export function isLikelySecret(value: string, _keyName: string): boolean {
	if (!value || value.length < 8) return false;
	if (value.startsWith("${") || value.startsWith("$")) return false;
	if (PLACEHOLDERS.has(value.toLowerCase())) return false;
	if (COMMON_USERNAMES.has(value.toLowerCase())) return false;
	if (/^[0-9a-f]{40}$/i.test(value)) return false; // git hash
	if (/^v?\d+\.\d+/.test(value)) return false; // version tag

	const hasUpper = /[A-Z]/.test(value);
	const hasLower = /[a-z]/.test(value);
	const hasDigit = /[0-9]/.test(value);
	const hasSpecial = /[^a-zA-Z0-9]/.test(value);
	const charTypes = [hasUpper, hasLower, hasDigit, hasSpecial].filter(Boolean).length;

	return charTypes >= 3;
}

interface ComplianceIssue {
	type: "secret" | "registry" | "env" | "compose-lint";
	severity: "error" | "warning";
	message: string;
	file: string;
	line?: number;
}

async function checkComposeFile(
	filePath: string,
	envWhitelist: string[],
	registryWhitelist: string[],
): Promise<ComplianceIssue[]> {
	const issues: ComplianceIssue[] = [];

	let content: string;
	try {
		content = await Bun.file(filePath).text();
	} catch {
		return issues;
	}

	let doc: Record<string, unknown>;
	try {
		doc = (yaml.load(content) as Record<string, unknown>) ?? {};
	} catch {
		return issues;
	}

	const services = doc.services as Record<string, Record<string, unknown>> | undefined;
	if (!services) return issues;

	const lines = content.split("\n");

	for (const [, config] of Object.entries(services)) {
		if (!config || typeof config !== "object") continue;

		// Check image registry
		if (config.image && typeof config.image === "string") {
			if (!isWhitelistedRegistry(config.image, registryWhitelist)) {
				issues.push({
					type: "registry",
					severity: "error",
					message: `Image from non-whitelisted registry: ${config.image}`,
					file: filePath,
				});
			}
		}

		// Check environment variables for secrets
		const env = config.environment;
		if (env) {
			const envEntries: [string, string][] = [];

			if (Array.isArray(env)) {
				for (const item of env) {
					if (typeof item === "string" && item.includes("=")) {
						const [key, ...valueParts] = item.split("=");
						envEntries.push([key, valueParts.join("=")]);
					}
				}
			} else if (typeof env === "object") {
				for (const [key, val] of Object.entries(env as Record<string, unknown>)) {
					if (val !== null && val !== undefined) envEntries.push([key, String(val)]);
				}
			}

			for (const [key, value] of envEntries) {
				if (isWhitelistedEnv(key, envWhitelist)) continue;

				// Check for inline ignore comment
				const keyLineIdx = lines.findIndex((l) => l.includes(key));
				if (keyLineIdx !== -1) {
					const lineContext = lines.slice(Math.max(0, keyLineIdx - 1), keyLineIdx + 2).join("\n");
					if (lineContext.includes("# compliance: ignore-secrets-policy")) continue;
				}

				if (isLikelySecret(value, key)) {
					issues.push({
						type: "secret",
						severity: "error",
						message: `Possible hardcoded secret in env var: ${key}`,
						file: filePath,
						line: keyLineIdx + 1,
					});
				}
			}
		}
	}

	return issues;
}

const NODE_IMAGE_PATTERNS = ["node", "next", "nuxt", "remix", "postgres-meta", "n8n", "ghost"];

function parseMemoryMB(mem: string): number {
	const match = mem.match(/^(\d+(?:\.\d+)?)\s*(M|G|m|g|MB|GB|mb|gb)?$/i);
	if (!match) return 0;
	const value = parseFloat(match[1]);
	const unit = (match[2] || "").toUpperCase();
	if (unit.startsWith("G")) return value * 1024;
	return value;
}

function isNodeImage(image: string): boolean {
	const lower = image.toLowerCase();
	return NODE_IMAGE_PATTERNS.some((p) => lower.includes(p));
}

function hasNodeEnv(env: unknown): boolean {
	if (Array.isArray(env)) {
		return env.some((e) => typeof e === "string" && e.startsWith("NODE_ENV="));
	}
	if (env && typeof env === "object") {
		return "NODE_ENV" in (env as Record<string, unknown>);
	}
	return false;
}

function getLabelsArray(config: Record<string, unknown>): string[] {
	const labels = config.labels;
	if (!labels) return [];
	if (Array.isArray(labels)) return labels.map(String);
	if (typeof labels === "object") {
		return Object.entries(labels as Record<string, unknown>).map(([k, v]) => `${k}=${v}`);
	}
	return [];
}

function checkHeredocQuoting(content: string, filePath: string): ComplianceIssue[] {
	const issues: ComplianceIssue[] = [];
	const lines = content.split("\n");

	for (let i = 0; i < lines.length; i++) {
		// Match single-quoted heredoc delimiter: << 'TAG' or <<'TAG'
		const heredocMatch = lines[i].match(/<<\s*'([A-Za-z_]+)'/);
		if (!heredocMatch) continue;

		const delimiter = heredocMatch[1];
		let hasEnvVar = false;

		// Scan body until closing delimiter
		for (let j = i + 1; j < lines.length; j++) {
			if (lines[j].trim() === delimiter) break;
			// Look for $VAR or ${VAR} patterns (but not $$ which is compose escaping)
			if (/\$[A-Za-z_]/.test(lines[j]) || /\$\{[A-Za-z_]/.test(lines[j])) {
				hasEnvVar = true;
				break;
			}
		}

		if (hasEnvVar) {
			issues.push({
				type: "compose-lint",
				severity: "warning",
				message: `Single-quoted heredoc <<'${delimiter}' prevents env var expansion (use <<${delimiter} instead)`,
				file: filePath,
				line: i + 1,
			});
		}
	}

	return issues;
}

async function checkComposeBestPractices(filePath: string): Promise<ComplianceIssue[]> {
	const issues: ComplianceIssue[] = [];

	let content: string;
	try {
		content = await Bun.file(filePath).text();
	} catch {
		return issues;
	}

	let doc: Record<string, unknown>;
	try {
		doc = (yaml.load(content) as Record<string, unknown>) ?? {};
	} catch {
		return issues;
	}

	const services = doc.services as Record<string, Record<string, unknown>> | undefined;
	if (!services) return issues;

	// Collect declared volume names (top-level volumes key)
	const declaredVolumes = new Set<string>();
	const topVolumes = doc.volumes;
	if (topVolumes && typeof topVolumes === "object") {
		for (const name of Object.keys(topVolumes as Record<string, unknown>)) {
			declaredVolumes.add(name);
		}
	}

	for (const [serviceName, config] of Object.entries(services)) {
		if (!config || typeof config !== "object") continue;

		const image = typeof config.image === "string" ? config.image : "";
		const labels = getLabelsArray(config);

		// A1: Node.js minimum memory
		if (isNodeImage(image) || (config.environment && hasNodeEnv(config.environment))) {
			const deploy = config.deploy as Record<string, unknown> | undefined;
			const resources = deploy?.resources as Record<string, unknown> | undefined;
			const limits = resources?.limits as Record<string, unknown> | undefined;
			const memory = limits?.memory;
			if (memory && typeof memory === "string") {
				const mb = parseMemoryMB(memory);
				if (mb > 0 && mb < 128) {
					issues.push({
						type: "compose-lint",
						severity: "warning",
						message: `Service "${serviceName}" uses Node.js image with only ${memory} memory (minimum 128M recommended to avoid silent OOM)`,
						file: filePath,
					});
				}
			}
		}

		// A3: Traefik middleware missing @provider suffix
		for (const label of labels) {
			const match = label.match(/traefik\.http\.routers\.[^.]+\.middlewares=(.+)/);
			if (match) {
				const middlewares = match[1].split(",").map((m) => m.trim());
				for (const mw of middlewares) {
					if (!mw.includes("@")) {
						issues.push({
							type: "compose-lint",
							severity: "warning",
							message: `Service "${serviceName}" has Traefik middleware "${mw}" without @docker suffix (will be silently ignored)`,
							file: filePath,
						});
					}
				}
			}
		}

		// A4: Traefik + shared network_mode without explicit service
		const networkMode = config.network_mode;
		if (typeof networkMode === "string" && networkMode.startsWith("service:")) {
			const hasRouterLabels = labels.some((l) => l.includes("traefik.http.routers."));
			const hasServiceLabel = labels.some((l) => /traefik\.http\.routers\.[^.]+\.service=/.test(l));
			if (hasRouterLabels && !hasServiceLabel) {
				issues.push({
					type: "compose-lint",
					severity: "warning",
					message: `Service "${serviceName}" uses network_mode "${networkMode}" with Traefik labels but no explicit service label (Traefik can't auto-link)`,
					file: filePath,
				});
			}
		}

		// A5 & A6: Volume checks
		const volumes = config.volumes;
		if (Array.isArray(volumes)) {
			for (const vol of volumes) {
				if (typeof vol !== "string") continue;
				const colonIdx = vol.indexOf(":");
				if (colonIdx === -1) continue; // named volume short form

				const source = vol.slice(0, colonIdx);
				const target = vol.slice(colonIdx + 1).split(":")[0]; // strip :ro etc

				// A5: Relative bind mount path
				const isNamedVolume = declaredVolumes.has(source) || (!source.includes("/") && !source.startsWith("."));
				if (!isNamedVolume && !source.startsWith("/") && !source.startsWith("$") && !source.startsWith("~")) {
					issues.push({
						type: "compose-lint",
						severity: "warning",
						message: `Service "${serviceName}" has relative bind mount "${source}" (Portainer resolves these inside its container, not on host)`,
						file: filePath,
					});
				}

				// A6: Bind mount inside Postgres data dir
				if (image.includes("postgres") && target.startsWith("/var/lib/postgresql/data/")) {
					issues.push({
						type: "compose-lint",
						severity: "warning",
						message: `Service "${serviceName}" has bind mount inside Postgres data dir "${target}" (Postgres chowns this directory, read-only mounts cause crash)`,
						file: filePath,
					});
				}
			}
		}
	}

	return issues;
}

export async function checkGitopsCompliance(
	stackDir: string,
	opts: { registryWhitelist?: string[]; envWhitelist?: string[]; strict?: boolean } = {},
): Promise<{ errors: number; warnings: number }> {
	const registryWhitelist = opts.registryWhitelist ?? DEFAULT_REGISTRY_WHITELIST;
	const envWhitelist = opts.envWhitelist ?? DEFAULT_ENV_WHITELIST;
	const strict = opts.strict ?? false;

	const allIssues: ComplianceIssue[] = [];

	// Find compose files
	const glob = new Bun.Glob("**/compose.yml");
	const composeFiles: string[] = [];
	for await (const file of glob.scan({ cwd: stackDir, onlyFiles: true })) {
		if (!file.includes("/archive/")) composeFiles.push(join(stackDir, file));
	}

	// Also check docker-compose.yml
	const glob2 = new Bun.Glob("**/docker-compose.yml");
	for await (const file of glob2.scan({ cwd: stackDir, onlyFiles: true })) {
		if (!file.includes("/archive/")) composeFiles.push(join(stackDir, file));
	}

	for (const filePath of composeFiles) {
		const issues = await checkComposeFile(filePath, envWhitelist, registryWhitelist);
		allIssues.push(...issues);
	}

	// Compose lint checks (warnings) - stub for now
	for (const filePath of composeFiles) {
		const lintIssues = await checkComposeBestPractices(filePath);
		allIssues.push(...lintIssues);
	}

	// Heredoc check (raw text, not parsed YAML)
	for (const filePath of composeFiles) {
		let content: string;
		try {
			content = await Bun.file(filePath).text();
		} catch {
			continue;
		}
		const heredocIssues = checkHeredocQuoting(content, filePath);
		allIssues.push(...heredocIssues);
	}

	const errors = allIssues.filter((i) => i.severity === "error");
	const warnings = allIssues.filter((i) => i.severity === "warning");

	for (const issue of errors) {
		const prefix = issue.type === "secret" ? "❌ SECRET" : "❌ REGISTRY";
		const location = issue.line ? `${issue.file}:${issue.line}` : issue.file;
		console.error(`${prefix}: ${issue.message} (${location})`);
	}

	for (const issue of warnings) {
		const location = issue.line ? `${issue.file}:${issue.line}` : issue.file;
		console.error(`⚠ WARNING: ${issue.message} (${location})`);
	}

	return {
		errors: strict ? errors.length + warnings.length : errors.length,
		warnings: warnings.length,
	};
}

if (import.meta.main) {
	const args = process.argv.slice(2);
	const strict = args.includes("--strict");
	const stackDir = args.find((a) => !a.startsWith("--"));
	if (!stackDir) {
		console.error("Usage: gitops-compliance <stack-dir> [--strict]");
		process.exit(1);
	}

	const result = await checkGitopsCompliance(stackDir, { strict });
	process.exit(result.errors > 0 ? 1 : 0);
}
