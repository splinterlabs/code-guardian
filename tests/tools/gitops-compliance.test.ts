import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	checkGitopsCompliance,
	isLikelySecret,
	isWhitelistedEnv,
	isWhitelistedRegistry,
} from "../../src/tools/gitops-compliance";

describe("isWhitelistedEnv", () => {
	const whitelist = ["PUID", "PGID", "TZ", "LOG_*"];

	test("exact match", () => expect(isWhitelistedEnv("PUID", whitelist)).toBe(true));
	test("glob match with wildcard", () => expect(isWhitelistedEnv("LOG_LEVEL", whitelist)).toBe(true));
	test("glob matches LOG_FORMAT", () => expect(isWhitelistedEnv("LOG_FORMAT", whitelist)).toBe(true));
	test("non-match returns false", () => expect(isWhitelistedEnv("SECRET_KEY", whitelist)).toBe(false));
	test("partial match without glob returns false", () => expect(isWhitelistedEnv("TZ_EXTRA", whitelist)).toBe(false));
});

describe("isWhitelistedRegistry", () => {
	const whitelist = ["docker.io", "ghcr.io", "lscr.io"];

	test("docker.io image matches", () => expect(isWhitelistedRegistry("docker.io/nginx:latest", whitelist)).toBe(true));
	test("ghcr.io image matches", () => expect(isWhitelistedRegistry("ghcr.io/user/repo:1.0", whitelist)).toBe(true));
	test("lscr.io image matches", () =>
		expect(isWhitelistedRegistry("lscr.io/linuxserver/sonarr:latest", whitelist)).toBe(true));
	test("unregistered registry returns false", () =>
		expect(isWhitelistedRegistry("evil.registry.io/image:latest", whitelist)).toBe(false));
	test("short name (no registry) treated as docker.io", () =>
		expect(isWhitelistedRegistry("nginx:latest", whitelist)).toBe(true));
});

describe("isLikelySecret", () => {
	test("env var reference is not a secret", () => expect(isLikelySecret("${MY_SECRET}", "PASSWORD")).toBe(false));
	test("simple env var reference is not a secret", () => expect(isLikelySecret("$MY_VAR", "PASSWORD")).toBe(false));
	test("placeholder is not a secret", () => expect(isLikelySecret("changeme", "PASSWORD")).toBe(false));
	test("common username is not a secret", () => expect(isLikelySecret("admin", "DB_USER")).toBe(false));
	test("empty string is not a secret", () => expect(isLikelySecret("", "PASSWORD")).toBe(false));
	test("version string is not a secret", () => expect(isLikelySecret("v1.2.3", "VERSION")).toBe(false));
	test("git hash is not a secret", () =>
		expect(isLikelySecret("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2", "SHA")).toBe(false));
	test("high entropy mixed string is a secret", () =>
		expect(isLikelySecret("xK3$mP9!qL2@nR7#", "SECRET_KEY")).toBe(true));
});

describe("checkGitopsCompliance", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = await mkdtemp(join(tmpdir(), "compliance-test-"));
	});

	afterEach(async () => {
		await rm(tempDir, { recursive: true, force: true });
	});

	test("returns false (no errors) for clean stack", async () => {
		await writeFile(
			join(tempDir, "compose.yml"),
			`services:
  myapp:
    image: docker.io/nginx:latest
    environment:
      - LOG_LEVEL=info
`,
		);
		const result = await checkGitopsCompliance(tempDir);
		expect(result.errors).toBe(0);
	});

	test("returns true (errors) for stack with unwhitelisted registry", async () => {
		await writeFile(
			join(tempDir, "compose.yml"),
			`services:
  myapp:
    image: suspicious.registry.io/malware:latest
`,
		);
		const result = await checkGitopsCompliance(tempDir);
		expect(result.errors).toBeGreaterThan(0);
	});
});

describe("compose best practices", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = await mkdtemp(join(tmpdir(), "compliance-test-"));
	});

	afterEach(async () => {
		await rm(tempDir, { recursive: true, force: true });
	});

	test("A1: warns on Node.js image with low memory limit", async () => {
		await writeFile(
			join(tempDir, "compose.yml"),
			`services:
  app:
    image: docker.io/node:20-alpine
    deploy:
      resources:
        limits:
          memory: 64M
`,
		);
		const result = await checkGitopsCompliance(tempDir);
		expect(result.warnings).toBeGreaterThan(0);
	});

	test("A1: no warning on Node.js image with sufficient memory", async () => {
		await writeFile(
			join(tempDir, "compose.yml"),
			`services:
  app:
    image: docker.io/node:20-alpine
    deploy:
      resources:
        limits:
          memory: 256M
`,
		);
		const result = await checkGitopsCompliance(tempDir);
		expect(result.warnings).toBe(0);
	});

	test("A1: no warning when memory limit is absent", async () => {
		await writeFile(
			join(tempDir, "compose.yml"),
			`services:
  app:
    image: docker.io/node:20-alpine
`,
		);
		const result = await checkGitopsCompliance(tempDir);
		expect(result.warnings).toBe(0);
	});

	test("A3: warns on Traefik middleware without @docker suffix", async () => {
		await writeFile(
			join(tempDir, "compose.yml"),
			`services:
  app:
    image: docker.io/nginx:latest
    labels:
      - "traefik.http.routers.app.middlewares=my-auth"
`,
		);
		const result = await checkGitopsCompliance(tempDir);
		expect(result.warnings).toBeGreaterThan(0);
	});

	test("A3: no warning with @docker suffix", async () => {
		await writeFile(
			join(tempDir, "compose.yml"),
			`services:
  app:
    image: docker.io/nginx:latest
    labels:
      - "traefik.http.routers.app.middlewares=my-auth@docker"
`,
		);
		const result = await checkGitopsCompliance(tempDir);
		expect(result.warnings).toBe(0);
	});

	test("A3: warns on one bare middleware in a chain", async () => {
		await writeFile(
			join(tempDir, "compose.yml"),
			`services:
  app:
    image: docker.io/nginx:latest
    labels:
      - "traefik.http.routers.app.middlewares=auth@docker,ratelimit"
`,
		);
		const result = await checkGitopsCompliance(tempDir);
		expect(result.warnings).toBeGreaterThan(0);
	});

	test("A4: warns on network_mode service with Traefik labels but no explicit service", async () => {
		await writeFile(
			join(tempDir, "compose.yml"),
			`services:
  gluetun:
    image: docker.io/qmcgaw/gluetun:latest
  torrent:
    image: docker.io/linuxserver/qbittorrent:latest
    network_mode: "service:gluetun"
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.torrent.rule=Host(\`torrent.home\`)"
`,
		);
		const result = await checkGitopsCompliance(tempDir);
		expect(result.warnings).toBeGreaterThan(0);
	});

	test("A4: no warning with explicit service label", async () => {
		await writeFile(
			join(tempDir, "compose.yml"),
			`services:
  gluetun:
    image: docker.io/qmcgaw/gluetun:latest
  torrent:
    image: docker.io/linuxserver/qbittorrent:latest
    network_mode: "service:gluetun"
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.torrent.rule=Host(\`torrent.home\`)"
      - "traefik.http.routers.torrent.service=torrent-svc"
`,
		);
		const result = await checkGitopsCompliance(tempDir);
		expect(result.warnings).toBe(0);
	});

	test("A5: warns on relative bind mount path", async () => {
		await writeFile(
			join(tempDir, "compose.yml"),
			`services:
  app:
    image: docker.io/nginx:latest
    volumes:
      - ./config:/app/config
`,
		);
		const result = await checkGitopsCompliance(tempDir);
		expect(result.warnings).toBeGreaterThan(0);
	});

	test("A5: no warning on absolute path", async () => {
		await writeFile(
			join(tempDir, "compose.yml"),
			`services:
  app:
    image: docker.io/nginx:latest
    volumes:
      - /data/config:/app/config
`,
		);
		const result = await checkGitopsCompliance(tempDir);
		expect(result.warnings).toBe(0);
	});

	test("A5: no warning on env var path", async () => {
		await writeFile(
			join(tempDir, "compose.yml"),
			`services:
  app:
    image: docker.io/nginx:latest
    volumes:
      - \${HOST_CONFIG}:/app/config
`,
		);
		const result = await checkGitopsCompliance(tempDir);
		expect(result.warnings).toBe(0);
	});

	test("A5: no warning on named volume", async () => {
		await writeFile(
			join(tempDir, "compose.yml"),
			`services:
  app:
    image: docker.io/nginx:latest
    volumes:
      - app_data:/app/data
volumes:
  app_data:
`,
		);
		const result = await checkGitopsCompliance(tempDir);
		expect(result.warnings).toBe(0);
	});

	test("A6: warns on bind mount inside postgres data dir", async () => {
		await writeFile(
			join(tempDir, "compose.yml"),
			`services:
  db:
    image: docker.io/postgres:16
    volumes:
      - /honeypot/pg_hba.conf:/var/lib/postgresql/data/backup/pg_hba.conf:ro
`,
		);
		const result = await checkGitopsCompliance(tempDir);
		expect(result.warnings).toBeGreaterThan(0);
	});

	test("A6: no warning on postgres volume outside data dir", async () => {
		await writeFile(
			join(tempDir, "compose.yml"),
			`services:
  db:
    image: docker.io/postgres:16
    volumes:
      - pg_data:/var/lib/postgresql/data
      - /honeypot/fake.conf:/root/.ssh/authorized_keys:ro
volumes:
  pg_data:
`,
		);
		const result = await checkGitopsCompliance(tempDir);
		expect(result.warnings).toBe(0);
	});
});

describe("A2: heredoc quoting", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = await mkdtemp(join(tmpdir(), "compliance-test-"));
	});

	afterEach(async () => {
		await rm(tempDir, { recursive: true, force: true });
	});

	test("warns on single-quoted heredoc with env vars", async () => {
		await writeFile(
			join(tempDir, "compose.yml"),
			`services:
  app:
    image: docker.io/nginx:latest
    entrypoint: ["/bin/sh", "-c"]
    command:
      - |
        cat > /config.yml << 'EOF'
        server:
          url: $SERVER_URL
          key: $API_KEY
        EOF
        exec /app
`,
		);
		const result = await checkGitopsCompliance(tempDir);
		expect(result.warnings).toBeGreaterThan(0);
	});

	test("no warning on unquoted heredoc with env vars", async () => {
		await writeFile(
			join(tempDir, "compose.yml"),
			`services:
  app:
    image: docker.io/nginx:latest
    entrypoint: ["/bin/sh", "-c"]
    command:
      - |
        cat > /config.yml << EOF
        server:
          url: $SERVER_URL
        EOF
        exec /app
`,
		);
		const result = await checkGitopsCompliance(tempDir);
		expect(result.warnings).toBe(0);
	});

	test("no warning on single-quoted heredoc without env vars", async () => {
		await writeFile(
			join(tempDir, "compose.yml"),
			`services:
  app:
    image: docker.io/nginx:latest
    command:
      - |
        cat > /config.yml << 'EOF'
        server:
          url: localhost
        EOF
`,
		);
		const result = await checkGitopsCompliance(tempDir);
		expect(result.warnings).toBe(0);
	});
});

describe("warning infrastructure", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = await mkdtemp(join(tmpdir(), "compliance-test-"));
	});

	afterEach(async () => {
		await rm(tempDir, { recursive: true, force: true });
	});

	test("returns { errors, warnings } shape instead of boolean", async () => {
		await writeFile(
			join(tempDir, "compose.yml"),
			`services:
  myapp:
    image: docker.io/nginx:latest
`,
		);
		const result = await checkGitopsCompliance(tempDir);
		expect(typeof result).toBe("object");
		expect(typeof result.errors).toBe("number");
		expect(typeof result.warnings).toBe("number");
		expect(result.errors).toBe(0);
	});

	test("errors still cause failure", async () => {
		await writeFile(
			join(tempDir, "compose.yml"),
			`services:
  myapp:
    image: suspicious.registry.io/malware:latest
`,
		);
		const result = await checkGitopsCompliance(tempDir);
		expect(result.errors).toBeGreaterThan(0);
	});
});
