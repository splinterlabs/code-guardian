import { randomUUID } from "node:crypto";
import { hostname } from "node:os";

export enum ReconcilerState {
	INIT = "INIT",
	IDLE = "IDLE",
	RUN = "RUN",
	TUNING = "TUNING",
	FAULT = "FAULT",
}

type LogLevel = "DEBUG" | "INFO" | "WARN" | "ERROR";

interface LogRecord {
	schema: string;
	timestamp: string;
	level: LogLevel;
	service: string;
	correlation_id: string;
	environment: string;
	message: string;
	metadata: {
		host: string;
		user: string;
		version: string;
		logger: string;
	};
	[key: string]: unknown;
}

export interface Logger {
	debug(msg: string, extra?: Record<string, unknown>): void;
	info(msg: string, extra?: Record<string, unknown>): void;
	warn(msg: string, extra?: Record<string, unknown>): void;
	error(msg: string, extra?: Record<string, unknown>): void;
}

const LEVEL_ORDER: LogLevel[] = ["DEBUG", "INFO", "WARN", "ERROR"];

const LEVEL_MAP: Record<string, LogLevel> = {
	DEBUG: "DEBUG",
	INFO: "INFO",
	WARNING: "WARN",
	WARN: "WARN",
	ERROR: "ERROR",
	CRITICAL: "ERROR",
};

export function getLogger(
	service: string,
	opts: { environment?: string; level?: string; version?: string } = {},
): Logger {
	const environment = opts.environment ?? "production";
	const version = opts.version ?? "unknown";
	const correlationId = randomUUID();
	const host = hostname();
	const user = process.env.USER ?? "unknown";

	const minLevel = LEVEL_MAP[(opts.level ?? "INFO").toUpperCase()] ?? "INFO";
	const minIdx = LEVEL_ORDER.indexOf(minLevel);

	function emit(level: LogLevel, msg: string, extra?: Record<string, unknown>) {
		if (LEVEL_ORDER.indexOf(level) < minIdx) return;

		const record: LogRecord = {
			schema: "1.0",
			timestamp: new Date().toISOString(),
			level,
			service,
			correlation_id: correlationId,
			environment,
			message: msg,
			metadata: { host, user, version, logger: service },
			...extra,
		};

		process.stdout.write(`${JSON.stringify(record)}\n`);
	}

	return {
		debug: (msg, extra) => emit("DEBUG", msg, extra),
		info: (msg, extra) => emit("INFO", msg, extra),
		warn: (msg, extra) => emit("WARN", msg, extra),
		error: (msg, extra) => emit("ERROR", msg, extra),
	};
}
