// exports createScanLogger

// structured JSON logger scoped to a single scan
// every line automatically includes scanId as a correlation ID

export type LogLevel = 'info' | 'warn' | 'error';

export interface LogEntry {
  timestamp: string;
  level: LogLevel;
  scanId: string;
  phase: string;
  tool?: string;
  message: string;
  durationMs?: number;
  [key: string]: unknown;
}

export interface ScanLogger {
  info(phase: string, message: string, extra?: Record<string, unknown>): void;
  warn(phase: string, message: string, extra?: Record<string, unknown>): void;
  error(phase: string, message: string, extra?: Record<string, unknown>): void;
}

export function createScanLogger(scanId: string): ScanLogger {
  function write(
    level: LogLevel,
    phase: string,
    message: string,
    extra?: Record<string, unknown>,
  ): void {
    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      scanId,
      phase,
      message,
      ...extra,
    };
    // write to stdout as a single JSON line — log aggregators (e.g. Loki) parse line by line
    process.stdout.write(JSON.stringify(entry) + '\n');
  }

  return {
    info: (phase, message, extra) => write('info', phase, message, extra),
    warn: (phase, message, extra) => write('warn', phase, message, extra),
    error: (phase, message, extra) => write('error', phase, message, extra),
  };
}
