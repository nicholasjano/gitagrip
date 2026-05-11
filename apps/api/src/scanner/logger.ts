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
  function safeSerialize(value: unknown): string {
    const seen = new WeakSet<object>();
    return JSON.stringify(value, (_key, item) => {
      if (typeof item === 'bigint') return item.toString();
      if (item && typeof item === 'object') {
        if (seen.has(item as object)) return '[circular]';
        seen.add(item as object);
      }
      return item;
    });
  }

  function write(
    level: LogLevel,
    phase: string,
    message: string,
    extra?: Record<string, unknown>,
  ): void {
    const entry: LogEntry = {
      ...(extra ?? {}),
      timestamp: new Date().toISOString(),
      level,
      scanId,
      phase,
      message,
    };
    // write to stdout as a single JSON line — log aggregators (e.g. Loki) parse line by line
    try {
      process.stdout.write(safeSerialize(entry) + '\n');
    } catch {
      process.stdout.write(
        JSON.stringify({
          timestamp: new Date().toISOString(),
          level: 'error',
          scanId,
          phase: 'logger',
          message: 'failed to serialize log entry',
          originalPhase: phase,
          originalMessage: message,
        }) + '\n',
      );
    }
  }

  return {
    info: (phase, message, extra) => write('info', phase, message, extra),
    warn: (phase, message, extra) => write('warn', phase, message, extra),
    error: (phase, message, extra) => write('error', phase, message, extra),
  };
}
