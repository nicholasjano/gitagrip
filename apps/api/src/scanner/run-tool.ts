// exports runTool, killAllToolProcesses

// generic tool runner — the only place in the codebase that spawns external processes
// every scan tool (gitleaks, trivy, opengrep, etc.) goes through here

import { execFile as execFileCb, type ChildProcess } from 'child_process';
import { performance } from 'perf_hooks';
import { promisify } from 'util';
import type { ScanLogger } from './logger.js';

// tracks every active child process so killAllToolProcesses() can reach them
const activeProcesses = new Set<ChildProcess>();
const execFile = promisify(execFileCb);

export interface RunToolOptions {
  cmd: string;
  args: string[];
  cwd?: string;
  timeoutMs?: number; // default 300_000 (5 min)
  maxBuffer?: number; // default 50 MB
  expectedExitCodes?: number[]; // exit codes that mean "findings found", not "crash"
  label: string; // human-readable name for logging
  logger: ScanLogger;
}

export interface ToolResult {
  status: 'clean' | 'findings' | 'timeout' | 'crash' | 'skipped';
  stdout: string;
  stderr: string;
  exitCode: number | null;
  durationMs: number;
  label: string;
}

export async function runTool(opts: RunToolOptions): Promise<ToolResult> {
  const {
    cmd,
    args,
    cwd,
    timeoutMs = 300_000,
    maxBuffer = 50 * 1024 * 1024,
    expectedExitCodes = [],
    label,
    logger,
  } = opts;

  logger.info('tool', `starting ${label}`, { tool: label });

  const start = performance.now();

  // execFile async promises expose the spawned child on `.child`
  const resultPromise = execFile(cmd, args, {
    cwd,
    timeout: timeoutMs,
    maxBuffer,
  }) as Promise<{ stdout: string; stderr: string }> & { child: ChildProcess };
  const childProcess = resultPromise.child;
  activeProcesses.add(childProcess);

  try {
    const { stdout, stderr } = await resultPromise;
    const durationMs = Math.round(performance.now() - start);

    logger.info('tool', `${label} finished clean`, { tool: label, durationMs });

    return { status: 'clean', stdout, stderr, exitCode: 0, durationMs, label };
  } catch (err: unknown) {
    const durationMs = Math.round(performance.now() - start);
    const e = err as NodeJS.ErrnoException & {
      killed?: boolean;
      code?: string | number;
      stdout?: string;
      stderr?: string;
    };

    const stdout = e.stdout ?? '';
    const stderr = e.stderr ?? '';
    const exitCode = typeof e.code === 'number' ? e.code : null;

    // process was killed due to timeout
    if (e.killed === true) {
      logger.warn('tool', `${label} timed out`, { tool: label, durationMs, timeoutMs });
      return { status: 'timeout', stdout, stderr, exitCode: null, durationMs, label };
    }

    // stdout exceeded the buffer limit
    if (e.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER') {
      logger.error('tool', `${label} exceeded output buffer`, { tool: label, durationMs });
      return {
        status: 'crash',
        stdout: '',
        stderr: 'output exceeded buffer limit',
        exitCode: null,
        durationMs,
        label,
      };
    }

    // non-zero exit code that means "tool ran fine, it just found something"
    // e.g. gitleaks exits 1 when secrets are found — that's not a crash
    if (exitCode !== null && expectedExitCodes.includes(exitCode)) {
      logger.info('tool', `${label} finished with findings`, { tool: label, durationMs, exitCode });
      return { status: 'findings', stdout, stderr, exitCode, durationMs, label };
    }

    // anything else is a genuine crash
    logger.error('tool', `${label} crashed`, { tool: label, durationMs, exitCode, stderr });
    return { status: 'crash', stdout, stderr, exitCode, durationMs, label };
  } finally {
    activeProcesses.delete(childProcess);
  }
}

// called in scan-processor's finally block and in the worker's SIGTERM handler
// gives each process 5 seconds to exit cleanly before force-killing
export function killAllToolProcesses(): void {
  if (activeProcesses.size === 0) return;

  for (const proc of activeProcesses) {
    proc.kill('SIGTERM');
  }

  // after 5 seconds, force-kill anything still alive
  // trivy needs time to release its vulnerability DB file locks
  setTimeout(() => {
    for (const proc of activeProcesses) {
      proc.kill('SIGKILL');
    }
    activeProcesses.clear();
  }, 5_000);
}
