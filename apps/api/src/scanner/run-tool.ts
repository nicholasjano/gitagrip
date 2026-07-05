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
let cleanupHooksRegistered = false;
let forceKillTimer: NodeJS.Timeout | null = null;
let isCleaningUp = false;

function safeKill(proc: ChildProcess, signal: NodeJS.Signals): void {
  try {
    proc.kill(signal);
  } catch (err: unknown) {
    // process already exited or pid got reused
    if ((err as NodeJS.ErrnoException).code !== 'ESRCH') {
      throw err;
    }
  }
}

export interface RunToolOptions {
  cmd: string;
  args: string[];
  cwd?: string;
  env?: NodeJS.ProcessEnv; // optional per-run env override (e.g. GITHUB_AUTH_TOKEN for scorecard)
  signal?: AbortSignal;
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
  registerCleanupHooks();

  const {
    cmd,
    args,
    cwd,
    env,
    signal,
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
    env,
    signal,
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
  if (isCleaningUp || activeProcesses.size === 0) return;
  isCleaningUp = true;

  if (forceKillTimer) {
    clearTimeout(forceKillTimer);
    forceKillTimer = null;
  }

  for (const proc of activeProcesses) {
    safeKill(proc, 'SIGTERM');
  }

  // after 5 seconds, force-kill anything still alive
  // trivy needs time to release its vulnerability DB file locks
  forceKillTimer = setTimeout(() => {
    for (const proc of activeProcesses) {
      safeKill(proc, 'SIGKILL');
    }
    activeProcesses.clear();
    forceKillTimer = null;
    isCleaningUp = false;
  }, 5_000);
  forceKillTimer.unref();
}

function registerCleanupHooks(): void {
  if (cleanupHooksRegistered) return;
  cleanupHooksRegistered = true;

  const cleanup = () => {
    killAllToolProcesses();
  };
  const cleanupOnExit = () => {
    for (const proc of activeProcesses) {
      safeKill(proc, 'SIGKILL');
    }
    activeProcesses.clear();
  };

  process.on('SIGTERM', cleanup);
  process.on('SIGINT', cleanup);
  process.on('exit', cleanupOnExit);
}
