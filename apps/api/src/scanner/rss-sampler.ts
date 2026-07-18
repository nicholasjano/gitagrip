// Process-tree RSS sampler (issue #17).
// BullMQ useWorkerThreads: true means worker threads + their tool child
// processes are all descendants of one Node PID. process.memoryUsage().rss is
// only the driver heap (massive undercount). We BFS descendants via ps and sum
// rss. Linux-only; on darwin we fall back to the Node PID's own rss.

import { execFile as execFileCb } from 'child_process';
import { promisify } from 'util';

const execFile = promisify(execFileCb);

interface RssSample {
  treeRssKb: number;
  nodeRssKb: number;
}

async function psLines(args: string[]): Promise<string[]> {
  try {
    const { stdout } = await execFile('ps', args);
    return stdout.trim().split('\n').filter(Boolean);
  } catch {
    return [];
  }
}

async function sampleTreeRss(rootPid: number): Promise<RssSample> {
  const nodeRssKb = Math.round(process.memoryUsage().rss / 1024);

  // darwin ps doesn't support -o pid=,ppid=,rss= -A; fall back to Node-only rss
  if (process.platform === 'darwin') {
    return { treeRssKb: nodeRssKb, nodeRssKb };
  }

  // BFS descendant PIDs from the root
  const all = await psLines(['-o', 'pid=,ppid=', '-A']);
  const childrenByPpid = new Map<number, number[]>();
  for (const line of all) {
    const [pidStr, ppidStr] = line.trim().split(/\s+/);
    const pid = Number(pidStr);
    const ppid = Number(ppidStr);
    if (!Number.isFinite(pid) || !Number.isFinite(ppid)) continue;
    const arr = childrenByPpid.get(ppid) ?? [];
    arr.push(pid);
    childrenByPpid.set(ppid, arr);
  }

  const pids: number[] = [rootPid];
  const queue = [rootPid];
  while (queue.length > 0) {
    const cur = queue.shift()!;
    for (const child of childrenByPpid.get(cur) ?? []) {
      pids.push(child);
      queue.push(child);
    }
  }

  if (pids.length === 0) return { treeRssKb: nodeRssKb, nodeRssKb };

  // sum rss across the process tree
  const { stdout } = await execFile('ps', ['-o', 'rss=', '-p', pids.join(',')]);
  let treeRssKb = 0;
  for (const line of stdout.trim().split('\n')) {
    const kb = Number(line.trim());
    if (Number.isFinite(kb)) treeRssKb += kb;
  }
  return { treeRssKb, nodeRssKb };
}

export interface RssTracker {
  peak: number;
  reset: () => void;
  stop: () => void;
}

// 2s sampler; updates `peak` with the max treeRssKb observed. reset() zeroes the
// peak so the caller can measure a single repo's window (used in the sequential
// pass for clean per-repo attribution).
export function startRssSampler(rootPid: number, intervalMs = 2000): RssTracker {
  let peak = 0;
  let stopped = false;
  const timer = setInterval(async () => {
    if (stopped) return;
    try {
      const sample = await sampleTreeRss(rootPid);
      if (sample.treeRssKb > peak) peak = sample.treeRssKb;
    } catch {
      // ps transient errors — ignore, we keep the last peak
    }
  }, intervalMs);
  timer.unref();
  return {
    get peak() {
      return peak;
    },
    reset() {
      peak = 0;
    },
    stop() {
      stopped = true;
      clearInterval(timer);
    },
  };
}
