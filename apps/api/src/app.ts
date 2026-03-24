// builds the express app

import express, { type Express } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import fs from 'fs/promises';
import { pool } from './db/index.js';
import { redis } from './db/redis.js';
import authRouter from './routes/auth.js';
import scanRouter, { batchRouter } from './routes/scans.js';

const app: Express = express();
const MIN_READY_DISK_BYTES = 5 * 1024 * 1024 * 1024;

app.set('trust proxy', 1);

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'none'"],
      },
    },
  }),
);
app.use(
  cors({
    origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
    credentials: true,
  }),
);
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());

app.use('/auth', authRouter);
app.use('/scans', scanRouter);
app.use('/batches', batchRouter);

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', uptime: process.uptime() });
});

app.get('/health/ready', async (_req, res) => {
  const services: Record<string, 'ok' | 'error'> = {
    database: 'error',
    redis: 'error',
    disk: 'error',
  };
  let diskFreeMb = 0;

  try {
    const client = await pool.connect();
    try {
      await client.query('SELECT 1');
      services.database = 'ok';
    } finally {
      client.release();
    }
  } catch {
    // services.database remains 'error'
  }

  try {
    const pong = await redis.ping();
    if (pong === 'PONG') services.redis = 'ok';
  } catch {
    // services.redis remains 'error'
  }

  try {
    const { bavail, bsize } = await fs.statfs('/tmp');
    const freeBytes = bavail * bsize;
    diskFreeMb = Math.round(freeBytes / 1024 / 1024);
    if (freeBytes >= MIN_READY_DISK_BYTES) {
      services.disk = 'ok';
    }
  } catch {
    // services.disk remains 'error'
  }

  const allHealthy = Object.values(services).every((s) => s === 'ok');

  res.status(allHealthy ? 200 : 503).json({
    status: allHealthy ? 'ok' : 'degraded',
    services,
    disk: {
      freeMb: diskFreeMb,
      minRequiredMb: Math.round(MIN_READY_DISK_BYTES / 1024 / 1024),
    },
  });
});

export default app;
