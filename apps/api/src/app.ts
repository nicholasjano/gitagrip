import express, { type Express } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import { pool } from './db/index.js';

const app: Express = express();

app.use(helmet());
app.use(
  cors({
    origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
    credentials: true,
  }),
);
app.use(express.json({ limit: '10kb' }));

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', uptime: process.uptime() });
});

app.get('/health/ready', async (_req, res) => {
  const services: Record<string, 'ok' | 'error'> = {
    database: 'error',
    redis: 'ok', // TODO: Add real Redis health check
  };

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

  const allHealthy = Object.values(services).every((s) => s === 'ok');

  res.status(allHealthy ? 200 : 503).json({
    status: allHealthy ? 'ok' : 'degraded',
    services,
  });
});

export default app;
