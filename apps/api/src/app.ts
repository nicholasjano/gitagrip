import express, { type Express } from 'express';
import helmet from 'helmet';
import cors from 'cors';

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

app.get('/health/ready', (_req, res) => {
  // TODO: Add real health checks for database and redis
  res.json({
    status: 'ok',
    services: {
      database: 'ok',
      redis: 'ok',
    },
  });
});

export default app;
