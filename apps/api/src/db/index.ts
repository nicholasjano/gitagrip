// creates the database connection (5), allows exporting the database connection to the app and worker

import { drizzle } from 'drizzle-orm/node-postgres';
import pg from 'pg';
import * as schema from './schema.js';

if (!process.env.DATABASE_URL) {
  throw new Error('DATABASE_URL environment variable is required');
}

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  max: 5,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000,
  options:
    '-c statement_timeout=30000 -c lock_timeout=5000 -c idle_in_transaction_session_timeout=60000',
});

export const db = drizzle(pool, {
  schema,
  casing: 'snake_case',
});

export { pool };

export type Database = typeof db;
