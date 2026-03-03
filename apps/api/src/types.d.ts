import type { UserSelect } from './db/schema.js';

declare global {
  namespace Express {
    interface Request {
      user?: UserSelect;
    }
  }
}
