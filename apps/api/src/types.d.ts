// define the types for the express app (declaration)

import type { UserSelect } from './db/schema.js';

declare global {
  namespace Express {
    interface Request {
      user?: UserSelect;
    }
  }
}
