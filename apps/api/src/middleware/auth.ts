// authentication middleware for the express app

import { jwtVerify } from 'jose';
import type { Request, Response, NextFunction } from 'express';
import { eq, and, isNull } from 'drizzle-orm';
import { db } from '../db/index.js';
import { users } from '../db/schema.js';

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  throw new Error('JWT_SECRET environment variable is required');
}

export const secret = new TextEncoder().encode(JWT_SECRET);

export const isProduction = process.env.NODE_ENV === 'production';
export const tokenCookieName = isProduction ? '__Host-token' : 'token';
export const refreshCookieName = isProduction ? '__Host-refresh' : 'refresh';

export function clearAuthCookies(res: Response): void {
  res.clearCookie(tokenCookieName, { path: '/' });
  res.clearCookie(refreshCookieName, { path: '/' });
}

async function verifyAndAttachUser(req: Request, res: Response): Promise<boolean> {
  const token = req.cookies?.[tokenCookieName];
  if (!token) return false;

  try {
    const { payload } = await jwtVerify(token, secret, {
      algorithms: ['HS256'],
      issuer: 'gitagrip',
      audience: 'gitagrip',
    });

    if (!payload.sub) return false;

    const [user] = await db
      .select()
      .from(users)
      .where(and(eq(users.id, payload.sub), isNull(users.deletedAt)))
      .limit(1);

    if (!user) {
      clearAuthCookies(res);
      return false;
    }

    req.user = user;
    return true;
  } catch {
    return false;
  }
}

export async function requireAuth(req: Request, res: Response, next: NextFunction): Promise<void> {
  const authenticated = await verifyAndAttachUser(req, res);
  if (!authenticated) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }
  next();
}

export async function optionalAuth(req: Request, res: Response, next: NextFunction): Promise<void> {
  await verifyAndAttachUser(req, res);
  next();
}
