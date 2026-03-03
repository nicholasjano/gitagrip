import { Router, type Request, type Response, type Router as RouterType } from 'express';
import { SignJWT } from 'jose';
import { randomBytes, randomUUID, createHash, timingSafeEqual } from 'node:crypto';
import { db } from '../db/index.js';
import { users } from '../db/schema.js';
import { redis } from '../db/redis.js';
import { encrypt } from '../lib/crypto.js';
import {
  secret,
  isProduction,
  tokenCookieName,
  refreshCookieName,
  clearAuthCookies,
  requireAuth,
} from '../middleware/auth.js';
import { authInitLimiter, authCallbackLimiter, refreshLimiter } from '../middleware/rate-limit.js';
import { eq, and, isNull } from 'drizzle-orm';

// ─── Environment Variable Validation ────────────────────────────

const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID;
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;
const GITHUB_CALLBACK_URL = process.env.GITHUB_CALLBACK_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const TOKEN_ENCRYPTION_KEY = process.env.TOKEN_ENCRYPTION_KEY;
const CORS_ORIGIN = process.env.CORS_ORIGIN;

if (
  !GITHUB_CLIENT_ID ||
  !GITHUB_CLIENT_SECRET ||
  !GITHUB_CALLBACK_URL ||
  !JWT_SECRET ||
  !TOKEN_ENCRYPTION_KEY
) {
  throw new Error(
    'Missing required auth environment variables: GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, GITHUB_CALLBACK_URL, JWT_SECRET, TOKEN_ENCRYPTION_KEY',
  );
}

if (JWT_SECRET.length < 32) {
  throw new Error('JWT_SECRET must be at least 32 characters');
}

if (TOKEN_ENCRYPTION_KEY.length !== 64 || !/^[0-9a-f]+$/i.test(TOKEN_ENCRYPTION_KEY)) {
  throw new Error('TOKEN_ENCRYPTION_KEY must be exactly 64 hex characters (32 bytes)');
}

// ─── Router ─────────────────────────────────────────────────────

const router: RouterType = Router();

router.use((_req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});

// ─── Helpers ────────────────────────────────────────────────────

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

function safeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

const ROTATE_REFRESH_TOKEN_SCRIPT = `
local current = redis.call('GET', KEYS[1])
if current == false then return 0 end
if current ~= ARGV[1] then return -1 end
redis.call('EXPIRE', KEYS[1], 30)
redis.call('SETEX', KEYS[2], tonumber(ARGV[3]), ARGV[2])
return 1
`;

// ─── Cookie Helpers ─────────────────────────────────────────────

function setTokenCookie(res: Response, jwt: string): void {
  res.cookie(tokenCookieName, jwt, {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'lax',
    maxAge: 60 * 60 * 1000,
    path: '/',
  });
}

function setRefreshCookie(res: Response, value: string): void {
  res.cookie(refreshCookieName, value, {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: '/',
  });
}

// ─── GET /auth/github ───────────────────────────────────────────

router.get('/github', authInitLimiter, (_req: Request, res: Response) => {
  const state = randomBytes(32).toString('hex');
  const codeVerifier = randomBytes(32).toString('base64url');
  const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');

  const oauthCookieOptions = {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'lax' as const,
    maxAge: 10 * 60 * 1000,
    path: '/',
  };

  res.cookie('oauth_state', state, oauthCookieOptions);
  res.cookie('pkce_verifier', codeVerifier, oauthCookieOptions);

  const params = new URLSearchParams({
    client_id: GITHUB_CLIENT_ID,
    redirect_uri: GITHUB_CALLBACK_URL,
    scope: 'read:user user:email',
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  });

  res.redirect(`https://github.com/login/oauth/authorize?${params.toString()}`);
});

// ─── GET /auth/github/callback ──────────────────────────────────

interface GitHubTokenResponse {
  access_token?: string;
  error?: string;
  error_description?: string;
}

interface GitHubUser {
  id: number;
  login: string;
  avatar_url: string;
}

interface GitHubEmail {
  email: string;
  primary: boolean;
  verified: boolean;
}

router.get('/github/callback', authCallbackLimiter, async (req: Request, res: Response) => {
  const { code, state } = req.query;
  const storedState = req.cookies?.oauth_state;
  const codeVerifier = req.cookies?.pkce_verifier;

  // Clear OAuth cookies immediately
  res.clearCookie('oauth_state', { path: '/' });
  res.clearCookie('pkce_verifier', { path: '/' });

  // Validate state
  if (
    !code ||
    !state ||
    !storedState ||
    !safeCompare(state as string, storedState as string) ||
    !codeVerifier
  ) {
    res.status(403).json({ error: 'Invalid OAuth state' });
    return;
  }

  try {
    // Exchange code for access token
    const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({
        client_id: GITHUB_CLIENT_ID,
        client_secret: GITHUB_CLIENT_SECRET,
        code,
        redirect_uri: GITHUB_CALLBACK_URL,
        code_verifier: codeVerifier,
      }),
    });

    const tokenData = (await tokenResponse.json()) as GitHubTokenResponse;
    if (!tokenData.access_token) {
      res.status(403).json({ error: 'GitHub OAuth failed' });
      return;
    }

    const githubAccessToken = tokenData.access_token;

    // Fetch GitHub user profile
    const userResponse = await fetch('https://api.github.com/user', {
      headers: { Authorization: `Bearer ${githubAccessToken}` },
    });

    if (!userResponse.ok) {
      res.status(403).json({ error: 'GitHub OAuth failed' });
      return;
    }

    const githubUser = (await userResponse.json()) as GitHubUser;

    // Fetch user's primary verified email
    const emailsResponse = await fetch('https://api.github.com/user/emails', {
      headers: { Authorization: `Bearer ${githubAccessToken}` },
    });

    let primaryEmail: string | null = null;
    if (emailsResponse.ok) {
      const emails = (await emailsResponse.json()) as GitHubEmail[];
      const primary = emails.find((e) => e.primary && e.verified);
      if (primary) {
        primaryEmail = primary.email;
      }
    }

    // Upsert user - encrypt and store GitHub access token on every login
    const [user] = await db
      .insert(users)
      .values({
        githubId: githubUser.id,
        username: githubUser.login,
        email: primaryEmail,
        avatarUrl: githubUser.avatar_url,
        accessToken: encrypt(githubAccessToken),
      })
      .onConflictDoUpdate({
        target: users.githubId,
        set: {
          username: githubUser.login,
          email: primaryEmail,
          avatarUrl: githubUser.avatar_url,
          accessToken: encrypt(githubAccessToken),
          deletedAt: null,
          updatedAt: new Date(),
        },
      })
      .returning();

    if (!user) {
      res.status(500).json({ error: 'Failed to create user' });
      return;
    }

    // Sign access JWT
    const jti = randomUUID();
    const accessJwt = await new SignJWT({ sub: user.id })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setIssuer('gitagrip')
      .setAudience('gitagrip')
      .setJti(jti)
      .setExpirationTime('1h')
      .sign(secret);

    // Create refresh token and store in Redis
    const refreshToken = randomBytes(32).toString('hex');
    const refreshId = randomUUID();
    await redis.set(
      `refresh:${user.id}:${refreshId}`,
      hashToken(refreshToken),
      'EX',
      7 * 24 * 60 * 60,
    );

    // Set cookies
    setTokenCookie(res, accessJwt);
    setRefreshCookie(res, `${user.id}:${refreshId}:${refreshToken}`);

    // Redirect to frontend
    const redirectUrl = CORS_ORIGIN || 'http://localhost:3000';
    res.redirect(redirectUrl);
  } catch (error) {
    console.error('OAuth callback error:', error);
    res.status(500).json({ error: 'Authentication failed' });
  }
});

// ─── GET /auth/me ───────────────────────────────────────────────

router.get('/me', requireAuth, (req: Request, res: Response) => {
  const user = req.user!;
  res.json({
    id: user.id,
    username: user.username,
    email: user.email,
    avatarUrl: user.avatarUrl,
    emailNotifications: user.emailNotifications,
    theme: user.theme,
    createdAt: user.createdAt,
  });
});

// ─── POST /auth/logout ─────────────────────────────────────────

router.post('/logout', async (req: Request, res: Response) => {
  const refreshCookie = req.cookies?.[refreshCookieName] as string | undefined;

  if (refreshCookie) {
    const parts = refreshCookie.split(':');
    if (parts.length === 3) {
      const [userId, refreshId] = parts;
      await redis.del(`refresh:${userId}:${refreshId}`);
    }
  }

  clearAuthCookies(res);
  res.json({ message: 'Logged out' });
});

// ─── POST /auth/refresh ────────────────────────────────────────

router.post('/refresh', refreshLimiter, async (req: Request, res: Response) => {
  const refreshCookie = req.cookies?.[refreshCookieName] as string | undefined;

  if (!refreshCookie) {
    res.status(401).json({ error: 'Invalid refresh token' });
    return;
  }

  const parts = refreshCookie.split(':');
  if (parts.length !== 3) {
    clearAuthCookies(res);
    res.status(401).json({ error: 'Invalid refresh token' });
    return;
  }

  const [userId, refreshId, refreshToken] = parts;

  // Verify user still exists and isn't soft-deleted
  const [user] = await db
    .select()
    .from(users)
    .where(and(eq(users.id, userId!), isNull(users.deletedAt)))
    .limit(1);

  if (!user) {
    await redis.del(`refresh:${userId}:${refreshId}`);
    clearAuthCookies(res);
    res.status(401).json({ error: 'Invalid refresh token' });
    return;
  }

  // Atomic rotation with 30s grace period via Lua script
  const newRefreshToken = randomBytes(32).toString('hex');
  const newRefreshId = randomUUID();

  const result = await redis.eval(
    ROTATE_REFRESH_TOKEN_SCRIPT,
    2,
    `refresh:${userId}:${refreshId}`,
    `refresh:${userId}:${newRefreshId}`,
    hashToken(refreshToken!),
    hashToken(newRefreshToken),
    String(7 * 24 * 60 * 60),
  );

  if (result === 0 || result === -1) {
    clearAuthCookies(res);
    res.status(401).json({ error: 'Invalid refresh token' });
    return;
  }

  // Issue new access JWT
  const jti = randomUUID();
  const accessJwt = await new SignJWT({ sub: user.id })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setIssuer('gitagrip')
    .setAudience('gitagrip')
    .setJti(jti)
    .setExpirationTime('1h')
    .sign(secret);

  // Set new cookies
  setTokenCookie(res, accessJwt);
  setRefreshCookie(res, `${user.id}:${newRefreshId}:${newRefreshToken}`);

  res.json({ message: 'Token refreshed' });
});

export default router;
