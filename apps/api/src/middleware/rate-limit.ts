import rateLimit from 'express-rate-limit';

const skipInDev = process.env.NODE_ENV !== 'production';

export const authInitLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  skip: () => skipInDev,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Try again in 15 minutes.' },
});

export const authCallbackLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  skip: () => skipInDev,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many callback attempts. Try again in 15 minutes.' },
});

export const refreshLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  skip: () => skipInDev,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many refresh attempts. Try again in 15 minutes.' },
});
