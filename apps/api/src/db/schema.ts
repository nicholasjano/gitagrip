import {
  pgTable,
  uuid,
  bigint,
  varchar,
  text,
  boolean,
  integer,
  numeric,
  timestamp,
  index,
  uniqueIndex,
  check,
} from 'drizzle-orm/pg-core';
import { relations, sql, type InferSelectModel, type InferInsertModel } from 'drizzle-orm';

// ─── Enum Value Constants ────────────────────────────────────────

export const SCAN_STATUSES = [
  'queued',
  'in_progress',
  'completed',
  'failed',
  'timeout',
  'cancelled',
] as const;

export const BATCH_STATUSES = [
  'queued',
  'in_progress',
  'completed',
  'failed',
  'cancelled',
] as const;

export const BATCH_TYPES = ['user', 'org'] as const;

export const THEME_OPTIONS = ['dark', 'light'] as const;

export const SCAN_CATEGORY_NAMES = [
  'repository_overview',
  'maintenance_community',
  'documentation_standards',
  'security_vulnerabilities',
  'exposed_secrets',
  'dependency_health',
  'code_quality',
  'cicd_devops',
  'repo_security_posture',
  'workflow_security',
  'iac_security',
  'dockerfile_best_practices',
  'container_security',
] as const;

// ─── Tables ──────────────────────────────────────────────────────

export const users = pgTable(
  'users',
  {
    id: uuid()
      .primaryKey()
      .default(sql`uuidv7()`),
    githubId: bigint({ mode: 'number' }).unique().notNull(),
    username: varchar().notNull(),
    email: varchar(),
    avatarUrl: varchar(),
    accessToken: text().notNull(),
    emailNotifications: boolean().default(true).notNull(),
    theme: text({ enum: THEME_OPTIONS }).default('dark').notNull(),
    deletedAt: timestamp({ withTimezone: true }),
    createdAt: timestamp({ withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp({ withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    check('users_theme_check', sql`${table.theme} IN ('dark', 'light')`),
    uniqueIndex('idx_users_username_active')
      .on(table.username)
      .where(sql`deleted_at IS NULL`),
  ],
);

export const scanBatches = pgTable(
  'scan_batches',
  {
    id: uuid()
      .primaryKey()
      .default(sql`uuidv7()`),
    requestedBy: uuid()
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    type: text({ enum: BATCH_TYPES }).notNull(),
    target: varchar().notNull(),
    status: text({ enum: BATCH_STATUSES }).default('queued').notNull(),
    totalRepos: integer().default(0).notNull(),
    completedRepos: integer().default(0).notNull(),
    averageScore: numeric(),
    showOnLeaderboard: boolean().default(true).notNull(),
    errorMessage: text(),
    startedAt: timestamp({ withTimezone: true }),
    completedAt: timestamp({ withTimezone: true }),
    createdAt: timestamp({ withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp({ withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    check('scan_batches_type_check', sql`${table.type} IN ('user', 'org')`),
    check(
      'scan_batches_status_check',
      sql`${table.status} IN ('queued', 'in_progress', 'completed', 'failed', 'cancelled')`,
    ),
    index('idx_batches_leaderboard')
      .on(table.type, table.target, table.createdAt.desc())
      .where(sql`status = 'completed' AND show_on_leaderboard = true`),
    index('idx_batches_user_history').on(table.requestedBy, table.createdAt),
    index('idx_batches_type_target').on(table.type, table.target),
    index('idx_batches_status').on(table.status),
  ],
);

export const scans = pgTable(
  'scans',
  {
    id: uuid()
      .primaryKey()
      .default(sql`uuidv7()`),
    requestedBy: uuid().references(() => users.id, { onDelete: 'cascade' }),
    batchId: uuid().references(() => scanBatches.id, { onDelete: 'cascade' }),
    githubRepoId: bigint({ mode: 'number' }).notNull(),
    repoOwner: varchar().notNull(),
    repoName: varchar().notNull(),
    isPrivate: boolean().default(false).notNull(),
    isFork: boolean().default(false).notNull(),
    defaultBranch: varchar().default('main').notNull(),
    language: varchar(),
    stars: integer().default(0).notNull(),
    sizeKb: integer().default(0).notNull(),
    pushedAt: timestamp({ withTimezone: true }),
    status: text({ enum: SCAN_STATUSES }).default('queued').notNull(),
    score: integer(),
    showOnLeaderboard: boolean().default(true).notNull(),
    errorMessage: text(),
    startedAt: timestamp({ withTimezone: true }),
    completedAt: timestamp({ withTimezone: true }),
    createdAt: timestamp({ withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp({ withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    check(
      'scans_status_check',
      sql`${table.status} IN ('queued', 'in_progress', 'completed', 'failed', 'timeout', 'cancelled')`,
    ),
    index('idx_scans_repo_leaderboard')
      .on(table.githubRepoId, table.createdAt.desc())
      .where(
        sql`status = 'completed' AND show_on_leaderboard = true AND is_private = false AND is_fork = false`,
      ),
    uniqueIndex('idx_one_active_scan_per_repo')
      .on(table.githubRepoId)
      .where(sql`status IN ('queued', 'in_progress')`),
    index('idx_scans_user_history').on(table.requestedBy, table.createdAt),
    index('idx_scans_batch_id').on(table.batchId),
    index('idx_scans_status').on(table.status),
    index('idx_scans_repo_latest').on(table.githubRepoId, table.createdAt),
    index('idx_scans_repo_owner_name').on(table.repoOwner, table.repoName),
  ],
);

export const scanCategories = pgTable(
  'scan_categories',
  {
    id: uuid()
      .primaryKey()
      .default(sql`uuidv7()`),
    scanId: uuid()
      .notNull()
      .references(() => scans.id, { onDelete: 'cascade' }),
    category: text({ enum: SCAN_CATEGORY_NAMES }).notNull(),
    score: numeric().notNull(),
    message: text().notNull(),
  },
  (table) => [
    check(
      'scan_categories_category_check',
      sql`${table.category} IN ('repository_overview', 'maintenance_community', 'documentation_standards', 'security_vulnerabilities', 'exposed_secrets', 'dependency_health', 'code_quality', 'cicd_devops', 'repo_security_posture', 'workflow_security', 'iac_security', 'dockerfile_best_practices', 'container_security')`,
    ),
    index('idx_scan_categories_scan_id').on(table.scanId),
    uniqueIndex('idx_scan_categories_unique').on(table.scanId, table.category),
  ],
);

// ─── Relations ───────────────────────────────────────────────────

export const usersRelations = relations(users, ({ many }) => ({
  scanBatches: many(scanBatches),
  scans: many(scans),
}));

export const scanBatchesRelations = relations(scanBatches, ({ one, many }) => ({
  requestedByUser: one(users, {
    fields: [scanBatches.requestedBy],
    references: [users.id],
  }),
  scans: many(scans),
}));

export const scansRelations = relations(scans, ({ one, many }) => ({
  requestedByUser: one(users, {
    fields: [scans.requestedBy],
    references: [users.id],
  }),
  batch: one(scanBatches, {
    fields: [scans.batchId],
    references: [scanBatches.id],
  }),
  categories: many(scanCategories),
}));

export const scanCategoriesRelations = relations(scanCategories, ({ one }) => ({
  scan: one(scans, {
    fields: [scanCategories.scanId],
    references: [scans.id],
  }),
}));

// ─── Inferred Types ──────────────────────────────────────────────

export type UserSelect = InferSelectModel<typeof users>;
export type UserInsert = InferInsertModel<typeof users>;

export type ScanBatchSelect = InferSelectModel<typeof scanBatches>;
export type ScanBatchInsert = InferInsertModel<typeof scanBatches>;

export type ScanSelect = InferSelectModel<typeof scans>;
export type ScanInsert = InferInsertModel<typeof scans>;

export type ScanCategorySelect = InferSelectModel<typeof scanCategories>;
export type ScanCategoryInsert = InferInsertModel<typeof scanCategories>;
