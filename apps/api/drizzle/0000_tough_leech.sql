CREATE TABLE "scan_batches" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"requested_by" uuid NOT NULL,
	"type" text NOT NULL,
	"target" varchar NOT NULL,
	"status" text DEFAULT 'queued' NOT NULL,
	"total_repos" integer DEFAULT 0 NOT NULL,
	"completed_repos" integer DEFAULT 0 NOT NULL,
	"average_score" numeric,
	"show_on_leaderboard" boolean DEFAULT true NOT NULL,
	"error_message" text,
	"started_at" timestamp with time zone,
	"completed_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "scan_batches_type_check" CHECK ("scan_batches"."type" IN ('user', 'org')),
	CONSTRAINT "scan_batches_status_check" CHECK ("scan_batches"."status" IN ('queued', 'in_progress', 'completed', 'failed', 'cancelled'))
);
--> statement-breakpoint
CREATE TABLE "scan_categories" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"scan_id" uuid NOT NULL,
	"category" text NOT NULL,
	"score" numeric NOT NULL,
	"message" text NOT NULL,
	CONSTRAINT "scan_categories_category_check" CHECK ("scan_categories"."category" IN ('repository_overview', 'maintenance_community', 'documentation_standards', 'security_vulnerabilities', 'exposed_secrets', 'dependency_health', 'code_quality', 'cicd_devops', 'repo_security_posture', 'workflow_security', 'iac_security', 'dockerfile_best_practices', 'container_security'))
);
--> statement-breakpoint
CREATE TABLE "scans" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"requested_by" uuid,
	"batch_id" uuid,
	"github_repo_id" bigint NOT NULL,
	"repo_owner" varchar NOT NULL,
	"repo_name" varchar NOT NULL,
	"is_private" boolean DEFAULT false NOT NULL,
	"is_fork" boolean DEFAULT false NOT NULL,
	"default_branch" varchar DEFAULT 'main' NOT NULL,
	"language" varchar,
	"stars" integer DEFAULT 0 NOT NULL,
	"size_kb" integer DEFAULT 0 NOT NULL,
	"pushed_at" timestamp with time zone,
	"status" text DEFAULT 'queued' NOT NULL,
	"score" integer,
	"show_on_leaderboard" boolean DEFAULT true NOT NULL,
	"error_message" text,
	"started_at" timestamp with time zone,
	"completed_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "scans_status_check" CHECK ("scans"."status" IN ('queued', 'in_progress', 'completed', 'failed', 'timeout', 'cancelled'))
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"github_id" bigint NOT NULL,
	"username" varchar NOT NULL,
	"email" varchar,
	"avatar_url" varchar,
	"access_token" text NOT NULL,
	"email_notifications" boolean DEFAULT true NOT NULL,
	"theme" text DEFAULT 'dark' NOT NULL,
	"deleted_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "users_githubId_unique" UNIQUE("github_id"),
	CONSTRAINT "users_theme_check" CHECK ("users"."theme" IN ('dark', 'light'))
);
--> statement-breakpoint
ALTER TABLE "scan_batches" ADD CONSTRAINT "scan_batches_requested_by_users_id_fk" FOREIGN KEY ("requested_by") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scan_categories" ADD CONSTRAINT "scan_categories_scan_id_scans_id_fk" FOREIGN KEY ("scan_id") REFERENCES "public"."scans"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scans" ADD CONSTRAINT "scans_requested_by_users_id_fk" FOREIGN KEY ("requested_by") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scans" ADD CONSTRAINT "scans_batch_id_scan_batches_id_fk" FOREIGN KEY ("batch_id") REFERENCES "public"."scan_batches"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "idx_batches_leaderboard" ON "scan_batches" USING btree ("type","target","created_at" DESC NULLS LAST) WHERE status = 'completed' AND show_on_leaderboard = true;--> statement-breakpoint
CREATE INDEX "idx_batches_user_history" ON "scan_batches" USING btree ("requested_by","created_at");--> statement-breakpoint
CREATE INDEX "idx_batches_type_target" ON "scan_batches" USING btree ("type","target");--> statement-breakpoint
CREATE INDEX "idx_batches_status" ON "scan_batches" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_scan_categories_scan_id" ON "scan_categories" USING btree ("scan_id");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_scan_categories_unique" ON "scan_categories" USING btree ("scan_id","category");--> statement-breakpoint
CREATE INDEX "idx_scans_repo_leaderboard" ON "scans" USING btree ("github_repo_id","created_at" DESC NULLS LAST) WHERE status = 'completed' AND show_on_leaderboard = true AND is_private = false AND is_fork = false;--> statement-breakpoint
CREATE UNIQUE INDEX "idx_one_active_scan_per_repo" ON "scans" USING btree ("github_repo_id") WHERE status IN ('queued', 'in_progress');--> statement-breakpoint
CREATE INDEX "idx_scans_user_history" ON "scans" USING btree ("requested_by","created_at");--> statement-breakpoint
CREATE INDEX "idx_scans_batch_id" ON "scans" USING btree ("batch_id");--> statement-breakpoint
CREATE INDEX "idx_scans_status" ON "scans" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_scans_repo_latest" ON "scans" USING btree ("github_repo_id","created_at");--> statement-breakpoint
CREATE INDEX "idx_scans_repo_owner_name" ON "scans" USING btree ("repo_owner","repo_name");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_users_username_active" ON "users" USING btree ("username") WHERE deleted_at IS NULL;