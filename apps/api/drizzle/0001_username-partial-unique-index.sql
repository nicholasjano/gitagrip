ALTER TABLE "users" DROP CONSTRAINT "users_username_unique";--> statement-breakpoint
CREATE UNIQUE INDEX "idx_users_username_active" ON "users" USING btree ("username") WHERE deleted_at IS NULL;