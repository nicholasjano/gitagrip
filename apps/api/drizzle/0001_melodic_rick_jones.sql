ALTER TABLE "scan_categories" ADD COLUMN "applicable" boolean DEFAULT true NOT NULL;--> statement-breakpoint
ALTER TABLE "scans" ADD COLUMN "description" text;