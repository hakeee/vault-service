-- Hand-edited from drizzle-kit output: IF NOT EXISTS on every statement so
-- a database whose app created these tables before this package owned its
-- migrations (Ebba, pre-0.2) adopts this baseline as a no-op instead of
-- failing. Only the baseline gets this treatment - later migrations are
-- plain drizzle-kit output. See README "Database".
CREATE TABLE IF NOT EXISTS `user` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`display_name` text NOT NULL,
	`email` text NOT NULL,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS `user_email_unique` ON `user` (`email`);--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `user_identity` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`user_id` integer NOT NULL,
	`provider` text NOT NULL,
	`issuer` text,
	`subject` text,
	`password_hash` text,
	FOREIGN KEY (`user_id`) REFERENCES `user`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `vault_unlock_method` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`user_id` integer NOT NULL,
	`method` text NOT NULL,
	`label` blob,
	`wrapped_dek` blob NOT NULL,
	`kdf_salt` blob,
	`kdf_params` text,
	`credential_id` text,
	`public_key` blob,
	`counter` integer,
	`prf_salt` blob,
	`created_at` integer NOT NULL,
	`last_used_at` integer,
	FOREIGN KEY (`user_id`) REFERENCES `user`(`id`) ON UPDATE no action ON DELETE no action
);
