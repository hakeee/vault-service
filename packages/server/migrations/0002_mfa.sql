CREATE TABLE `user_mfa_factor` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`user_id` integer NOT NULL,
	`kind` text NOT NULL,
	`label` text,
	`secret` blob,
	`last_step` integer,
	`credential_id` text,
	`public_key` blob,
	`counter` integer,
	`codes` text,
	`created_at` integer NOT NULL,
	`last_used_at` integer,
	FOREIGN KEY (`user_id`) REFERENCES `user`(`id`) ON UPDATE no action ON DELETE no action
);
