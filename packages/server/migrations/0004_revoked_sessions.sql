CREATE TABLE `revoked_session` (
	`session_id` text PRIMARY KEY NOT NULL,
	`revoked_at` integer NOT NULL
);
