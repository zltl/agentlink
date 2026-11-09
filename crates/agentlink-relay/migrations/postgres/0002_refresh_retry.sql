ALTER TABLE refresh_tokens ADD COLUMN replaced_by TEXT;
ALTER TABLE refresh_tokens ADD COLUMN acknowledged BIGINT NOT NULL DEFAULT 0;
ALTER TABLE access_tokens ADD COLUMN refresh_hash TEXT;
