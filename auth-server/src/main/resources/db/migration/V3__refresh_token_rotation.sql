-- V3__refresh_token_rotation.sql
-- Adds refresh-token family tracking for rotation and reuse detection.

ALTER TABLE refresh_tokens
    ADD COLUMN token_family_id UUID NOT NULL;

ALTER TABLE refresh_tokens
    ADD COLUMN replaced_by UUID;

CREATE INDEX idx_refresh_tokens_token_family_id
    ON refresh_tokens(token_family_id);

CREATE INDEX idx_refresh_tokens_replaced_by
    ON refresh_tokens(replaced_by);

ALTER TABLE refresh_tokens
    ADD CONSTRAINT fk_refresh_tokens_replaced_by
    FOREIGN KEY (replaced_by)
    REFERENCES refresh_tokens(id)
    ON DELETE SET NULL;
