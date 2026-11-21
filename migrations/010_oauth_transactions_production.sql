BEGIN;
CREATE SCHEMA IF NOT EXISTS velzx_central;

SET LOCAL search_path TO velzx_central, pg_catalog;

CREATE TABLE oauth_transactions (
    id UUID PRIMARY KEY,
    provider VARCHAR(16) NOT NULL
        CHECK (provider IN ('google', 'github', 'microsoft')),
    state_hash VARCHAR(64) NOT NULL UNIQUE
        CHECK (state_hash ~ '^[a-f0-9]{64}$'),
    nonce_hash VARCHAR(64)
        CHECK (nonce_hash IS NULL OR nonce_hash ~ '^[a-f0-9]{64}$'),
    browser_binding_hash VARCHAR(64) NOT NULL
        CHECK (browser_binding_hash ~ '^[a-f0-9]{64}$'),
    purpose VARCHAR(16) NOT NULL
        CHECK (purpose IN ('login', 'link')),
    initiating_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    initiating_session_id UUID REFERENCES sessions(id) ON DELETE CASCADE,
    secret_iv BYTEA NOT NULL CHECK (octet_length(secret_iv) = 12),
    secret_ciphertext BYTEA NOT NULL,
    secret_auth_tag BYTEA NOT NULL
        CHECK (octet_length(secret_auth_tag) = 16),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CHECK (expires_at > created_at),
    CHECK (consumed_at IS NULL OR consumed_at >= created_at),
    CHECK (
        (purpose = 'login'
            AND initiating_user_id IS NULL
            AND initiating_session_id IS NULL)
        OR
        (purpose = 'link'
            AND initiating_user_id IS NOT NULL
            AND initiating_session_id IS NOT NULL)
    )
);

CREATE INDEX idx_oauth_transactions_expiry
    ON oauth_transactions (expires_at);

CREATE INDEX idx_oauth_transactions_user
    ON oauth_transactions (initiating_user_id, created_at DESC)
    WHERE initiating_user_id IS NOT NULL;

COMMIT;
