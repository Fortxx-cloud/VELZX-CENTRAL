BEGIN;

SET LOCAL search_path TO velzx_central_test, pg_catalog;

-- 1. User accounts
CREATE TABLE users (
    id UUID PRIMARY KEY,
    email_normalized VARCHAR(320) NOT NULL UNIQUE
        CHECK (
            length(email_normalized) BETWEEN 3 AND 320
            AND email_normalized = lower(btrim(email_normalized))
        ),
    password_hash VARCHAR(255),
    email_verified_at TIMESTAMPTZ,
    account_status VARCHAR(24) NOT NULL DEFAULT 'pending_verification'
        CHECK (
            account_status IN (
                'pending_verification',
                'active',
                'suspended',
                'disabled'
            )
        ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (
        account_status <> 'active'
        OR email_verified_at IS NOT NULL
    )
);

CREATE INDEX idx_users_status_created
    ON users (account_status, created_at DESC);

-- 2. External identities: Google, GitHub, Microsoft
CREATE TABLE user_identities (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(16) NOT NULL
        CHECK (provider IN ('google', 'github', 'microsoft')),
    provider_subject VARCHAR(255) NOT NULL
        CHECK (length(provider_subject) BETWEEN 1 AND 255),
    provider_email VARCHAR(320),
    provider_email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (provider, provider_subject),
    CHECK (
        NOT provider_email_verified
        OR provider_email IS NOT NULL
    )
);

CREATE INDEX idx_user_identities_user
    ON user_identities (user_id);

-- 3. Email verification tokens: store SHA-256 digest only
CREATE TABLE email_verification_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL UNIQUE
        CHECK (token_hash ~ '^[a-f0-9]{64}$'),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    invalidated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (expires_at > created_at),
    CHECK (NOT (
        consumed_at IS NOT NULL AND invalidated_at IS NOT NULL
    ))
);

CREATE INDEX idx_email_verification_user_active
    ON email_verification_tokens (user_id, expires_at)
    WHERE consumed_at IS NULL AND invalidated_at IS NULL;

-- 4. Password reset tokens: 15-minute expiry enforced by service
CREATE TABLE password_reset_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL UNIQUE
        CHECK (token_hash ~ '^[a-f0-9]{64}$'),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    invalidated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (expires_at > created_at),
    CHECK (NOT (
        consumed_at IS NOT NULL AND invalidated_at IS NOT NULL
    ))
);

CREATE INDEX idx_password_reset_user_active
    ON password_reset_tokens (user_id, expires_at)
    WHERE consumed_at IS NULL AND invalidated_at IS NULL;

-- 5. Central-owned sessions: store token digest, never raw token
CREATE TABLE sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,
    session_token_hash VARCHAR(64) NOT NULL UNIQUE
        CHECK (session_token_hash ~ '^[a-f0-9]{64}$'),
    expires_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (expires_at > created_at),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at),
    CHECK (last_seen_at IS NULL OR last_seen_at >= created_at)
);

CREATE INDEX idx_sessions_user_active
    ON sessions (user_id, expires_at)
    WHERE revoked_at IS NULL;

COMMIT;
