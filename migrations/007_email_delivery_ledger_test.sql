BEGIN;

SET LOCAL search_path TO velzx_central_test, pg_catalog;

CREATE TABLE email_deliveries (
    request_id VARCHAR(256) PRIMARY KEY
        CHECK (length(request_id) > 0),

    payload_hash VARCHAR(64) NOT NULL
        CHECK (payload_hash ~ '^[a-f0-9]{64}$'),

    status TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (
            status IN (
                'PENDING',
                'SUCCESS',
                'FAILED',
                'UNKNOWN'
            )
        ),

    attempt_count INTEGER NOT NULL DEFAULT 0
        CHECK (attempt_count >= 0),

    successful_key_number SMALLINT
        CHECK (
            successful_key_number IS NULL
            OR successful_key_number BETWEEN 1 AND 9
        ),

    provider_email_id TEXT,

    last_error_code VARCHAR(100),

    lease_expires_at TIMESTAMPTZ,
    next_attempt_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT email_delivery_success_consistency
        CHECK (
            (
                status = 'SUCCESS'
                AND successful_key_number IS NOT NULL
                AND provider_email_id IS NOT NULL
            )
            OR
            (
                status <> 'SUCCESS'
                AND successful_key_number IS NULL
                AND provider_email_id IS NULL
            )
        )
);

CREATE INDEX idx_email_deliveries_status_updated
    ON email_deliveries (status, updated_at DESC);

CREATE INDEX idx_email_deliveries_created
    ON email_deliveries (created_at DESC);

CREATE TABLE email_delivery_attempts (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    request_id VARCHAR(256) NOT NULL
        REFERENCES email_deliveries(request_id)
        ON DELETE RESTRICT,

    key_number SMALLINT NOT NULL
        CHECK (key_number BETWEEN 1 AND 9),

    outcome TEXT NOT NULL
        CHECK (
            outcome IN (
                'IN_PROGRESS',
                'AUTH_REJECTED',
                'SUCCESS',
                'PROVIDER_REJECTED',
                'RATE_LIMITED',
                'RETRYABLE_ERROR',
                'BILLING_REJECTED',
                'UNKNOWN'
            )
        ),

    http_status SMALLINT
        CHECK (
            http_status IS NULL
            OR http_status BETWEEN 100 AND 599
        ),

    error_code VARCHAR(100),

    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    completed_at TIMESTAMPTZ,

    CONSTRAINT email_attempt_completion_consistency
        CHECK (
            (outcome = 'IN_PROGRESS' AND completed_at IS NULL)
            OR
            (outcome <> 'IN_PROGRESS' AND completed_at IS NOT NULL)
        )
);

CREATE INDEX idx_email_attempts_request
    ON email_delivery_attempts (request_id, started_at);

CREATE INDEX idx_email_attempts_status
    ON email_delivery_attempts (outcome, started_at DESC);


CREATE TABLE IF NOT EXISTS resend_key_quota (
    key_number SMALLINT PRIMARY KEY
        CHECK (key_number BETWEEN 1 AND 9),

    status TEXT NOT NULL DEFAULT 'UNVERIFIED'
        CHECK (status IN (
            'ACTIVE',
            'QUOTA_EXHAUSTED',
            'TEMPORARY_ERROR',
            'INVALID_KEY',
            'UNVERIFIED',
            'DISABLED'
        )),

    daily_used INTEGER
        CHECK (daily_used IS NULL OR daily_used >= 0),

    daily_limit INTEGER
        CHECK (daily_limit IS NULL OR daily_limit >= 0),

    resets_at TIMESTAMPTZ,
    cooldown_until TIMESTAMPTZ,
    last_checked_at TIMESTAMPTZ,
    last_error_code VARCHAR(100),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT resend_quota_exhausted_requires_reset
        CHECK (
            status <> 'QUOTA_EXHAUSTED'
            OR resets_at IS NOT NULL
        ),

    CONSTRAINT resend_quota_usage_consistency
        CHECK (
            daily_used IS NULL
            OR daily_limit IS NULL
            OR daily_used <= daily_limit
            OR status = 'QUOTA_EXHAUSTED'
        )
);

CREATE INDEX IF NOT EXISTS idx_resend_key_quota_status
    ON resend_key_quota (status, resets_at);


COMMIT;
