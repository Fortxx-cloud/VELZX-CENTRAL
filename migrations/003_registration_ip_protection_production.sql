BEGIN;

CREATE SCHEMA IF NOT EXISTS velzx_central;

SET LOCAL search_path TO velzx_central, pg_catalog;

CREATE TABLE registration_ip_claims (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    ip_fingerprint VARCHAR(67) NOT NULL
        CHECK (ip_fingerprint ~ '^v1:[a-f0-9]{64}$'),

    account_id UUID NOT NULL UNIQUE,

    verified_at TIMESTAMPTZ NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_registration_ip_claims_verified
    ON registration_ip_claims (ip_fingerprint, verified_at);

CREATE TABLE security_events (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    event_type TEXT NOT NULL
        CHECK (
            event_type IN (
                'registration_ip_limit_reached',
                'registration_ip_invalid',
                'registration_ip_untrusted_source'
            )
        ),

    ip_fingerprint VARCHAR(67)
        CHECK (
            ip_fingerprint IS NULL
            OR ip_fingerprint ~ '^v1:[a-f0-9]{64}$'
        ),

    account_id UUID,

    details JSONB NOT NULL DEFAULT '{}'::JSONB,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_security_events_created_at
    ON security_events (created_at DESC);

CREATE INDEX idx_security_events_fingerprint
    ON security_events (ip_fingerprint)
    WHERE ip_fingerprint IS NOT NULL;

COMMIT;
