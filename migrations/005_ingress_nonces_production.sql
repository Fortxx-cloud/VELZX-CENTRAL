BEGIN;

CREATE SCHEMA IF NOT EXISTS velzx_central;

SET LOCAL search_path TO velzx_central, pg_catalog;

CREATE TABLE ingress_nonces (
    nonce VARCHAR(43) PRIMARY KEY
        CHECK (nonce ~ '^[A-Za-z0-9_-]{43}$'),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    expires_at TIMESTAMPTZ NOT NULL,

    CHECK (expires_at > created_at)
);

CREATE INDEX idx_ingress_nonces_expires_at
    ON ingress_nonces (expires_at);

COMMIT;
