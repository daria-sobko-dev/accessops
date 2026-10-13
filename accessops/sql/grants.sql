-- Source of truth: which access should exist. Idempotent.

CREATE TABLE IF NOT EXISTS access_grants (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    subject     text        NOT NULL,
    system      text        NOT NULL CHECK (system IN ('postgres', 'rabbitmq', 'linux')),
    role        text        NOT NULL,
    ticket_id   text,
    actor       text        NOT NULL,
    approved_by text,
    granted_at  timestamptz NOT NULL,
    -- NULL means permanent access.
    expires_at  timestamptz,
    status      text        NOT NULL DEFAULT 'active'
                            CHECK (status IN ('active', 'revoked', 'expired')),
    revoked_at  timestamptz,
    revoked_by  text,
    CHECK (expires_at IS NULL OR expires_at > granted_at),
    CHECK ((status = 'active') = (revoked_at IS NULL))
);

-- At most one active grant per person and system.
CREATE UNIQUE INDEX IF NOT EXISTS access_grants_one_active
    ON access_grants (subject, system) WHERE status = 'active';

CREATE INDEX IF NOT EXISTS access_grants_active_expiry
    ON access_grants (expires_at) WHERE status = 'active';
