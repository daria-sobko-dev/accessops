-- Append-only audit log of every access change attempt. Idempotent.

CREATE TABLE IF NOT EXISTS access_audit (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    created_at  timestamptz NOT NULL DEFAULT now(),
    actor       text        NOT NULL,
    approved_by text,
    action      text        NOT NULL CHECK (action IN ('grant', 'revoke')),
    system      text        NOT NULL,
    subject     text        NOT NULL,
    role        text,
    ticket_id   text,
    result      text        NOT NULL CHECK (result IN ('success', 'denied', 'error')),
    details     jsonb       NOT NULL DEFAULT '{}'::jsonb
);

-- Allowed systems. Re-created on every init so new systems can be added.
-- ALTER TABLE changes the rule, not the rows, so the append-only trigger is not involved.
ALTER TABLE access_audit DROP CONSTRAINT IF EXISTS access_audit_system_check;
ALTER TABLE access_audit ADD CONSTRAINT access_audit_system_check
    CHECK (system IN ('postgres', 'rabbitmq', 'linux'));

CREATE OR REPLACE FUNCTION access_audit_reject_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'access_audit is append-only: % is not allowed', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

CREATE OR REPLACE TRIGGER access_audit_no_update_delete
    BEFORE UPDATE OR DELETE ON access_audit
    FOR EACH ROW EXECUTE FUNCTION access_audit_reject_change();

CREATE OR REPLACE TRIGGER access_audit_no_truncate
    BEFORE TRUNCATE ON access_audit
    FOR EACH STATEMENT EXECUTE FUNCTION access_audit_reject_change();
