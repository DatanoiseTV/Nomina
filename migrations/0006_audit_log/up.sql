-- Audit trail of mutating management actions (who did what, when, from where).
CREATE TABLE audit_log (
    id       INTEGER PRIMARY KEY,
    at       TEXT NOT NULL,
    username TEXT NOT NULL,
    action   TEXT NOT NULL,
    status   INTEGER NOT NULL,
    ip       TEXT NOT NULL DEFAULT ""
);
CREATE INDEX idx_audit_log_at ON audit_log(at);
