-- Offline regression artifact only. Do not apply to any live database.
-- Independently retained across discovery/app deletion and routine DB restore.
CREATE TABLE axon_admin_authority_state (
    organization_id TEXT NOT NULL,
    application_slug TEXT NOT NULL,
    enrollment_id TEXT NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
    digest TEXT NOT NULL CHECK (length(digest) = 43),
    generation BIGINT NOT NULL CHECK (generation > 0),
    withdrawn INTEGER NOT NULL CHECK (withdrawn IN (0, 1)),
    snapshot_json TEXT,
    expires_at BIGINT,
    CHECK ((snapshot_json IS NULL) = (expires_at IS NULL)),
    CHECK (withdrawn = 0 OR snapshot_json IS NULL),
    PRIMARY KEY (organization_id, application_slug)
);
