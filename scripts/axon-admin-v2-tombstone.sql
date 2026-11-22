-- Offline regression artifact only. Do not apply to any live database.
-- Independently retained across discovery/app deletion and routine DB restore.
CREATE TABLE axon_admin_authority_state (
    organization_id TEXT NOT NULL,
    application_slug TEXT NOT NULL,
    enrollment_id TEXT NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
    digest TEXT NOT NULL CHECK (length(digest) = 71),
    generation BIGINT NOT NULL CHECK (generation > 0),
    withdrawn SMALLINT NOT NULL CHECK (withdrawn IN (0, 1)),
    PRIMARY KEY (organization_id, application_slug)
);
