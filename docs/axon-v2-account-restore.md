# Axon v2 authority after a Signet restore

Signet checks the current administrator role both when issuing Axon v2 access
authority and when its confidential resource server introspects that
authority. An account demotion takes effect in the current database. A
backup that predates demotion does not remember the demotion; the application
rollback marker does not log per-account changes.

Before making a restored Signet database available, retain the independent
operator-owned rollback marker and keep the exact Axon enrollment halted.
Reconcile account roles against trustworthy evidence that was not rolled back.
Do not reopen the enrollment based on the restored role table alone. If the
original roles cannot be reconciled, leave the enrollment halted. Reopening
uses the existing higher signed revision and generation procedure; the old
generation and prior signed revision cannot reopen it. The halt is scoped to
this Axon v2 enrollment. It does not lock Signet management routes, Axon
v1, or other applications. Do not reopen any management traffic based on
the restored role table alone. Ordinary OIDC is not logged out by the halt.

The SQLite regression uses only disposable databases and synthetic users:

```sh
cargo test --offline --locked -p sso-backend axon_v2_ordinary_code_issues_full_access_only_and_rechecks_authority
```

It exercises actual management demotion, auth-code exchange, and confidential
introspection; the separately retained marker rejects both an existing bearer
and fresh v2 issuance against the restored backup. The same OIDC identity can
still receive an ID token without the privileged projection. This does not
qualify a production restore, PostgreSQL restore, automated role journal, or
an online cross-service cutover.

## Optional independently pinned account denials

With explicitly configured `discovery.axon_admin_v2.account_revocations`,
the v2 projection requires a matching signed evidence file. Configure an
absolute `marker_path`, the independent Ed25519 `signing_public_key`
(unpadded base64url raw public key), and the reviewed `payload_digest`
(unpadded base64url SHA-256 of the exact signed payload bytes).

The read-only regular file contains a JSON envelope with unpadded base64url
`payload` and `signature`. The Ed25519 signature covers the exact payload
bytes. The payload is JSON with format `signet-axon-account-revocations/v1`,
the floor's `organization_id`, `application_id`, `enrollment_id`,
`minimum_generation`, `revision`, and `digest`, and a lexically sorted
unique `revoked_account_ids` list of at most 512 canonical Signet account UUIDs.
A correctly signed empty list is valid; an absent or invalid file denies all
v2 authority for the enrollment. A valid list denies only the named accounts.
Signed evidence never grants authority or changes a Signet role.
The independently retained floor revision and digest must match the active
configured declaration exactly in this mode. A transitional mismatch remains
halted for v2 projection until independently reconciled.

Keep both evidence and its reviewed config pin independently of database
backups, in an operator-owned location that the service cannot replace.
An older valid file at the same generation fails the digest pin.
Installing a new list is a reviewed operator procedure: halt the enrollment
and stop serving old-config replicas, atomically replace the evidence, and
restart with the new independently retained pin before reopening. Do not
reopen based on an old pin, remove denials as part of a restore, or use
these files as a substitute for current role reconciliation. There is no
automatic journal, automatic unrevocation, or protection if both independent
inputs are rolled back.
