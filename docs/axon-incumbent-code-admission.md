# Incumbent authorization-code admission boundary

The website-managed incumbent writer and its readback are dormant. They
cannot authorize or mint an OAuth code. The existing generic website OAuth
path remains unchanged.

`oidc::issue_authorization_code_redirect` accepts previously resolved
request, user, session and policy snapshots. Trial eligibility, application
auth-context creation and `Db::insert_authorization_code` are separate
database calls. The last call uses its own pooled connection and inserts the
provided row without checking that the original browser still exists or is a
global admin. Adding an incumbent check before this call leaves a race with
logout, demotion, enrollment change, policy withdrawal or restore hold.

The narrow callable boundary is **inside the existing authorization-code
insertion on the caller's transaction connection**, not a preflight API.
Thread one private non-serializable incumbent input from the already parsed
request, containing the original server-resolved browser credential/session,
exact app/client binding, already verified incumbent activation identity,
and prepared code row. In one transaction:

1. Re-resolve the original browser credential and exact session against the
   current user. Require active, unarchived, non-trial, interactive session
   and a current global admin. A different session for the same user is
   insufficient. Use the existing credential parsing/expiry semantics.
2. Recheck exact organization, website enrollment and enrolled signing key,
   app/client binding, audience, S256 and exact callback/openid, nonwithdrawn
   ledger row and stable bytes, and the existing restore marker. Keep all
   existing assurance and consent checks; never treat this tuple as a grant.
3. Bind the existing authorization-code insert and any necessary auth-context
   write to that same connection. Expose only its exact committed result:
   never return an authorization marker that can reach a later transaction,
   never fall back to the generic issuer, and never use a probe as admission.

The SQLite candidate's `BEGIN IMMEDIATE` can serialize the reads and write.
For PostgreSQL, require a qualified transaction covering the exact signer,
site, binding, activation, credential, session, user and context rows, plus
protection against new trial rows/other negative-predicate changes (not
just row locks on existing rows). Verify lock order and transaction/restore
rollback before enabling it. Do not switch the configured database.

The synthetic discriminator is same-user old browser vs another browser,
with a role or credential change after preliminary checks: only the exact
same-transaction current query may pass; no authorization code is minted.
Follow-up native tests must exercise those cases at the existing code
insert and assert no inserted row/redirect on denial, along with ordinary
website continuity unchanged.
