# Existing Signet website and Axon administration

The registered OpenSponge website keeps its original Signet application, OAuth client,
callback, and users. Signet checks the user's current global administrator status.
An ordinary sign-in does not grant management access.

On Linux, build the backend with the deployment's database drivers and
`axon-incumbent-storage`. Normal database migration creates the incumbent storage
on PostgreSQL or SQLite. If migrations are managed separately, provision that schema
before activating the incumbent. MySQL remains available for ordinary Signet use.

The opt-in `discovery.axon_admin_incumbent_floor` names **existing, independently
provisioned** operator state for this specific application. It is not generated at
startup or inferred from a database row. Use the enrolled signer and binding in
`discovery.axon_admin_trust` and `discovery.axon_admin_v3`. Without valid/current
input this site cannot project administrator authority. Do not generate an approval
from the service's own database, change the site's management mode or use a different
client to make a deployment appear successful.

- The existing foreground `axon-v3 activate` accepts the enrolled signer's receipt.
  It compares the selected application, client, policy, revision, generation and
  permission set with operator state before writing the activation.
- Standard authorize, token and confidential introspection endpoints serve this
  path; there is no public administrative toggle or new OAuth scope. The original
  browser, user, live role, exact registration, S256 proof, code purpose and access
  token are checked. An unrelated ordinary code cannot become an administrator
  token by presenting it to the verifier. Role proof is returned only to the
  registered confidential verifier, not embedded as bearer authority.
- Withdrawal tombstones the exact activation. A demoted user or revoked session
  cannot continue managing through an existing token. When running the foreground
  withdrawal, also stop the independently maintained floor. If it is still active,
  the command reports that the database has been updated but a roll-back-resistant
  withdrawal is incomplete. Restoring only an older database does not override
  stopped operator state.
- SQLite uses an immediate write transaction. PostgreSQL uses a serializable write
  transaction for the same code admission and exchange, locks the matched
  registration rows, and checks protected state again before returning the result.

This is the source/runtime contract, not evidence that the deployment has been
configured or that end-to-end acceptance has been performed.
