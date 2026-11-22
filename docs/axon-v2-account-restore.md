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
