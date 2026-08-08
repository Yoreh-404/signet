# AnchorDocs project workflow

Read `.anchordocs.toml` and the AnchorDocs overview before changing Signet
authentication, OIDC, security policy, database, frontend, or deployment
behavior. Expand relevant developer documents and verify current claims against
a pinned commit and tests. Keep user setup and integration instructions
separate from technical reference material.

Route by the concrete identity, protocol, browser-security, directory, or key
rotation flow. Preserve the account/application/session boundaries and do not
assume Signet is a single OAuth callback service.

Obtain user confirmation before documentation/design writes. Discussion-only
work remains `DISCUSSION`; confirmed work follows `TODO` → `IN_PROGRESS` →
`DONE` with evidence. Inspect locks first and never bypass a user-owned lock.
Use AnchorDocs MCP for remote document changes and do not publish public docs
without explicit confirmation.
