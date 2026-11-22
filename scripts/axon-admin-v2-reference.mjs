// Offline conformance model only. Not an issuer, JWS verifier or JSON decoder.
// Inputs model trusted, independently loaded operator policy, verified claims,
// persisted revision high-water mark, authenticated grant and current directory row.
// No caller may source those trust facts from a client or signed mapping itself.
const claim = 'axon_admin_authority';
const bindings = ['tenant', 'application_id', 'origin', 'issuer', 'client_id', 'audience', 'signer'];
const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const positive = v => Number.isSafeInteger(v) && v > 0;
const id = v => typeof v === 'string' && v.trim() === v && v.length > 0;
const digest = v => typeof v === 'string' && /^sha256:[0-9a-f]{64}$/.test(v);
const mappingKeys = ['version', 'source', 'claim', 'output', 'client_id', 'audience', 'permissions'];

export function project(policy, snapshot, grant, account, now) {
  if (![policy, snapshot, grant, account].every(object) || !positive(now)) return null;
  const m = snapshot.mapping, list = policy.permissions;
  if (!object(m) || Object.keys(m).length !== mappingKeys.length ||
      !mappingKeys.every(k => Object.hasOwn(m, k)) ||
      m.version !== 2 || m.source !== 'signet.is_admin' || m.claim !== claim ||
      m.output !== 'access_token' || m.client_id !== policy.client_id ||
      m.audience !== policy.audience) return null;

  if (!Array.isArray(list) || !list.length || !Array.isArray(m.permissions) ||
      list.length !== m.permissions.length) return null;
  for (let i = 0; i < list.length; i++) {
    const p = list[i];
    if (typeof p !== 'string' || !/^admin:(?:[a-z0-9][a-z0-9._-]*:)+[a-z0-9][a-z0-9_-]*$/.test(p) ||
        p !== m.permissions[i] || (i && list[i-1] >= p)) return null;
  }

  if (!bindings.every(k => id(policy[k]) && policy[k] === snapshot[k]) ||
      snapshot.verified !== true || !positive(snapshot.notBefore) || !positive(snapshot.expires) ||
      snapshot.notBefore > now || now >= snapshot.expires ||
      !positive(policy.revision) || snapshot.revision !== policy.revision ||
      !digest(policy.digest) || snapshot.digest !== policy.digest) return null;

  if (!['tenant','application_id','origin','issuer','client_id','audience'].every(k => policy[k] === grant[k]) ||
      grant.registration !== 'operator_bound_axon' || grant.output !== 'access_token' ||
      grant.scope !== 'openid' || grant.browserSessionBound !== true ||
      !id(account.subject) || account.subject !== grant.subject ||
      account.currentAdmin !== true || !object(grant.customClaims) ||
      Object.hasOwn(grant.customClaims, claim)) return null;

  return { [claim]: { version: 2, application_id: policy.application_id,
    revision: policy.revision, permissions: [...list] } };
}

// Scoped to one authenticated tenant/app and its durable record. Withdrawal is a
// change of stable digest even if the old signature and expiry are still valid.
export function permitsRevision(previous, next) {
  const valid = r => object(r) && id(r.tenant) && id(r.application_id) &&
    positive(r.revision) && digest(r.digest);
  return valid(next) && (previous === null || (valid(previous) &&
    previous.tenant === next.tenant && previous.application_id === next.application_id &&
    (next.revision > previous.revision ||
      (next.revision === previous.revision && next.digest === previous.digest))));
}
