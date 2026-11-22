import assert from 'node:assert/strict';
import test from 'node:test';
import { project, permitsRevision } from './axon-admin-v2-reference.mjs';

const permissions = ['admin:agent:system.console:context', 'admin:standing:inbox'];
const binding = { tenant: 'example', application_id: 'axon', signer: 'pinned-test-key', origin: 'https://axon.test',
  issuer: 'https://issuer.test', client_id: 'axon-browser', audience: 'https://api.test/axon' };
const record = { ...binding, revision: 3, digest: 'sha256:' + 'a'.repeat(64) };
function inputs() {
  const m = { version: 2, source: 'signet.is_admin', claim: 'axon_admin_authority',
    output: 'access_token', client_id: binding.client_id, audience: binding.audience,
    permissions: [...permissions] };
  return [{ ...record, permissions: [...permissions] },
    { ...record, mapping: m, verified: true, notBefore: 10, expires: 100 },
    { ...binding, subject: 'sample', registration: 'operator_bound_axon', scope: 'openid',
      output: 'access_token', browserSessionBound: true, customClaims: {} },
    { tenant: binding.tenant, subject: 'sample', currentAdmin: true }, 50];
}
test('only the exact reserved resource access claim is projected', () => {
  assert.deepEqual(project(...inputs()), { axon_admin_authority: {
    version: 2, application_id: 'axon', revision: 3, permissions } });
});

for (const [index, changes] of [
  [0, { permissions: [], digest: null }],
  [1, { ...Object.fromEntries(Object.keys(binding).map(k => [k,'other'])),
    revision: 2, digest: 'sha256:' + 'b'.repeat(64), verified: false, mapping: true, expires: 50, notBefore: 51 }],
  [2, { ...Object.fromEntries(Object.keys(binding).filter(k=>k!=='signer').map(k => [k,'other'])),
    registration: 'public_dcr', output: 'id_token', scope: 'openid admin', browserSessionBound: false,
    customClaims: { axon_admin_authority: {} } }],
  [3, { currentAdmin: false, tenant: 'other', subject: 'other' }]
]) {
  for (const [k,v] of Object.entries(changes)) test('reject mismatch ' + index + '.' + k, () => {
    const args = inputs(); args[index][k] = v; assert.equal(project(...args), null);
  });
}
test('strict wire fields, catalogs, withdrawal and userinfo', () => {
  for (const [key,value] of [['extra',true],['version',1],['source','role'],['claim','permissions'],
    ['output','userinfo'],['client_id','other'],['audience','other'],['permissions',null],
    ...[[], permissions.slice(1), [...permissions].reverse(), [permissions[0],permissions[0]],
      ['*'], [...permissions,'admin:unknown:new']].map(v=>['permissions',v])]) {
    const args = inputs(); args[1].mapping[key] = value; assert.equal(project(...args),null);
  }
  const args = inputs(); args[2].output = 'userinfo'; assert.equal(project(...args),null);
  args[2].output = 'access_token'; delete args[1].mapping; assert.equal(project(...args),null);
});
test('revision continuity for the same identity only', () => {
  assert.ok(permitsRevision(null,record)); assert.ok(permitsRevision(record,{...record}));
  const changed = { ...record, digest: 'sha256:' + 'b'.repeat(64) };
  assert.equal(permitsRevision(record,changed),false);
  assert.ok(permitsRevision(record,{...changed,revision:4}));
  for (const update of [{revision:2},{revision:true},{digest:''},{tenant:'other'},{application_id:'other'}]) {
    assert.equal(permitsRevision(record,{...record,...update}),false);
  }
});
