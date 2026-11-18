import test from 'node:test';
import assert from 'node:assert/strict';

import {
  claimIngressNonce,
  cleanupExpiredIngressNonces,
} from '../../src/security/ingress-nonce-repository.mjs';

const nonce = 'A'.repeat(43);
const expiresAt = new Date(Date.now() + 120000);

function mockClient(result = { rows: [{ nonce }] }) {
  const calls = [];

  return {
    calls,
    client: {
      async query(sql, values) {
        calls.push({ sql, values });
        return result;
      },
    },
  };
}

test('claims a new nonce successfully', async () => {
  const mock = mockClient();

  const result = await claimIngressNonce({
    client: mock.client,
    nonce,
    expiresAt,
  });

  assert.deepEqual(result, { accepted: true });
  assert.match(mock.calls[0].sql, /ON CONFLICT \(nonce\) DO NOTHING/);
  assert.match(mock.calls[0].sql, /RETURNING nonce/);
  assert.equal(mock.calls[0].values[0], nonce);
  assert.equal(mock.calls[0].values[1], expiresAt);
});

test('rejects a previously claimed nonce', async () => {
  const mock = mockClient({ rows: [] });

  const result = await claimIngressNonce({
    client: mock.client,
    nonce,
    expiresAt,
  });

  assert.deepEqual(result, { accepted: false });
});

test('uses the test schema by default', async () => {
  const mock = mockClient();

  await claimIngressNonce({
    client: mock.client,
    nonce,
    expiresAt,
  });

  assert.match(
    mock.calls[0].sql,
    /velzx_central_test\.ingress_nonces/,
  );
});

test('allows an explicitly selected production schema', async () => {
  const mock = mockClient();

  await claimIngressNonce({
    client: mock.client,
    nonce,
    expiresAt,
    schema: 'velzx_central',
  });

  assert.match(
    mock.calls[0].sql,
    /velzx_central\.ingress_nonces/,
  );
});

test('rejects an unapproved schema', async () => {
  const mock = mockClient();

  await assert.rejects(
    claimIngressNonce({
      client: mock.client,
      nonce,
      expiresAt,
      schema: 'public',
    }),
    /not allowed/,
  );

  assert.equal(mock.calls.length, 0);
});

test('rejects malformed nonce', async () => {
  const mock = mockClient();

  await assert.rejects(
    claimIngressNonce({
      client: mock.client,
      nonce: 'invalid',
      expiresAt,
    }),
    /Invalid ingress nonce/,
  );

  assert.equal(mock.calls.length, 0);
});

test('rejects expired nonce retention date', async () => {
  const mock = mockClient();

  await assert.rejects(
    claimIngressNonce({
      client: mock.client,
      nonce,
      expiresAt: new Date(Date.now() - 1000),
    }),
    /must be in the future/,
  );

  assert.equal(mock.calls.length, 0);
});

test('rejects invalid expiry value', async () => {
  const mock = mockClient();

  await assert.rejects(
    claimIngressNonce({
      client: mock.client,
      nonce,
      expiresAt: 'tomorrow',
    }),
    /must be in the future/,
  );

  assert.equal(mock.calls.length, 0);
});

test('rejects missing database client', async () => {
  await assert.rejects(
    claimIngressNonce({
      client: null,
      nonce,
      expiresAt,
    }),
    /PostgreSQL client/,
  );
});

test('cleans expired nonces in bounded batches', async () => {
  const mock = mockClient({
    rows: [{ nonce }, { nonce: 'B'.repeat(43) }],
  });

  const result = await cleanupExpiredIngressNonces({
    client: mock.client,
    batchSize: 100,
  });

  assert.deepEqual(result, { deleted: 2 });
  assert.match(mock.calls[0].sql, /expires_at <= NOW\(\)/);
  assert.match(mock.calls[0].sql, /SKIP LOCKED/);
  assert.deepEqual(mock.calls[0].values, [100]);
});

test('rejects invalid cleanup batch size', async () => {
  const mock = mockClient();

  await assert.rejects(
    cleanupExpiredIngressNonces({
      client: mock.client,
      batchSize: 0,
    }),
    /Invalid ingress nonce cleanup batch size/,
  );

  assert.equal(mock.calls.length, 0);
});

test('does not delete from an unapproved schema', async () => {
  const mock = mockClient();

  await assert.rejects(
    cleanupExpiredIngressNonces({
      client: mock.client,
      schema: 'public',
    }),
    /not allowed/,
  );

  assert.equal(mock.calls.length, 0);
});
