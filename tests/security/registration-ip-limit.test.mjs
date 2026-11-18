import test from 'node:test';
import assert from 'node:assert/strict';

import {
  MAX_VERIFIED_ACCOUNTS_PER_IP,
  claimVerifiedRegistrationIpInTransaction,
} from '../../src/security/registration-ip-limit.mjs';

const fingerprint = `v1:${'a'.repeat(64)}`;

const accountId = '123e4567-e89b-42d3-a456-426614174000';

function createMockClient({ count = 0 } = {}) {
  const calls = [];

  return {
    calls,

    async query(sql, params = []) {
      calls.push({ sql, params });

      if (sql.includes('pg_advisory_xact_lock')) {
        return { rows: [{}] };
      }

      if (sql.includes('COUNT(*)')) {
        return {
          rows: [{ account_count: String(count) }],
        };
      }

      if (sql.includes('INSERT INTO security_events')) {
        return { rows: [] };
      }

      if (sql.includes('INSERT INTO registration_ip_claims')) {
        return {
          rows: [{
            id: '1',
            verified_at: '2026-11-18T09:00:00.000Z',
          }],
        };
      }

      throw new Error(`Unexpected SQL: ${sql}`);
    },
  };
}

test('maximum verified accounts per IP is three', () => {
  assert.equal(MAX_VERIFIED_ACCOUNTS_PER_IP, 3);
});

test('allows and records an account below the limit', async () => {
  const client = createMockClient({ count: 2 });

  const result = await claimVerifiedRegistrationIpInTransaction({
    client,
    ipFingerprint: fingerprint,
    accountId,
  });

  assert.equal(result.allowed, true);
  assert.equal(result.verifiedAccountCount, 3);
  assert.equal(result.claim.id, '1');

  assert.equal(client.calls.length, 3);
  assert.match(client.calls[0].sql, /pg_advisory_xact_lock/);
  assert.match(client.calls[1].sql, /COUNT\(\*\)/);
  assert.match(client.calls[2].sql, /INSERT INTO registration_ip_claims/);
});

test('rejects the fourth account and records a security event', async () => {
  const client = createMockClient({ count: 3 });

  const result = await claimVerifiedRegistrationIpInTransaction({
    client,
    ipFingerprint: fingerprint,
    accountId,
  });

  assert.deepEqual(result, {
    allowed: false,
    reason: 'ip_account_limit_reached',
    limit: 3,
    verifiedAccountCount: 3,
  });

  assert.equal(client.calls.length, 3);
  assert.match(client.calls[0].sql, /pg_advisory_xact_lock/);
  assert.match(client.calls[1].sql, /COUNT\(\*\)/);
  assert.match(client.calls[2].sql, /INSERT INTO security_events/);

  assert.equal(
    client.calls[2].params[0],
    'registration_ip_limit_reached',
  );

  assert.equal(
    JSON.parse(client.calls[2].params[3]).limit,
    3,
  );
});

test('rejects invalid fingerprint without database queries', async () => {
  const client = createMockClient();

  await assert.rejects(
    claimVerifiedRegistrationIpInTransaction({
      client,
      ipFingerprint: 'invalid',
      accountId,
    }),
    /Invalid registration IP fingerprint/,
  );

  assert.equal(client.calls.length, 0);
});

test('rejects invalid account UUID without database queries', async () => {
  const client = createMockClient();

  await assert.rejects(
    claimVerifiedRegistrationIpInTransaction({
      client,
      ipFingerprint: fingerprint,
      accountId: 'not-a-uuid',
    }),
    /Invalid account UUID/,
  );

  assert.equal(client.calls.length, 0);
});

test('rejects missing PostgreSQL client', async () => {
  await assert.rejects(
    claimVerifiedRegistrationIpInTransaction({
      ipFingerprint: fingerprint,
      accountId,
    }),
    /PostgreSQL transaction client is required/,
  );
});

test('does not manage BEGIN or COMMIT itself', async () => {
  const client = createMockClient({ count: 0 });

  await claimVerifiedRegistrationIpInTransaction({
    client,
    ipFingerprint: fingerprint,
    accountId,
  });

  assert.equal(
    client.calls.some(({ sql }) => /^\s*(BEGIN|COMMIT|ROLLBACK)\b/i.test(sql)),
    false,
  );
});
