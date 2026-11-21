import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';

import {
  createUserRepository,
} from '../../src/users/user-repository.mjs';

const fingerprint = `v1:${randomBytes(32).toString('hex')}`;
const rawToken = randomBytes(32).toString('base64url');
const tokenHash = createHash('sha256').update(rawToken).digest('hex');

function createMock({ denied = false, invalid = false, failActivation = false } = {}) {
  const calls = [];
  let released = false;

  const user = {
    id: randomUUID(),
    email_normalized: 'verify@example.test',
    account_status: 'pending_verification',
    email_verified_at: null,
  };

  const token = {
    token_id: randomUUID(),
    user_id: user.id,
    expires_at: new Date(Date.now() + 3600000),
    consumed_at: null,
    invalidated_at: null,
    email_normalized: user.email_normalized,
    account_status: user.account_status,
    email_verified_at: null,
  };

  const client = {
    async query(sql, params = []) {
      calls.push({ sql, params });

      if (/^(BEGIN|COMMIT|ROLLBACK)$/.test(sql)) {
        return { rowCount: null, rows: [] };
      }

      if (sql.startsWith('SET LOCAL search_path')) {
        return { rowCount: null, rows: [] };
      }

      if (sql.includes('FROM velzx_central_test.email_verification_tokens t')) {
        assert.equal(params[0], tokenHash);
        return invalid
          ? { rowCount: 0, rows: [] }
          : { rowCount: 1, rows: [{ ...token }] };
      }

      if (sql.includes('pg_advisory_xact_lock')) {
        return { rowCount: 1, rows: [] };
      }

      if (sql.includes('SELECT COUNT(*) AS account_count')) {
        return {
          rowCount: 1,
          rows: [{ account_count: denied ? '3' : '0' }],
        };
      }

      if (sql.includes('INSERT INTO security_events')) {
        return { rowCount: 1, rows: [] };
      }

      if (sql.includes('INSERT INTO registration_ip_claims')) {
        return {
          rowCount: 1,
          rows: [{ id: randomUUID(), verified_at: new Date() }],
        };
      }

      if (sql.includes('UPDATE velzx_central_test.email_verification_tokens')) {
        return { rowCount: 1, rows: [{ id: token.token_id }] };
      }

      if (sql.includes('UPDATE velzx_central_test.users')) {
        if (failActivation) {
          throw new Error('Simulated activation failure');
        }

        return {
          rowCount: 1,
          rows: [{
            id: user.id,
            email_normalized: user.email_normalized,
            account_status: 'active',
            email_verified_at: new Date(),
          }],
        };
      }

      throw new Error(`Unexpected SQL: ${sql}`);
    },

    release() {
      released = true;
    },
  };

  return {
    pool: { async connect() { return client; } },
    calls,
    wasReleased: () => released,
  };
}

test('valid token activates account and claims registration IP', async () => {
  const mock = createMock();
  const repo = createUserRepository(mock.pool);

  const result = await repo.verifyEmailToken({
    verificationToken: rawToken,
    ipFingerprint: fingerprint,
  });

  assert.equal(result.verified, true);
  assert.equal(result.user.account_status, 'active');
  assert.ok(mock.calls.some(x => x.sql.includes('INSERT INTO registration_ip_claims')));
  assert.ok(mock.calls.some(x => x.sql.includes('SET consumed_at = NOW()')));
  assert.ok(mock.calls.some(x => x.sql === 'COMMIT'));
  assert.ok(!mock.calls.some(x => x.sql === 'ROLLBACK'));
  assert.equal(mock.wasReleased(), true);
});

test('IP limit rejection preserves token and pending account', async () => {
  const mock = createMock({ denied: true });
  const repo = createUserRepository(mock.pool);

  const result = await repo.verifyEmailToken({
    verificationToken: rawToken,
    ipFingerprint: fingerprint,
  });

  assert.equal(result.verified, false);
  assert.equal(result.reason, 'ip_account_limit_reached');
  assert.ok(mock.calls.some(x => x.sql.includes('INSERT INTO security_events')));
  assert.ok(mock.calls.some(x => x.sql === 'COMMIT'));
  assert.ok(!mock.calls.some(x => x.sql.includes('SET consumed_at')));
  assert.ok(!mock.calls.some(x => x.sql.includes('UPDATE velzx_central_test.users')));
  assert.equal(mock.wasReleased(), true);
});

test('invalid token is rejected without IP claim', async () => {
  const mock = createMock({ invalid: true });
  const repo = createUserRepository(mock.pool);

  const result = await repo.verifyEmailToken({
    verificationToken: rawToken,
    ipFingerprint: fingerprint,
  });

  assert.equal(result.verified, false);
  assert.equal(result.reason, 'invalid_token');
  assert.ok(!mock.calls.some(x => x.sql.includes('INSERT INTO registration_ip_claims')));
  assert.ok(mock.calls.some(x => x.sql === 'COMMIT'));
});

test('malformed token is rejected before database connection', async () => {
  let connected = false;

  const repo = createUserRepository({
    async connect() {
      connected = true;
      throw new Error('Unexpected connection');
    },
  });

  const result = await repo.verifyEmailToken({
    verificationToken: 'invalid-token',
    ipFingerprint: fingerprint,
  });

  assert.equal(result.verified, false);
  assert.equal(result.reason, 'invalid_token');
  assert.equal(connected, false);
});

test('activation failure rolls back IP claim and token consumption', async () => {
  const mock = createMock({ failActivation: true });
  const repo = createUserRepository(mock.pool);

  await assert.rejects(
    repo.verifyEmailToken({
      verificationToken: rawToken,
      ipFingerprint: fingerprint,
    }),
    /Simulated activation failure/,
  );

  assert.ok(mock.calls.some(x => x.sql.includes('INSERT INTO registration_ip_claims')));
  assert.ok(mock.calls.some(x => x.sql.includes('SET consumed_at = NOW()')));
  assert.ok(mock.calls.some(x => x.sql === 'ROLLBACK'));
  assert.ok(!mock.calls.some(x => x.sql === 'COMMIT'));
  assert.equal(mock.wasReleased(), true);
});
