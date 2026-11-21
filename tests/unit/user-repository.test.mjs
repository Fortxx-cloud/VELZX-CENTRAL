import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import {
  createUserRepository,
} from '../../src/users/user-repository.mjs';

function createMockPool({
  duplicate = false,
  tokenInsertFails = false,
} = {}) {
  const calls = [];
  let released = false;

  const client = {
    async query(sql, params = []) {
      calls.push({ sql, params });

      if (sql === 'BEGIN' || sql === 'COMMIT' || sql === 'ROLLBACK') {
        return { rowCount: null, rows: [] };
      }

      if (sql.startsWith('SET LOCAL search_path')) {
        return { rowCount: null, rows: [] };
      }

      if (sql.includes('INSERT INTO velzx_central_test.users')) {
        if (duplicate) {
          return { rowCount: 0, rows: [] };
        }

        return {
          rowCount: 1,
          rows: [{
            id: params[0],
            email_normalized: params[1],
            account_status: 'pending_verification',
            created_at: new Date(),
          }],
        };
      }

      if (
        sql.includes(
          'INSERT INTO velzx_central_test.email_verification_tokens',
        )
      ) {
        if (tokenInsertFails) {
          throw new Error('Simulated token insert failure');
        }

        return {
          rowCount: 1,
          rows: [{ expires_at: new Date(Date.now() + 86400000) }],
        };
      }

      throw new Error(`Unexpected SQL: ${sql}`);
    },

    release() {
      released = true;
    },
  };

  return {
    pool: {
      async connect() {
        return client;
      },
    },
    calls,
    wasReleased: () => released,
  };
}

test('creates pending user and stores only SHA-256 token digest', async () => {
  const mock = createMockPool();
  const repository = createUserRepository(mock.pool);

  const result = await repository.createPendingUser({
    email: '  USER@Example.COM ',
    passwordHash: 'scrypt$test-hash',
  });

  assert.equal(result.created, true);
  assert.equal(result.user.email_normalized, 'user@example.com');
  assert.equal(result.user.account_status, 'pending_verification');

  assert.equal(typeof result.verificationToken, 'string');
  assert.equal(
    Buffer.from(result.verificationToken, 'base64url').length,
    32,
  );

  const tokenInsert = mock.calls.find(({ sql }) =>
    sql.includes('INSERT INTO velzx_central_test.email_verification_tokens'),
  );

  assert.ok(tokenInsert);
  assert.match(tokenInsert.params[2], /^[a-f0-9]{64}$/);

  const expectedHash = createHash('sha256')
    .update(result.verificationToken)
    .digest('hex');

  assert.equal(tokenInsert.params[2], expectedHash);
  assert.notEqual(tokenInsert.params[2], result.verificationToken);

  assert.ok(mock.calls.some(({ sql }) => sql === 'COMMIT'));
  assert.ok(!mock.calls.some(({ sql }) => sql === 'ROLLBACK'));
  assert.equal(mock.wasReleased(), true);
});

test('returns generic duplicate result without creating verification token', async () => {
  const mock = createMockPool({ duplicate: true });
  const repository = createUserRepository(mock.pool);

  const result = await repository.createPendingUser({
    email: 'user@example.com',
    passwordHash: 'scrypt$test-hash',
  });

  assert.deepEqual(result, { created: false });

  assert.ok(mock.calls.some(({ sql }) => sql === 'COMMIT'));
  assert.ok(
    !mock.calls.some(({ sql }) =>
      sql.includes('INSERT INTO velzx_central_test.email_verification_tokens'),
    ),
  );

  assert.equal(mock.wasReleased(), true);
});

test('rolls back user creation if verification token insert fails', async () => {
  const mock = createMockPool({ tokenInsertFails: true });
  const repository = createUserRepository(mock.pool);

  await assert.rejects(
    repository.createPendingUser({
      email: 'user@example.com',
      passwordHash: 'scrypt$test-hash',
    }),
    /Simulated token insert failure/,
  );

  assert.ok(mock.calls.some(({ sql }) => sql === 'ROLLBACK'));
  assert.ok(!mock.calls.some(({ sql }) => sql === 'COMMIT'));
  assert.equal(mock.wasReleased(), true);
});

test('rejects invalid email before opening a database connection', async () => {
  let connectionAttempted = false;

  const repository = createUserRepository({
    async connect() {
      connectionAttempted = true;
      throw new Error('Should not connect');
    },
  });

  await assert.rejects(
    repository.createPendingUser({
      email: 'not-an-email',
      passwordHash: 'scrypt$test-hash',
    }),
    /Format email tidak valid/,
  );

  assert.equal(connectionAttempted, false);
});

test('rejects invalid password hash before opening a database connection', async () => {
  let connectionAttempted = false;

  const repository = createUserRepository({
    async connect() {
      connectionAttempted = true;
      throw new Error('Should not connect');
    },
  });

  await assert.rejects(
    repository.createPendingUser({
      email: 'user@example.com',
      passwordHash: '',
    }),
    /Password hash tidak valid/,
  );

  assert.equal(connectionAttempted, false);
});

test('rejects unapproved schema', () => {
  const pool = {
    async connect() {
      throw new Error('Should not connect');
    },
  };

  assert.throws(
    () => createUserRepository(pool, { schema: 'public' }),
    /Schema database tidak diizinkan/,
  );
});

test('rejects invalid verification token lifetime', () => {
  const pool = {
    async connect() {
      throw new Error('Should not connect');
    },
  };

  assert.throws(
    () => createUserRepository(pool, {
      verificationTokenTtlSeconds: 10,
    }),
    /Masa berlaku token verifikasi tidak valid/,
  );
});
