import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import {
  createSessionRepository,
} from '../../src/auth/session/session-repository.mjs';

const USER_ID = '11111111-1111-4111-8111-111111111111';
const SESSION_ID = '22222222-2222-4222-8222-222222222222';
const TOKEN = 'a'.repeat(43);

function digest(token) {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

function createMockPool({ rows = [], rowCount = rows.length } = {}) {
  const calls = [];

  return {
    calls,
    pool: {
      async query(sql, params = []) {
        calls.push({ sql, params });
        return { rows, rowCount };
      },
    },
  };
}

test('accepts test and production schemas', () => {
  const mock = createMockPool();

  assert.doesNotThrow(() =>
    createSessionRepository(mock.pool),
  );

  assert.doesNotThrow(() =>
    createSessionRepository(mock.pool, {
      schema: 'velzx_central',
    }),
  );
});

test('rejects non-allowlisted schemas', () => {
  const mock = createMockPool();

  for (const schema of ['public', 'velzx_central_test;DROP SCHEMA']) {
    assert.throws(
      () => createSessionRepository(mock.pool, { schema }),
      /Schema database tidak diizinkan/,
    );
  }
});

test('rejects invalid pool', () => {
  assert.throws(
    () => createSessionRepository({}),
    /PostgreSQL pool tidak valid/,
  );
});

test('findActiveSession returns session and active user', async () => {
  const mock = createMockPool({
    rows: [{
      session_id: SESSION_ID,
      user_id: USER_ID,
      expires_at: new Date('2030-01-01T00:00:00Z'),
      last_seen_at: null,
      session_created_at: new Date('2026-01-01T00:00:00Z'),
      email_normalized: 'user@example.test',
      email_verified_at: new Date('2026-01-01T00:00:00Z'),
      account_status: 'active',
    }],
  });

  const repository = createSessionRepository(mock.pool);
  const result = await repository.findActiveSession({ token: TOKEN });

  assert.equal(result.session.id, SESSION_ID);
  assert.equal(result.session.userId, USER_ID);
  assert.equal(result.user.id, USER_ID);
  assert.equal(result.user.email, 'user@example.test');
  assert.equal(result.user.emailVerified, true);
  assert.equal(result.user.accountStatus, 'active');

  assert.deepEqual(mock.calls[0].params, [digest(TOKEN)]);
  assert.match(mock.calls[0].sql, /s\.revoked_at IS NULL/);
  assert.match(mock.calls[0].sql, /s\.expires_at > NOW\(\)/);
  assert.match(mock.calls[0].sql, /u\.email_verified_at/);
  assert.match(mock.calls[0].sql, /u\.account_status = 'active'/);
});

test('findActiveSession returns null when no active session exists', async () => {
  const mock = createMockPool({ rows: [], rowCount: 0 });
  const repository = createSessionRepository(mock.pool);

  const result = await repository.findActiveSession({ token: TOKEN });

  assert.equal(result, null);
});

test('findActiveSession rejects malformed tokens', async () => {
  const mock = createMockPool();
  const repository = createSessionRepository(mock.pool);

  for (const token of ['', 'short', 'a'.repeat(42), 'a'.repeat(44), null]) {
    await assert.rejects(
      repository.findActiveSession({ token }),
      /Session token tidak valid/,
    );
  }

  assert.equal(mock.calls.length, 0);
});

test('createSessionForUser creates a random session and stores only its digest', async () => {
  const mock = createMockPool({
    rows: [{
      id: SESSION_ID,
      user_id: USER_ID,
      expires_at: new Date('2030-01-01T00:00:00Z'),
    }],
  });
  const repository = createSessionRepository(mock.pool);
  const sessionExpiresAt = new Date(Date.now() + 3600000);

  const result = await repository.createSessionForUser({
    userId: USER_ID,
    sessionExpiresAt,
  });

  assert.equal(result.id, SESSION_ID);
  assert.equal(result.userId, USER_ID);
  assert.match(result.token, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(mock.calls[0].params[2], digest(result.token));
  assert.notEqual(mock.calls[0].params[2], result.token);
  assert.equal(mock.calls[0].params[0], USER_ID);
  assert.equal(mock.calls[0].params[3], sessionExpiresAt);
  assert.match(mock.calls[0].sql, /account_status = 'active'/);
  assert.match(mock.calls[0].sql, /FOR UPDATE/);
  assert.match(mock.calls[0].sql, /INSERT INTO .*sessions/);
});

test('createSessionForUser returns null when user is not active or missing', async () => {
  const mock = createMockPool({ rows: [], rowCount: 0 });
  const repository = createSessionRepository(mock.pool);

  const result = await repository.createSessionForUser({
    userId: USER_ID,
    sessionExpiresAt: new Date(Date.now() + 3600000),
  });

  assert.equal(result, null);
  assert.equal(mock.calls.length, 1);
});

test('createSessionForUser rejects invalid user IDs and expiry values', async () => {
  const mock = createMockPool();
  const repository = createSessionRepository(mock.pool);

  await assert.rejects(
    repository.createSessionForUser({
      userId: 'invalid',
      sessionExpiresAt: new Date(Date.now() + 3600000),
    }),
    /User ID tidak valid/,
  );

  for (const sessionExpiresAt of [
    null,
    '2030-01-01T00:00:00Z',
    new Date('invalid'),
    new Date(Date.now() - 1000),
  ]) {
    await assert.rejects(
      repository.createSessionForUser({
        userId: USER_ID,
        sessionExpiresAt,
      }),
      /Session expiry harus berupa tanggal masa depan/,
    );
  }

  assert.equal(mock.calls.length, 0);
});

test('revokeSession updates by token digest only', async () => {
  const mock = createMockPool({ rows: [{ id: SESSION_ID }], rowCount: 1 });
  const repository = createSessionRepository(mock.pool);

  const result = await repository.revokeSession({ token: TOKEN });

  assert.equal(result, true);
  assert.deepEqual(mock.calls[0].params, [digest(TOKEN)]);
  assert.match(mock.calls[0].sql, /revoked_at IS NULL/);
  assert.doesNotMatch(mock.calls[0].sql, /expires_at > NOW/);
});

test('revokeSession returns false when already revoked or not found', async () => {
  const mock = createMockPool({ rows: [], rowCount: 0 });
  const repository = createSessionRepository(mock.pool);

  const result = await repository.revokeSession({ token: TOKEN });

  assert.equal(result, false);
});

test('revokeSession rejects malformed tokens', async () => {
  const mock = createMockPool();
  const repository = createSessionRepository(mock.pool);

  await assert.rejects(
    repository.revokeSession({ token: 'invalid' }),
    /Session token tidak valid/,
  );

  assert.equal(mock.calls.length, 0);
});

test('revokeSessionById scopes update to session and owner', async () => {
  const mock = createMockPool({ rows: [{ id: SESSION_ID }], rowCount: 1 });
  const repository = createSessionRepository(mock.pool);

  const result = await repository.revokeSessionById({
    sessionId: SESSION_ID,
    userId: USER_ID,
  });

  assert.equal(result, true);
  assert.deepEqual(mock.calls[0].params, [SESSION_ID, USER_ID]);
  assert.match(mock.calls[0].sql, /id = \$1/);
  assert.match(mock.calls[0].sql, /user_id = \$2/);
  assert.match(mock.calls[0].sql, /revoked_at IS NULL/);
});

test('revokeSessionById rejects invalid UUIDs', async () => {
  const mock = createMockPool();
  const repository = createSessionRepository(mock.pool);

  await assert.rejects(
    repository.revokeSessionById({
      sessionId: 'invalid',
      userId: USER_ID,
    }),
    /Session ID tidak valid/,
  );

  await assert.rejects(
    repository.revokeSessionById({
      sessionId: SESSION_ID,
      userId: 'invalid',
    }),
    /User ID tidak valid/,
  );

  assert.equal(mock.calls.length, 0);
});

test('revokeSessionById returns false when session is not owned or already revoked', async () => {
  const mock = createMockPool({ rows: [], rowCount: 0 });
  const repository = createSessionRepository(mock.pool);

  const result = await repository.revokeSessionById({
    sessionId: SESSION_ID,
    userId: USER_ID,
  });

  assert.equal(result, false);
});

test('listActiveSessions returns only safe metadata for the requested user', async () => {
  const createdAt = new Date('2026-11-20T10:00:00Z');
  const expiresAt = new Date('2026-11-27T10:00:00Z');

  const mock = createMockPool({
    rows: [{
      id: SESSION_ID,
      created_at: createdAt,
      expires_at: expiresAt,
    }],
  });

  const repository = createSessionRepository(mock.pool);
  const result = await repository.listActiveSessions({
    userId: USER_ID,
  });

  assert.deepEqual(result, [{
    id: SESSION_ID,
    createdAt,
    expiresAt,
  }]);

  assert.deepEqual(mock.calls[0].params, [USER_ID]);
  assert.match(mock.calls[0].sql, /user_id = \$1/);
  assert.match(mock.calls[0].sql, /revoked_at IS NULL/);
  assert.match(mock.calls[0].sql, /expires_at > NOW\(\)/);
  assert.match(mock.calls[0].sql, /ORDER BY created_at DESC/);
  assert.doesNotMatch(mock.calls[0].sql, /session_token_hash/);
});

test('listActiveSessions rejects invalid user IDs without querying database', async () => {
  const mock = createMockPool();
  const repository = createSessionRepository(mock.pool);

  await assert.rejects(
    repository.listActiveSessions({ userId: 'invalid' }),
    /User ID tidak valid/,
  );

  assert.equal(mock.calls.length, 0);
});
