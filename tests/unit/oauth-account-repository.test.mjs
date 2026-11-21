import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import {
  createOAuthAccountRepository,
} from '../../src/auth/oauth/oauth-account-repository.mjs';

const USER_ID = '11111111-1111-4111-8111-111111111111';
const SESSION_ID = '22222222-2222-4222-8222-222222222222';
const FINGERPRINT = `v1:${'a'.repeat(64)}`;

function matchesTable(sql, table) {
  return sql.includes(`velzx_central_test.${table}`)
    || sql.includes(`velzx_central.${table}`);
}

function isInsertInto(sql, table) {
  return sql.trimStart().startsWith('INSERT INTO')
    && matchesTable(sql, table);
}

function createMockPool({
  identityExists = false,
  emailExists = false,
  ipLimitReached = false,
  ownerExists = true,
  insertSessionFails = false,
  linkIdentityExists = false,
  identityInsertFails = false,
  existingIdentity = null,
} = {}) {
  const calls = [];
  let released = false;

  const client = {
    async query(sql, params = []) {
      calls.push({ sql, params });

      if (['BEGIN', 'COMMIT', 'ROLLBACK'].includes(sql)) {
        return { rowCount: null, rows: [] };
      }

      if (sql.startsWith('SET LOCAL search_path')) {
        return { rowCount: null, rows: [] };
      }

      if (sql.includes('pg_advisory_xact_lock')) {
        return { rowCount: null, rows: [] };
      }

      if (sql.includes('SELECT COUNT(*) AS account_count')) {
        return {
          rowCount: 1,
          rows: [{
            account_count: ipLimitReached ? '3' : '0',
          }],
        };
      }

      if (sql.includes('INSERT INTO registration_ip_claims')) {
        return {
          rowCount: 1,
          rows: [{ id: '1', verified_at: new Date() }],
        };
      }

      if (sql.includes('INSERT INTO security_events')) {
        return { rowCount: 1, rows: [] };
      }

      if (
        sql.trimStart().startsWith('SELECT') &&
        matchesTable(sql, 'user_identities') &&
        sql.includes('provider_subject')
      ) {
        const row = existingIdentity ?? (
          identityExists || linkIdentityExists
            ? { id: USER_ID, user_id: USER_ID }
            : null
        );

        return {
          rowCount: row ? 1 : 0,
          rows: row ? [row] : [],
        };
      }

      if (
        sql.trimStart().startsWith('SELECT') &&
        matchesTable(sql, 'users') &&
        sql.includes('email_normalized')
      ) {
        return {
          rowCount: emailExists ? 1 : 0,
          rows: emailExists ? [{ id: USER_ID }] : [],
        };
      }

      if (
        sql.trimStart().startsWith('SELECT') &&
        matchesTable(sql, 'users') &&
        matchesTable(sql, 'sessions')
      ) {
        return {
          rowCount: ownerExists ? 1 : 0,
          rows: ownerExists
            ? [{ id: USER_ID, account_status: 'active', session_id: SESSION_ID }]
            : [],
        };
      }

      if (isInsertInto(sql, 'users')) {
        return { rowCount: 1, rows: [] };
      }

      if (isInsertInto(sql, 'user_identities')) {
        if (identityInsertFails) {
          throw new Error('Simulated identity insert failure');
        }

        return { rowCount: 1, rows: [] };
      }

      if (isInsertInto(sql, 'sessions')) {
        if (insertSessionFails) {
          throw new Error('Simulated session insert failure');
        }

        return { rowCount: 1, rows: [] };
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

function createRepository(pool, options = {}) {
  return createOAuthAccountRepository(pool, options);
}

function validRegistration(overrides = {}) {
  return {
    provider: 'google',
    providerSubject: 'google-subject-123',
    email: 'USER@example.com',
    providerEmail: 'user@example.com',
    providerEmailVerified: true,
    ipFingerprint: FINGERPRINT,
    sessionExpiresAt: new Date(Date.now() + 3600000),
    ...overrides,
  };
}

function validLink(overrides = {}) {
  return {
    userId: USER_ID,
    sessionId: SESSION_ID,
    provider: 'github',
    providerSubject: 'github-subject-123',
    providerEmail: 'user@example.com',
    providerEmailVerified: true,
    ...overrides,
  };
}

test('creates OAuth account, identity, IP claim, and hashed session atomically', async () => {
  const mock = createMockPool();
  const repository = createRepository(mock.pool);

  const result = await repository.createOAuthAccount(
    validRegistration(),
  );

  assert.equal(result.created, true);
  assert.equal(result.user.accountStatus, 'active');
  assert.equal(result.user.email, 'user@example.com');
  assert.equal(result.identity.provider, 'google');
  assert.match(result.session.token, /^[A-Za-z0-9_-]{43}$/);

  const sessionInsert = mock.calls.find(({ sql }) =>
    isInsertInto(sql, 'sessions'),
  );

  assert.ok(sessionInsert);

  const expectedHash = createHash('sha256')
    .update(result.session.token, 'utf8')
    .digest('hex');

  assert.equal(sessionInsert.params[2], expectedHash);
  assert.notEqual(sessionInsert.params[2], result.session.token);

  const claimIndex = mock.calls.findIndex(({ sql }) =>
    sql.includes('INSERT INTO registration_ip_claims'),
  );
  const userIndex = mock.calls.findIndex(({ sql }) =>
    isInsertInto(sql, 'users'),
  );
  const identityIndex = mock.calls.findIndex(({ sql }) =>
    isInsertInto(sql, 'user_identities'),
  );
  const sessionIndex = mock.calls.findIndex(({ sql }) =>
    isInsertInto(sql, 'sessions'),
  );

  assert.ok(claimIndex > -1);
  assert.ok(claimIndex < userIndex);
  assert.ok(userIndex < identityIndex);
  assert.ok(identityIndex < sessionIndex);
  assert.ok(mock.calls.some(({ sql }) => sql === 'COMMIT'));
  assert.ok(!mock.calls.some(({ sql }) => sql === 'ROLLBACK'));
  assert.equal(mock.wasReleased(), true);
});

test('rejects existing provider identity without claiming IP', async () => {
  const mock = createMockPool({ identityExists: true });
  const repository = createRepository(mock.pool);

  const result = await repository.createOAuthAccount(
    validRegistration(),
  );

  assert.deepEqual(result, {
    created: false,
    reason: 'identity_conflict',
  });

  assert.ok(!mock.calls.some(({ sql }) =>
    sql.includes('INSERT INTO registration_ip_claims'),
  ));
  assert.ok(mock.calls.some(({ sql }) => sql === 'ROLLBACK'));
  assert.equal(mock.wasReleased(), true);
});

test('rejects duplicate email without creating another account', async () => {
  const mock = createMockPool({ emailExists: true });
  const repository = createRepository(mock.pool);

  const result = await repository.createOAuthAccount(
    validRegistration(),
  );

  assert.deepEqual(result, {
    created: false,
    reason: 'account_conflict',
  });

  assert.ok(!mock.calls.some(({ sql }) =>
    sql.includes('INSERT INTO registration_ip_claims'),
  ));
  assert.ok(!mock.calls.some(({ sql }) =>
    isInsertInto(sql, 'users'),
  ));
});

test('commits security event but creates no account when IP limit is reached', async () => {
  const mock = createMockPool({ ipLimitReached: true });
  const repository = createRepository(mock.pool);

  const result = await repository.createOAuthAccount(
    validRegistration(),
  );

  assert.equal(result.created, false);
  assert.equal(result.reason, 'ip_account_limit_reached');
  assert.equal(result.limit, 3);
  assert.equal(result.verifiedAccountCount, 3);

  assert.ok(mock.calls.some(({ sql }) =>
    sql.includes('INSERT INTO security_events'),
  ));
  assert.ok(mock.calls.some(({ sql }) => sql === 'COMMIT'));
  assert.ok(!mock.calls.some(({ sql }) => sql === 'ROLLBACK'));

  for (const table of ['users', 'user_identities', 'sessions']) {
    assert.ok(!mock.calls.some(({ sql }) =>
      sql.includes(`INSERT INTO velzx_central_test.${table}`),
    ));
  }
});

test('rolls back account and IP claim when session insert fails', async () => {
  const mock = createMockPool({ insertSessionFails: true });
  const repository = createRepository(mock.pool);

  await assert.rejects(
    repository.createOAuthAccount(validRegistration()),
    /Simulated session insert failure/,
  );

  assert.ok(mock.calls.some(({ sql }) =>
    sql.includes('INSERT INTO registration_ip_claims'),
  ));
  assert.ok(mock.calls.some(({ sql }) =>
    isInsertInto(sql, 'users'),
  ));
  assert.ok(mock.calls.some(({ sql }) =>
    isInsertInto(sql, 'user_identities'),
  ));
  assert.ok(mock.calls.some(({ sql }) => sql === 'ROLLBACK'));
  assert.ok(!mock.calls.some(({ sql }) => sql === 'COMMIT'));
  assert.equal(mock.wasReleased(), true);
});

test('rolls back when provider identity insertion fails', async () => {
  const mock = createMockPool({ identityInsertFails: true });
  const repository = createRepository(mock.pool);

  await assert.rejects(
    repository.createOAuthAccount(validRegistration()),
    /Simulated identity insert failure/,
  );

  assert.ok(mock.calls.some(({ sql }) => sql === 'ROLLBACK'));
  assert.ok(!mock.calls.some(({ sql }) => sql === 'COMMIT'));
});

test('returns active account and identity from identity lookup', async () => {
  const mock = createMockPool({
    existingIdentity: {
      user_id: USER_ID,
      email_normalized: 'user@example.com',
      account_status: 'active',
      email_verified_at: new Date(),
      identity_id: SESSION_ID,
      provider: 'google',
      provider_subject: 'google-subject-123',
      provider_email: 'user@example.com',
      provider_email_verified: true,
    },
  });

  const repository = createRepository(mock.pool);

  const result = await repository.findUserByIdentity({
    provider: 'google',
    providerSubject: 'google-subject-123',
  });

  assert.equal(result.user.id, USER_ID);
  assert.equal(result.user.accountStatus, 'active');
  assert.equal(result.identity.provider, 'google');
  assert.equal(result.identity.emailVerified, true);
  assert.equal(mock.wasReleased(), true);
});

test('returns null when provider identity is not found', async () => {
  const mock = createMockPool();
  const repository = createRepository(mock.pool);

  const result = await repository.findUserByIdentity({
    provider: 'google',
    providerSubject: 'unknown-subject',
  });

  assert.equal(result, null);
});

test('links provider identity using active Central session', async () => {
  const mock = createMockPool();
  const repository = createRepository(mock.pool);

  const result = await repository.linkOAuthIdentity(validLink());

  assert.equal(result.linked, true);
  assert.equal(result.identity.provider, 'github');
  assert.equal(result.identity.emailVerified, true);

  const insert = mock.calls.find(({ sql }) =>
    isInsertInto(sql, 'user_identities'),
  );

  assert.ok(insert);
  assert.equal(insert.params[1], USER_ID);
  assert.ok(mock.calls.some(({ sql }) => sql === 'COMMIT'));
  assert.equal(mock.wasReleased(), true);
});

test('links GitHub identity without verified email', async () => {
  const mock = createMockPool();
  const repository = createRepository(mock.pool);

  const result = await repository.linkOAuthIdentity(validLink({
    providerEmail: null,
    providerEmailVerified: false,
  }));

  assert.equal(result.linked, true);
  assert.equal(result.identity.email, null);
  assert.equal(result.identity.emailVerified, false);

  const insert = mock.calls.find(({ sql }) =>
    isInsertInto(sql, 'user_identities'),
  );
  assert.ok(insert);
  assert.equal(insert.params[4], null);
  assert.equal(insert.params[5], false);
});

test('discards unverified Microsoft email when linking', async () => {
  const mock = createMockPool();
  const repository = createRepository(mock.pool);

  const result = await repository.linkOAuthIdentity(validLink({
    provider: 'microsoft',
    providerEmail: 'unverified@example.com',
    providerEmailVerified: false,
  }));

  assert.equal(result.linked, true);
  assert.equal(result.identity.email, null);
  assert.equal(result.identity.emailVerified, false);

  const insert = mock.calls.find(({ sql }) =>
    isInsertInto(sql, 'user_identities'),
  );
  assert.ok(insert);
  assert.equal(insert.params[4], null);
  assert.equal(insert.params[5], false);
});

test('rejects ambiguous email verification status when linking', async () => {
  let connected = false;

  const repository = createRepository({
    async connect() {
      connected = true;
      throw new Error('Unexpected connection');
    },
  });

  await assert.rejects(
    repository.linkOAuthIdentity(validLink({
      providerEmailVerified: null,
    })),
    /Status verifikasi email provider tidak valid/,
  );

  assert.equal(connected, false);
});

test('rejects account linking when Central session is invalid', async () => {
  const mock = createMockPool({ ownerExists: false });
  const repository = createRepository(mock.pool);

  const result = await repository.linkOAuthIdentity(validLink());

  assert.deepEqual(result, {
    linked: false,
    reason: 'session_invalid',
  });

  assert.ok(mock.calls.some(({ sql }) => sql === 'ROLLBACK'));
  assert.ok(!mock.calls.some(({ sql }) =>
    isInsertInto(sql, 'user_identities'),
  ));
});

test('rejects linking an identity already owned by an account', async () => {
  const mock = createMockPool({ linkIdentityExists: true });
  const repository = createRepository(mock.pool);

  const result = await repository.linkOAuthIdentity(validLink());

  assert.deepEqual(result, {
    linked: false,
    reason: 'identity_conflict',
  });

  assert.ok(mock.calls.some(({ sql }) => sql === 'ROLLBACK'));
});

test('validates registration input before opening database connection', async () => {
  let connected = false;

  const repository = createRepository({
    async connect() {
      connected = true;
      throw new Error('Unexpected connection');
    },
  });

  await assert.rejects(
    repository.createOAuthAccount(
      validRegistration({ providerEmailVerified: false }),
    ),
    /harus terverifikasi/,
  );

  await assert.rejects(
    repository.createOAuthAccount(
      validRegistration({ ipFingerprint: 'invalid' }),
    ),
    /fingerprint tidak valid/,
  );

  await assert.rejects(
    repository.createOAuthAccount(
      validRegistration({
        email: 'different@example.com',
      }),
    ),
    /harus sama/,
  );

  assert.equal(connected, false);
});

test('validates linking identifiers before opening database connection', async () => {
  let connected = false;

  const repository = createRepository({
    async connect() {
      connected = true;
      throw new Error('Unexpected connection');
    },
  });

  await assert.rejects(
    repository.linkOAuthIdentity(
      validLink({ userId: 'invalid-uuid' }),
    ),
    /User ID tidak valid/,
  );

  assert.equal(connected, false);
});

test('rejects unsupported schema', () => {
  assert.throws(
    () => createOAuthAccountRepository(
      { connect() {} },
      { schema: 'public' },
    ),
    /Schema database tidak diizinkan/,
  );
});


test('uses production schema only when explicitly selected', async () => {
  const mock = createMockPool();
  const repository = createRepository(mock.pool, {
    schema: 'velzx_central',
  });

  const result = await repository.createOAuthAccount(validRegistration());

  assert.equal(result.created, true);
  assert.ok(mock.calls.some(({ sql }) =>
    sql === 'SET LOCAL search_path TO velzx_central, pg_catalog'
  ));
  for (const table of ['users', 'user_identities', 'sessions']) {
    assert.ok(mock.calls.some(({ sql }) =>
      sql.includes(`INSERT INTO velzx_central.${table}`)
    ));
  }
  assert.ok(!mock.calls.some(({ sql }) =>
    sql.includes('velzx_central_test.')
  ));
});

test('keeps test schema as the account repository default', async () => {
  const mock = createMockPool();
  const repository = createRepository(mock.pool);

  await repository.findUserByIdentity({
    provider: 'google',
    providerSubject: 'default-schema-check',
  });

  assert.ok(mock.calls.some(({ sql }) =>
    sql.trimStart().startsWith('SELECT')
      && matchesTable(sql, 'user_identities')
      && matchesTable(sql, 'users')
      && !sql.includes('velzx_central.')
  ));
});
