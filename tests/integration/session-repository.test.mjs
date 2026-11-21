import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { randomBytes, createHash } from 'node:crypto';
import pg from 'pg';

import {
  createSessionRepository,
} from '../../src/auth/session/session-repository.mjs';

const { Pool } = pg;

function readEnv(key) {
  const content = fs.readFileSync('.env', 'utf8');
  const line = content
    .split(/\r?\n/)
    .find((item) => item.startsWith(`${key}=`));

  return line?.slice(key.length + 1)
    .trim()
    .replace(/^['"]|['"]$/g, '') ?? '';
}

function parseDatabaseUrl(value) {
  try {
    const url = new URL(value);

    return {
      host: url.hostname.toLowerCase().replace(/-pooler(?=\.|$)/, ''),
      port: url.port || '5432',
      database: decodeURIComponent(url.pathname.replace(/^\/+/, '')),
    };
  } catch {
    return null;
  }
}

function sameDatabase(a, b) {
  return a.host === b.host
    && a.port === b.port
    && a.database === b.database;
}

async function createTestPool() {
  const connectionString = readEnv('TEST_DATABASE_URL');

  assert.ok(connectionString, 'TEST_DATABASE_URL belum diisi');

  const target = parseDatabaseUrl(connectionString);
  const main = parseDatabaseUrl(readEnv('DATABASE_URL'));
  const direct = parseDatabaseUrl(readEnv('DIRECT_URL'));

  assert.ok(target, 'TEST_DATABASE_URL tidak valid');
  assert.ok(main, 'DATABASE_URL utama tidak valid');
  assert.ok(direct, 'DIRECT_URL utama tidak valid');

  assert.equal(
    sameDatabase(target, main),
    false,
    'DITOLAK: target sama dengan DATABASE_URL utama',
  );

  assert.equal(
    sameDatabase(target, direct),
    false,
    'DITOLAK: target sama dengan DIRECT_URL utama',
  );

  const pool = new Pool({
    connectionString,
    max: 4,
    connectionTimeoutMillis: 10000,
    ssl: { rejectUnauthorized: true },
  });

  try {
    const result = await pool.query(`
      SELECT
        to_regclass('velzx_central_test.users') AS users_table,
        to_regclass('velzx_central_test.sessions') AS sessions_table,
        to_regnamespace('velzx_central_test') IS NOT NULL AS test_schema
    `);

    const schema = result.rows[0];

    assert.equal(schema.test_schema, true, 'Schema test tidak ditemukan');
    assert.ok(schema.users_table, 'Tabel users test tidak ditemukan');
    assert.ok(schema.sessions_table, 'Tabel sessions test tidak ditemukan');

    return pool;
  } catch (error) {
    await pool.end();
    throw error;
  }
}

function makeToken() {
  return randomBytes(32).toString('base64url');
}

function tokenDigest(token) {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

test('session lookup, account status enforcement, and revocation', {
  timeout: 60000,
}, async () => {
  const pool = await createTestPool();
  const repository = createSessionRepository(pool, {
    schema: 'velzx_central_test',
  });

  const suffix = randomBytes(8).toString('hex');
  const users = [
    {
      email: `session-active-${suffix}@example.test`,
      status: 'active',
      verified: true,
    },
    {
      email: `session-suspended-${suffix}@example.test`,
      status: 'suspended',
      verified: true,
    },
    {
      email: `session-disabled-${suffix}@example.test`,
      status: 'disabled',
      verified: true,
    },
  ];

  const tokens = {
    active: makeToken(),
    expired: makeToken(),
    revoked: makeToken(),
    suspended: makeToken(),
    disabled: makeToken(),
    owned: makeToken(),
  };

  const userIds = {};
  const sessionIds = {};

  try {
    for (const user of users) {
      const inserted = await pool.query(
        `INSERT INTO velzx_central_test.users (
           id, email_normalized, email_verified_at, account_status
         )
         VALUES (
           gen_random_uuid(), $1,
           CASE WHEN $3 THEN NOW() ELSE NULL END,
           $2
         )
         RETURNING id`,
        [user.email, user.status, user.verified],
      );

      userIds[user.status] = inserted.rows[0].id;
    }

    const activeUserId = userIds.active;

    const sessionDefinitions = [
      {
        key: 'active',
        userId: activeUserId,
        expiresAt: new Date(Date.now() + 3600000),
        revoked: false,
      },
      {
        key: 'expired',
        userId: activeUserId,
        expiresAt: new Date(Date.now() - 3600000),
        revoked: false,
      },
      {
        key: 'revoked',
        userId: activeUserId,
        expiresAt: new Date(Date.now() + 3600000),
        revoked: true,
      },
      {
        key: 'owned',
        userId: activeUserId,
        expiresAt: new Date(Date.now() + 3600000),
        revoked: false,
      },
      {
        key: 'suspended',
        userId: userIds.suspended,
        expiresAt: new Date(Date.now() + 3600000),
        revoked: false,
      },
      {
        key: 'disabled',
        userId: userIds.disabled,
        expiresAt: new Date(Date.now() + 3600000),
        revoked: false,
      },
    ];

    for (const definition of sessionDefinitions) {
      const token = tokens[definition.key];

      const createdAt = definition.key === 'expired'
        ? new Date(definition.expiresAt.getTime() - 3600000)
        : new Date(Date.now() - 1000);

      const inserted = await pool.query(
        `INSERT INTO velzx_central_test.sessions (
           id, user_id, session_token_hash,
           expires_at, revoked_at, created_at
         )
         VALUES (
           gen_random_uuid(), $1, $2, $3,
           CASE WHEN $4 THEN NOW() ELSE NULL END,
           $5
         )
         RETURNING id`,
        [
          definition.userId,
          tokenDigest(token),
          definition.expiresAt,
          definition.revoked,
          createdAt,
        ],
      );

      sessionIds[definition.key] = inserted.rows[0].id;
    }

    const active = await repository.findActiveSession({
      token: tokens.active,
    });

    assert.ok(active);
    assert.equal(active.user.id, activeUserId);
    assert.equal(active.user.accountStatus, 'active');
    assert.equal(active.session.id, sessionIds.active);

    for (const key of ['expired', 'revoked', 'suspended', 'disabled']) {
      const result = await repository.findActiveSession({
        token: tokens[key],
      });

      assert.equal(result, null, `${key} session seharusnya ditolak`);
    }

    const unknown = await repository.findActiveSession({
      token: makeToken(),
    });

    assert.equal(unknown, null);

    const revokedByToken = await repository.revokeSession({
      token: tokens.active,
    });

    assert.equal(revokedByToken, true);

    const afterTokenRevocation = await repository.findActiveSession({
      token: tokens.active,
    });

    assert.equal(afterTokenRevocation, null);

    const revokedById = await repository.revokeSessionById({
      sessionId: sessionIds.owned,
      userId: activeUserId,
    });

    assert.equal(revokedById, true);

    const wrongOwner = await repository.revokeSessionById({
      sessionId: sessionIds.owned,
      userId: userIds.suspended,
    });

    assert.equal(wrongOwner, false);

    const repeatedRevocation = await repository.revokeSession({
      token: tokens.active,
    });

    assert.equal(repeatedRevocation, false);

    const stored = await pool.query(
      `SELECT session_token_hash
       FROM velzx_central_test.sessions
       WHERE id = $1`,
      [sessionIds.active],
    );

    assert.equal(stored.rowCount, 1);
    assert.equal(stored.rows[0].session_token_hash, tokenDigest(tokens.active));
    assert.notEqual(stored.rows[0].session_token_hash, tokens.active);
  } finally {
    for (const user of users) {
      await pool.query(
        `DELETE FROM velzx_central_test.users
         WHERE email_normalized = $1`,
        [user.email],
      );
    }

    await pool.end();
  }
});

test('creates a session for an existing active user without creating an account', {
  timeout: 60000,
}, async () => {
  const pool = await createTestPool();
  const repository = createSessionRepository(pool, {
    schema: 'velzx_central_test',
  });

  const suffix = randomBytes(8).toString('hex');
  const email = `session-create-${suffix}@example.test`;
  let userId;

  try {
    const insertedUser = await pool.query(
      `INSERT INTO velzx_central_test.users (
         id, email_normalized, email_verified_at, account_status
       )
       VALUES (gen_random_uuid(), $1, NOW(), 'active')
       RETURNING id`,
      [email],
    );

    userId = insertedUser.rows[0].id;

    const sessionExpiresAt = new Date(Date.now() + 3600000);
    const created = await repository.createSessionForUser({
      userId,
      sessionExpiresAt,
    });

    assert.ok(created);
    assert.equal(created.userId, userId);
    assert.match(created.token, /^[A-Za-z0-9_-]{43}$/);

    const stored = await pool.query(
      `SELECT id, user_id, session_token_hash, expires_at
       FROM velzx_central_test.sessions
       WHERE id = $1`,
      [created.id],
    );

    assert.equal(stored.rowCount, 1);
    assert.equal(stored.rows[0].user_id, userId);
    assert.equal(
      stored.rows[0].session_token_hash,
      tokenDigest(created.token),
    );
    assert.notEqual(stored.rows[0].session_token_hash, created.token);

    const active = await repository.findActiveSession({
      token: created.token,
    });

    assert.ok(active);
    assert.equal(active.session.id, created.id);
    assert.equal(active.user.id, userId);
    assert.equal(active.user.accountStatus, 'active');

    const sessionCount = await pool.query(
      `SELECT COUNT(*)::int AS count
       FROM velzx_central_test.sessions
       WHERE user_id = $1`,
      [userId],
    );

    assert.equal(sessionCount.rows[0].count, 1);
  } finally {
    if (userId) {
      await pool.query(
        `DELETE FROM velzx_central_test.users WHERE id = $1`,
        [userId],
      );
    }

    await pool.end();
  }
});
