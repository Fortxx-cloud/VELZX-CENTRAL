import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import pg from 'pg';

import {
  createOAuthAccountRepository,
} from '../../src/auth/oauth/oauth-account-repository.mjs';

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
      database: decodeURIComponent(
        url.pathname.replace(/^\/+/, ''),
      ),
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
        to_regclass('velzx_central_test.user_identities') AS identities_table,
        to_regclass('velzx_central_test.sessions') AS sessions_table,
        to_regclass('velzx_central_test.registration_ip_claims') AS claims_table,
        to_regclass('velzx_central_test.security_events') AS events_table,
        to_regnamespace('velzx_central_test') IS NOT NULL AS test_schema
    `);

    const schema = result.rows[0];

    assert.equal(schema.test_schema, true, 'Schema test tidak ditemukan');
    assert.ok(schema.users_table, 'Tabel users test tidak ditemukan');
    assert.ok(schema.identities_table, 'Tabel identities test tidak ditemukan');
    assert.ok(schema.sessions_table, 'Tabel sessions test tidak ditemukan');
    assert.ok(schema.claims_table, 'Tabel IP claims test tidak ditemukan');
    assert.ok(schema.events_table, 'Tabel security events test tidak ditemukan');

    return pool;
  } catch (error) {
    await pool.end();
    throw error;
  }
}

function registration({
  email,
  providerSubject,
  fingerprint,
  provider = 'google',
}) {
  return {
    provider,
    providerSubject,
    email,
    providerEmail: email,
    providerEmailVerified: true,
    ipFingerprint: fingerprint,
    sessionExpiresAt: new Date(Date.now() + 3600000),
  };
}

async function cleanup(pool, fingerprints, emails) {
  const errors = [];

  try {
    await pool.query(
      `DELETE FROM velzx_central_test.users
       WHERE email_normalized = ANY($1::varchar[])`,
      [emails],
    );
  } catch (error) {
    errors.push(error);
  }

  for (const fingerprint of fingerprints) {
    try {
      await pool.query(
        `DELETE FROM velzx_central_test.security_events
         WHERE ip_fingerprint = $1`,
        [fingerprint],
      );
    } catch (error) {
      errors.push(error);
    }

    try {
      await pool.query(
        `DELETE FROM velzx_central_test.registration_ip_claims
         WHERE ip_fingerprint = $1`,
        [fingerprint],
      );
    } catch (error) {
      errors.push(error);
    }
  }

  if (errors.length) {
    throw new AggregateError(errors, 'OAuth integration cleanup gagal');
  }
}

test('OAuth account creation, session digest, identity lookup, and linking', {
  timeout: 60000,
}, async () => {
  const pool = await createTestPool();
  const repository = createOAuthAccountRepository(pool, {
    schema: 'velzx_central_test',
  });

  const suffix = randomBytes(8).toString('hex');
  const email = `oauth-${suffix}@example.test`;
  const fingerprint = `v1:${randomBytes(32).toString('hex')}`;
  const emails = [email];

  try {
    const created = await repository.createOAuthAccount(
      registration({
        email,
        providerSubject: `google-${suffix}`,
        fingerprint,
      }),
    );

    assert.equal(created.created, true);
    assert.equal(created.user.email, email);
    assert.equal(created.user.accountStatus, 'active');
    assert.ok(created.session.token);

    const storedSession = await pool.query(
      `SELECT session_token_hash, expires_at, revoked_at
       FROM velzx_central_test.sessions
       WHERE id = $1 AND user_id = $2`,
      [created.session.id, created.user.id],
    );

    assert.equal(storedSession.rowCount, 1);

    const expectedDigest = createHash('sha256')
      .update(created.session.token, 'utf8')
      .digest('hex');

    assert.equal(storedSession.rows[0].session_token_hash, expectedDigest);
    assert.notEqual(
      storedSession.rows[0].session_token_hash,
      created.session.token,
    );
    assert.equal(storedSession.rows[0].revoked_at, null);

    const claim = await pool.query(
      `SELECT account_id
       FROM velzx_central_test.registration_ip_claims
       WHERE ip_fingerprint = $1`,
      [fingerprint],
    );

    assert.equal(claim.rowCount, 1);
    assert.equal(claim.rows[0].account_id, created.user.id);

    const found = await repository.findUserByIdentity({
      provider: 'google',
      providerSubject: `google-${suffix}`,
    });

    assert.equal(found.user.id, created.user.id);
    assert.equal(found.user.accountStatus, 'active');
    assert.equal(found.identity.provider, 'google');

    const linked = await repository.linkOAuthIdentity({
      userId: created.user.id,
      sessionId: created.session.id,
      provider: 'github',
      providerSubject: `github-${suffix}`,
      providerEmail: email,
      providerEmailVerified: true,
    });

    assert.equal(linked.linked, true);
    assert.equal(linked.identity.provider, 'github');

    const identityRows = await pool.query(
      `SELECT provider, provider_subject, user_id
       FROM velzx_central_test.user_identities
       WHERE user_id = $1
       ORDER BY provider`,
      [created.user.id],
    );

    assert.equal(identityRows.rowCount, 2);
    assert.deepEqual(
      identityRows.rows.map((row) => row.provider),
      ['github', 'google'],
    );

    const duplicateLink = await repository.linkOAuthIdentity({
      userId: created.user.id,
      sessionId: created.session.id,
      provider: 'github',
      providerSubject: `github-${suffix}`,
      providerEmail: email,
      providerEmailVerified: true,
    });

    assert.deepEqual(duplicateLink, {
      linked: false,
      reason: 'identity_conflict',
    });

    console.log('OAUTH ACCOUNT CREATION: PASS');
    console.log('SESSION DIGEST STORAGE: PASS');
    console.log('PROVIDER IDENTITY LOOKUP: PASS');
    console.log('OAUTH ACCOUNT LINKING: PASS');
  } finally {
    await cleanup(pool, [fingerprint], emails);
    await pool.end();
  }
});

test('OAuth registration enforces permanent three-account IP limit', {
  timeout: 60000,
}, async () => {
  const pool = await createTestPool();
  const repository = createOAuthAccountRepository(pool, {
    schema: 'velzx_central_test',
  });

  const suffix = randomBytes(8).toString('hex');
  const fingerprint = `v1:${randomBytes(32).toString('hex')}`;
  const emails = Array.from(
    { length: 4 },
    (_, index) => `oauth-limit-${suffix}-${index}@example.test`,
  );

  try {
    const results = [];

    for (let index = 0; index < 4; index += 1) {
      results.push(
        await repository.createOAuthAccount(
          registration({
            email: emails[index],
            providerSubject: `google-limit-${suffix}-${index}`,
            fingerprint,
          }),
        ),
      );
    }

    const allowed = results.filter((result) => result.created);
    const rejected = results.filter((result) => !result.created);

    assert.equal(allowed.length, 3);
    assert.equal(rejected.length, 1);
    assert.equal(rejected[0].reason, 'ip_account_limit_reached');
    assert.equal(rejected[0].limit, 3);
    assert.equal(rejected[0].verifiedAccountCount, 3);

    const stored = await pool.query(
      `SELECT
         (SELECT COUNT(*)::int
          FROM velzx_central_test.registration_ip_claims
          WHERE ip_fingerprint = $1) AS claims,
         (SELECT COUNT(*)::int
          FROM velzx_central_test.security_events
          WHERE ip_fingerprint = $1
            AND event_type = 'registration_ip_limit_reached') AS events,
         (SELECT COUNT(*)::int
          FROM velzx_central_test.users
          WHERE email_normalized = ANY($2::varchar[])) AS users`,
      [fingerprint, emails],
    );

    assert.equal(stored.rows[0].claims, 3);
    assert.equal(stored.rows[0].events, 1);
    assert.equal(stored.rows[0].users, 3);

    console.log('OAUTH REGISTRATIONS:', results.length);
    console.log('ALLOWED:', allowed.length);
    console.log('REJECTED:', rejected.length);
    console.log('STORED IP CLAIMS:', stored.rows[0].claims);
    console.log('STORED SECURITY EVENTS:', stored.rows[0].events);
    console.log('PERMANENT IP LIMIT: PASS');
  } finally {
    await cleanup(pool, [fingerprint], emails);
    await pool.end();
  }
});
