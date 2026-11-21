import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { randomBytes, randomUUID } from 'node:crypto';
import pg from 'pg';

import {
  createUserRepository,
} from '../../src/users/user-repository.mjs';

import {
  claimVerifiedRegistrationIpInTransaction,
} from '../../src/security/registration-ip-limit.mjs';

const { Client, Pool } = pg;

function readEnvValue(key) {
  const content = fs.readFileSync('.env', 'utf8');
  const line = content.split(/\r?\n/).find(x => x.startsWith(`${key}=`));
  return line?.slice(key.length + 1).trim().replace(/^['"]|['"]$/g, '') ?? '';
}

function parseDatabaseUrl(value) {
  try {
    const url = new URL(value);
    return {
      host: url.hostname.toLowerCase(),
      database: decodeURIComponent(url.pathname.replace(/^\/+/, '')),
      user: decodeURIComponent(url.username),
    };
  } catch {
    return null;
  }
}

function sameDatabase(a, b) {
  return a.host === b.host &&
    a.database === b.database &&
    a.user === b.user;
}

const connectionString = readEnvValue('TEST_DATABASE_URL');
const target = parseDatabaseUrl(connectionString);
const main = parseDatabaseUrl(readEnvValue('DATABASE_URL'));
const direct = parseDatabaseUrl(readEnvValue('DIRECT_URL'));

assert.ok(target, 'TEST_DATABASE_URL tidak valid');
assert.ok(main && direct, 'Database production URL tidak valid');
assert.equal(sameDatabase(target, main), false, 'Test target sama dengan DATABASE_URL');
assert.equal(sameDatabase(target, direct), false, 'Test target sama dengan DIRECT_URL');

const pool = new Pool({
  connectionString,
  max: 5,
  connectionTimeoutMillis: 10000,
  ssl: { rejectUnauthorized: true },
});

const repository = createUserRepository(pool);

test('concurrent verification with the same token activates exactly once', {
  timeout: 60000,
}, async () => {
  const suffix = randomUUID();
  const email = `verify-race-${suffix}@example.test`;
  const fingerprint = `v1:${randomBytes(32).toString('hex')}`;

  try {
    const created = await repository.createPendingUser({
      email,
      passwordHash: 'scrypt$integration-test',
    });

    assert.equal(created.created, true);

    const attempts = await Promise.all([
      repository.verifyEmailToken({
        verificationToken: created.verificationToken,
        ipFingerprint: fingerprint,
      }),
      repository.verifyEmailToken({
        verificationToken: created.verificationToken,
        ipFingerprint: fingerprint,
      }),
    ]);

    const successful = attempts.filter(x => x.verified);
    const rejected = attempts.filter(x => !x.verified);

    assert.equal(successful.length, 1);
    assert.equal(rejected.length, 1);
    assert.equal(rejected[0].reason, 'invalid_token');

    const audit = await pool.query(`
      SELECT
        u.account_status,
        u.email_verified_at,
        t.consumed_at,
        (
          SELECT COUNT(*)::int
          FROM velzx_central_test.registration_ip_claims
          WHERE ip_fingerprint = $2
            AND account_id = u.id
        ) AS claim_count
      FROM velzx_central_test.users u
      JOIN velzx_central_test.email_verification_tokens t
        ON t.user_id = u.id
      WHERE u.email_normalized = $1
    `, [email, fingerprint]);

    assert.equal(audit.rowCount, 1);
    assert.equal(audit.rows[0].account_status, 'active');
    assert.ok(audit.rows[0].email_verified_at);
    assert.ok(audit.rows[0].consumed_at);
    assert.equal(audit.rows[0].claim_count, 1);

    console.log('CONCURRENT VERIFICATION: PASS');
    console.log('SUCCESSFUL ACTIVATIONS:', successful.length);
    console.log('REJECTED REUSES:', rejected.length);
    console.log('IP CLAIMS:', audit.rows[0].claim_count);
  } finally {
    await pool.query(
      `DELETE FROM velzx_central_test.users WHERE email_normalized = $1`,
      [email],
    ).catch(() => {});

    await pool.query(
      `DELETE FROM velzx_central_test.security_events WHERE ip_fingerprint = $1`,
      [fingerprint],
    ).catch(() => {});

    await pool.query(
      `DELETE FROM velzx_central_test.registration_ip_claims WHERE ip_fingerprint = $1`,
      [fingerprint],
    ).catch(() => {});
  }
});

test('IP limit rejection preserves token for retry from another IP', {
  timeout: 60000,
}, async () => {
  const suffix = randomUUID();
  const email = `verify-retry-${suffix}@example.test`;
  const blockedFingerprint = `v1:${randomBytes(32).toString('hex')}`;
  const allowedFingerprint = `v1:${randomBytes(32).toString('hex')}`;

  try {
    const created = await repository.createPendingUser({
      email,
      passwordHash: 'scrypt$integration-test',
    });

    assert.equal(created.created, true);

    // Seed exactly three claims for the blocked IP.
    const seed = await pool.connect();

    try {
      await seed.query('BEGIN');
      await seed.query(
        'SET LOCAL search_path TO velzx_central_test, pg_catalog',
      );

      for (let i = 0; i < 3; i += 1) {
        await claimVerifiedRegistrationIpInTransaction({
          client: seed,
          ipFingerprint: blockedFingerprint,
          accountId: randomUUID(),
        });
      }

      await seed.query('COMMIT');
    } catch (error) {
      await seed.query('ROLLBACK').catch(() => {});
      throw error;
    } finally {
      seed.release();
    }

    const blocked = await repository.verifyEmailToken({
      verificationToken: created.verificationToken,
      ipFingerprint: blockedFingerprint,
    });

    assert.equal(blocked.verified, false);
    assert.equal(blocked.reason, 'ip_account_limit_reached');

    const afterBlock = await pool.query(`
      SELECT
        u.account_status,
        t.consumed_at,
        (
          SELECT COUNT(*)::int
          FROM velzx_central_test.security_events
          WHERE ip_fingerprint = $2
            AND event_type = 'registration_ip_limit_reached'
            AND account_id = u.id
        ) AS security_events
      FROM velzx_central_test.users u
      JOIN velzx_central_test.email_verification_tokens t
        ON t.user_id = u.id
      WHERE u.email_normalized = $1
    `, [email, blockedFingerprint]);

    assert.equal(afterBlock.rowCount, 1);
    assert.equal(afterBlock.rows[0].account_status, 'pending_verification');
    assert.equal(afterBlock.rows[0].consumed_at, null);
    assert.equal(afterBlock.rows[0].security_events, 1);

    const retried = await repository.verifyEmailToken({
      verificationToken: created.verificationToken,
      ipFingerprint: allowedFingerprint,
    });

    assert.equal(retried.verified, true);
    assert.equal(retried.user.account_status, 'active');

    console.log('IP LIMIT REJECTION: PASS');
    console.log('TOKEN PRESERVED: PASS');
    console.log('SECURITY EVENT PERSISTED: PASS');
    console.log('RETRY FROM ANOTHER IP: PASS');
  } finally {
    await pool.query(
      `DELETE FROM velzx_central_test.users WHERE email_normalized = $1`,
      [email],
    ).catch(() => {});

    for (const fingerprint of [blockedFingerprint, allowedFingerprint]) {
      await pool.query(
        `DELETE FROM velzx_central_test.security_events WHERE ip_fingerprint = $1`,
        [fingerprint],
      ).catch(() => {});

      await pool.query(
        `DELETE FROM velzx_central_test.registration_ip_claims WHERE ip_fingerprint = $1`,
        [fingerprint],
      ).catch(() => {});
    }
  }
});

test.after(async () => {
  await pool.end();
});
