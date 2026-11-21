import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { randomUUID, createHash } from 'node:crypto';
import pg from 'pg';

import {
  createUserRepository,
} from '../../src/users/user-repository.mjs';

const { Pool, Client } = pg;

function readEnvValue(key) {
  const content = fs.readFileSync('.env', 'utf8');
  const line = content
    .split(/\r?\n/)
    .find(item => item.startsWith(`${key}=`));

  return line?.slice(key.length + 1)
    .trim()
    .replace(/^['"]|['"]$/g, '') ?? '';
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

test('user repository creates pending accounts safely in test PostgreSQL', {
  timeout: 60000,
}, async () => {
  const connectionString = readEnvValue('TEST_DATABASE_URL');

  assert.ok(connectionString, 'TEST_DATABASE_URL belum diisi');

  const target = parseDatabaseUrl(connectionString);
  const main = parseDatabaseUrl(readEnvValue('DATABASE_URL'));
  const direct = parseDatabaseUrl(readEnvValue('DIRECT_URL'));

  assert.ok(target, 'Test database URL tidak valid');
  assert.ok(main, 'DATABASE_URL utama tidak valid');
  assert.ok(direct, 'DIRECT_URL utama tidak valid');

  assert.equal(
    sameDatabase(target, main),
    false,
    'DITOLAK: test target sama dengan DATABASE_URL utama',
  );

  assert.equal(
    sameDatabase(target, direct),
    false,
    'DITOLAK: test target sama dengan DIRECT_URL utama',
  );

  const audit = new Client({
    connectionString,
    connectionTimeoutMillis: 10000,
    ssl: { rejectUnauthorized: true },
  });

  await audit.connect();

  let pool;

  const suffix = randomUUID();
  const email = `repo-${suffix}@example.test`;
  const concurrentEmail = `race-${suffix}@example.test`;

  try {
    const schemaCheck = await audit.query(`
      SELECT
        to_regclass('velzx_central_test.users') AS users_table,
        to_regclass('velzx_central_test.email_verification_tokens') AS tokens_table,
        to_regclass('public.users') AS public_users,
        to_regclass('public.email_verification_tokens') AS public_tokens
    `);

    const schema = schemaCheck.rows[0];

    assert.ok(schema.users_table, 'Tabel users test tidak ditemukan');
    assert.ok(schema.tokens_table, 'Tabel token test tidak ditemukan');
    assert.equal(schema.public_users, null, 'Tabel users ditemukan di public');
    assert.equal(schema.public_tokens, null, 'Tabel token ditemukan di public');

    pool = new Pool({
      connectionString,
      max: 5,
      connectionTimeoutMillis: 10000,
      ssl: { rejectUnauthorized: true },
    });

    const repository = createUserRepository(pool, {
      schema: 'velzx_central_test',
    });

    // 1. Buat akun pending.
    const created = await repository.createPendingUser({
      email: `  ${email.toUpperCase()}  `,
      passwordHash: 'scrypt$integration-test-hash',
    });

    assert.equal(created.created, true);
    assert.equal(created.user.email_normalized, email);
    assert.equal(created.user.account_status, 'pending_verification');

    const rawToken = created.verificationToken;

    assert.equal(
      Buffer.from(rawToken, 'base64url').length,
      32,
    );

    const expectedHash = createHash('sha256')
      .update(rawToken, 'utf8')
      .digest('hex');

    const stored = await audit.query(`
      SELECT
        u.id,
        u.email_normalized,
        u.account_status,
        t.token_hash,
        t.expires_at,
        t.created_at
      FROM velzx_central_test.users u
      JOIN velzx_central_test.email_verification_tokens t
        ON t.user_id = u.id
      WHERE u.id = $1
    `, [created.user.id]);

    assert.equal(stored.rowCount, 1);
    assert.equal(stored.rows[0].token_hash, expectedHash);
    assert.notEqual(stored.rows[0].token_hash, rawToken);
    assert.ok(
      new Date(stored.rows[0].expires_at) >
      new Date(stored.rows[0].created_at),
    );

    // 2. Email duplikat dengan kapitalisasi berbeda.
    const duplicate = await repository.createPendingUser({
      email: email.toUpperCase(),
      passwordHash: 'scrypt$another-test-hash',
    });

    assert.deepEqual(duplicate, { created: false });

    const duplicateCount = await audit.query(`
      SELECT COUNT(*)::int AS total
      FROM velzx_central_test.users
      WHERE email_normalized = $1
    `, [email]);

    assert.equal(duplicateCount.rows[0].total, 1);

    // 3. Dua permintaan bersamaan untuk email yang sama.
    const concurrentResults = await Promise.all([
      repository.createPendingUser({
        email: concurrentEmail,
        passwordHash: 'scrypt$concurrent-test-hash-a',
      }),
      repository.createPendingUser({
        email: concurrentEmail,
        passwordHash: 'scrypt$concurrent-test-hash-b',
      }),
    ]);

    assert.equal(
      concurrentResults.filter(item => item.created).length,
      1,
    );

    assert.equal(
      concurrentResults.filter(item => !item.created).length,
      1,
    );

    const concurrentCount = await audit.query(`
      SELECT COUNT(*)::int AS total
      FROM velzx_central_test.users
      WHERE email_normalized = $1
    `, [concurrentEmail]);

    assert.equal(concurrentCount.rows[0].total, 1);

    console.log('PENDING ACCOUNT CREATION: PASS');
    console.log('TOKEN SHA-256 STORAGE: PASS');
    console.log('EMAIL DUPLICATE PROTECTION: PASS');
    console.log('CONCURRENT EMAIL REGISTRATION: PASS');
    console.log('DATABASE ISOLATION: PASS');
  } finally {
    if (pool) {
      await pool.query(`
        DELETE FROM velzx_central_test.users
        WHERE email_normalized = ANY($1::varchar[])
      `, [[email, concurrentEmail]]).catch(() => {});

      await pool.end();
    }

    await audit.end();
  }
});
