import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { randomBytes } from 'node:crypto';
import pg from 'pg';

import {
  createOAuthTransactionRepository,
} from '../../src/auth/oauth/oauth-transaction-repository.mjs';

const { Pool } = pg;

function readEnv(key) {
  const line = fs.readFileSync('.env', 'utf8')
    .split(/\r?\n/)
    .find((item) => item.startsWith(`${key}=`));

  return line?.slice(key.length + 1)
    .trim()
    .replace(/^['"]|['"]$/g, '') ?? '';
}

function parseUrl(value) {
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

async function createTestPool() {
  const connectionString = readEnv('TEST_DATABASE_URL');

  assert.ok(connectionString, 'TEST_DATABASE_URL belum diisi');

  const target = parseUrl(connectionString);
  const main = parseUrl(readEnv('DATABASE_URL'));
  const direct = parseUrl(readEnv('DIRECT_URL'));

  assert.ok(target, 'TEST_DATABASE_URL tidak valid');
  assert.ok(main, 'DATABASE_URL utama tidak valid');
  assert.ok(direct, 'DIRECT_URL utama tidak valid');

  const sameDatabase = (a, b) =>
    a.host === b.host &&
    a.port === b.port &&
    a.database === b.database;

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
    max: 2,
    connectionTimeoutMillis: 10000,
    ssl: { rejectUnauthorized: true },
  });

  try {
    const result = await pool.query(`
      SELECT
        to_regclass('velzx_central_test.oauth_transactions') AS test_table,
        to_regclass('velzx_central_test.users') AS test_users,
        to_regclass('velzx_central_test.sessions') AS test_sessions,
        to_regclass('public.oauth_transactions') AS public_table
    `);

    assert.ok(result.rows[0].test_table, 'Tabel OAuth test tidak ditemukan');
    assert.ok(result.rows[0].test_users, 'Tabel users test tidak ditemukan');
    assert.ok(result.rows[0].test_sessions, 'Tabel sessions test tidak ditemukan');
    assert.equal(
      result.rows[0].public_table,
      null,
      'DITOLAK: ditemukan oauth_transactions pada schema public',
    );

    return pool;
  } catch (error) {
    await pool.end();
    throw error;
  }
}

test('only one concurrent callback can consume the same OAuth transaction', {
  timeout: 60000,
}, async () => {
  const pool = await createTestPool();
  const encryptionKey = randomBytes(32);

  const repository = createOAuthTransactionRepository(pool, {
    schema: 'velzx_central_test',
    encryptionKey,
    ttlSeconds: 600,
  });
  let transactionId;
  try {
    const knownBinding = randomBytes(32).toString('base64url');

    const created = await repository.create({
      provider: 'google',
      purpose: 'login',
      browserBinding: knownBinding,
      pkceVerifier: randomBytes(32).toString('base64url'),
      nonce: randomBytes(32).toString('base64url'),
    });

    transactionId = created.id;
    assert.ok(created.state);
    assert.ok(created.id);


    const attempts = await Promise.all([
      repository.consume({
        provider: 'google',
        state: created.state,
        browserBinding: knownBinding,
      }),
      repository.consume({
        provider: 'google',
        state: created.state,
        browserBinding: knownBinding,
      }),
    ]);

    const successful = attempts.filter((result) => result !== null);
    const rejected = attempts.filter((result) => result === null);

    assert.equal(successful.length, 1, 'Harus tepat satu callback berhasil');
    assert.equal(rejected.length, 1, 'Callback kedua harus ditolak');
    assert.equal(successful[0].id, created.id);

    const stored = await pool.query(
      `SELECT consumed_at
       FROM velzx_central_test.oauth_transactions
       WHERE id = $1`,
      [created.id],
    );

    assert.equal(stored.rowCount, 1);
    assert.ok(stored.rows[0].consumed_at);

    console.log('OAUTH CONCURRENT CONSUMPTION: PASS');
    console.log('Successful callbacks:', successful.length);
    console.log('Rejected callbacks:', rejected.length);
  } finally {
    if (transactionId) {
      await pool.query(
        'DELETE FROM velzx_central_test.oauth_transactions WHERE id = $1',
        [transactionId],
      ).catch(() => {});
    }

    encryptionKey.fill(0);
    await pool.end();
  }
});
