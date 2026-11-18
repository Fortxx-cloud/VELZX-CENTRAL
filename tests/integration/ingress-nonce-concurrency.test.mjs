import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { randomBytes } from 'node:crypto';
import pg from 'pg';

import {
  claimIngressNonce,
  cleanupExpiredIngressNonces,
} from '../../src/security/ingress-nonce-repository.mjs';

const { Client } = pg;

function readEnv(key) {
  const line = fs.readFileSync('.env', 'utf8')
    .split(/\r?\n/)
    .find(item => item.startsWith(`${key}=`));

  return line?.slice(key.length + 1)
    .trim()
    .replace(/^['"]|['"]$/g, '') ?? '';
}

function databaseIdentity(value) {
  const url = new URL(value);

  return [
    url.hostname.toLowerCase(),
    decodeURIComponent(url.pathname.replace(/^\/+/, '')),
    decodeURIComponent(url.username),
  ].join('|');
}

function newNonce() {
  return randomBytes(32).toString('base64url');
}

async function connectTestDatabase() {
  const target = readEnv('TEST_DATABASE_URL');
  const main = readEnv('DATABASE_URL');
  const direct = readEnv('DIRECT_URL');

  assert.ok(target, 'TEST_DATABASE_URL tidak tersedia');
  assert.ok(main, 'DATABASE_URL tidak tersedia');
  assert.ok(direct, 'DIRECT_URL tidak tersedia');

  assert.notEqual(
    databaseIdentity(target),
    databaseIdentity(main),
    'DITOLAK: target sama dengan DATABASE_URL utama',
  );

  assert.notEqual(
    databaseIdentity(target),
    databaseIdentity(direct),
    'DITOLAK: target sama dengan DIRECT_URL utama',
  );

  const client = new Client({
    connectionString: target,
    connectionTimeoutMillis: 10000,
    ssl: { rejectUnauthorized: true },
  });

  await client.connect();

  const audit = await client.query(`
    SELECT
      to_regnamespace('velzx_central_test') IS NOT NULL AS test_schema,
      to_regclass('velzx_central_test.ingress_nonces') IS NOT NULL AS nonce_table,
      to_regclass('public.ingress_nonces') IS NOT NULL AS public_nonce_table
  `);

  assert.equal(audit.rows[0].test_schema, true);
  assert.equal(audit.rows[0].nonce_table, true);
  assert.equal(audit.rows[0].public_nonce_table, false);

  return client;
}

async function deleteNonces(client, nonces) {
  if (!nonces.length) return;

  await client.query(
    `DELETE FROM velzx_central_test.ingress_nonces
     WHERE nonce = ANY($1::varchar[])`,
    [nonces],
  );
}

test('concurrent requests can claim the same nonce only once', {
  timeout: 60000,
}, async () => {
  const clientA = await connectTestDatabase();
  const clientB = await connectTestDatabase();

  const nonce = newNonce();
  const expiresAt = new Date(Date.now() + 120000);

  try {
    const results = await Promise.all([
      claimIngressNonce({
        client: clientA,
        nonce,
        expiresAt,
      }),
      claimIngressNonce({
        client: clientB,
        nonce,
        expiresAt,
      }),
    ]);

    assert.equal(
      results.filter(result => result.accepted).length,
      1,
      'Harus tepat satu request yang berhasil mengklaim nonce',
    );

    assert.equal(
      results.filter(result => !result.accepted).length,
      1,
      'Request kedua harus ditolak sebagai replay',
    );

    const stored = await clientA.query(
      `SELECT COUNT(*)::int AS total
       FROM velzx_central_test.ingress_nonces
       WHERE nonce = $1`,
      [nonce],
    );

    assert.equal(stored.rows[0].total, 1);

    console.log('CONCURRENT NONCE CLAIM: PASS');
    console.log('SUCCESSFUL CLAIMS: 1');
    console.log('REJECTED REPLAY CLAIMS: 1');
  } finally {
    await deleteNonces(clientA, [nonce]);
    await clientA.end();
    await clientB.end();
  }
});

test('expired nonce cleanup preserves active nonces', {
  timeout: 60000,
}, async () => {
  const client = await connectTestDatabase();

  const expiredNonce = newNonce();
  const activeNonce = newNonce();

  try {
    await client.query(
      `INSERT INTO velzx_central_test.ingress_nonces
         (nonce, created_at, expires_at)
       VALUES
         ($1, NOW() - INTERVAL '10 minutes',
             NOW() - INTERVAL '1 minute'),
         ($2, NOW(), NOW() + INTERVAL '2 minutes')`,
      [expiredNonce, activeNonce],
    );

    const result = await cleanupExpiredIngressNonces({
      client,
      batchSize: 10,
    });

    assert.equal(result.deleted, 1);

    const remaining = await client.query(
      `SELECT nonce
       FROM velzx_central_test.ingress_nonces
       WHERE nonce = ANY($1::varchar[])`,
      [[expiredNonce, activeNonce]],
    );

    assert.deepEqual(
      remaining.rows.map(row => row.nonce),
      [activeNonce],
    );

    console.log('EXPIRED NONCE CLEANUP: PASS');
    console.log('EXPIRED NONCES DELETED:', result.deleted);
    console.log('ACTIVE NONCE PRESERVED: true');
  } finally {
    await deleteNonces(client, [expiredNonce, activeNonce]);
    await client.end();
  }
});
