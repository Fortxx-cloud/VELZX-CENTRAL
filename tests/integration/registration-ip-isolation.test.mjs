import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { randomBytes, randomUUID } from 'node:crypto';
import pg from 'pg';

import {
  claimVerifiedRegistrationIpInTransaction,
} from '../../src/security/registration-ip-limit.mjs';

const { Client } = pg;

function parseUrl(value) {
  try {
    const url = new URL(value);
    return {
      host: url.hostname.toLowerCase(),
      port: url.port || '5432',
      database: decodeURIComponent(url.pathname.replace(/^\/+/, '')),
      user: decodeURIComponent(url.username),
    };
  } catch {
    return null;
  }
}

function readEnv(key) {
  const line = fs.readFileSync('.env', 'utf8')
    .split(/\r?\n/)
    .find(item => item.startsWith(`${key}=`));

  return line?.slice(key.length + 1)
    .trim()
    .replace(/^['"]|['"]$/g, '') ?? '';
}

function sameDatabase(a, b) {
  const normalizeHost = (host) =>
    host.toLowerCase().replace(/-pooler(?=\.|$)/, '');

  return normalizeHost(a.host) === normalizeHost(b.host)
    && a.port === b.port
    && a.database === b.database;
}

function newFingerprint() {
  return `v1:${randomBytes(32).toString('hex')}`;
}

async function connectTestDatabase() {
  const connectionString = readEnv('TEST_DATABASE_URL');

  assert.ok(connectionString, 'TEST_DATABASE_URL belum diisi');

  const target = parseUrl(connectionString);
  const main = parseUrl(readEnv('DATABASE_URL'));
  const direct = parseUrl(readEnv('DIRECT_URL'));

  assert.ok(target, 'Test database URL tidak valid');
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

  const client = new Client({
    connectionString,
    connectionTimeoutMillis: 10000,
    ssl: { rejectUnauthorized: true },
  });

  await client.connect();

  const schema = await client.query(`
    SELECT
      to_regclass('velzx_central_test.registration_ip_claims') AS claims,
      to_regclass('velzx_central_test.security_events') AS events,
      to_regclass('public.registration_ip_claims') AS public_claims,
      to_regclass('public.security_events') AS public_events
  `);

  assert.ok(schema.rows[0].claims, 'Tabel claims tidak ditemukan');
  assert.ok(schema.rows[0].events, 'Tabel events tidak ditemukan');
  assert.equal(schema.rows[0].public_claims, null);
  assert.equal(schema.rows[0].public_events, null);

  return client;
}

async function beginTestTransaction(client) {
  await client.query('BEGIN ISOLATION LEVEL READ COMMITTED');
  await client.query(
    'SET LOCAL search_path TO velzx_central_test, pg_catalog',
  );
}

async function cleanup(client, fingerprints) {
  await client.query('ROLLBACK').catch(() => {});

  for (const fingerprint of fingerprints) {
    await client.query(
      `DELETE FROM velzx_central_test.security_events
       WHERE ip_fingerprint = $1`,
      [fingerprint],
    );

    await client.query(
      `DELETE FROM velzx_central_test.registration_ip_claims
       WHERE ip_fingerprint = $1`,
      [fingerprint],
    );
  }
}

test('different IP fingerprints have independent account limits', {
  timeout: 60000,
}, async () => {
  const client = await connectTestDatabase();
  const ipA = newFingerprint();
  const ipB = newFingerprint();

  try {
    // Isi batas IP A sampai tiga akun.
    for (let i = 0; i < 3; i++) {
      await beginTestTransaction(client);

      const result = await claimVerifiedRegistrationIpInTransaction({
        client,
        ipFingerprint: ipA,
        accountId: randomUUID(),
      });

      assert.equal(result.allowed, true);
      await client.query('COMMIT');
    }

    // IP B harus tetap bisa mendaftar.
    await beginTestTransaction(client);

    const resultB = await claimVerifiedRegistrationIpInTransaction({
      client,
      ipFingerprint: ipB,
      accountId: randomUUID(),
    });

    assert.equal(resultB.allowed, true);
    await client.query('COMMIT');

    const counts = await client.query(`
      SELECT ip_fingerprint, COUNT(*)::int AS total
      FROM velzx_central_test.registration_ip_claims
      WHERE ip_fingerprint = ANY($1::varchar[])
      GROUP BY ip_fingerprint
    `, [[ipA, ipB]]);

    const countMap = new Map(
      counts.rows.map(row => [row.ip_fingerprint, row.total]),
    );

    assert.equal(countMap.get(ipA), 3);
    assert.equal(countMap.get(ipB), 1);

    console.log('IP A CLAIMS:', countMap.get(ipA));
    console.log('IP B CLAIMS:', countMap.get(ipB));
    console.log('DIFFERENT IP ISOLATION: PASS');
  } finally {
    try {
      await cleanup(client, [ipA, ipB]);
    } finally {
      await client.end();
    }
  }
});

test('rollback leaves no registration IP claim', {
  timeout: 60000,
}, async () => {
  const client = await connectTestDatabase();
  const fingerprint = newFingerprint();

  try {
    await beginTestTransaction(client);

    const result = await claimVerifiedRegistrationIpInTransaction({
      client,
      ipFingerprint: fingerprint,
      accountId: randomUUID(),
    });

    assert.equal(result.allowed, true);

    // Sengaja batalkan transaksi.
    await client.query('ROLLBACK');

    const count = await client.query(`
      SELECT COUNT(*)::int AS total
      FROM velzx_central_test.registration_ip_claims
      WHERE ip_fingerprint = $1
    `, [fingerprint]);

    assert.equal(count.rows[0].total, 0);

    console.log('CLAIMS AFTER ROLLBACK:', count.rows[0].total);
    console.log('ROLLBACK TEST: PASS');
  } finally {
    try {
      await cleanup(client, [fingerprint]);
    } finally {
      await client.end();
    }
  }
});

test('security event persists after rejected transaction commits', {
  timeout: 60000,
}, async () => {
  const client = await connectTestDatabase();
  const fingerprint = newFingerprint();

  try {
    // Daftarkan tiga akun yang diizinkan.
    for (let i = 0; i < 3; i++) {
      await beginTestTransaction(client);

      const result = await claimVerifiedRegistrationIpInTransaction({
        client,
        ipFingerprint: fingerprint,
        accountId: randomUUID(),
      });

      assert.equal(result.allowed, true);
      await client.query('COMMIT');
    }

    // Percobaan keempat harus ditolak dan event di-commit.
    await beginTestTransaction(client);

    const rejected = await claimVerifiedRegistrationIpInTransaction({
      client,
      ipFingerprint: fingerprint,
      accountId: randomUUID(),
    });

    assert.equal(rejected.allowed, false);
    assert.equal(rejected.reason, 'ip_account_limit_reached');

    await client.query('COMMIT');

    const result = await client.query(`
      SELECT
        (
          SELECT COUNT(*)::int
          FROM velzx_central_test.registration_ip_claims
          WHERE ip_fingerprint = $1
        ) AS claims,
        (
          SELECT COUNT(*)::int
          FROM velzx_central_test.security_events
          WHERE ip_fingerprint = $1
            AND event_type = 'registration_ip_limit_reached'
        ) AS events
    `, [fingerprint]);

    assert.equal(result.rows[0].claims, 3);
    assert.equal(result.rows[0].events, 1);

    console.log('CLAIMS:', result.rows[0].claims);
    console.log('PERSISTED SECURITY EVENTS:', result.rows[0].events);
    console.log('SECURITY EVENT PERSISTENCE: PASS');
  } finally {
    try {
      await cleanup(client, [fingerprint]);
    } finally {
      await client.end();
    }
  }
});
