import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { randomBytes, randomUUID } from 'node:crypto';
import pg from 'pg';

import {
  claimVerifiedRegistrationIpInTransaction,
} from '../../src/security/registration-ip-limit.mjs';

const { Client } = pg;

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

function readEnvValue(key) {
  const content = fs.readFileSync('.env', 'utf8');
  const line = content
    .split(/\r?\n/)
    .find(item => item.startsWith(`${key}=`));

  return line?.slice(key.length + 1)
    .trim()
    .replace(/^['"]|['"]$/g, '') ?? '';
}

function sameDatabase(a, b) {
  return a.host === b.host &&
    a.database === b.database &&
    a.user === b.user;
}

test('10 concurrent registrations enforce the permanent IP limit of 3', {
  timeout: 60000,
}, async () => {
  const connectionString = process.env.TEST_DATABASE_URL;

  assert.ok(connectionString, 'TEST_DATABASE_URL belum diisi');

  const target = parseDatabaseUrl(connectionString);
  const main = parseDatabaseUrl(readEnvValue('DATABASE_URL'));
  const direct = parseDatabaseUrl(readEnvValue('DIRECT_URL'));

  assert.ok(target, 'Test database URL tidak valid');
  assert.ok(main, 'DATABASE_URL utama tidak valid');
  assert.ok(direct, 'DIRECT_URL utama tidak valid');

  assert.equal(sameDatabase(target, main), false,
    'DITOLAK: test target sama dengan DATABASE_URL utama');

  assert.equal(sameDatabase(target, direct), false,
    'DITOLAK: test target sama dengan DIRECT_URL utama');

  const audit = new Client({
    connectionString,
    connectionTimeoutMillis: 10000,
    ssl: { rejectUnauthorized: true },
  });

  await audit.connect();

  const fingerprint = `v1:${randomBytes(32).toString('hex')}`;

  try {
    const schemaCheck = await audit.query(`
      SELECT
        to_regclass('velzx_central_test.registration_ip_claims')
          AS claims_table,
        to_regclass('velzx_central_test.security_events')
          AS events_table,
        to_regclass('public.registration_ip_claims')
          AS public_claims,
        to_regclass('public.security_events')
          AS public_events
    `);

    const schema = schemaCheck.rows[0];

    assert.ok(schema.claims_table, 'Tabel claims tidak ditemukan');
    assert.ok(schema.events_table, 'Tabel events tidak ditemukan');
    assert.equal(schema.public_claims, null,
      'Tabel claims ditemukan di public');
    assert.equal(schema.public_events, null,
      'Tabel events ditemukan di public');

    const workers = Array.from({ length: 10 }, async () => {
      const client = new Client({
        connectionString,
        connectionTimeoutMillis: 10000,
        ssl: { rejectUnauthorized: true },
      });

      await client.connect();

      try {
        await client.query('BEGIN ISOLATION LEVEL READ COMMITTED');

        await client.query(
          'SET LOCAL search_path TO velzx_central_test, pg_catalog',
        );

        const result = await claimVerifiedRegistrationIpInTransaction({
          client,
          ipFingerprint: fingerprint,
          accountId: randomUUID(),
        });

        // Penolakan juga harus di-commit agar security event tersimpan.
        await client.query('COMMIT');

        return result;
      } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        throw error;
      } finally {
        await client.end().catch(() => {});
      }
    });

    const settled = await Promise.allSettled(workers);

    const failures = settled.filter(item => item.status === 'rejected');

    assert.equal(
      failures.length,
      0,
      `Ada transaksi gagal: ${failures.map(x => x.reason?.message).join('; ')}`,
    );

    const results = settled.map(item => item.value);

    const allowed = results.filter(item => item.allowed);
    const rejected = results.filter(item => !item.allowed);

    const stored = await audit.query(`
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

    const claims = stored.rows[0].claims;
    const events = stored.rows[0].events;

    console.log('CONCURRENT REQUESTS:', results.length);
    console.log('ALLOWED:', allowed.length);
    console.log('REJECTED:', rejected.length);
    console.log('STORED CLAIMS:', claims);
    console.log('STORED SECURITY EVENTS:', events);

    assert.equal(results.length, 10);
    assert.equal(allowed.length, 3);
    assert.equal(rejected.length, 7);
    assert.equal(claims, 3);
    assert.equal(events, 7);

    console.log('RACE CONDITION TEST: PASS');
  } finally {
    // Hanya menghapus data milik fingerprint acak tes ini.
    await audit.query(
      `DELETE FROM velzx_central_test.security_events
       WHERE ip_fingerprint = $1`,
      [fingerprint],
    ).catch(() => {});

    await audit.query(
      `DELETE FROM velzx_central_test.registration_ip_claims
       WHERE ip_fingerprint = $1`,
      [fingerprint],
    ).catch(() => {});

    await audit.end().catch(() => {});
  }
});
