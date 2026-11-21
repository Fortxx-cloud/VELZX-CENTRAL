import test from 'node:test';
import assert from 'node:assert/strict';

import {
  createEmailDeliveryRepository,
} from '../../src/services/email/email-delivery-repository.mjs';

function createPool() {
  const calls = [];
  let connectCount = 0;

  const quotaRow = {
    key_number: 1,
    status: 'QUOTA_EXHAUSTED',
    daily_used: 100,
    daily_limit: 100,
    resets_at: new Date('2026-11-20T00:00:00Z'),
  };

  const client = {
    async query(sql, params = []) {
      calls.push({ sql: String(sql), params, source: 'client' });

      if (String(sql).includes('INSERT INTO')) {
        return { rows: [{ ...quotaRow, status: params[1] }], rowCount: 1 };
      }

      if (String(sql).includes('UPDATE') && String(sql).includes('RETURNING key_number')) {
        return { rows: [{ key_number: 1 }], rowCount: 1 };
      }

      return { rows: [], rowCount: 0 };
    },
    release() {},
  };

  return {
    calls,
    get connectCount() {
      return connectCount;
    },
    async connect() {
      connectCount++;
      return client;
    },
    async query(sql, params = []) {
      calls.push({ sql: String(sql), params, source: 'pool' });
      return {
        rows: [{
          ...quotaRow,
          key_number: params[0] ?? 1,
        }],
        rowCount: 1,
      };
    },
  };
}

function createRepository(pool) {
  return createEmailDeliveryRepository(pool, {
    schema: 'velzx_central_test',
  });
}

test('menyimpan status kuota melalui UPSERT', async () => {
  const pool = createPool();
  const repository = createRepository(pool);

  const result = await repository.setKeyQuotaState({
    keyNumber: 1,
    status: 'QUOTA_EXHAUSTED',
    dailyUsed: 100,
    dailyLimit: 100,
    resetsAt: '2026-11-20T00:00:00Z',
  });

  assert.equal(result.key_number, 1);

  const write = pool.calls.find(call =>
    call.sql.includes('INSERT INTO velzx_central_test.resend_key_quota')
  );

  assert.ok(write);
  assert.equal(write.params[0], 1);
  assert.equal(write.params[1], 'QUOTA_EXHAUSTED');
  assert.equal(write.params[2], 100);
  assert.equal(write.params[3], 100);
  assert.ok(write.sql.includes('ON CONFLICT'));
});

test('menolak nomor key di luar rentang tanpa koneksi database', async () => {
  const pool = createPool();
  const repository = createRepository(pool);

  await assert.rejects(
    repository.setKeyQuotaState({
      keyNumber: 10,
      status: 'ACTIVE',
    }),
    /Nomor email key tidak valid/
  );

  assert.equal(pool.connectCount, 0);
});

test('menolak status kuota yang tidak dikenal', async () => {
  const pool = createPool();
  const repository = createRepository(pool);

  await assert.rejects(
    repository.setKeyQuotaState({
      keyNumber: 1,
      status: 'UNKNOWN_STATUS',
    }),
    /Status kuota tidak valid/
  );

  assert.equal(pool.connectCount, 0);
});

test('menolak kuota habis tanpa waktu reset', async () => {
  const pool = createPool();
  const repository = createRepository(pool);

  await assert.rejects(
    repository.setKeyQuotaState({
      keyNumber: 1,
      status: 'QUOTA_EXHAUSTED',
      dailyUsed: 100,
      dailyLimit: 100,
    }),
    /Waktu reset wajib/
  );

  assert.equal(pool.connectCount, 0);
});

test('mengaktifkan kembali key setelah waktu reset', async () => {
  const pool = createPool();
  const repository = createRepository(pool);

  const result = await repository.refreshExpiredQuotaKeys();

  assert.deepEqual(result, [1]);

  const update = pool.calls.find(call =>
    call.sql.includes('UPDATE velzx_central_test.resend_key_quota')
  );

  assert.ok(update);
  assert.match(update.sql, /status = 'QUOTA_EXHAUSTED'/);
  assert.match(update.sql, /resets_at <= NOW\(\)/);
});

test('membaca status key setelah memproses reset', async () => {
  const pool = createPool();
  const repository = createRepository(pool);

  const result = await repository.getKeyQuotaState(1);

  assert.equal(result.key_number, 1);

  const updateIndex = pool.calls.findIndex(call =>
    call.sql.includes('UPDATE velzx_central_test.resend_key_quota')
  );

  const selectIndex = pool.calls.findIndex(call =>
    call.sql.includes('SELECT *') &&
    call.source === 'pool'
  );

  assert.ok(updateIndex >= 0);
  assert.ok(selectIndex > updateIndex);
});

test('membaca seluruh status key dalam urutan nomor', async () => {
  const pool = createPool();
  const repository = createRepository(pool);

  const result = await repository.listKeyQuotaStates();

  assert.equal(result.length, 1);

  const select = pool.calls.find(call =>
    call.sql.includes('ORDER BY key_number ASC')
  );

  assert.ok(select);
});


function createTransitionPool() {
  const calls = [];
  const client = {
    async query(sql, params = []) {
      const query = String(sql);
      calls.push({ sql: query, params });

      if (query.includes('SELECT request_id, outcome')) {
        return {
          rows: [{ request_id: 'request-403', outcome: 'IN_PROGRESS' }],
          rowCount: 1,
        };
      }

      if (query.includes('SELECT') && query.includes('lease_active')) {
        return {
          rows: [{ status: 'PENDING', lease_active: true }],
          rowCount: 1,
        };
      }

      if (query.includes('COUNT(*)::INTEGER')) {
        return {
          rows: [{ total: 1, all_retryable: true, active: false }],
          rowCount: 1,
        };
      }

      if (query.includes('RETURNING request_id, next_attempt_at')) {
        return {
          rows: [{
            request_id: 'request-403',
            next_attempt_at: params[1],
          }],
          rowCount: 1,
        };
      }

      return { rows: [], rowCount: 0 };
    },
    release() {},
  };

  return {
    calls,
    async connect() {
      return client;
    },
  };
}

test('PROVIDER_REJECTED 403 mempertahankan delivery PENDING untuk failover', async () => {
  const pool = createTransitionPool();
  const repository = createRepository(pool);

  const result = await repository.finishAttempt({
    attemptId: 1,
    outcome: 'PROVIDER_REJECTED',
    httpStatus: 403,
    errorCode: 'DOMAIN_NOT_VERIFIED',
  });

  assert.equal(result.requestId, 'request-403');

  const deliveryUpdate = pool.calls.find(call =>
    call.sql.includes('UPDATE velzx_central_test.email_deliveries')
  );

  assert.ok(deliveryUpdate);
  assert.match(deliveryUpdate.sql, /lease_expires_at = NOW\(\)/);
  assert.match(deliveryUpdate.sql, /status = 'PENDING'/);
});

test('scheduleRetry menerima PROVIDER_REJECTED hanya untuk 4xx selain 429', async () => {
  const pool = createTransitionPool();
  const repository = createRepository(pool);

  const result = await repository.scheduleRetry({
    requestId: 'request-403',
    nextAttemptAt: new Date(Date.now() + 60000),
    errorCode: 'ALL_KEYS_UNAVAILABLE',
  });

  assert.equal(result.state, 'WAITING_RETRY');

  const historyQuery = pool.calls.find(call =>
    call.sql.includes('COUNT(*)::INTEGER')
  );

  assert.ok(historyQuery);
  assert.match(historyQuery.sql, /outcome = 'PROVIDER_REJECTED'/);
  assert.match(historyQuery.sql, /http_status BETWEEN 400 AND 499/);
  assert.match(historyQuery.sql, /http_status <> 429/);
});
