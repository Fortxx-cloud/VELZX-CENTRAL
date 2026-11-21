import test from 'node:test';
import assert from 'node:assert/strict';

import {
  createEmailDeliveryRepository,
} from '../../src/services/email/email-delivery-repository.mjs';

function createPool({ leaseValid = true } = {}) {
  const calls = [];

  const client = {
    async query(sql, params = []) {
      const query = String(sql).replace(/\s+/g, ' ').trim();
      calls.push({ query, params });

      if (query === 'BEGIN' || query === 'COMMIT' || query === 'ROLLBACK') {
        return { rows: [], rowCount: 0 };
      }

      if (query.includes('SELECT request_id, outcome')) {
        return {
          rows: [{ request_id: 'request-1', outcome: 'IN_PROGRESS' }],
          rowCount: 1,
        };
      }

      if (query.includes('SELECT status, lease_expires_at')) {
        return {
          rows: [{
            status: 'PENDING',
            lease_expires_at: new Date(Date.now() + 60000),
            lease_valid: leaseValid,
          }],
          rowCount: 1,
        };
      }

      if (query.includes('INSERT INTO velzx_central_test.email_delivery_attempts')) {
        return { rows: [{ id: 42 }], rowCount: 1 };
      }

      return { rows: [], rowCount: 1 };
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

function repository(pool) {
  return createEmailDeliveryRepository(pool, {
    schema: 'velzx_central_test',
    leaseSeconds: 120,
  });
}

test('RETRYABLE_ERROR menyelesaikan attempt tanpa menutup delivery', async () => {
  const pool = createPool();
  const repo = repository(pool);

  const result = await repo.finishAttempt({
    attemptId: 42,
    outcome: 'RETRYABLE_ERROR',
    httpStatus: 503,
    errorCode: 'PROVIDER_TEMPORARY_ERROR',
  });

  assert.equal(result.requestId, 'request-1');
  assert.equal(result.outcome, 'RETRYABLE_ERROR');

  const deliveryUpdate = pool.calls.find(call =>
    call.query.includes('UPDATE velzx_central_test.email_deliveries')
  );

  assert.ok(deliveryUpdate);
  assert.match(deliveryUpdate.query, /lease_expires_at = NOW\(\)/);
  assert.match(deliveryUpdate.query, /status = 'PENDING'/);
  assert.ok(pool.calls.some(call => call.query === 'COMMIT'));
  assert.ok(!pool.calls.some(call => call.query === 'ROLLBACK'));
});

test('lease kedaluwarsa menjadi UNKNOWN dan transaksi tetap COMMIT', async () => {
  const pool = createPool({ leaseValid: false });
  const repo = repository(pool);

  await assert.rejects(
    repo.beginAttempt({
      requestId: 'request-1',
      keyNumber: 1,
    }),
    /lease sudah kedaluwarsa/
  );

  const update = pool.calls.find(call =>
    call.query.includes('UPDATE velzx_central_test.email_deliveries')
  );

  assert.ok(update);
  assert.match(update.query, /status = 'UNKNOWN'/);
  assert.ok(pool.calls.some(call => call.query === 'COMMIT'));
  assert.ok(!pool.calls.some(call => call.query === 'ROLLBACK'));
});


function createRetryPool({
  leaseActive = true,
  total = 2,
  allRetryable = true,
  active = false,
  retryTimeFuture = true,
} = {}) {
  const calls = [];

  const client = {
    async query(sql, params = []) {
      const query = String(sql).replace(/\s+/g, ' ').trim();
      calls.push({ query, params });

      if (['BEGIN', 'COMMIT', 'ROLLBACK'].includes(query)) {
        return { rows: [], rowCount: 0 };
      }

      if (query.includes('SELECT status, (lease_expires_at > NOW())')) {
        return {
          rows: [{
            status: 'PENDING',
            lease_active: leaseActive,
          }],
          rowCount: 1,
        };
      }

      if (query.includes('COUNT(*)::INTEGER AS total')) {
        return {
          rows: [{
            total,
            all_retryable: allRetryable,
            active,
          }],
          rowCount: 1,
        };
      }

      if (query.includes('RETURNING request_id, next_attempt_at')) {
        if (!retryTimeFuture) {
          return { rows: [], rowCount: 0 };
        }

        return {
          rows: [{
            request_id: 'request-1',
            next_attempt_at: params[1],
          }],
          rowCount: 1,
        };
      }

      return { rows: [], rowCount: 1 };
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

test('scheduleRetry menyimpan jadwal setelah seluruh attempt aman', async () => {
  const pool = createRetryPool();
  const repo = repository(pool);

  const result = await repo.scheduleRetry({
    requestId: 'request-1',
    nextAttemptAt: '2026-11-20T00:00:00.000Z',
  });

  assert.equal(result.state, 'WAITING_RETRY');
  assert.equal(result.requestId, 'request-1');

  const update = pool.calls.find(call =>
    call.query.includes('UPDATE velzx_central_test.email_deliveries')
  );

  assert.ok(update);
  assert.match(update.query, /lease_expires_at = NULL/);
  assert.match(update.query, /next_attempt_at = \$2/);

  assert.ok(pool.calls.some(call => call.query === 'COMMIT'));
  assert.ok(!pool.calls.some(call => call.query === 'ROLLBACK'));
});


test('scheduleRetry menolak jadwal kedaluwarsa berdasarkan waktu database', async () => {
  const pool = createRetryPool({ retryTimeFuture: false });
  const repo = repository(pool);

  await assert.rejects(
    repo.scheduleRetry({
      requestId: 'request-1',
      nextAttemptAt: '2020-01-01T00:00:00.000Z',
    }),
    /Gagal menyimpan jadwal retry/
  );

  const update = pool.calls.find(call =>
    call.query.includes('UPDATE velzx_central_test.email_deliveries')
  );

  assert.ok(update);
  assert.match(update.query, /\$2::TIMESTAMPTZ > NOW\(\)/);
  assert.ok(pool.calls.some(call => call.query === 'ROLLBACK'));
});

test('scheduleRetry menolak riwayat attempt yang tidak aman', async () => {
  const pool = createRetryPool({
    allRetryable: false,
  });
  const repo = repository(pool);

  await assert.rejects(
    repo.scheduleRetry({
      requestId: 'request-1',
      nextAttemptAt: '2026-11-20T00:00:00.000Z',
    }),
    /Riwayat attempt tidak aman/
  );

  assert.ok(pool.calls.some(call => call.query === 'ROLLBACK'));
  assert.ok(!pool.calls.some(call =>
    call.query.includes('UPDATE velzx_central_test.email_deliveries')
  ));
});

test('scheduleRetry menolak lease tidak aktif dan attempt aktif', async () => {
  for (const options of [
    { leaseActive: false },
    { active: true },
  ]) {
    const pool = createRetryPool(options);
    const repo = repository(pool);

    await assert.rejects(
      repo.scheduleRetry({
        requestId: 'request-1',
        nextAttemptAt: '2026-11-20T00:00:00.000Z',
      })
    );

    assert.ok(pool.calls.some(call => call.query === 'ROLLBACK'));
    assert.ok(!pool.calls.some(call =>
      call.query.includes('UPDATE velzx_central_test.email_deliveries')
    ));
  }
});

test('scheduleRetry mengizinkan nol attempt hanya dengan izin eksplisit', async () => {
  const pool = createRetryPool({ total: 0, allRetryable: false });
  const repo = repository(pool);

  const result = await repo.scheduleRetry({
    requestId: 'request-1',
    nextAttemptAt: '2026-11-20T00:00:00.000Z',
    allowNoAttempts: true,
    errorCode: 'ALL_KEYS_UNAVAILABLE',
  });

  assert.equal(result.state, 'WAITING_RETRY');
  assert.ok(pool.calls.some(call => call.query === 'COMMIT'));
});

test('scheduleRetry menolak nol attempt tanpa izin eksplisit', async () => {
  const pool = createRetryPool({ total: 0, allRetryable: false });
  const repo = repository(pool);

  await assert.rejects(
    repo.scheduleRetry({
      requestId: 'request-1',
      nextAttemptAt: '2026-11-20T00:00:00.000Z',
    }),
    /Riwayat attempt tidak aman/
  );

  assert.ok(pool.calls.some(call => call.query === 'ROLLBACK'));
});
