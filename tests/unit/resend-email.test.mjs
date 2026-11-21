import test from 'node:test';
import assert from 'node:assert/strict';

import {
  sendEmail,
  EmailDeliveryError,
} from '../../src/services/email/resend-email.mjs';

function createEnv(prefix, keyCount = 9) {
  const env = {
    APP_ORIGIN: 'http://node18.botkeep.cloud:61909',
  };

  for (let i = 1; i <= keyCount; i++) {
    env[`RESEN_API_KEY${i}`] = `${prefix}-key-${i}`;
    env[`RESEN_EMAIL_FROM${i}`] = `VELZX AI Key ${i} <sender${i}@resend.dev>`;
  }

  return env;
}

function response(status, body = {}, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...headers,
    },
  });
}

const message = {
  to: 'test@example.com',
  subject: 'VELZX AI test',
  html: '<p>Test email</p>',
};

const availableUsage = {
  dailyUsed: 20,
  dailyLimit: 100,
  resetsAt: new Date(Date.now() + 86400000).toISOString(),
  quotaExhausted: false,
};

const requestId = 'velzx-email-test-001';

function createRepository(overrides = {}) {
  const calls = {
    claims: [],
    begins: [],
    finishes: [],
    schedules: [],
    successes: [],
    quotaReads: [],
    quotaWrites: [],
  };

  let nextAttemptId = 1;

  const repository = {
    async claim(args) {
      calls.claims.push(args);
      return overrides.claim
        ? overrides.claim(args)
        : {
            state: 'CLAIMED',
            requestId: args.requestId,
            attemptAllowed: true,
          };
    },

    async beginAttempt(args) {
      calls.begins.push(args);
      return {
        attemptId: nextAttemptId++,
        requestId: args.requestId,
        keyNumber: args.keyNumber,
      };
    },

    async finishAttempt(args) {
      calls.finishes.push(args);
      return { requestId, outcome: args.outcome };
    },

    async scheduleRetry(args) {
      calls.schedules.push(args);
      return { state: 'WAITING_RETRY' };
    },

    async completeSuccess(args) {
      calls.successes.push(args);
      return {
        state: 'SUCCESS',
        requestId: args.requestId,
        successfulKeyNumber: args.keyNumber,
        providerEmailId: args.providerEmailId,
      };
    },

    async listKeyQuotaStates() {
      calls.quotaReads.push(true);
      return overrides.quotaStates ?? [];
    },

    async setKeyQuotaState(args) {
      calls.quotaWrites.push(args);
      if (overrides.setKeyQuotaState) {
        return overrides.setKeyQuotaState(args);
      }
      return args;
    },
  };

  return { repository, calls };
}

async function send(options) {
  return sendEmail({
    usageCheck: async () => availableUsage,
    ...options,
  });
}

test('setiap API key wajib memiliki sender address pasangannya', async () => {
  const { repository } = createRepository();
  const env = createEnv('missing-sender');
  delete env.RESEN_EMAIL_FROM4;

  await assert.rejects(
    send({
      ...message,
      idempotencyKey: requestId,
      repository,
      env,
    }),
    /RESEN_EMAIL_FROM4 wajib dikonfigurasi/,
  );
});

test('idempotency key dan repository wajib tersedia', async () => {
  const { repository } = createRepository();

  await assert.rejects(
    send({
      ...message,
      repository,
      env: createEnv('required'),
    }),
    error => error instanceof TypeError,
  );

  await assert.rejects(
    send({
      ...message,
      idempotencyKey: requestId,
      env: createEnv('required'),
    }),
    error => error instanceof TypeError,
  );
});

test('menggunakan key 1 dan menyelesaikan delivery melalui ledger', async () => {
  const { repository, calls } = createRepository();
  const fetchCalls = [];

  const result = await send({
    ...message,
    idempotencyKey: requestId,
    repository,
    env: createEnv('primary'),
    fetchImpl: async (url, options) => {
      fetchCalls.push({ url, options });
      return response(200, { id: 'email-primary' });
    },
  });

  assert.equal(result.success, true);
  assert.equal(result.state, 'SUCCESS');
  assert.equal(result.keyNumber, 1);
  assert.equal(result.id, 'email-primary');
  assert.equal(calls.claims.length, 1);
  assert.equal(calls.claims[0].requestId, requestId);
  assert.match(calls.claims[0].payloadHash, /^[a-f0-9]{64}$/);
  assert.deepEqual(calls.begins.map(item => item.keyNumber), [1]);
  assert.equal(calls.successes.length, 1);
  assert.equal(calls.successes[0].providerEmailId, 'email-primary');
  assert.equal(calls.finishes.length, 0);
  const primaryPayload = JSON.parse(fetchCalls[0].options.body);
  assert.equal(primaryPayload.from, 'VELZX AI Key 1 <sender1@resend.dev>');
  assert.match(
    fetchCalls[0].options.headers['Idempotency-Key'],
    /^[a-f0-9]{64}$/,
  );
  assert.notEqual(
    fetchCalls[0].options.headers['Idempotency-Key'],
    requestId,
  );
});

test('HTTP 401 dicatat dan failover ke key berikutnya', async () => {
  const { repository, calls } = createRepository();
  const fetchCalls = [];

  const result = await send({
    ...message,
    idempotencyKey: requestId,
    repository,
    env: createEnv('invalidkey'),
    fetchImpl: async (url, options) => {
      fetchCalls.push(options);
      if (fetchCalls.length === 1) {
        return response(401, { message: 'Invalid API key' });
      }
      return response(200, { id: 'email-after-401' });
    },
  });

  assert.equal(result.keyNumber, 2);
  assert.equal(fetchCalls.length, 2);

  const firstPayload = JSON.parse(fetchCalls[0].body);
  const secondPayload = JSON.parse(fetchCalls[1].body);
  assert.equal(firstPayload.from, 'VELZX AI Key 1 <sender1@resend.dev>');
  assert.equal(secondPayload.from, 'VELZX AI Key 2 <sender2@resend.dev>');
  assert.notEqual(
    fetchCalls[0].headers['Idempotency-Key'],
    fetchCalls[1].headers['Idempotency-Key'],
  );
  assert.equal(calls.finishes.length, 1);
  assert.equal(calls.finishes[0].outcome, 'AUTH_REJECTED');
  assert.equal(calls.begins.length, 2);
  assert.equal(calls.successes.length, 1);
  assert.ok(calls.quotaWrites.some(
    item => item.keyNumber === 1 && item.status === 'INVALID_KEY',
  ));
});

test('HTTP 503 menjadi UNKNOWN dan tidak failover', async () => {
  const { repository, calls } = createRepository();
  let fetchCount = 0;

  await assert.rejects(
    send({
      ...message,
      idempotencyKey: requestId,
      repository,
      env: createEnv('server-error'),
      fetchImpl: async () => {
        fetchCount++;
        return response(503, { message: 'Temporary outage' });
      },
    }),
    error => {
      assert.ok(error instanceof EmailDeliveryError);
      assert.equal(error.status, 503);
      assert.equal(error.code, 'EMAIL_DELIVERY_UNKNOWN');
      return true;
    },
  );

  assert.equal(fetchCount, 1);
  assert.equal(calls.finishes.length, 1);
  assert.equal(calls.finishes[0].outcome, 'UNKNOWN');
  assert.equal(calls.schedules.length, 0);
});

test('network error menjadi UNKNOWN dan tidak failover', async () => {
  const { repository, calls } = createRepository();
  let fetchCount = 0;

  await assert.rejects(
    send({
      ...message,
      idempotencyKey: requestId,
      repository,
      env: createEnv('network-error'),
      fetchImpl: async () => {
        fetchCount++;
        throw new Error('Connection reset');
      },
    }),
    error => error.code === 'EMAIL_DELIVERY_UNKNOWN',
  );

  assert.equal(fetchCount, 1);
  assert.equal(calls.finishes[0].outcome, 'UNKNOWN');
  assert.equal(calls.finishes[0].errorCode, 'EMAIL_NETWORK_ERROR');
  assert.equal(calls.schedules.length, 0);
});

test('HTTP 429 dengan kuota tersedia melakukan failover', async () => {
  const { repository, calls } = createRepository();
  let fetchCount = 0;
  let usageCount = 0;

  const result = await send({
    ...message,
    idempotencyKey: requestId,
    repository,
    env: createEnv('rate-limit'),
    usageCheck: async () => {
      usageCount++;
      return availableUsage;
    },
    fetchImpl: async () => {
      fetchCount++;
      if (fetchCount === 1) {
        return response(
          429,
          { message: 'Rate limited' },
          { 'retry-after': '30' },
        );
      }
      return response(200, { id: 'email-after-429' });
    },
  });

  assert.equal(result.success, true);
  assert.equal(result.keyNumber, 2);
  assert.equal(fetchCount, 2);
  assert.equal(usageCount, 3);
  assert.equal(calls.finishes[0].outcome, 'RETRYABLE_ERROR');
  assert.ok(calls.quotaWrites.some(
    item => item.keyNumber === 1 && item.status === 'TEMPORARY_ERROR',
  ));
  assert.equal(calls.schedules.length, 0);
});

test('HTTP 429 dengan kuota habis menyimpan resets_at lalu failover', async () => {
  const { repository, calls } = createRepository();
  const resetAt = new Date(Date.now() + 48 * 3600000).toISOString();
  let fetchCount = 0;
  let usageCount = 0;

  const result = await send({
    ...message,
    idempotencyKey: requestId,
    repository,
    env: createEnv('quota-exhausted'),
    usageCheck: async () => {
      usageCount++;
      if (usageCount === 2) {
        return {
          dailyUsed: 100,
          dailyLimit: 100,
          resetsAt: resetAt,
          quotaExhausted: true,
        };
      }
      return availableUsage;
    },
    fetchImpl: async () => {
      fetchCount++;
      if (fetchCount === 1) {
        return response(429, {}, { 'retry-after': '30' });
      }
      return response(200, { id: 'email-after-quota' });
    },
  });

  assert.equal(result.keyNumber, 2);
  assert.equal(fetchCount, 2);

  const quotaWrite = calls.quotaWrites.find(
    item => item.keyNumber === 1 && item.status === 'QUOTA_EXHAUSTED',
  );

  assert.ok(quotaWrite);
  assert.equal(quotaWrite.resetsAt, resetAt);
});

test('kegagalan database saat menyimpan status 429 diteruskan', async () => {
  const databaseError = new Error('Database write failed');
  const { repository, calls } = createRepository({
    setKeyQuotaState: async args => {
      if (args.status === 'QUOTA_EXHAUSTED') {
        throw databaseError;
      }
      return args;
    },
  });

  let usageCount = 0;
  let fetchCount = 0;

  await assert.rejects(
    send({
      ...message,
      idempotencyKey: requestId,
      repository,
      env: createEnv('database-failure'),
      usageCheck: async () => {
        usageCount++;
        if (usageCount === 2) {
          return {
            dailyUsed: 100,
            dailyLimit: 100,
            resetsAt: new Date(Date.now() + 48 * 3600000).toISOString(),
            quotaExhausted: true,
          };
        }
        return availableUsage;
      },
      fetchImpl: async () => {
        fetchCount++;
        return response(429, {}, { 'retry-after': '30' });
      },
    }),
    error => error === databaseError,
  );

  assert.equal(fetchCount, 1);
  assert.equal(calls.finishes[0].outcome, 'RETRYABLE_ERROR');
  assert.equal(calls.schedules.length, 0);
});

test('HTTP 403 dicatat dan failover ke seluruh key berikutnya', async () => {
  const { repository, calls } = createRepository();
  let fetchCount = 0;

  await assert.rejects(
    send({
      ...message,
      idempotencyKey: requestId,
      repository,
      env: createEnv('forbidden'),
      fetchImpl: async () => {
        fetchCount++;
        return response(403, { message: 'Domain not verified' });
      },
    }),
    error => error.code === 'ALL_KEYS_UNAVAILABLE',
  );

  assert.equal(fetchCount, 9);
  assert.equal(calls.finishes.length, 9);
  assert.ok(calls.finishes.every(item =>
    item.outcome === 'PROVIDER_REJECTED' && item.httpStatus === 403
  ));
  assert.equal(calls.schedules.length, 1);
});

test('respons sukses tanpa provider email ID menjadi UNKNOWN', async () => {
  const { repository, calls } = createRepository();

  await assert.rejects(
    send({
      ...message,
      idempotencyKey: requestId,
      repository,
      env: createEnv('missing-id'),
      fetchImpl: async () => response(200, {}),
    }),
    error => error.code === 'EMAIL_DELIVERY_UNKNOWN',
  );

  assert.equal(calls.finishes[0].outcome, 'UNKNOWN');
  assert.equal(calls.successes.length, 0);
  assert.equal(calls.schedules.length, 0);
});

test('delivery yang belum boleh dicoba tidak mengirim email lagi', async () => {
  const { repository, calls } = createRepository({
    claim: async () => ({
      state: 'WAITING_RETRY',
      requestId,
      attemptAllowed: false,
      nextAttemptAt: new Date(Date.now() + 60000),
    }),
  });

  let fetchCount = 0;

  const result = await send({
    ...message,
    idempotencyKey: requestId,
    repository,
    env: createEnv('waiting'),
    fetchImpl: async () => {
      fetchCount++;
      return response(200, { id: 'unexpected' });
    },
  });

  assert.equal(result.state, 'WAITING_RETRY');
  assert.equal(result.success, false);
  assert.equal(fetchCount, 0);
  assert.equal(calls.begins.length, 0);
});

test('semua key INVALID_KEY dijadwalkan ulang setelah 24 jam', async () => {
  const { repository, calls } = createRepository();
  let usageCount = 0;
  let fetchCount = 0;

  await assert.rejects(
    send({
      ...message,
      idempotencyKey: requestId,
      repository,
      env: createEnv('all-invalid'),
      usageCheck: async () => {
        usageCount++;
        throw Object.assign(new Error('Invalid key'), {
          code: 'INVALID_API_KEY',
        });
      },
      fetchImpl: async () => {
        fetchCount++;
        return response(200, {});
      },
    }),
    error => error.code === 'ALL_KEYS_UNAVAILABLE',
  );

  assert.equal(usageCount, 9);
  assert.equal(fetchCount, 0);
  assert.equal(calls.begins.length, 0);
  assert.equal(calls.schedules.length, 1);
  assert.equal(calls.schedules[0].allowNoAttempts, true);

  const delay = calls.schedules[0].nextAttemptAt.getTime() - Date.now();
  assert.ok(delay > 86390000 && delay <= 86400000);
});

test('semua key DISABLED dijadwalkan ulang setelah 24 jam', async () => {
  const states = Array.from({ length: 9 }, (_, index) => ({
    key_number: index + 1,
    status: 'DISABLED',
  }));

  const { repository, calls } = createRepository({ quotaStates: states });
  let usageCount = 0;
  let fetchCount = 0;

  await assert.rejects(
    send({
      ...message,
      idempotencyKey: requestId,
      repository,
      env: createEnv('all-disabled'),
      usageCheck: async () => {
        usageCount++;
        return availableUsage;
      },
      fetchImpl: async () => {
        fetchCount++;
        return response(200, {});
      },
    }),
    error => error.code === 'ALL_KEYS_UNAVAILABLE',
  );

  assert.equal(usageCount, 0);
  assert.equal(fetchCount, 0);
  assert.equal(calls.schedules.length, 1);

  const delay = calls.schedules[0].nextAttemptAt.getTime() - Date.now();
  assert.ok(delay > 86390000 && delay <= 86400000);
});

test('reset kuota 48 jam tidak dipercepat menjadi 24 jam', async () => {
  const resetAt = new Date(Date.now() + 48 * 3600000);
  const states = Array.from({ length: 9 }, (_, index) => ({
    key_number: index + 1,
    status: 'QUOTA_EXHAUSTED',
    resets_at: resetAt.toISOString(),
  }));

  const { repository, calls } = createRepository({ quotaStates: states });

  await assert.rejects(
    send({
      ...message,
      idempotencyKey: requestId,
      repository,
      env: createEnv('all-quota-exhausted'),
      fetchImpl: async () => response(200, {}),
    }),
    error => error.code === 'ALL_KEYS_UNAVAILABLE',
  );

  assert.equal(calls.begins.length, 0);
  assert.equal(calls.schedules.length, 1);

  const scheduled = calls.schedules[0].nextAttemptAt.getTime();
  assert.ok(Math.abs(scheduled - resetAt.getTime()) < 1000);
});
