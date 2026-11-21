import test from 'node:test';
import assert from 'node:assert/strict';

import {
  getResendUsage,
  ResendUsageError,
} from '../../src/services/email/resend-usage.mjs';

function response(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

const validUsage = {
  emails: {
    daily: {
      used: 50,
      limit: 100,
      resets_at: '2026-11-20T00:00:00.000Z',
    },
  },
};

test('membaca kuota harian yang masih tersedia', async () => {
  const result = await getResendUsage({
    apiKey: 'test-key',
    fetchImpl: async () => response(200, validUsage),
  });

  assert.equal(result.dailyUsed, 50);
  assert.equal(result.dailyLimit, 100);
  assert.equal(result.quotaExhausted, false);
});

test('mengidentifikasi kuota harian yang habis', async () => {
  const result = await getResendUsage({
    apiKey: 'test-key',
    fetchImpl: async () => response(200, {
      emails: {
        daily: {
          used: 100,
          limit: 100,
          resets_at: '2026-11-20T00:00:00.000Z',
        },
      },
    }),
  });

  assert.equal(result.quotaExhausted, true);
});

test('limit null berarti tidak ada batas harian', async () => {
  const result = await getResendUsage({
    apiKey: 'test-key',
    fetchImpl: async () => response(200, {
      emails: {
        daily: {
          used: 1000,
          limit: null,
          resets_at: '2026-11-20T00:00:00.000Z',
        },
      },
    }),
  });

  assert.equal(result.quotaExhausted, false);
});

test('menolak data Usage API yang tidak lengkap', async () => {
  await assert.rejects(
    getResendUsage({
      apiKey: 'test-key',
      fetchImpl: async () => response(200, { emails: {} }),
    }),
    error => error.code === 'USAGE_INVALID_RESPONSE',
  );
});

test('membedakan izin Usage API yang ditolak', async () => {
  await assert.rejects(
    getResendUsage({
      apiKey: 'test-key',
      fetchImpl: async () => response(403, {}),
    }),
    error => error.code === 'USAGE_PERMISSION_DENIED',
  );
});

test('membedakan key yang tidak valid', async () => {
  await assert.rejects(
    getResendUsage({
      apiKey: 'test-key',
      fetchImpl: async () => response(401, {}),
    }),
    error => error.code === 'INVALID_API_KEY',
  );
});

test('membedakan rate limit Usage API', async () => {
  await assert.rejects(
    getResendUsage({
      apiKey: 'test-key',
      fetchImpl: async () => response(429, {}),
    }),
    error => error.code === 'USAGE_RATE_LIMITED',
  );
});

test('tidak menganggap gangguan jaringan sebagai kuota habis', async () => {
  await assert.rejects(
    getResendUsage({
      apiKey: 'test-key',
      fetchImpl: async () => {
        throw new Error('network failure');
      },
    }),
    error => {
      assert.ok(error instanceof ResendUsageError);
      assert.equal(error.code, 'USAGE_NETWORK_ERROR');
      return true;
    },
  );
});
