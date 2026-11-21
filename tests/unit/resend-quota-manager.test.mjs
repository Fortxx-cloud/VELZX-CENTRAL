import test from 'node:test';
import assert from 'node:assert/strict';

import {
  prepareResendKeys,
} from '../../src/services/email/resend-quota-manager.mjs';

function createRepository(states = []) {
  const writes = [];

  return {
    writes,
    async listKeyQuotaStates() {
      return states;
    },
    async setKeyQuotaState(args) {
      writes.push(args);
      return args;
    },
  };
}

const keys = [
  { number: 1, value: 'key-1' },
  { number: 2, value: 'key-2' },
  { number: 3, value: 'key-3' },
];

const availableUsage = {
  dailyUsed: 20,
  dailyLimit: 100,
  resetsAt: '2026-11-20T00:00:00.000Z',
  quotaExhausted: false,
};

test('memeriksa key berurutan dan mempertahankan key dengan kuota tersedia', async () => {
  const repository = createRepository();
  const checked = [];

  const result = await prepareResendKeys({
    keys,
    repository,
    usageCheck: async ({ apiKey }) => {
      checked.push(apiKey);
      return availableUsage;
    },
  });

  assert.deepEqual(checked, ['key-1', 'key-2', 'key-3']);
  assert.deepEqual(result.availableKeys, keys);
  assert.equal(repository.writes.length, 3);
  assert.ok(repository.writes.every(item => item.status === 'ACTIVE'));
});

test('melewati key dengan status INVALID_KEY dan DISABLED', async () => {
  const repository = createRepository([
    { key_number: 1, status: 'INVALID_KEY' },
    { key_number: 2, status: 'DISABLED' },
  ]);

  const checked = [];

  const result = await prepareResendKeys({
    keys,
    repository,
    usageCheck: async ({ apiKey }) => {
      checked.push(apiKey);
      return availableUsage;
    },
  });

  assert.deepEqual(checked, ['key-3']);
  assert.deepEqual(result.availableKeys, [keys[2]]);
  assert.equal(result.skipped.length, 2);
});

test('melewati key yang kuota hariannya belum reset', async () => {
  const repository = createRepository([
    {
      key_number: 1,
      status: 'QUOTA_EXHAUSTED',
      resets_at: '2026-11-20T00:00:00.000Z',
    },
  ]);

  const result = await prepareResendKeys({
    keys,
    repository,
    now: () => new Date('2026-11-19T13:00:00.000Z'),
    usageCheck: async () => availableUsage,
  });

  assert.deepEqual(result.availableKeys, [keys[1], keys[2]]);
  assert.equal(result.skipped[0].reason, 'QUOTA_EXHAUSTED');
});

test('melewati key selama cooldown masih aktif', async () => {
  const repository = createRepository([
    {
      key_number: 1,
      status: 'TEMPORARY_ERROR',
      cooldown_until: '2026-11-19T14:00:00.000Z',
    },
  ]);

  const result = await prepareResendKeys({
    keys,
    repository,
    now: () => new Date('2026-11-19T13:00:00.000Z'),
    usageCheck: async () => availableUsage,
  });

  assert.deepEqual(result.availableKeys, [keys[1], keys[2]]);
  assert.equal(result.skipped[0].reason, 'TEMPORARY_ERROR');
});

test('menandai kuota habis hanya berdasarkan Usage API', async () => {
  const repository = createRepository();

  const result = await prepareResendKeys({
    keys: [keys[0]],
    repository,
    usageCheck: async () => ({
      dailyUsed: 100,
      dailyLimit: 100,
      resetsAt: '2026-11-20T00:00:00.000Z',
      quotaExhausted: true,
    }),
  });

  assert.equal(result.availableKeys.length, 0);
  assert.equal(repository.writes[0].status, 'QUOTA_EXHAUSTED');
  assert.equal(repository.writes[0].resetsAt, '2026-11-20T00:00:00.000Z');
});

test('Usage API 401 menandai key INVALID_KEY', async () => {
  const repository = createRepository();

  const result = await prepareResendKeys({
    keys: [keys[0]],
    repository,
    usageCheck: async () => {
      throw Object.assign(new Error('invalid'), {
        code: 'INVALID_API_KEY',
      });
    },
  });

  assert.equal(result.availableKeys.length, 0);
  assert.equal(repository.writes[0].status, 'INVALID_KEY');
});

test('kegagalan Usage API tidak dianggap kuota habis', async () => {
  const repository = createRepository();

  const result = await prepareResendKeys({
    keys: [keys[0]],
    repository,
    usageCheck: async () => {
      throw Object.assign(new Error('permission denied'), {
        code: 'USAGE_PERMISSION_DENIED',
      });
    },
  });

  assert.deepEqual(result.availableKeys, [keys[0]]);
  assert.equal(repository.writes[0].status, 'UNVERIFIED');
});

test('Usage API network error tidak menonaktifkan key', async () => {
  const repository = createRepository();

  const result = await prepareResendKeys({
    keys: [keys[0]],
    repository,
    usageCheck: async () => {
      throw Object.assign(new Error('network'), {
        code: 'USAGE_NETWORK_ERROR',
      });
    },
  });

  assert.deepEqual(result.availableKeys, [keys[0]]);
  assert.equal(repository.writes[0].status, 'UNVERIFIED');
});
