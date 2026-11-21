import { getResendUsage } from './resend-usage.mjs';

const SKIP_STATUSES = new Set([
  'INVALID_KEY',
  'DISABLED',
]);

export async function prepareResendKeys({
  keys,
  repository,
  usageCheck = getResendUsage,
  now = () => new Date(),
}) {
  if (!Array.isArray(keys)) {
    throw new TypeError('Daftar Resend key tidak valid');
  }

  if (
    !repository ||
    typeof repository.listKeyQuotaStates !== 'function' ||
    typeof repository.setKeyQuotaState !== 'function'
  ) {
    throw new TypeError('Quota repository tidak valid');
  }

  if (typeof usageCheck !== 'function' || typeof now !== 'function') {
    throw new TypeError('Dependency quota manager tidak valid');
  }

  const states = await repository.listKeyQuotaStates();
  const stateByNumber = new Map(
    states.map(state => [Number(state.key_number), state])
  );

  const availableKeys = [];
  const skipped = [];

  for (const key of keys) {
    const state = stateByNumber.get(key.number);
    const currentTime = new Date(now()).getTime();

    if (SKIP_STATUSES.has(state?.status)) {
      skipped.push({
        keyNumber: key.number,
        reason: state.status,
      });
      continue;
    }

    if (state?.status === 'QUOTA_EXHAUSTED') {
      const resetTime = Date.parse(state.resets_at);

      if (!Number.isFinite(resetTime) || resetTime > currentTime) {
        skipped.push({
          keyNumber: key.number,
          reason: 'QUOTA_EXHAUSTED',
          retryAt: state.resets_at,
        });
        continue;
      }
    }

    if (state?.status === 'TEMPORARY_ERROR') {
      const cooldownTime = state.cooldown_until
        ? Date.parse(state.cooldown_until)
        : NaN;

      if (Number.isFinite(cooldownTime) && cooldownTime > currentTime) {
        skipped.push({
          keyNumber: key.number,
          reason: 'TEMPORARY_ERROR',
          retryAt: state.cooldown_until,
        });
        continue;
      }
    }

    let usage;

    try {
      usage = await usageCheck({ apiKey: key.value });
    } catch (error) {
      const invalidKey = error?.code === 'INVALID_API_KEY';

      // Persistensi database berada di luar catch Usage API.
      // Jika database gagal, error harus diteruskan dan pengiriman dihentikan.
      await repository.setKeyQuotaState({
        keyNumber: key.number,
        status: invalidKey ? 'INVALID_KEY' : 'UNVERIFIED',
        lastErrorCode: error?.code || 'USAGE_CHECK_FAILED',
      });

      if (invalidKey) {
        skipped.push({
          keyNumber: key.number,
          reason: 'INVALID_KEY',
        });
        continue;
      }

      // Kegagalan Usage API bukan bukti kuota habis.
      availableKeys.push(key);
      continue;
    }

    if (usage.quotaExhausted) {
      await repository.setKeyQuotaState({
        keyNumber: key.number,
        status: 'QUOTA_EXHAUSTED',
        dailyUsed: usage.dailyUsed,
        dailyLimit: usage.dailyLimit,
        resetsAt: usage.resetsAt,
        lastErrorCode: null,
      });

      skipped.push({
        keyNumber: key.number,
        reason: 'QUOTA_EXHAUSTED',
        retryAt: usage.resetsAt,
      });
      continue;
    }

    await repository.setKeyQuotaState({
      keyNumber: key.number,
      status: 'ACTIVE',
      dailyUsed: usage.dailyUsed,
      dailyLimit: usage.dailyLimit,
      resetsAt: usage.resetsAt,
      lastErrorCode: null,
    });

    availableKeys.push(key);
  }

  return {
    availableKeys,
    skipped,
  };
}
