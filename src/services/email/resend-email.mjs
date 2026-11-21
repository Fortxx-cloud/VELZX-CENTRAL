import { createHash } from 'node:crypto';
import { getEmailConfig } from '../../config/email.mjs';
import { getResendUsage } from './resend-usage.mjs';
import { prepareResendKeys } from './resend-quota-manager.mjs';

const RESEND_ENDPOINT = 'https://api.resend.com/emails';
const REQUEST_TIMEOUT_MS = 15000;
const DEFAULT_COOLDOWN_SECONDS = 60;
const INVALID_KEYS_RETRY_SECONDS = 86400;

export class EmailDeliveryError extends Error {
  constructor(message, options = {}) {
    super(message);
    this.name = 'EmailDeliveryError';
    this.status = options.status ?? null;
    this.code = options.code ?? 'EMAIL_DELIVERY_FAILED';
    this.retryAfterSeconds = options.retryAfterSeconds ?? null;
  }
}

function parseRetryAfter(value) {
  if (!value) return DEFAULT_COOLDOWN_SECONDS;

  const seconds = Number(value);
  if (Number.isFinite(seconds) && seconds > 0) {
    return Math.ceil(seconds);
  }

  const date = Date.parse(value);
  if (Number.isFinite(date)) {
    return Math.max(1, Math.ceil((date - Date.now()) / 1000));
  }

  return DEFAULT_COOLDOWN_SECONDS;
}

function validateMessage({ to, subject, html, text }) {
  if (
    !(typeof to === 'string' && to.trim()) &&
    !(Array.isArray(to) && to.length > 0 &&
      to.every(item => typeof item === 'string' && item.trim()))
  ) {
    throw new TypeError('Penerima email tidak valid');
  }

  if (typeof subject !== 'string' || !subject.trim()) {
    throw new TypeError('Subject email wajib diisi');
  }

  if (
    !(typeof html === 'string' && html.length > 0) &&
    !(typeof text === 'string' && text.length > 0)
  ) {
    throw new TypeError('Konten HTML atau text wajib diisi');
  }
}

function validateDependencies({
  idempotencyKey,
  repository,
  fetchImpl,
  usageCheck,
}) {
  if (
    typeof idempotencyKey !== 'string' ||
    !idempotencyKey.trim() ||
    idempotencyKey.length > 256
  ) {
    throw new TypeError('Idempotency key wajib diisi dan valid');
  }

  const methods = [
    'claim',
    'beginAttempt',
    'finishAttempt',
    'scheduleRetry',
    'completeSuccess',
    'listKeyQuotaStates',
    'setKeyQuotaState',
  ];

  if (!repository || methods.some(name => typeof repository[name] !== 'function')) {
    throw new TypeError('Email delivery repository tidak valid');
  }

  if (typeof fetchImpl !== 'function') {
    throw new TypeError('Fetch implementation tidak tersedia');
  }

  if (typeof usageCheck !== 'function') {
    throw new TypeError('Usage API checker tidak valid');
  }
}

function createPayloadHash(payload) {
  return createHash('sha256')
    .update(JSON.stringify(payload))
    .digest('hex');
}

async function readResponse(response) {
  try {
    return await response.json();
  } catch {
    return {};
  }
}

async function markUnknown(repository, attemptId, status, code) {
  await repository.finishAttempt({
    attemptId,
    outcome: 'UNKNOWN',
    httpStatus: status,
    errorCode: code,
  });
}

function nextRetryTime(skipped, now = Date.now()) {
  const scheduled = skipped
    .filter(item =>
      item.reason === 'QUOTA_EXHAUSTED' ||
      item.reason === 'TEMPORARY_ERROR'
    )
    .map(item => item.retryAt ? Date.parse(item.retryAt) : NaN)
    .filter(value => Number.isFinite(value) && value > now);

  // Reset kuota/cooldown selalu mengikuti waktu provider.
  if (scheduled.length > 0) {
    return new Date(Math.min(...scheduled));
  }

  // INVALID_KEY dan DISABLED diperiksa ulang setiap 24 jam.
  // Statusnya tidak otomatis diaktifkan.
  const allRequireManualRepair =
    skipped.length > 0 &&
    skipped.every(item =>
      item.reason === 'INVALID_KEY' ||
      item.reason === 'DISABLED'
    );

  if (allRequireManualRepair) {
    return new Date(now + INVALID_KEYS_RETRY_SECONDS * 1000);
  }

  // Fallback sementara, bukan klaim bahwa kuota harian habis.
  return new Date(now + DEFAULT_COOLDOWN_SECONDS * 1000);
}

export async function sendEmail({
  to,
  subject,
  html,
  text,
  idempotencyKey,
  repository,
  fetchImpl = globalThis.fetch,
  usageCheck = getResendUsage,
  env = process.env,
}) {
  validateMessage({ to, subject, html, text });
  validateDependencies({
    idempotencyKey,
    repository,
    fetchImpl,
    usageCheck,
  });

  const config = getEmailConfig(env);
  const requestId = idempotencyKey;

  const logicalPayload = {
    to,
    subject,
    ...(html ? { html } : {}),
    ...(text ? { text } : {}),
  };

  const payloadHash = createPayloadHash(logicalPayload);
  const claim = await repository.claim({ requestId, payloadHash });

  if (claim.state !== 'CLAIMED' || claim.attemptAllowed !== true) {
    return {
      success: claim.state === 'SUCCESS',
      state: claim.state,
      requestId,
      providerEmailId: claim.providerEmailId ?? null,
      keyNumber: claim.successfulKeyNumber ?? null,
      nextAttemptAt: claim.nextAttemptAt ?? null,
      lastErrorCode: claim.lastErrorCode ?? null,
    };
  }

  const skipped = [];

  for (const key of config.keys) {
    // Pemeriksaan dilakukan per key, tepat sebelum pengiriman.
    const prepared = await prepareResendKeys({
      keys: [key],
      repository,
      usageCheck: args => usageCheck({
        ...args,
        fetchImpl,
      }),
    });

    skipped.push(...prepared.skipped);

    if (prepared.availableKeys.length === 0) {
      continue;
    }

    const attempt = await repository.beginAttempt({
      requestId,
      keyNumber: key.number,
    });

    let response;

    const body = {
      from: key.from,
      to,
      subject,
      ...(html ? { html } : {}),
      ...(text ? { text } : {}),
    };

    const providerPayloadHash = createPayloadHash(body);
    const providerIdempotencyKey = createHash('sha256')
      .update(`${requestId}:${key.number}:${providerPayloadHash}`)
      .digest('hex');

    try {
      response = await fetchImpl(RESEND_ENDPOINT, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${key.value}`,
          'Content-Type': 'application/json',
          'Idempotency-Key': providerIdempotencyKey,
        },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });

    } catch {
      await markUnknown(
        repository,
        attempt.attemptId,
        null,
        'EMAIL_NETWORK_ERROR',
      );

      throw new EmailDeliveryError(
        'Hasil pengiriman tidak diketahui akibat gangguan jaringan',
        { code: 'EMAIL_DELIVERY_UNKNOWN' },
      );
    }

    const result = await readResponse(response);

    if (response.ok) {
      if (typeof result.id !== 'string' || !result.id.trim()) {
        await markUnknown(
          repository,
          attempt.attemptId,
          response.status,
          'MISSING_PROVIDER_EMAIL_ID',
        );

        throw new EmailDeliveryError(
          'Provider menerima respons sukses tanpa ID email',
          {
            status: response.status,
            code: 'EMAIL_DELIVERY_UNKNOWN',
          },
        );
      }

      const completed = await repository.completeSuccess({
        requestId,
        attemptId: attempt.attemptId,
        keyNumber: key.number,
        providerEmailId: result.id,
      });

      return {
        success: true,
        state: completed.state,
        id: completed.providerEmailId,
        provider: 'resend',
        keyNumber: completed.successfulKeyNumber,
        requestId,
      };
    }

    if (response.status === 401) {
      await repository.finishAttempt({
        attemptId: attempt.attemptId,
        outcome: 'AUTH_REJECTED',
        httpStatus: 401,
        errorCode: 'INVALID_API_KEY',
      });

      await repository.setKeyQuotaState({
        keyNumber: key.number,
        status: 'INVALID_KEY',
        lastErrorCode: 'INVALID_API_KEY',
      });

      skipped.push({
        keyNumber: key.number,
        reason: 'INVALID_KEY',
      });

      continue;
    }

    if (response.status === 429) {
      const retryAfterSeconds = parseRetryAfter(
        response.headers.get('retry-after'),
      );

      const cooldownUntil = new Date(
        Date.now() + retryAfterSeconds * 1000,
      );

      await repository.finishAttempt({
        attemptId: attempt.attemptId,
        outcome: 'RETRYABLE_ERROR',
        httpStatus: 429,
        errorCode: 'RATE_LIMITED',
      });

      // 429 bukan bukti kuota harian habis.
      // Hanya error Usage API yang ditangkap di blok ini.
      let usage = null;
      let usageError = null;

      try {
        usage = await usageCheck({
          apiKey: key.value,
          fetchImpl,
        });
      } catch (error) {
        usageError = error;
      }

      if (usageError) {
        const invalidKey = usageError?.code === 'INVALID_API_KEY';

        await repository.setKeyQuotaState({
          keyNumber: key.number,
          status: invalidKey ? 'INVALID_KEY' : 'TEMPORARY_ERROR',
          cooldownUntil: invalidKey ? null : cooldownUntil,
          lastErrorCode: usageError?.code || 'USAGE_CHECK_FAILED',
        });

        skipped.push({
          keyNumber: key.number,
          reason: invalidKey ? 'INVALID_KEY' : 'TEMPORARY_ERROR',
          ...(invalidKey ? {} : { retryAt: cooldownUntil.toISOString() }),
        });
      } else if (usage.quotaExhausted) {
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
      } else {
        await repository.setKeyQuotaState({
          keyNumber: key.number,
          status: 'TEMPORARY_ERROR',
          cooldownUntil,
          lastErrorCode: 'RATE_LIMITED',
        });

        skipped.push({
          keyNumber: key.number,
          reason: 'TEMPORARY_ERROR',
          retryAt: cooldownUntil.toISOString(),
        });
      }

      continue;
    }

    if (response.status >= 500) {
      await markUnknown(
        repository,
        attempt.attemptId,
        response.status,
        'PROVIDER_SERVER_ERROR',
      );

      throw new EmailDeliveryError(
        'Hasil pengiriman tidak diketahui akibat gangguan provider',
        {
          status: response.status,
          code: 'EMAIL_DELIVERY_UNKNOWN',
        },
      );
    }

    await repository.finishAttempt({
      attemptId: attempt.attemptId,
      outcome: 'PROVIDER_REJECTED',
      httpStatus: response.status,
      errorCode: result.name || 'PROVIDER_REJECTED',
    });

    skipped.push({
      keyNumber: key.number,
      reason: 'PROVIDER_REJECTED',
    });

    continue;
  }

  const retryAt = nextRetryTime(skipped);

  await repository.scheduleRetry({
    requestId,
    nextAttemptAt: retryAt,
    errorCode: 'ALL_KEYS_UNAVAILABLE',
    allowNoAttempts: true,
  });

  const retryAfterSeconds = Math.max(
    1,
    Math.ceil((retryAt.getTime() - Date.now()) / 1000),
  );

  throw new EmailDeliveryError(
    'Seluruh API key Resend tidak tersedia. Delivery tetap PENDING dan retry dijadwalkan.',
    {
      code: 'ALL_KEYS_UNAVAILABLE',
      retryAfterSeconds,
    },
  );
}
