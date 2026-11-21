const USAGE_ENDPOINT = 'https://api.resend.com/usage';
const REQUEST_TIMEOUT_MS = 10000;

export class ResendUsageError extends Error {
  constructor(message, { status = null, code = 'USAGE_CHECK_FAILED' } = {}) {
    super(message);
    this.name = 'ResendUsageError';
    this.status = status;
    this.code = code;
  }
}

export async function getResendUsage({
  apiKey,
  fetchImpl = globalThis.fetch,
}) {
  if (typeof apiKey !== 'string' || !apiKey.trim()) {
    throw new TypeError('Resend API key tidak valid');
  }

  if (typeof fetchImpl !== 'function') {
    throw new TypeError('Fetch implementation tidak tersedia');
  }

  let response;

  try {
    response = await fetchImpl(USAGE_ENDPOINT, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        Accept: 'application/json',
      },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch {
    throw new ResendUsageError('Gagal menghubungi Usage API', {
      code: 'USAGE_NETWORK_ERROR',
    });
  }

  let body;

  try {
    body = await response.json();
  } catch {
    throw new ResendUsageError('Respons Usage API tidak valid', {
      status: response.status,
      code: 'USAGE_INVALID_RESPONSE',
    });
  }

  if (!response.ok) {
    throw new ResendUsageError('Usage API menolak permintaan', {
      status: response.status,
      code: response.status === 401
        ? 'INVALID_API_KEY'
        : response.status === 403
          ? 'USAGE_PERMISSION_DENIED'
          : response.status === 429
            ? 'USAGE_RATE_LIMITED'
            : 'USAGE_PROVIDER_ERROR',
    });
  }

  const daily = body?.emails?.daily;

  if (
    !daily ||
    !Number.isSafeInteger(daily.used) ||
    daily.used < 0 ||
    !(
      daily.limit === null ||
      (
        Number.isSafeInteger(daily.limit) &&
        daily.limit >= 0
      )
    ) ||
    typeof daily.resets_at !== 'string' ||
    !Number.isFinite(Date.parse(daily.resets_at))
  ) {
    throw new ResendUsageError('Data kuota harian tidak lengkap', {
      code: 'USAGE_INVALID_RESPONSE',
    });
  }

  const resetsAt = new Date(daily.resets_at);

  return Object.freeze({
    dailyUsed: daily.used,
    dailyLimit: daily.limit,
    resetsAt: resetsAt.toISOString(),
    quotaExhausted:
      daily.limit !== null && daily.used >= daily.limit,
  });
}
