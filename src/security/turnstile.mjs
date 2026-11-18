import { randomUUID } from 'node:crypto';

const SITEVERIFY_URL =
  'https://challenges.cloudflare.com/turnstile/v0/siteverify';

export async function verifyTurnstile({
  token,
  secret,
  expectedHostname,
  expectedAction,
  fetchImpl = globalThis.fetch,
  timeoutMs = 5000,
} = {}) {
  if (typeof secret !== 'string' || secret.trim() === '') {
    return { success: false, code: 'captcha_not_configured' };
  }

  if (
    typeof token !== 'string' ||
    token.trim() === '' ||
    token.length > 2048
  ) {
    return { success: false, code: 'invalid_captcha_token' };
  }

  if (typeof fetchImpl !== 'function') {
    return { success: false, code: 'verification_unavailable' };
  }

  let response;

  try {
    response = await fetchImpl(SITEVERIFY_URL, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        secret,
        response: token,
        idempotency_key: randomUUID(),
      }),
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch {
    return { success: false, code: 'verification_unavailable' };
  }

  if (!response.ok) {
    return { success: false, code: 'verification_unavailable' };
  }

  let result;

  try {
    result = await response.json();
  } catch {
    return { success: false, code: 'invalid_provider_response' };
  }

  if (!result || typeof result.success !== 'boolean') {
    return { success: false, code: 'invalid_provider_response' };
  }

  if (result.success !== true) {
    return {
      success: false,
      code: 'captcha_rejected',
      providerErrorCodes: Array.isArray(result['error-codes'])
        ? result['error-codes'].filter(
            (item) => typeof item === 'string',
          )
        : [],
    };
  }

  if (
    expectedHostname &&
    result.hostname !== expectedHostname
  ) {
    return { success: false, code: 'captcha_hostname_mismatch' };
  }

  if (
    expectedAction &&
    result.action !== expectedAction
  ) {
    return { success: false, code: 'captcha_action_mismatch' };
  }

  return {
    success: true,
    hostname: result.hostname ?? null,
    action: result.action ?? null,
  };
}
