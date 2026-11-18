import test from 'node:test';
import assert from 'node:assert/strict';

import { verifyTurnstile } from '../../src/security/turnstile.mjs';

const validOptions = {
  token: 'test-token',
  secret: 'test-secret',
};

function mockFetch(payload, status = 200) {
  return async (url, options) => {
    assert.equal(
      url,
      'https://challenges.cloudflare.com/turnstile/v0/siteverify',
    );
    assert.equal(options.method, 'POST');

    const body = JSON.parse(options.body);
    assert.equal(body.secret, 'test-secret');
    assert.equal(body.response, 'test-token');
    assert.ok(body.idempotency_key);

    return new Response(JSON.stringify(payload), {
      status,
      headers: { 'content-type': 'application/json' },
    });
  };
}

test('accepts a valid Turnstile token', async () => {
  const result = await verifyTurnstile({
    ...validOptions,
    expectedHostname: 'example.com',
    expectedAction: 'register',
    fetchImpl: mockFetch({
      success: true,
      hostname: 'example.com',
      action: 'register',
    }),
  });

  assert.equal(result.success, true);
  assert.equal(result.hostname, 'example.com');
  assert.equal(result.action, 'register');
});

test('rejects missing secret', async () => {
  const result = await verifyTurnstile({
    token: 'test-token',
    secret: '',
  });

  assert.equal(result.code, 'captcha_not_configured');
});

test('rejects missing or oversized token', async () => {
  const missing = await verifyTurnstile({
    ...validOptions,
    token: '',
  });

  const oversized = await verifyTurnstile({
    ...validOptions,
    token: 'x'.repeat(2049),
  });

  assert.equal(missing.code, 'invalid_captcha_token');
  assert.equal(oversized.code, 'invalid_captcha_token');
});

test('rejects invalid or reused token', async () => {
  const result = await verifyTurnstile({
    ...validOptions,
    fetchImpl: mockFetch({
      success: false,
      'error-codes': ['timeout-or-duplicate'],
    }),
  });

  assert.equal(result.success, false);
  assert.equal(result.code, 'captcha_rejected');
  assert.deepEqual(result.providerErrorCodes, [
    'timeout-or-duplicate',
  ]);
});

test('rejects hostname mismatch', async () => {
  const result = await verifyTurnstile({
    ...validOptions,
    expectedHostname: 'velzx.example',
    fetchImpl: mockFetch({
      success: true,
      hostname: 'other.example',
    }),
  });

  assert.equal(result.code, 'captcha_hostname_mismatch');
});

test('rejects action mismatch', async () => {
  const result = await verifyTurnstile({
    ...validOptions,
    expectedAction: 'register',
    fetchImpl: mockFetch({
      success: true,
      hostname: 'example.com',
      action: 'login',
    }),
  });

  assert.equal(result.code, 'captcha_action_mismatch');
});

test('fails closed when Cloudflare is unavailable', async () => {
  const result = await verifyTurnstile({
    ...validOptions,
    fetchImpl: async () => {
      throw new Error('network failure');
    },
  });

  assert.equal(result.success, false);
  assert.equal(result.code, 'verification_unavailable');
});

test('rejects malformed provider response', async () => {
  const result = await verifyTurnstile({
    ...validOptions,
    fetchImpl: async () =>
      new Response('not-json', { status: 200 }),
  });

  assert.equal(result.code, 'invalid_provider_response');
});

test('rejects HTTP error from provider', async () => {
  const result = await verifyTurnstile({
    ...validOptions,
    fetchImpl: mockFetch({}, 503),
  });

  assert.equal(result.code, 'verification_unavailable');
});
