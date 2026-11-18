import test from 'node:test';
import assert from 'node:assert/strict';

import {
  createIngressSignature,
  hashIngressBody,
  verifyIngressSignature,
} from '../../src/security/ingress-signature.mjs';

const secret = 'test-only-secret-with-at-least-32-bytes';

const nowSeconds = Math.floor(Date.now() / 1000);

const request = {
  method: 'POST',
  pathname: '/api/test',
  search: '?source=unit',
  timestamp: String(nowSeconds),
  nonce: 'A'.repeat(43),
  bodyHash: hashIngressBody('{"test":true}'),
  clientIp: '203.0.113.10',
};

test('creates a valid HMAC signature', () => {
  const signature = createIngressSignature({
    secret,
    ...request,
  });

  assert.match(signature, /^[a-f0-9]{64}$/);
});

test('accepts a valid signature', () => {
  const signature = createIngressSignature({
    secret,
    ...request,
  });

  assert.equal(
    verifyIngressSignature({
      secret,
      signature,
      nowSeconds,
      ...request,
    }),
    true,
  );
});

test('rejects a modified HTTP method', () => {
  const signature = createIngressSignature({
    secret,
    ...request,
  });

  assert.equal(
    verifyIngressSignature({
      secret,
      signature,
      nowSeconds,
      ...request,
      method: 'GET',
    }),
    false,
  );
});

test('rejects a modified request body hash', () => {
  const signature = createIngressSignature({
    secret,
    ...request,
  });

  assert.equal(
    verifyIngressSignature({
      secret,
      signature,
      nowSeconds,
      ...request,
      bodyHash: hashIngressBody('{"test":false}'),
    }),
    false,
  );
});

test('rejects an incorrect secret', () => {
  const signature = createIngressSignature({
    secret,
    ...request,
  });

  assert.equal(
    verifyIngressSignature({
      secret: 'another-secret-with-at-least-32-bytes',
      signature,
      nowSeconds,
      ...request,
    }),
    false,
  );
});

test('rejects an expired timestamp', () => {
  const oldRequest = {
    ...request,
    timestamp: String(nowSeconds - 120),
  };

  const signature = createIngressSignature({
    secret,
    ...oldRequest,
  });

  assert.equal(
    verifyIngressSignature({
      secret,
      signature,
      nowSeconds,
      ...oldRequest,
    }),
    false,
  );
});

test('rejects a future timestamp outside the allowed window', () => {
  const futureRequest = {
    ...request,
    timestamp: String(nowSeconds + 120),
  };

  const signature = createIngressSignature({
    secret,
    ...futureRequest,
  });

  assert.equal(
    verifyIngressSignature({
      secret,
      signature,
      nowSeconds,
      ...futureRequest,
    }),
    false,
  );
});

test('rejects malformed signatures', () => {
  assert.equal(
    verifyIngressSignature({
      secret,
      signature: 'invalid',
      nowSeconds,
      ...request,
    }),
    false,
  );
});

test('rejects malformed nonces', () => {
  assert.equal(
    verifyIngressSignature({
      secret,
      signature: 'a'.repeat(64),
      nowSeconds,
      ...request,
      nonce: 'invalid',
    }),
    false,
  );
});

test('rejects a missing or weak secret', () => {
  assert.throws(
    () => createIngressSignature({
      secret: 'weak',
      ...request,
    }),
    /at least 32 bytes/,
  );
});

test('hashes empty request bodies deterministically', () => {
  assert.equal(
    hashIngressBody(''),
    hashIngressBody(Buffer.alloc(0)),
  );
});

test('hashes identical body bytes identically', () => {
  assert.equal(
    hashIngressBody('hello'),
    hashIngressBody(Buffer.from('hello')),
  );
});
