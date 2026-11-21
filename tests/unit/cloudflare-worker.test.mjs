import test from 'node:test';
import assert from 'node:assert/strict';

import worker from '../../cloudflare/worker.js';

import {
  hashIngressBody,
  verifyIngressSignature,
} from '../../src/security/ingress-signature.mjs';

const SECRET = 'velzx-ingress-test-secret-32-bytes-minimum';
const ORIGIN = 'https://central.example';
const CLIENT_IP = '203.0.113.10';

async function invokeWorker(request, env, mockFetch) {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = mockFetch;

  try {
    return await worker.fetch(request, env);
  } finally {
    globalThis.fetch = originalFetch;
  }
}

function makeEnv(overrides = {}) {
  return {
    CENTRAL_ORIGIN: ORIGIN,
    CENTRAL_INGRESS_SECRET: SECRET,
    ...overrides,
  };
}

test('rejects HTTP origin', async () => {
  let called = false;

  const response = await invokeWorker(
    new Request('https://ingress.example/api/test', {
      headers: { 'CF-Connecting-IP': CLIENT_IP },
    }),
    makeEnv({ CENTRAL_ORIGIN: 'http://central.example' }),
    async () => {
      called = true;
      return new Response('unexpected');
    },
  );

  assert.equal(response.status, 503);
  assert.equal(called, false);
});

test('rejects ambiguous double-slash path', async () => {
  let called = false;

  const response = await invokeWorker(
    new Request('https://ingress.example//attacker.example/collect', {
      headers: { 'CF-Connecting-IP': CLIENT_IP },
    }),
    makeEnv(),
    async () => {
      called = true;
      return new Response('unexpected');
    },
  );

  assert.equal(response.status, 400);
  assert.equal(called, false);
});

test('overwrites spoofed ingress headers and signs exact forwarded body', async () => {
  const body = JSON.stringify({ ping: 'velzx' });
  const url = 'https://ingress.example/api/v1/models?b=2&a=1';

  let capturedUrl;
  let capturedInit;

  const response = await invokeWorker(
    new Request(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'CF-Connecting-IP': CLIENT_IP,
        'X-Velzx-Timestamp': '1111111111',
        'X-Velzx-Nonce': 'spoofed',
        'X-Velzx-Client-IP': '198.51.100.99',
        'X-Velzx-Body-SHA256': '0'.repeat(64),
        'X-Velzx-Signature': '0'.repeat(64),
        'X-Forwarded-For': '198.51.100.99',
      },
      body,
    }),
    makeEnv(),
    async (target, init) => {
      capturedUrl = target;
      capturedInit = init;
      return new Response('central-response', { status: 404 });
    },
  );

  assert.equal(response.status, 404);
  assert.equal(capturedUrl, `${ORIGIN}/api/v1/models?b=2&a=1`);
  assert.equal(Buffer.from(capturedInit.body).toString(), body);

  const headers = new Headers(capturedInit.headers);
  const timestamp = headers.get('X-Velzx-Timestamp');
  const nonce = headers.get('X-Velzx-Nonce');
  const bodyHash = headers.get('X-Velzx-Body-SHA256');
  const signature = headers.get('X-Velzx-Signature');

  assert.match(timestamp, /^\d{10}$/);
  assert.match(nonce, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(headers.get('X-Velzx-Client-IP'), CLIENT_IP);
  assert.equal(bodyHash, hashIngressBody(body));

  assert.notEqual(timestamp, '1111111111');
  assert.notEqual(nonce, 'spoofed');
  assert.notEqual(headers.get('X-Velzx-Signature'), '0'.repeat(64));

  assert.equal(headers.has('X-Forwarded-For'), false);

  const verified = verifyIngressSignature({
    secret: SECRET,
    signature,
    method: 'POST',
    pathname: '/api/v1/models',
    search: '?b=2&a=1',
    timestamp,
    nonce,
    bodyHash,
    clientIp: CLIENT_IP,
    nowSeconds: Number(timestamp),
  });

  assert.equal(verified, true);
});

test('forwards empty GET body with matching empty-body hash', async () => {
  let capturedInit;

  const response = await invokeWorker(
    new Request('https://ingress.example/api/empty', {
      method: 'GET',
      headers: { 'CF-Connecting-IP': CLIENT_IP },
    }),
    makeEnv(),
    async (_target, init) => {
      capturedInit = init;
      return new Response('ok');
    },
  );

  assert.equal(response.status, 200);
  assert.equal(capturedInit.body, undefined);

  const headers = new Headers(capturedInit.headers);
  assert.equal(headers.get('X-Velzx-Body-SHA256'), hashIngressBody(''));
});

test('rejects request body larger than 1 MiB', async () => {
  let called = false;

  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array(1024 * 1024));
      controller.enqueue(new Uint8Array(1));
      controller.close();
    },
  });

  const response = await invokeWorker(
    new Request('https://ingress.example/api/large', {
      method: 'POST',
      headers: { 'CF-Connecting-IP': CLIENT_IP },
      body: stream,
      duplex: 'half',
    }),
    makeEnv(),
    async () => {
      called = true;
      return new Response('unexpected');
    },
  );

  assert.equal(response.status, 413);
  assert.equal(called, false);
});

test('health endpoint forwards without ingress signature', async () => {
  let capturedUrl;
  let capturedInit;

  const response = await invokeWorker(
    new Request('https://ingress.example/health', {
      method: 'GET',
      headers: {
        'X-Velzx-Signature': 'spoofed',
        'X-Velzx-Nonce': 'spoofed',
      },
    }),
    makeEnv(),
    async (target, init) => {
      capturedUrl = target;
      capturedInit = init;
      return new Response('healthy', { status: 200 });
    },
  );

  assert.equal(response.status, 200);
  assert.equal(capturedUrl, `${ORIGIN}/health`);

  const headers = new Headers(capturedInit.headers);
  assert.equal(headers.has('X-Velzx-Signature'), false);
  assert.equal(headers.has('X-Velzx-Nonce'), false);
});

test('fails closed when Central origin is unavailable', async () => {
  const response = await invokeWorker(
    new Request('https://ingress.example/api/test', {
      headers: { 'CF-Connecting-IP': CLIENT_IP },
    }),
    makeEnv(),
    async () => {
      throw new Error('simulated network failure');
    },
  );

  assert.equal(response.status, 502);
});

test('preserves multiple Set-Cookie response headers', async () => {
  const response = await invokeWorker(
    new Request('https://ingress.example/api/cookies', {
      headers: { 'CF-Connecting-IP': CLIENT_IP },
    }),
    makeEnv(),
    async () => {
      const upstream = new Response('cookies', { status: 200 });
      upstream.headers.append('Set-Cookie', 'session=alpha; Path=/; HttpOnly');
      upstream.headers.append('Set-Cookie', 'csrf=beta; Path=/; Secure');
      return upstream;
    },
  );

  assert.equal(response.status, 200);
  assert.deepEqual(response.headers.getSetCookie(), [
    'session=alpha; Path=/; HttpOnly',
    'csrf=beta; Path=/; Secure',
  ]);
});

test('forwards redirects without following them automatically', async () => {
  for (const status of [301, 302, 307, 308]) {
    let capturedInit;

    const response = await invokeWorker(
      new Request('https://ingress.example/api/redirect', {
        headers: { 'CF-Connecting-IP': CLIENT_IP },
      }),
      makeEnv(),
      async (_target, init) => {
        capturedInit = init;
        return new Response(null, {
          status,
          headers: { Location: 'https://central.example/login' },
        });
      },
    );

    assert.equal(response.status, status);
    assert.equal(
      response.headers.get('Location'),
      'https://central.example/login',
    );
    assert.equal(capturedInit.redirect, 'manual');
  }
});

test('preserves HTTP methods and binary request bodies', async () => {
  const methods = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'];
  const binaryBody = new Uint8Array([0, 255, 1, 128, 42]);

  for (const method of methods) {
    let capturedInit;

    const request = new Request(
      `https://ingress.example/api/method/${method.toLowerCase()}`,
      {
        method,
        headers: { 'CF-Connecting-IP': CLIENT_IP },
        ...(method !== 'GET' && method !== 'HEAD'
          ? { body: binaryBody }
          : {}),
      },
    );

    const response = await invokeWorker(
      request,
      makeEnv(),
      async (_target, init) => {
        capturedInit = init;
        return new Response(null, { status: 204 });
      },
    );

    assert.equal(response.status, 204);
    assert.equal(capturedInit.method, method);

    if (method === 'GET' || method === 'HEAD') {
      assert.equal(capturedInit.body, undefined);
    } else {
      assert.deepEqual(
        new Uint8Array(capturedInit.body),
        binaryBody,
      );
    }
  }
});

test('preserves encoded path and query order in forwarding signature', async () => {
  const url =
    'https://ingress.example/api/%2Fencoded/%252e%252e/item?z=3&x=1';

  const request = new Request(url, {
    headers: { 'CF-Connecting-IP': CLIENT_IP },
  });

  const parsedUrl = new URL(request.url);
  let capturedUrl;
  let capturedInit;

  const response = await invokeWorker(
    request,
    makeEnv(),
    async (target, init) => {
      capturedUrl = target;
      capturedInit = init;
      return new Response('ok');
    },
  );

  assert.equal(response.status, 200);
  assert.equal(
    capturedUrl,
    `${ORIGIN}${parsedUrl.pathname}${parsedUrl.search}`,
  );

  const headers = new Headers(capturedInit.headers);
  const timestamp = headers.get('X-Velzx-Timestamp');

  assert.equal(
    verifyIngressSignature({
      secret: SECRET,
      signature: headers.get('X-Velzx-Signature'),
      method: 'GET',
      pathname: parsedUrl.pathname,
      search: parsedUrl.search,
      timestamp,
      nonce: headers.get('X-Velzx-Nonce'),
      bodyHash: hashIngressBody(''),
      clientIp: CLIENT_IP,
      nowSeconds: Number(timestamp),
    }),
    true,
  );
});

test('forwards the URL normalized by the request URL parser', async () => {
  const request = new Request(
    'https://ingress.example/api/a/../models?b=2&a=1',
    {
      headers: { 'CF-Connecting-IP': CLIENT_IP },
    },
  );

  const parsedUrl = new URL(request.url);

  assert.equal(parsedUrl.pathname, '/api/models');

  let capturedUrl;

  const response = await invokeWorker(
    request,
    makeEnv(),
    async (target) => {
      capturedUrl = target;
      return new Response('ok');
    },
  );

  assert.equal(response.status, 200);
  assert.equal(
    capturedUrl,
    `${ORIGIN}${parsedUrl.pathname}${parsedUrl.search}`,
  );
});
