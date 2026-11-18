import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import {
  createCentralServer,
} from '../../src/http/server.mjs';

import {
  createIngressSignature,
  hashIngressBody,
} from '../../src/security/ingress-signature.mjs';

const secret = 'local-test-ingress-secret-at-least-32-bytes';

function createPool({ fail = false } = {}) {
  const claimed = new Set();

  return {
    async query(sql, values) {
      if (fail) throw new Error('Database unavailable');

      const nonce = values[0];

      if (claimed.has(nonce)) {
        return { rows: [] };
      }

      claimed.add(nonce);
      return { rows: [{ nonce }] };
    },
  };
}

async function withServer(callback, options = {}) {
  const server = createCentralServer({
    pool: options.pool ?? createPool(),
    env: {
      CENTRAL_INGRESS_SECRET: secret,
    },
  });

  await new Promise((resolve) => {
    server.listen(0, '127.0.0.1', resolve);
  });

  const address = server.address();
  const origin = `http://127.0.0.1:${address.port}`;

  try {
    await callback(origin);
  } finally {
    await new Promise((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    });
  }
}

function signedHeaders({
  method = 'POST',
  path = '/api/test',
  body = Buffer.from('{"test":true}'),
  nonce = randomBytes(32).toString('base64url'),
} = {}) {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const clientIp = '203.0.113.10';
  const bodyHash = hashIngressBody(body);
  const parsed = new URL(path, 'http://central.invalid');

  const signature = createIngressSignature({
    secret,
    method,
    pathname: parsed.pathname,
    search: parsed.search,
    timestamp,
    nonce,
    bodyHash,
    clientIp,
  });

  return {
    nonce,
    body,
    headers: {
      'X-Velzx-Timestamp': timestamp,
      'X-Velzx-Nonce': nonce,
      'X-Velzx-Client-IP': clientIp,
      'X-Velzx-Body-SHA256': bodyHash,
      'X-Velzx-Signature': signature,
      'Content-Type': 'application/json',
    },
  };
}

test('GET /health remains public', async () => {
  await withServer(async (origin) => {
    const response = await fetch(`${origin}/health`);

    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), {
      status: 'ok',
      service: 'velzx-central',
    });
  });
});

test('unsigned API request is rejected', async () => {
  await withServer(async (origin) => {
    const response = await fetch(`${origin}/api/test`, {
      method: 'POST',
      body: '{}',
    });

    assert.equal(response.status, 401);
  });
});

test('valid signed request passes ingress verification', async () => {
  await withServer(async (origin) => {
    const signed = signedHeaders();

    const response = await fetch(`${origin}/api/test`, {
      method: 'POST',
      headers: signed.headers,
      body: signed.body,
    });

    // 404 berarti lolos ingress; route API belum dibuat.
    assert.equal(response.status, 404);
  });
});

test('replayed nonce is rejected', async () => {
  await withServer(async (origin) => {
    const signed = signedHeaders();

    const send = () => fetch(`${origin}/api/test`, {
      method: 'POST',
      headers: signed.headers,
      body: signed.body,
    });

    assert.equal((await send()).status, 404);
    assert.equal((await send()).status, 409);
  });
});

test('modified body is rejected', async () => {
  await withServer(async (origin) => {
    const signed = signedHeaders();

    const response = await fetch(`${origin}/api/test`, {
      method: 'POST',
      headers: signed.headers,
      body: '{"test":false}',
    });

    assert.equal(response.status, 401);
  });
});

test('database failure fails closed', async () => {
  await withServer(async (origin) => {
    const signed = signedHeaders();

    const response = await fetch(`${origin}/api/test`, {
      method: 'POST',
      headers: signed.headers,
      body: signed.body,
    });

    assert.equal(response.status, 503);
  }, { pool: createPool({ fail: true }) });
});

test('oversized request body is rejected', async () => {
  await withServer(async (origin) => {
    const body = Buffer.alloc(1024 * 1024 + 1, 65);

    const response = await fetch(`${origin}/api/test`, {
      method: 'POST',
      body,
    });

    assert.equal(response.status, 413);
    assert.equal(response.headers.get('connection'), 'close');
  });
});

test('missing ingress secret prevents server creation', () => {
  assert.throws(
    () => createCentralServer({
      pool: createPool(),
      env: {},
    }),
    /CENTRAL_INGRESS_SECRET/,
  );
});
