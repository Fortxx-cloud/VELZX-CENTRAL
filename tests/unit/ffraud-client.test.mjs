import test from 'node:test';
import assert from 'node:assert/strict';

import {
  createFfraudClient,
} from '../../src/security/ip-intelligence/ffraud-client.mjs';

const TEST_IP = '80.82.77.33';

function providerData(overrides = {}) {
  return {
    success: true,
    ip: TEST_IP,
    vpn: false,
    proxy: false,
    tor: false,
    hosting: false,
    is_residential_proxy: false,
    confidence: 'high',
    data_completeness: 0.8,
    ...overrides,
  };
}

function mockFetch({
  status = 200,
  body = providerData(),
  text,
} = {}) {
  const calls = [];

  const fetchImpl = async (url, options) => {
    calls.push({ url, options });

    const raw = text !== undefined ? text : JSON.stringify(body);
    const bytes = new TextEncoder().encode(raw);

    return {
      status,
      ok: status >= 200 && status < 300,
      body: new ReadableStream({
        start(controller) {
          controller.enqueue(bytes);
          controller.close();
        },
      }),
    };
  };

  return { fetchImpl, calls };
}

test('valid high-confidence clean IP is allowed', async () => {
  const mock = mockFetch();
  const client = createFfraudClient({
    fetchImpl: mock.fetchImpl,
  });

  const result = await client.inspectIp({ ingressVerification: { accepted: true, clientIp: TEST_IP } });

  assert.equal(result.decision, 'allow');
  assert.equal(result.source, 'ffraud');
  assert.equal(result.confidence, 'high');
  assert.equal(result.dataCompleteness, 0.8);
  assert.equal(mock.calls.length, 1);
  assert.match(
    mock.calls[0].url,
    /^https:\/\/api\.ffraud\.com\/public\/ip\//,
  );
});

test('confirmed VPN signal is blocked', async () => {
  const mock = mockFetch({
    body: providerData({ vpn: true }),
  });

  const client = createFfraudClient({
    fetchImpl: mock.fetchImpl,
  });

  const result = await client.inspectIp({ ingressVerification: { accepted: true, clientIp: TEST_IP } });

  assert.equal(result.decision, 'block');
  assert.equal(
    result.reason,
    'confirmed_proxy_vpn_or_tor_signal',
  );
});

test('confirmed proxy signal is blocked', async () => {
  const mock = mockFetch({
    body: providerData({ proxy: true }),
  });

  const client = createFfraudClient({
    fetchImpl: mock.fetchImpl,
  });

  const result = await client.inspectIp({ ingressVerification: { accepted: true, clientIp: TEST_IP } });

  assert.equal(result.decision, 'block');
});

test('confirmed residential proxy is blocked', async () => {
  const mock = mockFetch({
    body: providerData({
      proxy: true,
      is_residential_proxy: true,
    }),
  });

  const client = createFfraudClient({
    fetchImpl: mock.fetchImpl,
  });

  const result = await client.inspectIp({ ingressVerification: { accepted: true, clientIp: TEST_IP } });

  assert.equal(result.decision, 'block');
  assert.equal(result.signals.is_residential_proxy, true);
});

test('datacenter or hosting alone is not blocked', async () => {
  const mock = mockFetch({
    body: providerData({
      hosting: true,
      connection_type: 'Data Center',
    }),
  });

  const client = createFfraudClient({
    fetchImpl: mock.fetchImpl,
  });

  const result = await client.inspectIp({ ingressVerification: { accepted: true, clientIp: TEST_IP } });

  assert.equal(result.decision, 'allow');
});

test('suspicious signal with low confidence requires challenge', async () => {
  const mock = mockFetch({
    body: providerData({
      proxy: true,
      confidence: 'medium',
    }),
  });

  const client = createFfraudClient({
    fetchImpl: mock.fetchImpl,
  });

  const result = await client.inspectIp({ ingressVerification: { accepted: true, clientIp: TEST_IP } });

  assert.equal(result.decision, 'challenge');
  assert.equal(
    result.reason,
    'suspicious_signal_without_sufficient_evidence',
  );
});

test('incomplete data requires challenge', async () => {
  const mock = mockFetch({
    body: providerData({
      proxy: true,
      data_completeness: 0.4,
    }),
  });

  const client = createFfraudClient({
    fetchImpl: mock.fetchImpl,
  });

  const result = await client.inspectIp({ ingressVerification: { accepted: true, clientIp: TEST_IP } });

  assert.equal(result.decision, 'challenge');
});

test('missing classification field requires challenge', async () => {
  const data = providerData();
  delete data.tor;

  const mock = mockFetch({ body: data });
  const client = createFfraudClient({
    fetchImpl: mock.fetchImpl,
  });

  const result = await client.inspectIp({ ingressVerification: { accepted: true, clientIp: TEST_IP } });

  assert.equal(result.decision, 'challenge');
  assert.equal(result.signals.tor, null);
});

test('HTTP 429 returns unavailable', async () => {
  const mock = mockFetch({ status: 429 });
  const client = createFfraudClient({
    fetchImpl: mock.fetchImpl,
  });

  const result = await client.inspectIp({ ingressVerification: { accepted: true, clientIp: TEST_IP } });

  assert.equal(result.decision, 'unavailable');
  assert.equal(result.reason, 'provider_rate_limited');
});

test('provider network error returns unavailable', async () => {
  const client = createFfraudClient({
    fetchImpl: async () => {
      throw new Error('simulated network failure');
    },
  });

  const result = await client.inspectIp({ ingressVerification: { accepted: true, clientIp: TEST_IP } });

  assert.equal(result.decision, 'unavailable');
  assert.equal(result.reason, 'provider_unreachable');
});

test('invalid JSON returns unavailable', async () => {
  const mock = mockFetch({ text: '<html>invalid</html>' });
  const client = createFfraudClient({
    fetchImpl: mock.fetchImpl,
  });

  const result = await client.inspectIp({ ingressVerification: { accepted: true, clientIp: TEST_IP } });

  assert.equal(result.decision, 'unavailable');
  assert.equal(result.reason, 'provider_invalid_json');
});

test('invalid IP is rejected before provider request', async () => {
  const mock = mockFetch();
  const client = createFfraudClient({
    fetchImpl: mock.fetchImpl,
  });

  await assert.rejects(
    client.inspectIp({ ingressVerification: { accepted: true, clientIp: 'not-an-ip' } }),
    /Alamat IP tidak valid/,
  );

  assert.equal(mock.calls.length, 0);
});

test('response larger than limit returns unavailable', async () => {
  const mock = mockFetch({
    text: 'x'.repeat(65 * 1024),
  });

  const client = createFfraudClient({
    fetchImpl: mock.fetchImpl,
  });

  const result = await client.inspectIp({ ingressVerification: { accepted: true, clientIp: TEST_IP } });

  assert.equal(result.decision, 'unavailable');
  assert.equal(result.reason, 'provider_response_too_large');
});

test('invalid timeout configuration is rejected', () => {
  assert.throws(
    () => createFfraudClient({ timeoutMs: 50 }),
    /timeout/,
  );
});


test('provider IP mismatch returns unavailable', async () => {
  const mock = mockFetch({
    body: providerData({ ip: '1.1.1.1' }),
  });
  const client = createFfraudClient({ fetchImpl: mock.fetchImpl });

  const result = await client.inspectIp({
    ingressVerification: { accepted: true, clientIp: TEST_IP },
  });

  assert.equal(result.decision, 'unavailable');
  assert.equal(result.reason, 'provider_ip_mismatch');
});

test('request refuses redirects', async () => {
  const mock = mockFetch();
  const client = createFfraudClient({ fetchImpl: mock.fetchImpl });

  await client.inspectIp({
    ingressVerification: { accepted: true, clientIp: TEST_IP },
  });

  assert.equal(mock.calls[0].options.redirect, 'error');
});

test('streaming response exceeding limit returns unavailable', async () => {
  const client = createFfraudClient({
    fetchImpl: async () => ({
      status: 200,
      ok: true,
      body: new ReadableStream({
        start(controller) {
          controller.enqueue(new Uint8Array(40 * 1024));
          controller.enqueue(new Uint8Array(30 * 1024));
          controller.close();
        },
      }),
    }),
  });

  const result = await client.inspectIp({
    ingressVerification: { accepted: true, clientIp: TEST_IP },
  });

  assert.equal(result.decision, 'unavailable');
  assert.equal(result.reason, 'provider_response_too_large');
});

test('equivalent IPv6 representations match', async () => {
  const mock = mockFetch({
    body: providerData({
      ip: '2001:0db8:0000:0000:0000:0000:0000:0001',
    }),
  });
  const client = createFfraudClient({ fetchImpl: mock.fetchImpl });

  const result = await client.inspectIp({
    ingressVerification: {
      accepted: true,
      clientIp: '2001:db8::1',
    },
  });

  assert.equal(result.decision, 'allow');
});
