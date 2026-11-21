import test from 'node:test';
import assert from 'node:assert/strict';
import { createOAuthRouteHandler } from '../../src/http/routes/oauth-routes.mjs';

const STATE = 'A'.repeat(43);
const BINDING = 'B'.repeat(43);
const SESSION = 'C'.repeat(43);

function createResponse() {
  const headers = {};
  return {
    headers,
    status: null,
    body: '',
    headersSent: false,
    destroyed: false,
    writeHead(status, values = {}) {
      this.status = status;
      Object.assign(headers, values);
      this.headersSent = true;
    },
    setHeader(name, value) {
      headers[name] = value;
    },
    getHeader(name) {
      return headers[name];
    },
    end(body = '') {
      this.body = body;
    },
  };
}

function createService(overrides = {}) {
  const calls = [];

  const service = {
    async startLogin(args) {
      calls.push(['startLogin', args]);
      return {
        provider: args.provider,
        authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
        state: STATE,
      };
    },
    async startLink(args) {
      calls.push(['startLink', args]);
      return {
        provider: args.provider,
        authorizationUrl: 'https://github.com/login/oauth/authorize',
        state: STATE,
      };
    },
    async completeCallback(args) {
      calls.push(['completeCallback', args]);
      return {
        authenticated: true,
        created: false,
        user: { id: 'user-1' },
        session: { token: SESSION },
      };
    },
    ...overrides,
  };

  return { service, calls };
}

test('login start fails closed when public origin is not configured', async () => {
  const { service, calls } = createService();
  const handler = createOAuthRouteHandler({ oauthService: service });
  const res = createResponse();

  await handler({
    method: 'GET',
    url: '/auth/oauth/google/start',
    headers: {},
  }, res);

  assert.equal(res.status, 503);
  assert.equal(JSON.parse(res.body).code, 'oauth_origin_not_configured');
  assert.equal(calls.length, 0);
});

test('login start creates state-specific binding cookie and redirects', async () => {
  const { service, calls } = createService();
  const handler = createOAuthRouteHandler({ oauthService: service, publicOrigin: 'https://central.example' });
  const res = createResponse();

  const handled = await handler({
    method: 'GET',
    url: '/auth/oauth/google/start',
    headers: {},
  }, res);

  assert.equal(handled, true);
  assert.equal(res.status, 302);
  assert.equal(res.headers.Location, 'https://accounts.google.com/o/oauth2/v2/auth');

  const cookie = res.headers['Set-Cookie'][0];
  assert.match(cookie, new RegExp(`__Host-velzx_oauth_${STATE}=${BINDING.slice(0, 0)}`));
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /Secure/);
  assert.match(cookie, /SameSite=Lax/);
  assert.equal(calls[0][0], 'startLogin');
  assert.equal(calls[0][1].provider, 'google');
  assert.match(calls[0][1].browserBinding, /^[A-Za-z0-9_-]{43}$/);
});

test('callback fails closed when public origin is not configured', async () => {
  const { service, calls } = createService();
  const handler = createOAuthRouteHandler({ oauthService: service });
  const res = createResponse();

  await handler({
    method: 'GET',
    url: `/auth/oauth/google/callback?code=auth-code&state=${STATE}`,
    headers: {
      cookie: `__Host-velzx_oauth_${STATE}=${BINDING}`,
    },
  }, res, { clientIp: '203.0.113.10' });

  assert.equal(res.status, 503);
  assert.equal(JSON.parse(res.body).code, 'oauth_origin_not_configured');
  assert.equal(calls.length, 0);
});

test('callback completes login and creates session cookie', async () => {
  const { service, calls } = createService();
  const handler = createOAuthRouteHandler({ oauthService: service, publicOrigin: 'https://central.example' });
  const res = createResponse();

  await handler({
    method: 'GET',
    url: `/auth/oauth/google/callback?code=auth-code&state=${STATE}`,
    headers: {
      cookie: `__Host-velzx_oauth_${STATE}=${BINDING}`,
    },
  }, res, { clientIp: '203.0.113.10' });

  assert.equal(res.status, 200);
  assert.deepEqual(JSON.parse(res.body), {
    status: 'ok',
    authenticated: true,
    created: false,
  });

  const call = calls.find(([name]) => name === 'completeCallback');
  assert.ok(call);
  assert.equal(call[1].provider, 'google');
  assert.equal(call[1].state, STATE);
  assert.equal(call[1].browserBinding, BINDING);
  assert.equal(call[1].clientIp, '203.0.113.10');

  const cookies = res.headers['Set-Cookie'];
  assert.equal(cookies.length, 2);
  assert.match(cookies[0], new RegExp(`__Host-velzx_oauth_${STATE}=`));
  assert.match(cookies[0], /Max-Age=0/);
  assert.match(cookies[1], new RegExp(`__Host-velzx_session=${SESSION}`));
});

test('callback linking clears binding cookie without replacing session', async () => {
  const { service, calls } = createService({
    async completeCallback(args) {
      calls.push(['completeCallback', args]);
      return { linked: true, userId: 'user-1' };
    },
  });

  const handler = createOAuthRouteHandler({ oauthService: service, publicOrigin: 'https://central.example' });
  const res = createResponse();

  await handler({
    method: 'GET',
    url: `/auth/oauth/github/callback?code=auth-code&state=${STATE}`,
    headers: {
      cookie: `__Host-velzx_oauth_${STATE}=${BINDING}; __Host-velzx_session=${SESSION}`,
    },
  }, res);

  assert.equal(res.status, 200);
  assert.deepEqual(JSON.parse(res.body), {
    status: 'ok',
    linked: true,
  });

  const call = calls.find(([name]) => name === 'completeCallback');
  assert.equal(call[1].sessionToken, SESSION);
  assert.equal(res.headers['Set-Cookie'].length, 1);
  assert.match(res.headers['Set-Cookie'][0], /Max-Age=0/);
});

test('unknown provider is rejected', async () => {
  const { service } = createService();
  const handler = createOAuthRouteHandler({ oauthService: service });
  const res = createResponse();

  await handler({
    method: 'GET',
    url: '/auth/oauth/unknown/start',
    headers: {},
  }, res);

  assert.equal(res.status, 404);
  assert.equal(JSON.parse(res.body).code, 'unsupported_provider');
});

test('callback without valid state is rejected before service call', async () => {
  const { service, calls } = createService();
  const handler = createOAuthRouteHandler({ oauthService: service });
  const res = createResponse();

  await handler({
    method: 'GET',
    url: '/auth/oauth/google/callback?code=auth-code&state=bad',
    headers: {},
  }, res);

  assert.equal(res.status, 400);
  assert.equal(calls.length, 0);
});

test('callback without browser binding is rejected', async () => {
  const { service, calls } = createService();
  const handler = createOAuthRouteHandler({ oauthService: service });
  const res = createResponse();

  await handler({
    method: 'GET',
    url: `/auth/oauth/google/callback?code=auth-code&state=${STATE}`,
    headers: {},
  }, res);

  assert.equal(res.status, 400);
  assert.equal(calls.length, 0);
});

test('link start fails closed when public origin is not configured', async () => {
  const { service, calls } = createService();
  const handler = createOAuthRouteHandler({ oauthService: service });
  const res = createResponse();

  await handler({
    method: 'POST',
    url: '/auth/oauth/google/link/start',
    headers: {
      cookie: `__Host-velzx_session=${SESSION}`,
      origin: 'https://central.example',
    },
  }, res);

  assert.equal(res.status, 503);
  assert.equal(calls.length, 0);
});

test('link start rejects mismatched origin', async () => {
  const { service, calls } = createService();
  const handler = createOAuthRouteHandler({
    oauthService: service,
    publicOrigin: 'https://central.example',
  });
  const res = createResponse();

  await handler({
    method: 'POST',
    url: '/auth/oauth/github/link/start',
    headers: {
      cookie: `__Host-velzx_session=${SESSION}`,
      origin: 'https://attacker.example',
    },
  }, res);

  assert.equal(res.status, 403);
  assert.equal(calls.length, 0);
});

test('link start accepts matching origin and active session token', async () => {
  const { service, calls } = createService();
  const handler = createOAuthRouteHandler({
    oauthService: service,
    publicOrigin: 'https://central.example',
  });
  const res = createResponse();

  await handler({
    method: 'POST',
    url: '/auth/oauth/github/link/start',
    headers: {
      cookie: `__Host-velzx_session=${SESSION}`,
      origin: 'https://central.example',
    },
  }, res);

  assert.equal(res.status, 302);
  assert.equal(res.headers.Location, 'https://github.com/login/oauth/authorize');

  const call = calls.find(([name]) => name === 'startLink');
  assert.ok(call);
  assert.equal(call[1].provider, 'github');
  assert.equal(call[1].sessionToken, SESSION);
  assert.match(call[1].browserBinding, /^[A-Za-z0-9_-]{43}$/);
});

test('unmatched route is not handled', async () => {
  const { service } = createService();
  const handler = createOAuthRouteHandler({ oauthService: service });
  const res = createResponse();

  const handled = await handler({
    method: 'GET',
    url: '/health',
    headers: {},
  }, res);

  assert.equal(handled, false);
  assert.equal(res.status, null);
});


test('rejects authorization URL from an untrusted host', async () => {
  const { service } = createService({
    async startLogin() {
      return {
        provider: 'google',
        authorizationUrl: 'https://attacker.example/o/oauth2/v2/auth',
        state: STATE,
      };
    },
  });

  const handler = createOAuthRouteHandler({ oauthService: service, publicOrigin: 'https://central.example' });
  const res = createResponse();

  await handler({
    method: 'GET',
    url: '/auth/oauth/google/start',
    headers: {},
  }, res);

  assert.equal(res.status, 400);
  assert.equal(res.headers.Location, undefined);
  assert.equal(res.headers['Set-Cookie'], undefined);
  assert.equal(JSON.parse(res.body).code, 'oauth_failed');
});

test('rejects authorization URL with an unexpected provider path', async () => {
  const { service } = createService({
    async startLogin() {
      return {
        provider: 'github',
        authorizationUrl: 'https://github.com/attacker/authorize',
        state: STATE,
      };
    },
  });

  const handler = createOAuthRouteHandler({ oauthService: service, publicOrigin: 'https://central.example' });
  const res = createResponse();

  await handler({
    method: 'GET',
    url: '/auth/oauth/github/start',
    headers: {},
  }, res);

  assert.equal(res.status, 400);
  assert.equal(res.headers.Location, undefined);
  assert.equal(res.headers['Set-Cookie'], undefined);
});

test('accepts Microsoft authorization URL with supported tenant', async () => {
  const { service } = createService({
    async startLogin() {
      return {
        provider: 'microsoft',
        authorizationUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=test',
        state: STATE,
      };
    },
  });

  const handler = createOAuthRouteHandler({ oauthService: service, publicOrigin: 'https://central.example' });
  const res = createResponse();

  await handler({
    method: 'GET',
    url: '/auth/oauth/microsoft/start',
    headers: {},
  }, res);

  assert.equal(res.status, 302);
  assert.equal(
    res.headers.Location,
    'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=test',
  );
});

test('rejects invalid public origins at handler construction', () => {
  const { service } = createService();

  const invalidOrigins = [
    'http://central.example',
    'https://user:pass@central.example',
    'https://central.example/path',
    'https://central.example?query=1',
    'https://central.example#fragment',
    'not-a-valid-url',
  ];

  for (const publicOrigin of invalidOrigins) {
    assert.throws(
      () => createOAuthRouteHandler({ oauthService: service, publicOrigin }),
      TypeError,
      `Origin seharusnya ditolak: ${publicOrigin}`,
    );
  }
});
