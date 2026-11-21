import test from 'node:test';
import assert from 'node:assert/strict';

import {
  createAuthRouteHandler,
} from '../../src/http/routes/auth-routes.mjs';

const ORIGIN = 'https://central.example';
const TOKEN = 'A'.repeat(43);
const SESSION_ID = '11111111-1111-4111-8111-111111111111';
const OTHER_SESSION_ID = '22222222-2222-4222-8222-222222222222';
const USER_ID = '33333333-3333-4333-8333-333333333333';

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

    end(body = '') {
      this.body = body;
    },
  };
}

function createRepository(overrides = {}) {
  const calls = [];

  const active = {
    session: {
      id: SESSION_ID,
      userId: USER_ID,
      createdAt: new Date('2026-01-01T00:00:00Z'),
      expiresAt: new Date('2027-01-01T00:00:00Z'),
    },
    user: {
      id: USER_ID,
      email: 'user@example.test',
      accountStatus: 'active',
      emailVerified: true,
    },
  };

  const repository = {
    async findActiveSession(args) {
      calls.push(['findActiveSession', args]);
      return active;
    },

    async listActiveSessions(args) {
      calls.push(['listActiveSessions', args]);

      return [
        {
          id: SESSION_ID,
          createdAt: new Date('2026-01-01T00:00:00Z'),
          expiresAt: new Date('2027-01-01T00:00:00Z'),
        },
        {
          id: OTHER_SESSION_ID,
          createdAt: new Date('2026-02-01T00:00:00Z'),
          expiresAt: new Date('2027-02-01T00:00:00Z'),
        },
      ];
    },

    async revokeSession(args) {
      calls.push(['revokeSession', args]);
      return true;
    },

    async revokeSessionById(args) {
      calls.push(['revokeSessionById', args]);
      return true;
    },

    ...overrides,
  };

  return { repository, calls, active };
}

function createRequest({
  method = 'GET',
  url = '/api/v1/me',
  token = TOKEN,
  origin,
  cookie,
} = {}) {
  const headers = {};

  if (cookie !== undefined) {
    headers.cookie = cookie;
  } else if (token !== null) {
    headers.cookie = `__Host-velzx_session=${token}`;
  }

  if (origin !== undefined) headers.origin = origin;

  return { method, url, headers };
}

function createHandler(repository) {
  return createAuthRouteHandler({
    sessionRepository: repository,
    publicOrigin: ORIGIN,
  });
}

test('rejects invalid repository and public origin', () => {
  assert.throws(
    () => createAuthRouteHandler({
      sessionRepository: {},
      publicOrigin: ORIGIN,
    }),
    TypeError,
  );

  const { repository } = createRepository();

  for (const publicOrigin of [
    'http://central.example',
    'https://user:pass@central.example',
    'https://central.example/path',
    'https://central.example?x=1',
    'https://central.example#fragment',
    'not-a-url',
  ]) {
    assert.throws(
      () => createAuthRouteHandler({
        sessionRepository: repository,
        publicOrigin,
      }),
      TypeError,
    );
  }
});

test('GET /api/v1/me returns safe user identity', async () => {
  const { repository, calls } = createRepository();
  const handler = createHandler(repository);
  const res = createResponse();

  assert.equal(await handler(createRequest(), res), true);

  assert.equal(res.status, 200);
  assert.deepEqual(JSON.parse(res.body), {
    status: 'ok',
    user: {
      id: USER_ID,
      email: 'user@example.test',
      accountStatus: 'active',
      emailVerified: true,
    },
  });

  assert.deepEqual(calls[0], [
    'findActiveSession',
    { token: TOKEN },
  ]);
  assert.equal(res.headers['Cache-Control'], 'no-store');
  assert.equal(res.headers['X-Content-Type-Options'], 'nosniff');
});

test('GET /api/v1/me rejects missing, malformed and duplicate cookies', async () => {
  const { repository, calls } = createRepository();
  const handler = createHandler(repository);

  for (const cookie of [
    undefined,
    '__Host-velzx_session=invalid',
    `__Host-velzx_session=${TOKEN}; __Host-velzx_session=${TOKEN}`,
    '__Host-velzx_session',
  ]) {
    const res = createResponse();

    await handler(createRequest({
      token: null,
      cookie,
    }), res);

    assert.equal(res.status, 401);
  }

  assert.equal(calls.length, 0);
});

test('GET /api/v1/me rejects inactive or expired sessions', async () => {
  const { repository } = createRepository({
    async findActiveSession() {
      return null;
    },
  });

  const res = createResponse();

  await createHandler(repository)(createRequest(), res);

  assert.equal(res.status, 401);
});

test('GET /api/v1/auth/sessions returns safe session metadata', async () => {
  const { repository, calls } = createRepository();
  const res = createResponse();

  await createHandler(repository)(
    createRequest({ url: '/api/v1/auth/sessions' }),
    res,
  );

  const payload = JSON.parse(res.body);

  assert.equal(res.status, 200);
  assert.equal(payload.sessions.length, 2);
  assert.equal(payload.sessions[0].current, true);
  assert.equal(payload.sessions[1].current, false);
  assert.equal(payload.sessions[0].id, SESSION_ID);
  assert.equal(Object.hasOwn(payload.sessions[0], 'token'), false);

  assert.deepEqual(calls[1], [
    'listActiveSessions',
    { userId: USER_ID },
  ]);
});

test('logout rejects missing or mismatched Origin', async () => {
  const { repository, calls } = createRepository();
  const handler = createHandler(repository);

  for (const origin of [undefined, 'https://attacker.example']) {
    const res = createResponse();

    await handler(createRequest({
      method: 'POST',
      url: '/api/v1/auth/logout',
      origin,
    }), res);

    assert.equal(res.status, 403);
  }

  assert.equal(calls.length, 0);
});

test('logout revokes valid token and clears secure session cookie', async () => {
  const { repository, calls } = createRepository();
  const res = createResponse();

  await createHandler(repository)(
    createRequest({
      method: 'POST',
      url: '/api/v1/auth/logout',
      origin: ORIGIN,
    }),
    res,
  );

  assert.equal(res.status, 204);
  assert.deepEqual(calls, [
    ['revokeSession', { token: TOKEN }],
  ]);

  const cookie = res.headers['Set-Cookie'];

  assert.match(cookie, /^__Host-velzx_session=;/);
  assert.match(cookie, /Path=\//);
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /Secure/);
  assert.match(cookie, /SameSite=Lax/);
  assert.match(cookie, /Max-Age=0/);
  assert.doesNotMatch(cookie, /Domain=/i);
});

test('logout is idempotent for missing, malformed or duplicate cookie', async () => {
  const { repository, calls } = createRepository();
  const handler = createHandler(repository);

  for (const cookie of [
    undefined,
    '__Host-velzx_session=invalid',
    `__Host-velzx_session=${TOKEN}; __Host-velzx_session=${TOKEN}`,
  ]) {
    const res = createResponse();

    await handler(createRequest({
      method: 'POST',
      url: '/api/v1/auth/logout',
      token: null,
      cookie,
      origin: ORIGIN,
    }), res);

    assert.equal(res.status, 204);
    assert.match(res.headers['Set-Cookie'], /Max-Age=0/);
  }

  assert.equal(calls.length, 0);
});

test('logout propagates database errors', async () => {
  const { repository } = createRepository({
    async revokeSession() {
      throw new Error('database unavailable');
    },
  });

  await assert.rejects(
    () => createHandler(repository)(
      createRequest({
        method: 'POST',
        url: '/api/v1/auth/logout',
        origin: ORIGIN,
      }),
      createResponse(),
    ),
    /database unavailable/,
  );
});

test('DELETE session rejects missing or mismatched Origin', async () => {
  const { repository, calls } = createRepository();
  const handler = createHandler(repository);

  for (const origin of [undefined, 'https://attacker.example']) {
    const res = createResponse();

    await handler(createRequest({
      method: 'DELETE',
      url: `/api/v1/auth/sessions/${OTHER_SESSION_ID}`,
      origin,
    }), res);

    assert.equal(res.status, 403);
  }

  assert.equal(calls.length, 0);
});

test('DELETE current session revokes it and clears cookie', async () => {
  const { repository, calls } = createRepository();
  const res = createResponse();

  await createHandler(repository)(
    createRequest({
      method: 'DELETE',
      url: `/api/v1/auth/sessions/${SESSION_ID}`,
      origin: ORIGIN,
    }),
    res,
  );

  assert.equal(res.status, 204);
  assert.deepEqual(calls[1], [
    'revokeSessionById',
    { sessionId: SESSION_ID, userId: USER_ID },
  ]);
  assert.match(res.headers['Set-Cookie'], /Max-Age=0/);
});

test('DELETE another owned session does not clear current cookie', async () => {
  const { repository } = createRepository();
  const res = createResponse();

  await createHandler(repository)(
    createRequest({
      method: 'DELETE',
      url: `/api/v1/auth/sessions/${OTHER_SESSION_ID}`,
      origin: ORIGIN,
    }),
    res,
  );

  assert.equal(res.status, 204);
  assert.equal(res.headers['Set-Cookie'], undefined);
});

test('DELETE rejects unowned or nonexistent session', async () => {
  const { repository } = createRepository({
    async revokeSessionById() {
      return false;
    },
  });

  const res = createResponse();

  await createHandler(repository)(
    createRequest({
      method: 'DELETE',
      url: `/api/v1/auth/sessions/${OTHER_SESSION_ID}`,
      origin: ORIGIN,
    }),
    res,
  );

  assert.equal(res.status, 404);
});

test('DELETE rejects malformed session ID without repository mutation', async () => {
  const { repository, calls } = createRepository();
  const res = createResponse();

  await createHandler(repository)(
    createRequest({
      method: 'DELETE',
      url: '/api/v1/auth/sessions/not-a-uuid',
      origin: ORIGIN,
    }),
    res,
  );

  assert.equal(res.status, 404);
  assert.equal(
    calls.some(([name]) => name === 'revokeSessionById'),
    false,
  );
});

test('known route with wrong method returns 405', async () => {
  const { repository } = createRepository();
  const res = createResponse();

  await createHandler(repository)(
    createRequest({
      method: 'POST',
      url: '/api/v1/me',
      origin: ORIGIN,
    }),
    res,
  );

  assert.equal(res.status, 405);
});

test('unmatched route is not handled', async () => {
  const { repository } = createRepository();
  const res = createResponse();

  const handled = await createHandler(repository)(
    createRequest({ url: '/api/v1/unknown' }),
    res,
  );

  assert.equal(handled, false);
  assert.equal(res.status, null);
});
