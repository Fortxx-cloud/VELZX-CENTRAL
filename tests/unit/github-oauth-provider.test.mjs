import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import {
  createGitHubOAuthProvider,
} from '../../src/auth/oauth/providers/github.mjs';

const CLIENT_ID = 'github-client-id';
const CLIENT_SECRET = 'github-client-secret';
const REDIRECT_URI = 'https://central.example.test/oauth/github/callback';

const STATE = 'S'.repeat(43);
const VERIFIER = 'V'.repeat(64);

function response(data, ok = true) {
  return {
    ok,
    status: ok ? 200 : 500,
    async json() {
      return data;
    },
  };
}

function createMockFetch({
  user = { id: 123456, login: 'test-user' },
  emails = [
    {
      email: 'secondary@example.org',
      primary: false,
      verified: true,
    },
    {
      email: 'primary@example.org',
      primary: true,
      verified: true,
    },
  ],
  scope = 'read:user,user:email',
  tokenType = 'bearer',
  accessToken = 'mock-github-access-token',
  failUrl = null,
} = {}) {
  const calls = [];

  const fetchImpl = async (url, options = {}) => {
    const target = String(url);
    calls.push({ url: target, options });

    if (target === 'https://github.com/login/oauth/access_token') {
      if (failUrl === 'token') return response({}, false);

      return response({
        access_token: accessToken,
        token_type: tokenType,
        scope,
      });
    }

    if (target === 'https://api.github.com/user') {
      if (failUrl === 'user') return response({}, false);
      return response(user);
    }

    if (target === 'https://api.github.com/user/emails?per_page=100') {
      if (failUrl === 'emails') return response({}, false);
      return response(emails);
    }

    throw new Error(`Unexpected URL: ${target}`);
  };

  return { fetchImpl, calls };
}

function createProvider(fetchImpl) {
  return createGitHubOAuthProvider({
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    redirectUri: REDIRECT_URI,
    fetchImpl,
  });
}

test('builds GitHub authorization URL with state and PKCE S256', async () => {
  const mock = createMockFetch();
  const provider = createProvider(mock.fetchImpl);

  const authorizationUrl = await provider.createAuthorizationUrl({
    state: STATE,
    pkceVerifier: VERIFIER,
  });

  const url = new URL(authorizationUrl);

  const expectedChallenge = createHash('sha256')
    .update(VERIFIER, 'utf8')
    .digest('base64url');

  assert.equal(
    url.origin + url.pathname,
    'https://github.com/login/oauth/authorize',
  );
  assert.equal(url.searchParams.get('client_id'), CLIENT_ID);
  assert.equal(url.searchParams.get('redirect_uri'), REDIRECT_URI);
  assert.equal(url.searchParams.get('response_type'), 'code');
  assert.equal(url.searchParams.get('scope'), 'read:user user:email');
  assert.equal(url.searchParams.get('state'), STATE);
  assert.equal(url.searchParams.get('code_challenge'), expectedChallenge);
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
});

test('exchanges code and selects verified primary email', async () => {
  const mock = createMockFetch();
  const provider = createProvider(mock.fetchImpl);

  const identity = await provider.exchangeAuthorizationCode({
    code: 'github-authorization-code',
    pkceVerifier: VERIFIER,
  });

  assert.deepEqual(identity, {
    provider: 'github',
    providerSubject: '123456',
    email: 'primary@example.org',
    emailVerified: true,
    providerEmailVerified: true,
    emailAuthority: 'github_verified_email',
    registrationEligible: true,
  });

  const tokenCall = mock.calls.find(
    (call) => call.url === 'https://github.com/login/oauth/access_token',
  );

  assert.ok(tokenCall);
  assert.equal(tokenCall.options.method, 'POST');

  const body = new URLSearchParams(tokenCall.options.body);
  assert.equal(body.get('client_id'), CLIENT_ID);
  assert.equal(body.get('client_secret'), CLIENT_SECRET);
  assert.equal(body.get('code'), 'github-authorization-code');
  assert.equal(body.get('code_verifier'), VERIFIER);
  assert.equal(body.get('redirect_uri'), REDIRECT_URI);

  const apiCall = mock.calls.find(
    (call) => call.url === 'https://api.github.com/user',
  );

  assert.equal(apiCall.options.headers.authorization, 'Bearer mock-github-access-token');
  assert.equal(apiCall.options.headers['x-github-api-version'], '2026-03-10');
});

test('falls back to another verified email when primary is unverified', async () => {
  const mock = createMockFetch({
    emails: [
      {
        email: 'primary@example.org',
        primary: true,
        verified: false,
      },
      {
        email: 'verified@example.org',
        primary: false,
        verified: true,
      },
    ],
  });

  const provider = createProvider(mock.fetchImpl);

  const identity = await provider.exchangeAuthorizationCode({
    code: 'github-authorization-code',
    pkceVerifier: VERIFIER,
  });

  assert.equal(identity.email, 'verified@example.org');
  assert.equal(identity.providerEmailVerified, true);
  assert.equal(identity.registrationEligible, true);
});

test('rejects registration when no verified email exists', async () => {
  const mock = createMockFetch({
    emails: [
      {
        email: 'unverified@example.org',
        primary: true,
        verified: false,
      },
    ],
  });

  const provider = createProvider(mock.fetchImpl);

  const identity = await provider.exchangeAuthorizationCode({
    code: 'github-authorization-code',
    pkceVerifier: VERIFIER,
  });

  assert.equal(identity.email, null);
  assert.equal(identity.emailVerified, false);
  assert.equal(identity.providerEmailVerified, false);
  assert.equal(identity.registrationEligible, false);
});

test('accepts token with user:email scope alone', async () => {
  const mock = createMockFetch({
    scope: 'user:email',
  });
  const provider = createProvider(mock.fetchImpl);

  const identity = await provider.exchangeAuthorizationCode({
    code: 'github-authorization-code',
    pkceVerifier: VERIFIER,
  });

  assert.equal(identity.provider, 'github');
  assert.equal(identity.providerEmailVerified, true);
  assert.equal(identity.registrationEligible, true);
});

test('rejects token without user:email scope', async () => {
  const mock = createMockFetch({
    scope: 'read:user',
  });

  const provider = createProvider(mock.fetchImpl);

  await assert.rejects(
    provider.exchangeAuthorizationCode({
      code: 'github-authorization-code',
      pkceVerifier: VERIFIER,
    }),
    /email permission tidak diberikan/,
  );
});

test('rejects malformed GitHub account ID', async () => {
  const mock = createMockFetch({
    user: { id: 'not-numeric' },
  });

  const provider = createProvider(mock.fetchImpl);

  await assert.rejects(
    provider.exchangeAuthorizationCode({
      code: 'github-authorization-code',
      pkceVerifier: VERIFIER,
    }),
    /account ID tidak valid/,
  );
});

test('rejects malformed token response', async () => {
  const mock = createMockFetch({
    tokenType: 'mac',
  });

  const provider = createProvider(mock.fetchImpl);

  await assert.rejects(
    provider.exchangeAuthorizationCode({
      code: 'github-authorization-code',
      pkceVerifier: VERIFIER,
    }),
    /token response tidak valid/,
  );
});

test('rejects GitHub API failure', async () => {
  const mock = createMockFetch({
    failUrl: 'emails',
  });

  const provider = createProvider(mock.fetchImpl);

  await assert.rejects(
    provider.exchangeAuthorizationCode({
      code: 'github-authorization-code',
      pkceVerifier: VERIFIER,
    }),
    /GitHub verified emails gagal/,
  );
});

test('rejects malformed state and PKCE verifier', async () => {
  const mock = createMockFetch();
  const provider = createProvider(mock.fetchImpl);

  await assert.rejects(
    provider.createAuthorizationUrl({
      state: 'invalid',
      pkceVerifier: VERIFIER,
    }),
    /OAuth state tidak valid/,
  );

  await assert.rejects(
    provider.createAuthorizationUrl({
      state: STATE,
      pkceVerifier: 'invalid',
    }),
    /PKCE verifier tidak valid/,
  );
});

test('rejects malformed provider configuration', () => {
  assert.throws(
    () => createGitHubOAuthProvider({
      clientId: '',
      clientSecret: CLIENT_SECRET,
      redirectUri: REDIRECT_URI,
    }),
    /Client ID tidak valid/,
  );

  assert.throws(
    () => createGitHubOAuthProvider({
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      redirectUri: 'http://central.example.test/callback',
    }),
    /harus menggunakan HTTPS/,
  );
});


test('accepts HTTP localhost and rejects non-HTTPS localhost redirect schemes', () => {
  assert.doesNotThrow(() => createGitHubOAuthProvider({
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    redirectUri: 'http://localhost:3000/oauth/github/callback',
  }));

  assert.throws(() => createGitHubOAuthProvider({
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    redirectUri: 'ftp://localhost/callback',
  }), /harus menggunakan HTTPS/);
});

test('applies redirect rejection and timeout signal to GitHub requests', async () => {
  const mock = createMockFetch();
  const provider = createProvider(mock.fetchImpl);

  await provider.exchangeAuthorizationCode({
    code: 'github-authorization-code',
    pkceVerifier: VERIFIER,
  });

  assert.equal(mock.calls.length, 3);
  for (const call of mock.calls) {
    assert.equal(call.options.redirect, 'error');
    assert.ok(call.options.signal instanceof AbortSignal);
  }
});

test('aborts a stalled GitHub provider request at configured timeout', async () => {
  const provider = createGitHubOAuthProvider({
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    redirectUri: REDIRECT_URI,
    timeoutMs: 5,
    fetchImpl: (_url, options) => new Promise((resolve, reject) => {
      options.signal.addEventListener(
        'abort',
        () => reject(options.signal.reason),
        { once: true },
      );
    }),
  });

  await assert.rejects(
    provider.exchangeAuthorizationCode({
      code: 'github-authorization-code',
      pkceVerifier: VERIFIER,
    }),
    /koneksi gagal/,
  );
});

test('rejects an invalid GitHub fetch timeout', () => {
  assert.throws(() => createGitHubOAuthProvider({
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    redirectUri: REDIRECT_URI,
    timeoutMs: 60_001,
  }), /Fetch timeout tidak valid/);
});
