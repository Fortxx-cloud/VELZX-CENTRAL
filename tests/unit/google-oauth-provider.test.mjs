import test from 'node:test';
import assert from 'node:assert/strict';
import {
  generateKeyPairSync,
} from 'node:crypto';

import {
  SignJWT,
} from 'jose';

import {
  createGoogleOAuthProvider,
} from '../../src/auth/oauth/providers/google.mjs';

const CLIENT_ID = 'google-client-id';
const CLIENT_SECRET = 'google-client-secret';
const REDIRECT_URI = 'https://central.example.test/oauth/google/callback';

const STATE = 'S'.repeat(43);
const NONCE = 'N'.repeat(43);
const VERIFIER = 'V'.repeat(64);

const ISSUER = 'https://accounts.google.com';
const KID = 'google-test-key';

const { publicKey, privateKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
});

const publicJwk = {
  ...publicKey.export({ format: 'jwk' }),
  kid: KID,
  use: 'sig',
  alg: 'RS256',
};

function response(data, ok = true) {
  return {
    ok,
    status: ok ? 200 : 500,
    async json() {
      return data;
    },
  };
}

async function createIdToken(overrides = {}, signingKey = privateKey) {
  const payload = {
    sub: 'google-subject-123',
    email: 'user@gmail.com',
    email_verified: true,
    nonce: NONCE,
    ...overrides,
  };

  return new SignJWT(payload)
    .setProtectedHeader({
      alg: 'RS256',
      kid: KID,
    })
    .setIssuer(ISSUER)
    .setAudience(CLIENT_ID)
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(signingKey);
}

function createMockFetch({ idToken, jwks = [publicJwk] }) {
  const calls = [];

  const fetchImpl = async (url, options = {}) => {
    const target = String(url);
    calls.push({ url: target, options });

    if (
      target ===
      'https://accounts.google.com/.well-known/openid-configuration'
    ) {
      return response({
        issuer: ISSUER,
        authorization_endpoint:
          'https://accounts.google.com/o/oauth2/v2/auth',
        token_endpoint: 'https://oauth2.googleapis.com/token',
        jwks_uri: 'https://www.googleapis.com/oauth2/v3/certs',
      });
    }

    if (target === 'https://oauth2.googleapis.com/token') {
      return response({
        access_token: 'mock-access-token',
        token_type: 'Bearer',
        id_token: idToken,
      });
    }

    if (target === 'https://www.googleapis.com/oauth2/v3/certs') {
      return response({ keys: jwks });
    }

    throw new Error(`Unexpected URL: ${target}`);
  };

  return { fetchImpl, calls };
}

function createProvider(fetchImpl) {
  return createGoogleOAuthProvider({
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    redirectUri: REDIRECT_URI,
    fetchImpl,
  });
}

test('builds Google authorization URL with state, nonce and PKCE S256', async () => {
  const mock = createMockFetch({ idToken: 'unused' });
  const provider = createProvider(mock.fetchImpl);

  const authorizationUrl = await provider.createAuthorizationUrl({
    state: STATE,
    nonce: NONCE,
    pkceVerifier: VERIFIER,
  });

  const url = new URL(authorizationUrl);

  assert.equal(
    url.origin + url.pathname,
    'https://accounts.google.com/o/oauth2/v2/auth',
  );
  assert.equal(url.searchParams.get('client_id'), CLIENT_ID);
  assert.equal(url.searchParams.get('redirect_uri'), REDIRECT_URI);
  assert.equal(url.searchParams.get('response_type'), 'code');
  assert.equal(url.searchParams.get('scope'), 'openid email profile');
  assert.equal(url.searchParams.get('state'), STATE);
  assert.equal(url.searchParams.get('nonce'), NONCE);
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  assert.match(
    url.searchParams.get('code_challenge'),
    /^[A-Za-z0-9_-]{43}$/,
  );
});

test('exchanges authorization code and accepts verified Gmail registration', async () => {
  const idToken = await createIdToken();
  const mock = createMockFetch({ idToken });
  const provider = createProvider(mock.fetchImpl);

  const identity = await provider.exchangeAuthorizationCode({
    code: 'authorization-code',
    pkceVerifier: VERIFIER,
    nonce: NONCE,
  });

  assert.equal(identity.provider, 'google');
  assert.equal(identity.providerSubject, 'google-subject-123');
  assert.equal(identity.email, 'user@gmail.com');
  assert.equal(identity.emailVerified, true);
  assert.equal(identity.providerEmailVerified, true);
  assert.equal(identity.emailAuthority, 'gmail');
  assert.equal(identity.registrationEligible, true);

  const tokenCall = mock.calls.find(
    (call) => call.url === 'https://oauth2.googleapis.com/token',
  );

  assert.ok(tokenCall);
  assert.equal(tokenCall.options.method, 'POST');

  const body = new URLSearchParams(tokenCall.options.body);
  assert.equal(body.get('code'), 'authorization-code');
  assert.equal(body.get('code_verifier'), VERIFIER);
  assert.equal(body.get('client_id'), CLIENT_ID);
  assert.equal(body.get('client_secret'), CLIENT_SECRET);
  assert.equal(body.get('redirect_uri'), REDIRECT_URI);
});

test('accepts verified Google Workspace email when hd matches email domain', async () => {
  const idToken = await createIdToken({
    email: 'admin@example.org',
    hd: 'example.org',
  });

  const mock = createMockFetch({ idToken });
  const provider = createProvider(mock.fetchImpl);

  const identity = await provider.exchangeAuthorizationCode({
    code: 'authorization-code',
    pkceVerifier: VERIFIER,
    nonce: NONCE,
  });

  assert.equal(identity.emailAuthority, 'workspace');
  assert.equal(identity.hostedDomain, 'example.org');
  assert.equal(identity.registrationEligible, true);
});

test('does not allow third-party verified email for new registration', async () => {
  const idToken = await createIdToken({
    email: 'user@external.example',
    email_verified: true,
  });

  const mock = createMockFetch({ idToken });
  const provider = createProvider(mock.fetchImpl);

  const identity = await provider.exchangeAuthorizationCode({
    code: 'authorization-code',
    pkceVerifier: VERIFIER,
    nonce: NONCE,
  });

  assert.equal(identity.emailVerified, true);
  assert.equal(identity.registrationEligible, false);
  assert.equal(identity.emailAuthority, null);
});

test('does not allow Workspace email when hd is missing or mismatched', async () => {
  for (const claims of [
    { email: 'user@example.org' },
    { email: 'user@example.org', hd: 'other.example' },
  ]) {
    const idToken = await createIdToken({
      ...claims,
      email_verified: true,
    });

    const mock = createMockFetch({ idToken });
    const provider = createProvider(mock.fetchImpl);

    const identity = await provider.exchangeAuthorizationCode({
      code: 'authorization-code',
      pkceVerifier: VERIFIER,
      nonce: NONCE,
    });

    assert.equal(identity.registrationEligible, false);
  }
});

test('does not allow unverified Gmail for new registration', async () => {
  const idToken = await createIdToken({
    email_verified: false,
  });

  const mock = createMockFetch({ idToken });
  const provider = createProvider(mock.fetchImpl);

  const identity = await provider.exchangeAuthorizationCode({
    code: 'authorization-code',
    pkceVerifier: VERIFIER,
    nonce: NONCE,
  });

  assert.equal(identity.emailVerified, false);
  assert.equal(identity.registrationEligible, false);
});


test('rejects Google ID token without exp claim', async () => {
  const idToken = await new SignJWT({
    sub: 'google-subject-123',
    email: 'user@gmail.com',
    email_verified: true,
    nonce: NONCE,
  })
    .setProtectedHeader({ alg: 'RS256', kid: KID })
    .setIssuer(ISSUER)
    .setAudience(CLIENT_ID)
    .setIssuedAt()
    .sign(privateKey);

  const mock = createMockFetch({ idToken });
  const provider = createProvider(mock.fetchImpl);

  await assert.rejects(
    provider.exchangeAuthorizationCode({
      code: 'authorization-code',
      pkceVerifier: VERIFIER,
      nonce: NONCE,
    }),
    /exp/,
  );
});

test('rejects Google ID token without iat claim', async () => {
  const idToken = await new SignJWT({
    sub: 'google-subject-123',
    email: 'user@gmail.com',
    email_verified: true,
    nonce: NONCE,
  })
    .setProtectedHeader({ alg: 'RS256', kid: KID })
    .setIssuer(ISSUER)
    .setAudience(CLIENT_ID)
    .setExpirationTime('5m')
    .sign(privateKey);

  const mock = createMockFetch({ idToken });
  const provider = createProvider(mock.fetchImpl);

  await assert.rejects(
    provider.exchangeAuthorizationCode({
      code: 'authorization-code',
      pkceVerifier: VERIFIER,
      nonce: NONCE,
    }),
    /iat/,
  );
});

test('rejects OIDC nonce mismatch', async () => {
  const idToken = await createIdToken({
    nonce: 'X'.repeat(43),
  });

  const mock = createMockFetch({ idToken });
  const provider = createProvider(mock.fetchImpl);

  await assert.rejects(
    provider.exchangeAuthorizationCode({
      code: 'authorization-code',
      pkceVerifier: VERIFIER,
      nonce: NONCE,
    }),
    /nonce tidak cocok/,
  );
});

test('rejects token signed by an unknown key', async () => {
  const anotherKey = generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });

  const idToken = await createIdToken({}, anotherKey.privateKey);
  const mock = createMockFetch({ idToken });
  const provider = createProvider(mock.fetchImpl);

  await assert.rejects(
    provider.exchangeAuthorizationCode({
      code: 'authorization-code',
      pkceVerifier: VERIFIER,
      nonce: NONCE,
    }),
  );
});

test('rejects invalid state, nonce and PKCE verifier', async () => {
  const mock = createMockFetch({ idToken: 'unused' });
  const provider = createProvider(mock.fetchImpl);

  await assert.rejects(
    provider.createAuthorizationUrl({
      state: 'invalid',
      nonce: NONCE,
      pkceVerifier: VERIFIER,
    }),
    /OAuth state tidak valid/,
  );

  await assert.rejects(
    provider.createAuthorizationUrl({
      state: STATE,
      nonce: 'invalid',
      pkceVerifier: VERIFIER,
    }),
    /OIDC nonce tidak valid/,
  );

  await assert.rejects(
    provider.exchangeAuthorizationCode({
      code: 'authorization-code',
      pkceVerifier: 'invalid',
      nonce: NONCE,
    }),
    /PKCE verifier tidak valid/,
  );
});

test('rejects malformed provider configuration', () => {
  assert.throws(
    () => createGoogleOAuthProvider({
      clientId: '',
      clientSecret: CLIENT_SECRET,
      redirectUri: REDIRECT_URI,
    }),
    /Client ID tidak valid/,
  );

  assert.throws(
    () => createGoogleOAuthProvider({
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      redirectUri: 'http://central.example.test/callback',
    }),
    /harus menggunakan HTTPS/,
  );
});


test('accepts HTTP localhost and rejects non-HTTPS localhost redirect schemes', () => {
  assert.doesNotThrow(() => createGoogleOAuthProvider({
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    redirectUri: 'http://localhost:3000/oauth/google/callback',
  }));

  assert.throws(() => createGoogleOAuthProvider({
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    redirectUri: 'ftp://localhost/callback',
  }), /harus menggunakan HTTPS/);
});

test('applies redirect rejection and timeout signal to Google requests', async () => {
  const idToken = await createIdToken();
  const mock = createMockFetch({ idToken });
  const provider = createProvider(mock.fetchImpl);

  await provider.exchangeAuthorizationCode({
    code: 'authorization-code',
    pkceVerifier: VERIFIER,
    nonce: NONCE,
  });

  assert.ok(mock.calls.length >= 3);
  for (const call of mock.calls) {
    assert.equal(call.options.redirect, 'error');
    assert.ok(call.options.signal instanceof AbortSignal);
  }
});

test('aborts a stalled Google provider request at configured timeout', async () => {
  const provider = createGoogleOAuthProvider({
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
      code: 'authorization-code',
      pkceVerifier: VERIFIER,
      nonce: NONCE,
    }),
    /koneksi gagal/,
  );
});

test('rejects an invalid Google fetch timeout', () => {
  assert.throws(() => createGoogleOAuthProvider({
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    redirectUri: REDIRECT_URI,
    timeoutMs: 0,
  }), /Fetch timeout tidak valid/);
});
