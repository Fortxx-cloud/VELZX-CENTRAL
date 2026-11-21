import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { SignJWT } from 'jose';

import {
  createMicrosoftOAuthProvider,
} from '../../src/auth/oauth/providers/microsoft.mjs';

const CLIENT_ID = 'microsoft-client-id';
const CLIENT_SECRET = 'microsoft-client-secret';
const REDIRECT_URI =
  'https://central.example.test/oauth/microsoft/callback';

const TENANT_ID = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
const CONSUMER_TENANT_ID =
  '9188040d-6c67-4c5b-b112-36a304b66dad';

const STATE = 'S'.repeat(43);
const NONCE = 'N'.repeat(43);
const VERIFIER = 'V'.repeat(64);
const KID = 'microsoft-test-key';
const NOW = 1795132500000;

const ISSUER = `https://login.microsoftonline.com/${TENANT_ID}/v2.0`;

const { publicKey, privateKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
});

const publicJwk = {
  ...publicKey.export({ format: 'jwk' }),
  kid: KID,
  use: 'sig',
  alg: 'RS256',
  issuer: 'https://login.microsoftonline.com/{tenantid}/v2.0',
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

async function createIdToken(
  overrides = {},
  signingKey = privateKey,
) {
  const payload = {
    sub: 'microsoft-subject-123',
    tid: TENANT_ID,
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
    .setIssuedAt(Math.floor(NOW / 1000))
    .setExpirationTime(Math.floor(NOW / 1000) + 300)
    .sign(signingKey);
}

function createMockFetch({ idToken, jwks = [publicJwk] }) {
  const calls = [];

  const fetchImpl = async (url, options = {}) => {
    const target = String(url);
    calls.push({ url: target, options });

    const discoveryMatch = target.match(
      /^https:\/\/login\.microsoftonline\.com\/([^/]+)\/v2\.0\/\.well-known\/openid-configuration$/,
    );

    if (discoveryMatch) {
      const tenant = discoveryMatch[1];
      const issuer = /^[0-9a-f-]{36}$/i.test(tenant)
        ? `https://login.microsoftonline.com/${tenant}/v2.0`
        : 'https://login.microsoftonline.com/{tenantid}/v2.0';

      return response({
        issuer,
        authorization_endpoint:
          `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize`,
        token_endpoint:
          `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`,
        jwks_uri:
          `https://login.microsoftonline.com/${tenant}/discovery/v2.0/keys`,
      });
    }

    const tokenMatch = target.match(
      /^https:\/\/login\.microsoftonline\.com\/([^/]+)\/oauth2\/v2\.0\/token$/,
    );

    if (tokenMatch) {
      return response({
        access_token: 'mock-access-token',
        token_type: 'Bearer',
        id_token: idToken,
      });
    }

    const jwksMatch = target.match(
      /^https:\/\/login\.microsoftonline\.com\/([^/]+)\/discovery\/v2\.0\/keys$/,
    );

    if (jwksMatch) {
      return response({ keys: jwks });
    }

    throw new Error(`Unexpected URL: ${target}`);
  };

  return { fetchImpl, calls };
}
function createProvider(fetchImpl, options = {}) {
  return createMicrosoftOAuthProvider({
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    redirectUri: REDIRECT_URI,
    fetchImpl,
    clock: () => NOW,
    ...options,
  });
}

async function exchange(provider) {
  return provider.exchangeAuthorizationCode({
    code: 'authorization-code',
    pkceVerifier: VERIFIER,
    nonce: NONCE,
  });
}

test('builds Microsoft authorization URL with state, nonce and PKCE S256', async () => {
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
    'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
  );
  assert.equal(url.searchParams.get('client_id'), CLIENT_ID);
  assert.equal(url.searchParams.get('redirect_uri'), REDIRECT_URI);
  assert.equal(url.searchParams.get('response_type'), 'code');
  assert.equal(url.searchParams.get('response_mode'), 'query');
  assert.equal(url.searchParams.get('scope'), 'openid profile email');
  assert.equal(url.searchParams.get('state'), STATE);
  assert.equal(url.searchParams.get('nonce'), NONCE);
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  assert.match(
    url.searchParams.get('code_challenge'),
    /^[A-Za-z0-9_-]{43}$/,
  );
});

test('accepts authoritative verified_primary_email', async () => {
  const idToken = await createIdToken({
    verified_primary_email: 'Primary@Example.com',
    email: 'untrusted@example.net',
  });

  const mock = createMockFetch({ idToken });
  const identity = await exchange(createProvider(mock.fetchImpl));

  assert.equal(identity.provider, 'microsoft');
  assert.equal(identity.providerSubject, 'microsoft-subject-123');
  assert.equal(identity.tenantId, TENANT_ID);
  assert.equal(identity.email, 'primary@example.com');
  assert.equal(identity.emailVerified, true);
  assert.equal(identity.providerEmailVerified, true);
  assert.equal(
    identity.emailAuthority,
    'microsoft_verified_primary_email',
  );
  assert.equal(identity.registrationEligible, true);
});

test('accepts authoritative verified_secondary_email as fallback', async () => {
  const idToken = await createIdToken({
    verified_secondary_email: 'secondary@example.org',
  });

  const mock = createMockFetch({ idToken });
  const identity = await exchange(createProvider(mock.fetchImpl));

  assert.equal(identity.email, 'secondary@example.org');
  assert.equal(
    identity.emailAuthority,
    'microsoft_verified_secondary_email',
  );
  assert.equal(identity.registrationEligible, true);
});

test('prefers valid primary email over secondary email', async () => {
  const idToken = await createIdToken({
    verified_primary_email: 'primary@example.org',
    verified_secondary_email: 'secondary@example.org',
  });

  const mock = createMockFetch({ idToken });
  const identity = await exchange(createProvider(mock.fetchImpl));

  assert.equal(identity.email, 'primary@example.org');
  assert.equal(
    identity.emailAuthority,
    'microsoft_verified_primary_email',
  );
});

test('does not treat ordinary email as verified registration evidence', async () => {
  const idToken = await createIdToken({
    email: 'ordinary@example.org',
  });

  const mock = createMockFetch({ idToken });
  const identity = await exchange(createProvider(mock.fetchImpl));

  assert.equal(identity.email, null);
  assert.equal(identity.emailVerified, false);
  assert.equal(identity.providerEmailVerified, false);
  assert.equal(identity.registrationEligible, false);
});

test('does not treat xms_edov as verified email evidence', async () => {
  const idToken = await createIdToken({
    email: 'ordinary@example.org',
    xms_edov: true,
  });

  const mock = createMockFetch({ idToken });
  const identity = await exchange(createProvider(mock.fetchImpl));

  assert.equal(identity.email, null);
  assert.equal(identity.registrationEligible, false);
});

test('allows valid linked identity without authoritative email claims', async () => {
  const idToken = await createIdToken({
    email: 'ordinary@example.org',
  });

  const mock = createMockFetch({ idToken });
  const identity = await exchange(createProvider(mock.fetchImpl));

  assert.equal(identity.providerSubject, 'microsoft-subject-123');
  assert.equal(identity.registrationEligible, false);
});

test('rejects OIDC nonce mismatch', async () => {
  const idToken = await createIdToken({
    nonce: 'X'.repeat(43),
  });

  const mock = createMockFetch({ idToken });

  await assert.rejects(
    exchange(createProvider(mock.fetchImpl)),
    /nonce tidak cocok/,
  );
});

test('rejects token with mismatched tenant issuer', async () => {
  const idToken = await createIdToken({
    tid: TENANT_ID,
  });

  const wrongIssuerKey = generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });

  const wrongIssuerToken = await new SignJWT({
    sub: 'microsoft-subject-123',
    tid: TENANT_ID,
    nonce: NONCE,
  })
    .setProtectedHeader({ alg: 'RS256', kid: KID })
    .setIssuer(
      'https://login.microsoftonline.com/bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee/v2.0',
    )
    .setAudience(CLIENT_ID)
    .setIssuedAt(Math.floor(NOW / 1000))
    .setExpirationTime(Math.floor(NOW / 1000) + 300)
    .sign(privateKey);

  assert.ok(idToken);

  const mock = createMockFetch({ idToken: wrongIssuerToken });

  await assert.rejects(
    exchange(createProvider(mock.fetchImpl)),
    /issuer tidak valid/,
  );

  assert.ok(wrongIssuerKey.privateKey);
});

test('rejects token from a different tenant in single-tenant mode', async () => {
  const idToken = await createIdToken();

  const mock = createMockFetch({ idToken });

  await assert.rejects(
    exchange(
      createProvider(mock.fetchImpl, {
        tenantId: 'bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee',
      }),
    ),
  );
});

test('rejects consumer tenant when authority is organizations', async () => {
  const idToken = await createIdToken({
    tid: CONSUMER_TENANT_ID,
  });

  const mock = createMockFetch({ idToken });

  await assert.rejects(
    exchange(
      createProvider(mock.fetchImpl, {
        tenantId: 'organizations',
      }),
    ),
    /tenant tidak valid/,
  );
});

test('rejects invalid tenant claim', async () => {
  const idToken = await createIdToken({
    tid: 'not-a-tenant-guid',
  });

  const mock = createMockFetch({ idToken });

  await assert.rejects(
    exchange(createProvider(mock.fetchImpl)),
    /tenant tidak valid/,
  );
});


test('rejects Microsoft ID token without exp claim', async () => {
  const idToken = await new SignJWT({
    sub: 'microsoft-subject-123',
    tid: TENANT_ID,
    nonce: NONCE,
  })
    .setProtectedHeader({ alg: 'RS256', kid: KID })
    .setIssuer(ISSUER)
    .setAudience(CLIENT_ID)
    .setIssuedAt(Math.floor(NOW / 1000))
    .sign(privateKey);

  const mock = createMockFetch({ idToken });

  await assert.rejects(
    exchange(createProvider(mock.fetchImpl)),
    /exp/,
  );
});

test('rejects token without issued-at claim', async () => {
  const idToken = await new SignJWT({
    sub: 'microsoft-subject-123',
    tid: TENANT_ID,
    nonce: NONCE,
  })
    .setProtectedHeader({ alg: 'RS256', kid: KID })
    .setIssuer(ISSUER)
    .setAudience(CLIENT_ID)
    .setExpirationTime(Math.floor(NOW / 1000) + 300)
    .sign(privateKey);

  const mock = createMockFetch({ idToken });

  await assert.rejects(
    exchange(createProvider(mock.fetchImpl)),
    /(?:issued-at tidak valid|missing required "iat" claim)/,
  );
});

test('rejects signing key with mismatched issuer', async () => {
  const idToken = await createIdToken();

  const mock = createMockFetch({
    idToken,
    jwks: [{
      ...publicJwk,
      issuer:
        'https://login.microsoftonline.com/bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee/v2.0',
    }],
  });

  await assert.rejects(
    exchange(createProvider(mock.fetchImpl)),
    /signing key issuer tidak valid/,
  );
});

test('rejects signing key without issuer metadata', async () => {
  const idToken = await createIdToken();
  const { issuer, ...keyWithoutIssuer } = publicJwk;

  const mock = createMockFetch({
    idToken,
    jwks: [keyWithoutIssuer],
  });

  await assert.rejects(
    exchange(createProvider(mock.fetchImpl)),
    /signing key issuer tidak valid/,
  );
});

test('rejects token signed by unknown key', async () => {
  const anotherKey = generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });

  const idToken = await createIdToken({}, anotherKey.privateKey);
  const mock = createMockFetch({ idToken });

  await assert.rejects(
    exchange(createProvider(mock.fetchImpl)),
  );
});

test('rejects malformed state, nonce and PKCE verifier', async () => {
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
    provider.createAuthorizationUrl({
      state: STATE,
      nonce: NONCE,
      pkceVerifier: 'invalid',
    }),
    /PKCE verifier tidak valid/,
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
    () =>
      createMicrosoftOAuthProvider({
        clientId: '',
        clientSecret: CLIENT_SECRET,
        redirectUri: REDIRECT_URI,
      }),
    /Client ID tidak valid/,
  );

  assert.throws(
    () =>
      createMicrosoftOAuthProvider({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        redirectUri: 'http://central.example.test/callback',
      }),
    /harus menggunakan HTTPS/,
  );

  assert.throws(
    () =>
      createMicrosoftOAuthProvider({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        redirectUri: REDIRECT_URI,
        tenantId: 'invalid-tenant',
      }),
    /Tenant ID tidak valid/,
  );
});


test('applies redirect rejection and timeout signal to Microsoft requests', async () => {
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

test('aborts a stalled Microsoft provider request at configured timeout', async () => {
  const provider = createProvider(
    (_url, options) => new Promise((resolve, reject) => {
      options.signal.addEventListener(
        'abort',
        () => reject(options.signal.reason),
        { once: true },
      );
    }),
    { timeoutMs: 5 },
  );

  await assert.rejects(
    provider.exchangeAuthorizationCode({
      code: 'authorization-code',
      pkceVerifier: VERIFIER,
      nonce: NONCE,
    }),
    /koneksi gagal/,
  );
});

test('rejects an invalid Microsoft fetch timeout', () => {
  assert.throws(() => createMicrosoftOAuthProvider({
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    redirectUri: REDIRECT_URI,
    timeoutMs: -1,
  }), /Fetch timeout tidak valid/);
});
