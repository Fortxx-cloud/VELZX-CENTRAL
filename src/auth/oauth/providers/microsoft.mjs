import { createHash, timingSafeEqual } from 'node:crypto';
import { importJWK, jwtVerify } from 'jose';

const MICROSOFT_ORIGIN = 'https://login.microsoftonline.com';
const CONSUMER_TENANT_ID = '9188040d-6c67-4c5b-b112-36a304b66dad';
const TENANT_ID_PATTERN =
  /^(?:common|organizations|consumers|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SECRET_PATTERN = /^[A-Za-z0-9_-]{43,128}$/;

function validateSecret(value, name) {
  if (typeof value !== 'string' || !SECRET_PATTERN.test(value)) {
    throw new TypeError(`${name} tidak valid`);
  }
}

function normalizeEmail(value) {
  if (typeof value !== 'string') return null;

  const email = value.trim().toLowerCase();

  if (
    email.length < 3 ||
    email.length > 320 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  ) {
    return null;
  }

  return email;
}

function safeEqual(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') {
    return false;
  }

  const a = Buffer.from(left, 'utf8');
  const b = Buffer.from(right, 'utf8');

  return a.length === b.length && timingSafeEqual(a, b);
}

async function readJsonResponse(response, name) {
  if (!response || response.ok !== true) {
    throw new Error(`${name} gagal`);
  }

  try {
    return await response.json();
  } catch {
    throw new Error(`${name} memberikan respons tidak valid`);
  }
}

function validateTenant(tenantId, tokenTenantId) {
  if (!UUID_PATTERN.test(tokenTenantId)) return false;

  const normalizedTenant = tenantId.toLowerCase();
  const normalizedTokenTenant = tokenTenantId.toLowerCase();

  if (UUID_PATTERN.test(normalizedTenant)) {
    return normalizedTenant === normalizedTokenTenant;
  }

  if (
    normalizedTenant === 'organizations' &&
    normalizedTokenTenant === CONSUMER_TENANT_ID
  ) {
    return false;
  }

  if (
    normalizedTenant === 'consumers' &&
    normalizedTokenTenant !== CONSUMER_TENANT_ID
  ) {
    return false;
  }

  return true;
}

export function createMicrosoftOAuthProvider({
  clientId,
  clientSecret,
  redirectUri,
  tenantId = 'common',
  fetchImpl = globalThis.fetch,
  clock = () => Date.now(),
  timeoutMs = 10_000,
} = {}) {
  if (typeof clientId !== 'string' || !clientId.trim()) {
    throw new TypeError('Microsoft Client ID tidak valid');
  }

  if (typeof clientSecret !== 'string' || !clientSecret) {
    throw new TypeError('Microsoft Client Secret tidak valid');
  }

  if (typeof redirectUri !== 'string') {
    throw new TypeError('Microsoft Redirect URI tidak valid');
  }

  const redirect = new URL(redirectUri);

  if (
    redirect.protocol !== 'https:' &&
    !(redirect.protocol === 'http:' && redirect.hostname === 'localhost')
  ) {
    throw new TypeError('Microsoft Redirect URI harus menggunakan HTTPS');
  }

  if (
    typeof tenantId !== 'string' ||
    !TENANT_ID_PATTERN.test(tenantId)
  ) {
    throw new TypeError('Microsoft Tenant ID tidak valid');
  }

  const normalizedTenantId = tenantId.toLowerCase();

  if (typeof fetchImpl !== 'function') {
    throw new TypeError('Fetch implementation tidak valid');
  }

  if (
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs < 1 ||
    timeoutMs > 60_000
  ) {
    throw new TypeError('Fetch timeout tidak valid');
  }

  if (typeof clock !== 'function') {
    throw new TypeError('Clock tidak valid');
  }

  const discoveryUrl =
    `${MICROSOFT_ORIGIN}/${normalizedTenantId}/v2.0/` +
    '.well-known/openid-configuration';

  let discoveryPromise;

  async function fetchJson(url, options, label) {
    let response;

    try {
      response = await fetchImpl(url, {
        ...options,
        redirect: 'error',
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch {
      throw new Error(`${label}: koneksi gagal`);
    }

    return readJsonResponse(response, label);
  }

  async function getDiscovery() {
    if (!discoveryPromise) {
      discoveryPromise = (async () => {
        const metadata = await fetchJson(
          discoveryUrl,
          { method: 'GET' },
          'Microsoft OIDC discovery',
        );

        const expectedIssuer = UUID_PATTERN.test(normalizedTenantId)
          ? `${MICROSOFT_ORIGIN}/${normalizedTenantId}/v2.0`
          : `${MICROSOFT_ORIGIN}/{tenantid}/v2.0`;

        const expectedAuthorizationEndpoint =
          `${MICROSOFT_ORIGIN}/${normalizedTenantId}/oauth2/v2.0/authorize`;

        const expectedTokenEndpoint =
          `${MICROSOFT_ORIGIN}/${normalizedTenantId}/oauth2/v2.0/token`;

        if (
          metadata.issuer !== expectedIssuer ||
          metadata.authorization_endpoint !== expectedAuthorizationEndpoint ||
          metadata.token_endpoint !== expectedTokenEndpoint
        ) {
          throw new Error('Microsoft OIDC metadata tidak sesuai');
        }

        let jwksUrl;

        try {
          jwksUrl = new URL(metadata.jwks_uri);
        } catch {
          throw new Error('Microsoft JWKS URI tidak valid');
        }

        if (
          jwksUrl.protocol !== 'https:' ||
          jwksUrl.hostname !== 'login.microsoftonline.com' ||
          !/^\/[a-z0-9-]+\/discovery\/v2\.0\/keys$/i.test(jwksUrl.pathname)
        ) {
          throw new Error('Microsoft JWKS endpoint tidak diizinkan');
        }

        return metadata;
      })().catch((error) => {
        discoveryPromise = null;
        throw error;
      });
    }

    return discoveryPromise;
  }

  async function createAuthorizationUrl({
    state,
    nonce,
    pkceVerifier,
  }) {
    validateSecret(state, 'OAuth state');
    validateSecret(nonce, 'OIDC nonce');
    validateSecret(pkceVerifier, 'PKCE verifier');

    const metadata = await getDiscovery();

    const challenge = createHash('sha256')
      .update(pkceVerifier, 'utf8')
      .digest('base64url');

    const url = new URL(metadata.authorization_endpoint);

    url.search = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: 'code',
      response_mode: 'query',
      scope: 'openid profile email',
      state,
      nonce,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    }).toString();

    return url.toString();
  }

  async function verifyIdToken(idToken, expectedNonce) {
    if (typeof idToken !== 'string' || idToken.length > 16384) {
      throw new Error('Microsoft ID token tidak valid');
    }

    const metadata = await getDiscovery();
    const parts = idToken.split('.');

    if (parts.length !== 3) {
      throw new Error('Microsoft ID token tidak valid');
    }

    let protectedHeader;

    try {
      protectedHeader = JSON.parse(
        Buffer.from(parts[0], 'base64url').toString('utf8'),
      );
    } catch {
      throw new Error('Microsoft ID token header tidak valid');
    }

    if (
      protectedHeader.alg !== 'RS256' ||
      typeof protectedHeader.kid !== 'string' ||
      !protectedHeader.kid
    ) {
      throw new Error('Algoritma Microsoft ID token tidak diizinkan');
    }

    const jwks = await fetchJson(
      metadata.jwks_uri,
      { method: 'GET' },
      'Microsoft JWKS',
    );

    if (!Array.isArray(jwks.keys)) {
      throw new Error('Microsoft JWKS tidak valid');
    }

    const matchingKeys = jwks.keys.filter(
      (key) =>
        key.kid === protectedHeader.kid &&
        key.kty === 'RSA' &&
        (!key.use || key.use === 'sig') &&
        (!key.alg || key.alg === 'RS256'),
    );

    if (matchingKeys.length !== 1) {
      throw new Error(
        'Microsoft signing key tidak ditemukan atau ambigu',
      );
    }

    const publicKey = await importJWK(matchingKeys[0], 'RS256');

    const { payload } = await jwtVerify(idToken, publicKey, {
      audience: clientId,
      algorithms: ['RS256'],
      requiredClaims: ['iss', 'sub', 'aud', 'exp', 'iat'],
      clockTolerance: 5,
      currentDate: new Date(clock()),
    });

    const nowSeconds = Math.floor(clock() / 1000);

    if (
      typeof payload.sub !== 'string' ||
      payload.sub.length < 1 ||
      payload.sub.length > 255
    ) {
      throw new Error('Microsoft subject tidak valid');
    }

    if (
      typeof payload.tid !== 'string' ||
      !UUID_PATTERN.test(payload.tid) ||
      !validateTenant(normalizedTenantId, payload.tid)
    ) {
      throw new Error('Microsoft tenant tidak valid');
    }

    const expectedIssuer =
      `${MICROSOFT_ORIGIN}/${payload.tid.toLowerCase()}/v2.0`;

    if (payload.iss !== expectedIssuer) {
      throw new Error('Microsoft issuer tidak valid');
    }

    if (
      typeof payload.iat !== 'number' ||
      !Number.isFinite(payload.iat) ||
      payload.iat > nowSeconds + 5
    ) {
      throw new Error('Microsoft issued-at tidak valid');
    }

    const signingKeyIssuer =
      typeof matchingKeys[0].issuer === 'string'
        ? matchingKeys[0].issuer.replace(
            /\{tenantid\}/gi,
            payload.tid,
          )
        : null;

    if (
      !signingKeyIssuer ||
      signingKeyIssuer !== payload.iss
    ) {
      throw new Error('Microsoft signing key issuer tidak valid');
    }

    if (
      typeof payload.nonce !== 'string' ||
      !safeEqual(payload.nonce, expectedNonce)
    ) {
      throw new Error('Microsoft OIDC nonce tidak cocok');
    }

    if (
      Array.isArray(payload.aud) &&
      payload.aud.length > 1 &&
      payload.azp !== clientId
    ) {
      throw new Error('Microsoft authorized party tidak valid');
    }

    if (
      payload.azp !== undefined &&
      payload.azp !== clientId
    ) {
      throw new Error('Microsoft authorized party tidak valid');
    }

    const primaryEmail = normalizeEmail(
      payload.verified_primary_email,
    );

    const secondaryEmail = normalizeEmail(
      payload.verified_secondary_email,
    );

    let email = null;
    let emailAuthority = null;

    if (primaryEmail) {
      email = primaryEmail;
      emailAuthority = 'microsoft_verified_primary_email';
    } else if (secondaryEmail) {
      email = secondaryEmail;
      emailAuthority = 'microsoft_verified_secondary_email';
    }

    const emailVerified = emailAuthority !== null;

    return {
      provider: 'microsoft',
      providerSubject: payload.sub,
      tenantId: payload.tid.toLowerCase(),
      email,
      emailVerified,
      providerEmailVerified: emailVerified,
      emailAuthority,
      registrationEligible: emailVerified,
    };
  }

  async function exchangeAuthorizationCode({
    code,
    pkceVerifier,
    nonce,
  }) {
    if (
      typeof code !== 'string' ||
      code.length < 1 ||
      code.length > 2048
    ) {
      throw new TypeError('Microsoft authorization code tidak valid');
    }

    validateSecret(pkceVerifier, 'PKCE verifier');
    validateSecret(nonce, 'OIDC nonce');

    const metadata = await getDiscovery();

    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri,
      code_verifier: pkceVerifier,
      scope: 'openid profile email',
    });

    const tokens = await fetchJson(
      metadata.token_endpoint,
      {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          accept: 'application/json',
        },
        body,
      },
      'Microsoft token exchange',
    );

    if (
      typeof tokens.id_token !== 'string' ||
      tokens.token_type?.toLowerCase() !== 'bearer'
    ) {
      throw new Error('Microsoft token response tidak valid');
    }

    return verifyIdToken(tokens.id_token, nonce);
  }

  return Object.freeze({
    createAuthorizationUrl,
    exchangeAuthorizationCode,
  });
}
