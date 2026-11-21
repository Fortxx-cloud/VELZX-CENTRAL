import {
  createHash,
  timingSafeEqual,
} from 'node:crypto';

import {
  importJWK,
  jwtVerify,
} from 'jose';

const DISCOVERY_URL =
  'https://accounts.google.com/.well-known/openid-configuration';

const EXPECTED_ISSUER = 'https://accounts.google.com';
const EXPECTED_AUTHORIZATION_ENDPOINT =
  'https://accounts.google.com/o/oauth2/v2/auth';
const EXPECTED_TOKEN_ENDPOINT =
  'https://oauth2.googleapis.com/token';
const EXPECTED_JWKS_URI =
  'https://www.googleapis.com/oauth2/v3/certs';

const SECRET_PATTERN = /^[A-Za-z0-9_-]{43,128}$/;
const DOMAIN_PATTERN =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

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

export function createGoogleOAuthProvider({
  clientId,
  clientSecret,
  redirectUri,
  fetchImpl = globalThis.fetch,
  clock = () => Date.now(),
  timeoutMs = 10_000,
} = {}) {
  if (typeof clientId !== 'string' || !clientId.trim()) {
    throw new TypeError('Google Client ID tidak valid');
  }

  if (typeof clientSecret !== 'string' || !clientSecret) {
    throw new TypeError('Google Client Secret tidak valid');
  }

  if (typeof redirectUri !== 'string') {
    throw new TypeError('Google Redirect URI tidak valid');
  }

  const redirect = new URL(redirectUri);

  if (
    redirect.protocol !== 'https:' &&
    !(redirect.protocol === 'http:' && redirect.hostname === 'localhost')
  ) {
    throw new TypeError('Google Redirect URI harus menggunakan HTTPS');
  }

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
          DISCOVERY_URL,
          { method: 'GET' },
          'Google OIDC discovery',
        );

        if (
          metadata.issuer !== EXPECTED_ISSUER ||
          metadata.authorization_endpoint !== EXPECTED_AUTHORIZATION_ENDPOINT ||
          metadata.token_endpoint !== EXPECTED_TOKEN_ENDPOINT ||
          metadata.jwks_uri !== EXPECTED_JWKS_URI
        ) {
          throw new Error('Google OIDC metadata tidak sesuai');
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
      scope: 'openid email profile',
      state,
      nonce,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    }).toString();

    return url.toString();
  }

  async function verifyIdToken(idToken, expectedNonce) {
    if (typeof idToken !== 'string' || idToken.length > 16384) {
      throw new Error('Google ID token tidak valid');
    }

    const metadata = await getDiscovery();

    const parts = idToken.split('.');
    if (parts.length !== 3) {
      throw new Error('Google ID token tidak valid');
    }

    let protectedHeader;

    try {
      protectedHeader = JSON.parse(
        Buffer.from(parts[0], 'base64url').toString('utf8'),
      );
    } catch {
      throw new Error('Google ID token header tidak valid');
    }

    if (
      protectedHeader.alg !== 'RS256' ||
      typeof protectedHeader.kid !== 'string' ||
      !protectedHeader.kid
    ) {
      throw new Error('Algoritma Google ID token tidak diizinkan');
    }

    const jwks = await fetchJson(
      metadata.jwks_uri,
      { method: 'GET' },
      'Google JWKS',
    );

    if (!Array.isArray(jwks.keys)) {
      throw new Error('Google JWKS tidak valid');
    }

    const matchingKeys = jwks.keys.filter((key) =>
      key.kid === protectedHeader.kid &&
      key.kty === 'RSA' &&
      (!key.use || key.use === 'sig') &&
      (!key.alg || key.alg === 'RS256'),
    );

    if (matchingKeys.length !== 1) {
      throw new Error('Google signing key tidak ditemukan atau ambigu');
    }

    const publicKey = await importJWK(matchingKeys[0], 'RS256');

    const { payload } = await jwtVerify(idToken, publicKey, {
      issuer: [
        EXPECTED_ISSUER,
        'accounts.google.com',
      ],
      audience: clientId,
      algorithms: ['RS256'],
      requiredClaims: ['iss', 'sub', 'aud', 'exp', 'iat'],
      clockTolerance: 5,
      currentDate: new Date(clock()),
    });

    const nowSeconds = Math.floor(clock() / 1000);

    if (
      typeof payload.iat !== 'number' ||
      !Number.isFinite(payload.iat) ||
      payload.iat > nowSeconds + 5
    ) {
      throw new Error('Google issued-at tidak valid');
    }

    if (
      typeof payload.sub !== 'string' ||
      payload.sub.length < 1 ||
      payload.sub.length > 255
    ) {
      throw new Error('Google subject tidak valid');
    }

    if (
      Array.isArray(payload.aud) &&
      payload.aud.length > 1 &&
      payload.azp !== clientId
    ) {
      throw new Error('Google authorized party tidak valid');
    }

    if (payload.azp !== undefined && payload.azp !== clientId) {
      throw new Error('Google authorized party tidak valid');
    }

    if (
      typeof payload.nonce !== 'string' ||
      !safeEqual(payload.nonce, expectedNonce)
    ) {
      throw new Error('Google OIDC nonce tidak cocok');
    }

    const email = normalizeEmail(payload.email);
    const emailVerified = payload.email_verified === true;

    const hostedDomain =
      typeof payload.hd === 'string'
        ? payload.hd.trim().toLowerCase()
        : null;

    let emailAuthority = null;
    let registrationEligible = false;

    if (email && emailVerified) {
      const emailDomain = email.split('@')[1];

      if (emailDomain === 'gmail.com') {
        emailAuthority = 'gmail';
        registrationEligible = true;
      } else if (
        hostedDomain &&
        DOMAIN_PATTERN.test(hostedDomain) &&
        emailDomain === hostedDomain
      ) {
        emailAuthority = 'workspace';
        registrationEligible = true;
      }
    }

    return {
      provider: 'google',
      providerSubject: payload.sub,
      email,
      emailVerified,
      providerEmailVerified: emailVerified,
      hostedDomain,
      emailAuthority,
      registrationEligible,
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
      throw new TypeError('Google authorization code tidak valid');
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
      'Google token exchange',
    );

    if (
      typeof tokens.id_token !== 'string' ||
      tokens.token_type?.toLowerCase() !== 'bearer'
    ) {
      throw new Error('Google token response tidak valid');
    }

    return verifyIdToken(tokens.id_token, nonce);
  }

  return Object.freeze({
    createAuthorizationUrl,
    exchangeAuthorizationCode,
  });
}
