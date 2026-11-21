import { createHash } from 'node:crypto';

const AUTHORIZE_URL = 'https://github.com/login/oauth/authorize';
const TOKEN_URL = 'https://github.com/login/oauth/access_token';
const API_BASE = 'https://api.github.com';
const API_VERSION = '2026-03-10';

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

function parseGrantedScopes(value) {
  if (typeof value !== 'string') return new Set();

  return new Set(
    value
      .split(',')
      .map((scope) => scope.trim())
      .filter(Boolean),
  );
}

function normalizeSubject(value) {
  if (
    (typeof value !== 'number' && typeof value !== 'string') ||
    !/^[1-9][0-9]*$/.test(String(value))
  ) {
    return null;
  }

  const normalized = String(value);

  if (normalized.length > 255) return null;

  return normalized;
}

export function createGitHubOAuthProvider({
  clientId,
  clientSecret,
  redirectUri,
  fetchImpl = globalThis.fetch,
  timeoutMs = 10_000,
} = {}) {
  if (typeof clientId !== 'string' || !clientId.trim()) {
    throw new TypeError('GitHub Client ID tidak valid');
  }

  if (typeof clientSecret !== 'string' || !clientSecret) {
    throw new TypeError('GitHub Client Secret tidak valid');
  }

  if (typeof redirectUri !== 'string') {
    throw new TypeError('GitHub Redirect URI tidak valid');
  }

  const redirect = new URL(redirectUri);

  if (
    redirect.protocol !== 'https:' &&
    !(redirect.protocol === 'http:' && redirect.hostname === 'localhost')
  ) {
    throw new TypeError('GitHub Redirect URI harus menggunakan HTTPS');
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

  async function createAuthorizationUrl({
    state,
    pkceVerifier,
  }) {
    validateSecret(state, 'OAuth state');
    validateSecret(pkceVerifier, 'PKCE verifier');

    const challenge = createHash('sha256')
      .update(pkceVerifier, 'utf8')
      .digest('base64url');

    const url = new URL(AUTHORIZE_URL);

    url.search = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: 'code',
      scope: 'read:user user:email',
      state,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    }).toString();

    return url.toString();
  }

  async function exchangeAuthorizationCode({
    code,
    pkceVerifier,
  }) {
    if (
      typeof code !== 'string' ||
      code.length < 1 ||
      code.length > 2048
    ) {
      throw new TypeError('GitHub authorization code tidak valid');
    }

    validateSecret(pkceVerifier, 'PKCE verifier');

    const body = new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      code,
      redirect_uri: redirectUri,
      code_verifier: pkceVerifier,
    });

    const tokens = await fetchJson(
      TOKEN_URL,
      {
        method: 'POST',
        headers: {
          accept: 'application/json',
          'content-type': 'application/x-www-form-urlencoded',
        },
        body,
      },
      'GitHub token exchange',
    );

    if (
      typeof tokens.access_token !== 'string' ||
      tokens.access_token.length < 1 ||
      tokens.access_token.length > 8192 ||
      tokens.token_type?.toLowerCase() !== 'bearer'
    ) {
      throw new Error('GitHub token response tidak valid');
    }

    const scopes = parseGrantedScopes(tokens.scope);

    if (!scopes.has('user:email')) {
      throw new Error('GitHub email permission tidak diberikan');
    }

    const authorization = `Bearer ${tokens.access_token}`;

    const apiHeaders = {
      accept: 'application/vnd.github+json',
      authorization,
      'x-github-api-version': API_VERSION,
      'user-agent': 'VELZX-Central',
    };

    const user = await fetchJson(
      `${API_BASE}/user`,
      {
        method: 'GET',
        headers: apiHeaders,
      },
      'GitHub authenticated user',
    );

    const providerSubject = normalizeSubject(user.id);

    if (!providerSubject) {
      throw new Error('GitHub account ID tidak valid');
    }

    const emails = await fetchJson(
      `${API_BASE}/user/emails?per_page=100`,
      {
        method: 'GET',
        headers: apiHeaders,
      },
      'GitHub verified emails',
    );

    if (!Array.isArray(emails) || emails.length > 100) {
      throw new Error('GitHub email response tidak valid');
    }

    const verifiedEmails = emails
      .filter((entry) =>
        entry &&
        entry.verified === true &&
        typeof entry.email === 'string',
      )
      .map((entry) => ({
        email: normalizeEmail(entry.email),
        primary: entry.primary === true,
      }))
      .filter((entry) => entry.email !== null);

    const selectedEmail =
      verifiedEmails.find((entry) => entry.primary) ??
      verifiedEmails[0] ??
      null;

    return {
      provider: 'github',
      providerSubject,
      email: selectedEmail?.email ?? null,
      emailVerified: selectedEmail !== null,
      providerEmailVerified: selectedEmail !== null,
      emailAuthority: selectedEmail ? 'github_verified_email' : null,
      registrationEligible: selectedEmail !== null,
    };
  }

  return Object.freeze({
    createAuthorizationUrl,
    exchangeAuthorizationCode,
  });
}
