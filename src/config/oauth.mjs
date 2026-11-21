const PROVIDER_FIELDS = {
  google: [
    'GOOGLE_CLIENT_ID',
    'GOOGLE_CLIENT_SECRET',
    'GOOGLE_REDIRECT_URI',
  ],
  github: [
    'GITHUB_CLIENT_ID',
    'GITHUB_CLIENT_SECRET',
    'GITHUB_REDIRECT_URI',
  ],
  microsoft: [
    'MICROSOFT_CLIENT_ID',
    'MICROSOFT_CLIENT_SECRET',
    'MICROSOFT_REDIRECT_URI',
  ],
};

const OAUTH_KEY = 'OAUTH_TRANSACTION_ENCRYPTION_KEY';
const IP_PEPPER = 'REGISTRATION_IP_PEPPER';

function present(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function validateRedirectUri(value, provider) {
  let url;

  try {
    url = new URL(value);
  } catch {
    throw new TypeError(`${provider} redirect URI tidak valid`);
  }

  if (
    url.protocol !== 'https:'
    || url.username
    || url.password
    || url.search
    || url.hash
    || url.pathname !== `/auth/oauth/${provider}/callback`
  ) {
    throw new TypeError(`${provider} redirect URI tidak memenuhi kebijakan`);
  }
}

function decodeEncryptionKey(value) {
  if (
    typeof value !== 'string'
    || !/^[A-Za-z0-9_-]{43}$/.test(value)
  ) {
    throw new TypeError(`${OAUTH_KEY} harus berupa Base64URL 32 byte`);
  }

  const key = Buffer.from(value, 'base64url');

  if (
    key.length !== 32
    || key.toString('base64url') !== value
  ) {
    throw new TypeError(`${OAUTH_KEY} tidak valid`);
  }

  return key;
}

function loadProviderConfig(env, provider, fields) {
  const configuredFields = fields.filter(name => present(env[name]));

  if (configuredFields.length === 0) {
    return null;
  }

  const missing = fields.filter(name => !present(env[name]));

  if (missing.length > 0) {
    return null;
  }

  validateRedirectUri(env[fields[2]], provider);

  return Object.freeze({
    clientId: env[fields[0]],
    clientSecret: env[fields[1]],
    redirectUri: env[fields[2]],
  });
}

export function loadOAuthConfig(env = process.env) {
  const google = loadProviderConfig(env, 'google', PROVIDER_FIELDS.google);
  const github = loadProviderConfig(env, 'github', PROVIDER_FIELDS.github);
  const microsoftBase = loadProviderConfig(
    env,
    'microsoft',
    PROVIDER_FIELDS.microsoft,
  );

  if (!google && !github && !microsoftBase) {
    return null;
  }

  if (!present(env[OAUTH_KEY])) {
    throw new Error(`${OAUTH_KEY} wajib tersedia ketika OAuth aktif`);
  }

  if (
    !present(env[IP_PEPPER])
    || Buffer.byteLength(env[IP_PEPPER], 'utf8') < 32
  ) {
    throw new Error(`${IP_PEPPER} tidak tersedia atau tidak valid`);
  }

  let microsoft = null;

  if (microsoftBase) {
    const microsoftTenantId = env.MICROSOFT_TENANT_ID || 'common';

    if (
      !/^(common|organizations|consumers|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i
        .test(microsoftTenantId)
    ) {
      throw new TypeError('MICROSOFT_TENANT_ID tidak valid');
    }

    microsoft = Object.freeze({
      ...microsoftBase,
      tenantId: microsoftTenantId,
    });
  }

  return Object.freeze({
    google,
    github,
    microsoft,
    encryptionKey: decodeEncryptionKey(env[OAUTH_KEY]),
    registrationIpPepper: env[IP_PEPPER],
  });
}
