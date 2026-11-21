import { randomBytes } from 'node:crypto';
import { createIpFingerprint } from '../../security/ip-fingerprint.mjs';

export const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;

const PROVIDERS = new Set(['google', 'github', 'microsoft']);
const OIDC_PROVIDERS = new Set(['google', 'microsoft']);

export class OAuthServiceError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'OAuthServiceError';
    this.code = code;
  }
}

function requireFunction(value, name) {
  if (typeof value !== 'function') {
    throw new TypeError(`${name} harus berupa function`);
  }
}

function validateProvider(provider) {
  if (!PROVIDERS.has(provider)) {
    throw new OAuthServiceError(
      'unsupported_provider',
      'OAuth provider tidak didukung',
    );
  }
}

function validateIdentity(identity, provider) {
  if (
    !identity ||
    identity.provider !== provider ||
    typeof identity.providerSubject !== 'string' ||
    identity.providerSubject.length < 1 ||
    identity.providerSubject.length > 255 ||
    typeof identity.providerEmailVerified !== 'boolean'
  ) {
    throw new OAuthServiceError(
      'invalid_provider_identity',
      'Identitas dari provider tidak valid',
    );
  }
}

function sessionExpiry(clock, ttlSeconds) {
  const now = clock();

  if (!Number.isFinite(now)) {
    throw new TypeError('Clock OAuth tidak valid');
  }

  return new Date(now + ttlSeconds * 1000);
}

function authorizationUrlValue(value) {
  if (typeof value === 'string' && value.length > 0) {
    return value;
  }

  if (value instanceof URL) {
    return value.toString();
  }

  throw new OAuthServiceError(
    'authorization_url_failed',
    'Authorization URL provider tidak valid',
  );
}

export function createOAuthService({
  providers,
  accountRepository,
  transactionRepository,
  sessionRepository,
  registrationIpPepper,
  sessionTtlSeconds = SESSION_TTL_SECONDS,
  clock = Date.now,
}) {
  if (!providers || typeof providers !== 'object') {
    throw new TypeError('OAuth providers tidak valid');
  }

  const configuredProviders = Object.entries(providers);

  if (configuredProviders.length === 0) {
    throw new TypeError('Minimal satu OAuth provider harus dikonfigurasi');
  }

  for (const [provider, implementation] of configuredProviders) {
    validateProvider(provider);

    if (
      !implementation ||
      typeof implementation.createAuthorizationUrl !== 'function' ||
      typeof implementation.exchangeAuthorizationCode !== 'function'
    ) {
      throw new TypeError(`Implementasi provider ${provider} tidak valid`);
    }
  }

  if (
    !accountRepository ||
    typeof accountRepository.findUserByIdentity !== 'function' ||
    typeof accountRepository.createOAuthAccount !== 'function' ||
    typeof accountRepository.linkOAuthIdentity !== 'function'
  ) {
    throw new TypeError('OAuth account repository tidak valid');
  }

  if (
    !transactionRepository ||
    typeof transactionRepository.create !== 'function' ||
    typeof transactionRepository.consume !== 'function'
  ) {
    throw new TypeError('OAuth transaction repository tidak valid');
  }

  if (
    !sessionRepository ||
    typeof sessionRepository.findActiveSession !== 'function' ||
    typeof sessionRepository.createSessionForUser !== 'function'
  ) {
    throw new TypeError('Session repository tidak valid');
  }

  requireFunction(clock, 'Clock');

  if (
    !Number.isSafeInteger(sessionTtlSeconds) ||
    sessionTtlSeconds !== SESSION_TTL_SECONDS
  ) {
    throw new TypeError('Session OAuth harus menggunakan TTL 7 hari');
  }

  if (
    typeof registrationIpPepper !== 'string' ||
    Buffer.byteLength(registrationIpPepper, 'utf8') < 32
  ) {
    throw new TypeError('Registration IP pepper tidak valid');
  }

  async function startLogin({ provider, browserBinding }) {
    validateProvider(provider);

    const pkceVerifier = randomBytes(32).toString('base64url');
    const nonce = OIDC_PROVIDERS.has(provider)
      ? randomBytes(32).toString('base64url')
      : null;

    const transaction = await transactionRepository.create({
      provider,
      purpose: 'login',
      browserBinding,
      pkceVerifier,
      nonce,
    });

    const url = await providers[provider].createAuthorizationUrl({
      state: transaction.state,
      pkceVerifier,
      nonce,
    });

    return {
      provider,
      authorizationUrl: authorizationUrlValue(url),
      state: transaction.state,
      expiresAt: transaction.expiresAt,
    };
  }

  async function startLink({
    provider,
    browserBinding,
    sessionToken,
  }) {
    validateProvider(provider);

    if (typeof sessionToken !== 'string' || sessionToken.length === 0) {
      throw new OAuthServiceError(
        'authentication_required',
        'Session aktif diperlukan untuk menghubungkan akun',
      );
    }

    const activeSession = await sessionRepository.findActiveSession({
      token: sessionToken,
    });

    if (!activeSession) {
      throw new OAuthServiceError(
        'authentication_required',
        'Session Central tidak aktif',
      );
    }

    const pkceVerifier = randomBytes(32).toString('base64url');
    const nonce = OIDC_PROVIDERS.has(provider)
      ? randomBytes(32).toString('base64url')
      : null;

    const transaction = await transactionRepository.create({
      provider,
      purpose: 'link',
      browserBinding,
      pkceVerifier,
      nonce,
      initiatingUserId: activeSession.user.id,
      initiatingSessionId: activeSession.session.id,
    });

    const url = await providers[provider].createAuthorizationUrl({
      state: transaction.state,
      pkceVerifier,
      nonce,
    });

    return {
      provider,
      authorizationUrl: authorizationUrlValue(url),
      state: transaction.state,
      expiresAt: transaction.expiresAt,
    };
  }

  async function consumeProviderIdentity({
    provider,
    code,
    state,
    browserBinding,
  }) {
    validateProvider(provider);

    if (typeof code !== 'string' || code.length === 0) {
      throw new OAuthServiceError(
        'invalid_authorization_code',
        'Authorization code tidak valid',
      );
    }

    const transaction = await transactionRepository.consume({
      provider,
      state,
      browserBinding,
    });

    if (!transaction) {
      throw new OAuthServiceError(
        'invalid_oauth_transaction',
        'OAuth transaction tidak valid atau sudah kedaluwarsa',
      );
    }

    if (transaction.provider !== provider) {
      throw new OAuthServiceError(
        'invalid_oauth_transaction',
        'OAuth transaction tidak cocok',
      );
    }

    const identity = await providers[provider].exchangeAuthorizationCode({
      code,
      pkceVerifier: transaction.pkceVerifier,
      nonce: transaction.nonce,
    });

    validateIdentity(identity, provider);

    return { transaction, identity };
  }

  async function completeLoginFromIdentity({
    provider,
    transaction,
    identity,
    clientIp,
  }) {
    const existing = await accountRepository.findUserByIdentity({
      provider,
      providerSubject: identity.providerSubject,
    });

    if (existing) {
      if (existing.user.accountStatus !== 'active') {
        throw new OAuthServiceError(
          'account_unavailable',
          'Akun Central tidak dapat digunakan',
        );
      }

      const session = await sessionRepository.createSessionForUser({
        userId: existing.user.id,
        sessionExpiresAt: sessionExpiry(clock, sessionTtlSeconds),
      });

      if (!session) {
        throw new OAuthServiceError(
          'session_creation_failed',
          'Session Central gagal dibuat',
        );
      }

      return {
        authenticated: true,
        created: false,
        user: existing.user,
        session,
      };
    }

    if (
      identity.registrationEligible !== true ||
      identity.providerEmailVerified !== true ||
      typeof identity.email !== 'string' ||
      identity.email.length === 0
    ) {
      throw new OAuthServiceError(
        'registration_not_eligible',
        'Provider tidak memberikan email yang memenuhi kebijakan registrasi',
      );
    }

    const ipFingerprint = createIpFingerprint({
      ip: clientIp,
      pepper: registrationIpPepper,
    });

    const result = await accountRepository.createOAuthAccount({
      provider,
      providerSubject: identity.providerSubject,
      email: identity.email,
      providerEmail: identity.email,
      providerEmailVerified: identity.providerEmailVerified,
      ipFingerprint,
      sessionExpiresAt: sessionExpiry(clock, sessionTtlSeconds),
    });

    if (!result.created) {
      const codes = {
        identity_conflict: 'account_conflict',
        account_conflict: 'account_conflict',
        ip_account_limit_reached: 'registration_ip_limit_reached',
      };

      const code = codes[result.reason] ?? 'registration_failed';

      throw new OAuthServiceError(
        code,
        'Registrasi OAuth tidak dapat diselesaikan',
      );
    }

    return {
      authenticated: true,
      created: true,
      user: result.user,
      session: result.session,
    };
  }

  async function completeLogin(args) {
    const { transaction, identity } = await consumeProviderIdentity(args);

    if (transaction.purpose !== 'login') {
      throw new OAuthServiceError(
        'invalid_oauth_purpose',
        'OAuth transaction bukan untuk login',
      );
    }

    return completeLoginFromIdentity({
      ...args,
      transaction,
      identity,
    });
  }

  async function completeLink(args) {
    const { transaction, identity } = await consumeProviderIdentity(args);

    return completeLinkFromIdentity({
      ...args,
      transaction,
      identity,
    });
  }

  async function completeCallback({
    provider,
    code,
    state,
    browserBinding,
    clientIp,
    sessionToken,
  }) {
    const { transaction, identity } = await consumeProviderIdentity({
      provider,
      code,
      state,
      browserBinding,
    });

    const callbackContext = {
      provider,
      transaction,
      identity,
    };

    if (transaction.purpose === 'login') {
      return completeLoginFromIdentity({
        ...callbackContext,
        clientIp,
      });
    }

    if (transaction.purpose === 'link') {
      return completeLinkFromIdentity({
        ...callbackContext,
        sessionToken,
      });
    }

    throw new OAuthServiceError(
      'invalid_oauth_purpose',
      'OAuth transaction purpose tidak didukung',
    );
  }

  async function completeLinkFromIdentity({
    provider,
    transaction,
    identity,
    sessionToken,
  }) {
    if (
      transaction.purpose !== 'link' ||
      typeof transaction.initiatingUserId !== 'string' ||
      typeof transaction.initiatingSessionId !== 'string'
    ) {
      throw new OAuthServiceError(
        'invalid_oauth_purpose',
        'OAuth transaction bukan untuk account linking',
      );
    }

    if (typeof sessionToken !== 'string' || sessionToken.length === 0) {
      throw new OAuthServiceError(
        'authentication_required',
        'Session aktif diperlukan untuk account linking',
      );
    }

    const activeSession = await sessionRepository.findActiveSession({
      token: sessionToken,
    });

    if (
      !activeSession ||
      activeSession.user.id !== transaction.initiatingUserId ||
      activeSession.session.id !== transaction.initiatingSessionId
    ) {
      throw new OAuthServiceError(
        'session_mismatch',
        'Session account linking sudah tidak valid',
      );
    }

    const result = await accountRepository.linkOAuthIdentity({
      userId: transaction.initiatingUserId,
      sessionId: transaction.initiatingSessionId,
      provider,
      providerSubject: identity.providerSubject,
      providerEmail: identity.email,
      providerEmailVerified: identity.providerEmailVerified,
    });

    if (!result.linked) {
      throw new OAuthServiceError(
        result.reason === 'identity_conflict'
          ? 'identity_conflict'
          : 'link_failed',
        'Identitas provider tidak dapat dihubungkan',
      );
    }

    return {
      linked: true,
      userId: transaction.initiatingUserId,
      identity: result.identity,
    };
  }

  return Object.freeze({
    startLogin,
    startLink,
    completeLogin,
    completeLink,
    completeCallback,
  });
}
