import {
  createHash,
  randomBytes,
  randomUUID,
} from 'node:crypto';

import {
  claimVerifiedRegistrationIpInTransaction,
} from '../../security/registration-ip-limit.mjs';

const ALLOWED_SCHEMAS = new Set(['velzx_central_test', 'velzx_central']);
const PROVIDERS = new Set(['google', 'github', 'microsoft']);

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const FINGERPRINT_PATTERN = /^v1:[a-f0-9]{64}$/;

function sha256(value) {
  return createHash('sha256')
    .update(value, 'utf8')
    .digest('hex');
}

function normalizeEmail(value, name = 'Email') {
  if (typeof value !== 'string') {
    throw new TypeError(`${name} tidak valid`);
  }

  const normalized = value.trim().toLowerCase();

  if (
    normalized.length < 3 ||
    normalized.length > 320 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized)
  ) {
    throw new TypeError(`${name} tidak valid`);
  }

  return normalized;
}

function validateProviderIdentity({
  provider,
  providerSubject,
  providerEmail,
  providerEmailVerified,
}) {
  if (!PROVIDERS.has(provider)) {
    throw new TypeError('OAuth provider tidak diizinkan');
  }

  if (
    typeof providerSubject !== 'string' ||
    providerSubject.length < 1 ||
    providerSubject.length > 255
  ) {
    throw new TypeError('Provider subject tidak valid');
  }

  if (providerEmailVerified !== true) {
    throw new TypeError('Email provider harus terverifikasi');
  }

  return normalizeEmail(providerEmail, 'Provider email');
}

function validateProviderIdentityForLinking({
  provider,
  providerSubject,
  providerEmail,
  providerEmailVerified,
}) {
  if (!PROVIDERS.has(provider)) {
    throw new TypeError('OAuth provider tidak diizinkan');
  }

  if (
    typeof providerSubject !== 'string' ||
    providerSubject.length < 1 ||
    providerSubject.length > 255
  ) {
    throw new TypeError('Provider subject tidak valid');
  }

  if (providerEmailVerified === true) {
    return {
      email: normalizeEmail(providerEmail, 'Provider email'),
      emailVerified: true,
    };
  }

  if (providerEmailVerified === false) {
    return { email: null, emailVerified: false };
  }

  throw new TypeError('Status verifikasi email provider tidak valid');
}

function validateUuid(value, name) {
  if (typeof value !== 'string' || !UUID_PATTERN.test(value)) {
    throw new TypeError(`${name} tidak valid`);
  }
}

function validateSessionExpiry(value) {
  if (
    !(value instanceof Date) ||
    !Number.isFinite(value.getTime()) ||
    value.getTime() <= Date.now()
  ) {
    throw new TypeError('Session expiry tidak valid');
  }
}

function isUniqueViolation(error) {
  return error?.code === '23505';
}

export function createOAuthAccountRepository(
  pool,
  { schema = 'velzx_central_test' } = {},
) {
  if (!pool || typeof pool.connect !== 'function') {
    throw new TypeError('PostgreSQL pool tidak valid');
  }

  if (!ALLOWED_SCHEMAS.has(schema)) {
    throw new TypeError('Schema database tidak diizinkan');
  }

  const usersTable = `${schema}.users`;
  const identitiesTable = `${schema}.user_identities`;
  const sessionsTable = `${schema}.sessions`;

  async function findUserByIdentity({
    provider,
    providerSubject,
  }) {
    if (!PROVIDERS.has(provider)) {
      throw new TypeError('OAuth provider tidak diizinkan');
    }

    if (
      typeof providerSubject !== 'string' ||
      providerSubject.length < 1 ||
      providerSubject.length > 255
    ) {
      throw new TypeError('Provider subject tidak valid');
    }

    const client = await pool.connect();

    try {
      const result = await client.query(
        `SELECT
           u.id AS user_id,
           u.email_normalized,
           u.account_status,
           u.email_verified_at,
           i.id AS identity_id,
           i.provider,
           i.provider_subject,
           i.provider_email,
           i.provider_email_verified
         FROM ${identitiesTable} i
         JOIN ${usersTable} u ON u.id = i.user_id
         WHERE i.provider = $1
           AND i.provider_subject = $2
         LIMIT 1`,
        [provider, providerSubject],
      );

      const row = result.rows?.[0];

      if (!row) {
        return null;
      }

      return {
        user: {
          id: row.user_id,
          email: row.email_normalized,
          accountStatus: row.account_status,
          emailVerifiedAt: row.email_verified_at,
        },
        identity: {
          id: row.identity_id,
          provider: row.provider,
          subject: row.provider_subject,
          email: row.provider_email,
          emailVerified: row.provider_email_verified,
        },
      };
    } finally {
      client.release();
    }
  }

  async function createOAuthAccount({
    provider,
    providerSubject,
    email,
    providerEmail,
    providerEmailVerified,
    ipFingerprint,
    sessionExpiresAt,
  }) {
    const verifiedProviderEmail = validateProviderIdentity({
      provider,
      providerSubject,
      providerEmail,
      providerEmailVerified,
    });

    const normalizedEmail = normalizeEmail(email);

    if (normalizedEmail !== verifiedProviderEmail) {
      throw new TypeError(
        'Email akun harus sama dengan email provider terverifikasi',
      );
    }

    if (
      typeof ipFingerprint !== 'string' ||
      !FINGERPRINT_PATTERN.test(ipFingerprint)
    ) {
      throw new TypeError('Registration IP fingerprint tidak valid');
    }

    validateSessionExpiry(sessionExpiresAt);

    const userId = randomUUID();
    const identityId = randomUUID();
    const sessionId = randomUUID();
    const sessionToken = randomBytes(32).toString('base64url');
    const sessionTokenHash = sha256(sessionToken);

    const client = await pool.connect();
    let transactionStarted = false;

    try {
      await client.query('BEGIN');
      transactionStarted = true;

      await client.query(
        `SET LOCAL search_path TO ${schema}, pg_catalog`,
      );

      const existingIdentity = await client.query(
        `SELECT id
         FROM ${identitiesTable}
         WHERE provider = $1
           AND provider_subject = $2
         LIMIT 1`,
        [provider, providerSubject],
      );

      if (existingIdentity.rowCount > 0) {
        await client.query('ROLLBACK');
        transactionStarted = false;

        return {
          created: false,
          reason: 'identity_conflict',
        };
      }

      const existingEmail = await client.query(
        `SELECT id
         FROM ${usersTable}
         WHERE email_normalized = $1
         LIMIT 1`,
        [normalizedEmail],
      );

      if (existingEmail.rowCount > 0) {
        await client.query('ROLLBACK');
        transactionStarted = false;

        return {
          created: false,
          reason: 'account_conflict',
        };
      }

      const claim = await claimVerifiedRegistrationIpInTransaction({
        client,
        ipFingerprint,
        accountId: userId,
      });

      if (!claim.allowed) {
        // COMMIT diperlukan agar security event tetap tersimpan.
        await client.query('COMMIT');
        transactionStarted = false;

        return {
          created: false,
          reason: 'ip_account_limit_reached',
          limit: claim.limit,
          verifiedAccountCount: claim.verifiedAccountCount,
        };
      }

      await client.query(
        `INSERT INTO ${usersTable} (
           id,
           email_normalized,
           password_hash,
           email_verified_at,
           account_status
         )
         VALUES ($1, $2, NULL, NOW(), 'active')`,
        [userId, normalizedEmail],
      );

      await client.query(
        `INSERT INTO ${identitiesTable} (
           id,
           user_id,
           provider,
           provider_subject,
           provider_email,
           provider_email_verified
         )
         VALUES ($1, $2, $3, $4, $5, TRUE)`,
        [
          identityId,
          userId,
          provider,
          providerSubject,
          verifiedProviderEmail,
        ],
      );

      await client.query(
        `INSERT INTO ${sessionsTable} (
           id,
           user_id,
           session_token_hash,
           expires_at
         )
         VALUES ($1, $2, $3, $4)`,
        [
          sessionId,
          userId,
          sessionTokenHash,
          sessionExpiresAt,
        ],
      );

      await client.query('COMMIT');
      transactionStarted = false;

      return {
        created: true,
        user: {
          id: userId,
          email: normalizedEmail,
          accountStatus: 'active',
        },
        identity: {
          id: identityId,
          provider,
          subject: providerSubject,
        },
        session: {
          id: sessionId,
          token: sessionToken,
          expiresAt: sessionExpiresAt,
        },
      };
    } catch (error) {
      if (transactionStarted) {
        await client.query('ROLLBACK').catch(() => {});
      }

      if (isUniqueViolation(error)) {
        return {
          created: false,
          reason: 'account_conflict',
        };
      }

      throw error;
    } finally {
      client.release();
    }
  }

  async function linkOAuthIdentity({
    userId,
    sessionId,
    provider,
    providerSubject,
    providerEmail,
    providerEmailVerified,
  }) {
    const linkIdentity = validateProviderIdentityForLinking({
      provider,
      providerSubject,
      providerEmail,
      providerEmailVerified,
    });

    validateUuid(userId, 'User ID');
    validateUuid(sessionId, 'Session ID');

    const identityId = randomUUID();
    const client = await pool.connect();
    let transactionStarted = false;

    try {
      await client.query('BEGIN');
      transactionStarted = true;

      const owner = await client.query(
        `SELECT
           u.id,
           u.account_status,
           s.id AS session_id
         FROM ${usersTable} u
         JOIN ${sessionsTable} s ON s.user_id = u.id
         WHERE u.id = $1
           AND s.id = $2
           AND u.account_status = 'active'
           AND s.revoked_at IS NULL
           AND s.expires_at > NOW()
         FOR UPDATE OF u, s`,
        [userId, sessionId],
      );

      if (owner.rowCount !== 1) {
        await client.query('ROLLBACK');
        transactionStarted = false;

        return {
          linked: false,
          reason: 'session_invalid',
        };
      }

      const existingIdentity = await client.query(
        `SELECT user_id
         FROM ${identitiesTable}
         WHERE provider = $1
           AND provider_subject = $2
         LIMIT 1`,
        [provider, providerSubject],
      );

      if (existingIdentity.rowCount > 0) {
        await client.query('ROLLBACK');
        transactionStarted = false;

        return {
          linked: false,
          reason: 'identity_conflict',
        };
      }

      await client.query(
        `INSERT INTO ${identitiesTable} (
           id,
           user_id,
           provider,
           provider_subject,
           provider_email,
           provider_email_verified
         )
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          identityId,
          userId,
          provider,
          providerSubject,
          linkIdentity.email,
          linkIdentity.emailVerified,
        ],
      );

      await client.query('COMMIT');
      transactionStarted = false;

      return {
        linked: true,
        identity: {
          id: identityId,
          provider,
          subject: providerSubject,
          email: linkIdentity.email,
          emailVerified: linkIdentity.emailVerified,
        },
      };
    } catch (error) {
      if (transactionStarted) {
        await client.query('ROLLBACK').catch(() => {});
      }

      if (isUniqueViolation(error)) {
        return {
          linked: false,
          reason: 'identity_conflict',
        };
      }

      throw error;
    } finally {
      client.release();
    }
  }

  return Object.freeze({
    findUserByIdentity,
    createOAuthAccount,
    linkOAuthIdentity,
  });
}
