import {
  createHash,
  randomBytes,
  randomUUID,
} from 'node:crypto';

import {
  claimVerifiedRegistrationIpInTransaction,
} from '../security/registration-ip-limit.mjs';

const ALLOWED_SCHEMAS = new Set([
  'velzx_central_test',
  'velzx_central',
]);

const DEFAULT_TOKEN_TTL_SECONDS = 86400;

function validateEmail(value) {
  if (typeof value !== 'string') {
    throw new TypeError('Email harus berupa string');
  }

  const email = value.trim().toLowerCase();

  if (
    email.length < 3 ||
    email.length > 320 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  ) {
    throw new TypeError('Format email tidak valid');
  }

  return email;
}

function validatePasswordHash(value) {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > 255
  ) {
    throw new TypeError('Password hash tidak valid');
  }

  return value;
}

function validatePool(pool) {
  if (!pool || typeof pool.connect !== 'function') {
    throw new TypeError('PostgreSQL pool tidak valid');
  }
}

export function createUserRepository(
  pool,
  {
    schema = 'velzx_central_test',
    verificationTokenTtlSeconds = DEFAULT_TOKEN_TTL_SECONDS,
  } = {},
) {
  validatePool(pool);

  if (!ALLOWED_SCHEMAS.has(schema)) {
    throw new TypeError('Schema database tidak diizinkan');
  }

  if (
    !Number.isSafeInteger(verificationTokenTtlSeconds) ||
    verificationTokenTtlSeconds < 60 ||
    verificationTokenTtlSeconds > 604800
  ) {
    throw new TypeError('Masa berlaku token verifikasi tidak valid');
  }

  const usersTable = `${schema}.users`;
  const tokensTable = `${schema}.email_verification_tokens`;

  async function createPendingUser({ email, passwordHash }) {
    const normalizedEmail = validateEmail(email);
    const safePasswordHash = validatePasswordHash(passwordHash);

    const client = await pool.connect();

    try {
      await client.query('BEGIN');

      await client.query(
        `SET LOCAL search_path TO ${schema}, pg_catalog`,
      );

      const userId = randomUUID();

      const insertedUser = await client.query(
        `INSERT INTO ${usersTable}
          (id, email_normalized, password_hash, account_status)
         VALUES ($1, $2, $3, 'pending_verification')
         ON CONFLICT (email_normalized) DO NOTHING
         RETURNING
           id,
           email_normalized,
           account_status,
           created_at`,
        [userId, normalizedEmail, safePasswordHash],
      );

      if (insertedUser.rowCount !== 1) {
        await client.query('COMMIT');

        return {
          created: false,
        };
      }

      const rawToken = randomBytes(32).toString('base64url');

      const tokenHash = createHash('sha256')
        .update(rawToken, 'utf8')
        .digest('hex');

      const tokenId = randomUUID();

      const insertedToken = await client.query(
        `INSERT INTO ${tokensTable}
          (id, user_id, token_hash, expires_at)
         VALUES (
           $1,
           $2,
           $3,
           NOW() + ($4 * INTERVAL '1 second')
         )
         RETURNING expires_at`,
        [
          tokenId,
          userId,
          tokenHash,
          verificationTokenTtlSeconds,
        ],
      );

      if (insertedToken.rowCount !== 1) {
        throw new Error('Token verifikasi gagal dibuat');
      }

      await client.query('COMMIT');

      return {
        created: true,
        user: insertedUser.rows[0],
        verificationToken: rawToken,
        verificationTokenExpiresAt: insertedToken.rows[0].expires_at,
      };
    } catch (error) {
      await client.query('ROLLBACK').catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }

  async function verifyEmailToken({
    verificationToken,
    ipFingerprint,
  }) {
    if (
      typeof verificationToken !== 'string' ||
      !/^[A-Za-z0-9_-]{43}$/.test(verificationToken)
    ) {
      return { verified: false, reason: 'invalid_token' };
    }

    const tokenHash = createHash('sha256')
      .update(verificationToken, 'utf8')
      .digest('hex');

    const client = await pool.connect();

    try {
      await client.query('BEGIN');
      await client.query(
        `SET LOCAL search_path TO ${schema}, pg_catalog`,
      );

      const tokenResult = await client.query(
        `SELECT
           t.id AS token_id,
           t.user_id,
           t.expires_at,
           t.consumed_at,
           t.invalidated_at,
           u.email_normalized,
           u.account_status,
           u.email_verified_at
         FROM ${tokensTable} t
         JOIN ${usersTable} u ON u.id = t.user_id
         WHERE t.token_hash = $1
           AND t.expires_at > NOW()
         FOR UPDATE OF t, u`,
        [tokenHash],
      );

      const record = tokenResult.rows?.[0];

      if (
        !record ||
        record.consumed_at !== null ||
        record.invalidated_at !== null ||
        record.account_status !== 'pending_verification' ||
        record.email_verified_at !== null
      ) {
        await client.query('COMMIT');
        return { verified: false, reason: 'invalid_token' };
      }

      const claim = await claimVerifiedRegistrationIpInTransaction({
        client,
        ipFingerprint,
        accountId: record.user_id,
      });

      if (!claim.allowed) {
        // Persist security event. Token and account remain unchanged.
        await client.query('COMMIT');

        return {
          verified: false,
          reason: 'ip_account_limit_reached',
          limit: claim.limit,
        };
      }

      const consumed = await client.query(
        `UPDATE ${tokensTable}
         SET consumed_at = NOW()
         WHERE id = $1
           AND consumed_at IS NULL
           AND invalidated_at IS NULL
           AND expires_at > NOW()
         RETURNING id`,
        [record.token_id],
      );

      if (consumed.rowCount !== 1) {
        throw new Error('Token verifikasi gagal dikonsumsi');
      }

      const activated = await client.query(
        `UPDATE ${usersTable}
         SET account_status = 'active',
             email_verified_at = NOW(),
             updated_at = NOW()
         WHERE id = $1
           AND account_status = 'pending_verification'
           AND email_verified_at IS NULL
         RETURNING
           id,
           email_normalized,
           account_status,
           email_verified_at`,
        [record.user_id],
      );

      if (activated.rowCount !== 1) {
        throw new Error('Aktivasi akun gagal');
      }

      await client.query('COMMIT');

      return {
        verified: true,
        user: activated.rows[0],
      };
    } catch (error) {
      await client.query('ROLLBACK').catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }

  return Object.freeze({
    createPendingUser,
    verifyEmailToken,
  });
}
