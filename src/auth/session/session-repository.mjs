import {
  createHash,
  randomBytes,
  randomUUID,
} from 'node:crypto';

const ALLOWED_SCHEMAS = new Set([
  'velzx_central_test',
  'velzx_central',
]);

const DEFAULT_SCHEMA = 'velzx_central_test';
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function validateToken(token) {
  if (typeof token !== 'string' || !TOKEN_PATTERN.test(token)) {
    throw new TypeError('Session token tidak valid');
  }

  return createHash('sha256')
    .update(token, 'utf8')
    .digest('hex');
}

function validateUuid(value, label) {
  if (typeof value !== 'string' || !UUID_PATTERN.test(value)) {
    throw new TypeError(`${label} tidak valid`);
  }
}

export function createSessionRepository(
  pool,
  { schema = DEFAULT_SCHEMA } = {},
) {
  if (!pool || typeof pool.query !== 'function') {
    throw new TypeError('PostgreSQL pool tidak valid');
  }

  if (!ALLOWED_SCHEMAS.has(schema)) {
    throw new TypeError('Schema database tidak diizinkan');
  }

  const sessionsTable = `${schema}.sessions`;
  const usersTable = `${schema}.users`;

  async function findActiveSession({ token }) {
    const tokenHash = validateToken(token);

    const result = await pool.query(
      `SELECT
         s.id AS session_id,
         s.user_id,
         s.expires_at,
         s.last_seen_at,
         s.created_at AS session_created_at,
         u.email_normalized,
         u.email_verified_at,
         u.account_status
       FROM ${sessionsTable} s
       JOIN ${usersTable} u ON u.id = s.user_id
       WHERE s.session_token_hash = $1
         AND s.revoked_at IS NULL
         AND s.expires_at > NOW()
         AND u.account_status = 'active'
       LIMIT 1`,
      [tokenHash],
    );

    if (result.rowCount !== 1) {
      return null;
    }

    const row = result.rows[0];

    return {
      session: {
        id: row.session_id,
        userId: row.user_id,
        expiresAt: row.expires_at,
        lastSeenAt: row.last_seen_at,
        createdAt: row.session_created_at,
      },
      user: {
        id: row.user_id,
        email: row.email_normalized,
        emailVerified: row.email_verified_at != null,
        accountStatus: row.account_status,
      },
    };
  }

  async function createSessionForUser({ userId, sessionExpiresAt }) {
    validateUuid(userId, 'User ID');

    if (
      !(sessionExpiresAt instanceof Date)
      || !Number.isFinite(sessionExpiresAt.getTime())
      || sessionExpiresAt.getTime() <= Date.now()
    ) {
      throw new TypeError('Session expiry harus berupa tanggal masa depan');
    }

    const token = randomBytes(32).toString('base64url');
    const sessionId = randomUUID();
    const tokenHash = createHash('sha256')
      .update(token, 'utf8')
      .digest('hex');

    const result = await pool.query(
      `WITH active_user AS (
         SELECT id
         FROM ${usersTable}
         WHERE id = $1
           AND account_status = 'active'
           AND $4::timestamptz > NOW()
         FOR UPDATE
       )
       INSERT INTO ${sessionsTable} (
         id,
         user_id,
         session_token_hash,
         expires_at
       )
       SELECT $2, id, $3, $4
       FROM active_user
       RETURNING id, user_id, expires_at`,
      [userId, sessionId, tokenHash, sessionExpiresAt],
    );

    if (result.rowCount !== 1) {
      return null;
    }

    const row = result.rows[0];

    return {
      id: row.id,
      userId: row.user_id,
      token,
      expiresAt: row.expires_at,
    };
  }

  async function revokeSession({ token }) {
    const tokenHash = validateToken(token);

    const result = await pool.query(
      `UPDATE ${sessionsTable}
       SET revoked_at = NOW()
       WHERE session_token_hash = $1
         AND revoked_at IS NULL
       RETURNING id`,
      [tokenHash],
    );

    return result.rowCount === 1;
  }

  async function revokeSessionById({ sessionId, userId }) {
    validateUuid(sessionId, 'Session ID');
    validateUuid(userId, 'User ID');

    const result = await pool.query(
      `UPDATE ${sessionsTable}
       SET revoked_at = NOW()
       WHERE id = $1
         AND user_id = $2
         AND revoked_at IS NULL
       RETURNING id`,
      [sessionId, userId],
    );

    return result.rowCount === 1;
  }

  async function listActiveSessions({ userId }) {
    validateUuid(userId, 'User ID');

    const result = await pool.query(
      `SELECT
         id,
         expires_at,
         created_at
       FROM ${sessionsTable}
       WHERE user_id = $1
         AND revoked_at IS NULL
         AND expires_at > NOW()
       ORDER BY created_at DESC`,
      [userId],
    );

    return result.rows.map((row) => ({
      id: row.id,
      expiresAt: row.expires_at,
      createdAt: row.created_at,
    }));
  }

  return {
    findActiveSession,
    listActiveSessions,
    createSessionForUser,
    revokeSession,
    revokeSessionById,
  };
}
