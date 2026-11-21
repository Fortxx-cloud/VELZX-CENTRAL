import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from 'node:crypto';

const ALLOWED_SCHEMAS = new Set(['velzx_central_test', 'velzx_central']);
const PROVIDERS = new Set(['google', 'github', 'microsoft']);
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SECRET_PATTERN = /^[A-Za-z0-9_-]{43,128}$/;
const DEFAULT_TTL_SECONDS = 600;

function hash(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function validateSecret(value, name) {
  if (typeof value !== 'string' || !SECRET_PATTERN.test(value)) {
    throw new TypeError(`${name} tidak valid`);
  }
}

function encryptSecrets(key, secrets) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify(secrets), 'utf8'),
    cipher.final(),
  ]);

  return {
    iv,
    ciphertext,
    authTag: cipher.getAuthTag(),
  };
}

function decryptSecrets(key, row) {
  const decipher = createDecipheriv(
    'aes-256-gcm',
    key,
    row.secret_iv,
  );

  decipher.setAuthTag(row.secret_auth_tag);

  const plaintext = Buffer.concat([
    decipher.update(row.secret_ciphertext),
    decipher.final(),
  ]).toString('utf8');

  return JSON.parse(plaintext);
}

function safeHashEqual(left, right) {
  const a = Buffer.from(left, 'hex');
  const b = Buffer.from(right, 'hex');

  return a.length === 32 &&
    b.length === 32 &&
    timingSafeEqual(a, b);
}

export function createOAuthTransactionRepository(
  pool,
  {
    schema = 'velzx_central_test',
    encryptionKey,
    ttlSeconds = DEFAULT_TTL_SECONDS,
  } = {},
) {
  if (!pool || typeof pool.connect !== 'function') {
    throw new TypeError('PostgreSQL pool tidak valid');
  }

  if (!ALLOWED_SCHEMAS.has(schema)) {
    throw new TypeError('Schema database tidak diizinkan');
  }

  const key = Buffer.isBuffer(encryptionKey)
    ? Buffer.from(encryptionKey)
    : null;

  if (!key || key.length !== 32) {
    throw new TypeError('OAuth encryption key harus 32 byte');
  }

  if (
    !Number.isSafeInteger(ttlSeconds) ||
    ttlSeconds < 60 ||
    ttlSeconds > 900
  ) {
    throw new TypeError('OAuth transaction TTL tidak valid');
  }

  const table = `${schema}.oauth_transactions`;

  async function create({
    provider,
    purpose = 'login',
    browserBinding,
    pkceVerifier,
    nonce = null,
    initiatingUserId = null,
    initiatingSessionId = null,
  }) {
    if (!PROVIDERS.has(provider)) {
      throw new TypeError('OAuth provider tidak diizinkan');
    }

    if (!['login', 'link'].includes(purpose)) {
      throw new TypeError('OAuth transaction purpose tidak valid');
    }

    validateSecret(browserBinding, 'Browser binding');
    validateSecret(pkceVerifier, 'PKCE verifier');

    if (nonce !== null) {
      validateSecret(nonce, 'OIDC nonce');
    }

    if (purpose === 'link') {
      if (
        typeof initiatingUserId !== 'string' ||
        !UUID_PATTERN.test(initiatingUserId) ||
        typeof initiatingSessionId !== 'string' ||
        !UUID_PATTERN.test(initiatingSessionId)
      ) {
        throw new TypeError('Identitas sesi account linking tidak valid');
      }
    } else if (
      initiatingUserId !== null ||
      initiatingSessionId !== null
    ) {
      throw new TypeError('Login tidak boleh membawa identitas sesi linking');
    }

    const state = randomBytes(32).toString('base64url');
    const id = randomUUID();
    const encrypted = encryptSecrets(key, { pkceVerifier, nonce });

    const client = await pool.connect();

    try {
      await client.query('BEGIN');
      await client.query(`SET LOCAL search_path TO ${schema}, pg_catalog`);

      const result = await client.query(
        `INSERT INTO ${table} (
          id, provider, state_hash, nonce_hash,
          browser_binding_hash, purpose,
          initiating_user_id, initiating_session_id,
          secret_iv, secret_ciphertext, secret_auth_tag,
          expires_at
        ) VALUES (
          $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
          NOW() + ($12 * INTERVAL '1 second')
        )
        RETURNING expires_at`,
        [
          id,
          provider,
          hash(state),
          nonce === null ? null : hash(nonce),
          hash(browserBinding),
          purpose,
          initiatingUserId,
          initiatingSessionId,
          encrypted.iv,
          encrypted.ciphertext,
          encrypted.authTag,
          ttlSeconds,
        ],
      );

      if (result.rowCount !== 1) {
        throw new Error('OAuth transaction gagal dibuat');
      }

      await client.query('COMMIT');

      return {
        id,
        state,
        expiresAt: result.rows[0].expires_at,
      };
    } catch (error) {
      await client.query('ROLLBACK').catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }

  async function consume({
    provider,
    state,
    browserBinding,
  }) {
    if (
      !PROVIDERS.has(provider) ||
      typeof state !== 'string' ||
      !/^[A-Za-z0-9_-]{43}$/.test(state) ||
      typeof browserBinding !== 'string' ||
      !SECRET_PATTERN.test(browserBinding)
    ) {
      return null;
    }

    const client = await pool.connect();

    try {
      await client.query('BEGIN');
      await client.query(`SET LOCAL search_path TO ${schema}, pg_catalog`);

      const result = await client.query(
        `SELECT *, (expires_at > NOW()) AS is_unexpired
         FROM ${table}
         WHERE provider = $1
           AND state_hash = $2
         FOR UPDATE`,
        [provider, hash(state)],
      );

      const row = result.rows?.[0];

      if (
        !row ||
        row.consumed_at !== null ||
        row.is_unexpired !== true ||
        !safeHashEqual(row.browser_binding_hash, hash(browserBinding))
      ) {
        await client.query('COMMIT');
        return null;
      }

      const secrets = decryptSecrets(key, row);

      const nonceMatches = secrets.nonce === null
        ? row.nonce_hash === null
        : typeof secrets.nonce === 'string' &&
          row.nonce_hash !== null &&
          safeHashEqual(row.nonce_hash, hash(secrets.nonce));

      if (!nonceMatches) {
        throw new Error('OAuth nonce integrity check failed');
      }

      const consumed = await client.query(
        `UPDATE ${table}
         SET consumed_at = NOW()
         WHERE id = $1
           AND consumed_at IS NULL
           AND expires_at > NOW()
         RETURNING id`,
        [row.id],
      );

      if (consumed.rowCount !== 1) {
        throw new Error('OAuth transaction gagal dikonsumsi');
      }

      await client.query('COMMIT');

      return {
        id: row.id,
        provider: row.provider,
        purpose: row.purpose,
        initiatingUserId: row.initiating_user_id,
        initiatingSessionId: row.initiating_session_id,
        pkceVerifier: secrets.pkceVerifier,
        nonce: secrets.nonce,
      };
    } catch (error) {
      await client.query('ROLLBACK').catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }

  return Object.freeze({ create, consume });
}
