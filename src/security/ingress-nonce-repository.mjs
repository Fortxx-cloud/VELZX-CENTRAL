const ALLOWED_SCHEMAS = new Set([
  'velzx_central_test',
  'velzx_central',
]);

const NONCE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

function validateClient(client) {
  if (!client || typeof client.query !== 'function') {
    throw new TypeError('Valid PostgreSQL client is required');
  }
}

function validateSchema(schema) {
  if (!ALLOWED_SCHEMAS.has(schema)) {
    throw new Error('Ingress nonce schema is not allowed');
  }

  return schema;
}

function validateNonce(nonce) {
  if (
    typeof nonce !== 'string' ||
    !NONCE_PATTERN.test(nonce)
  ) {
    throw new Error('Invalid ingress nonce');
  }
}

function validateExpiry(expiresAt) {
  if (
    !(expiresAt instanceof Date) ||
    !Number.isFinite(expiresAt.getTime()) ||
    expiresAt.getTime() <= Date.now()
  ) {
    throw new Error('Ingress nonce expiry must be in the future');
  }
}

export async function claimIngressNonce({
  client,
  nonce,
  expiresAt,
  schema = 'velzx_central_test',
}) {
  validateClient(client);
  validateSchema(schema);
  validateNonce(nonce);
  validateExpiry(expiresAt);

  const result = await client.query(
    `INSERT INTO ${schema}.ingress_nonces (
       nonce,
       expires_at
     )
     VALUES ($1, $2)
     ON CONFLICT (nonce) DO NOTHING
     RETURNING nonce`,
    [nonce, expiresAt],
  );

  return {
    accepted: result.rows.length === 1,
  };
}

export async function cleanupExpiredIngressNonces({
  client,
  schema = 'velzx_central_test',
  batchSize = 500,
}) {
  validateClient(client);
  validateSchema(schema);

  if (
    !Number.isSafeInteger(batchSize) ||
    batchSize < 1 ||
    batchSize > 10000
  ) {
    throw new Error('Invalid ingress nonce cleanup batch size');
  }

  const result = await client.query(
    `WITH expired AS (
       SELECT nonce
       FROM ${schema}.ingress_nonces
       WHERE expires_at <= NOW()
       ORDER BY expires_at
       LIMIT $1
       FOR UPDATE SKIP LOCKED
     )
     DELETE FROM ${schema}.ingress_nonces AS target
     USING expired
     WHERE target.nonce = expired.nonce
     RETURNING target.nonce`,
    [batchSize],
  );

  return {
    deleted: result.rows.length,
  };
}
