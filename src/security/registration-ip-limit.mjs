export const MAX_VERIFIED_ACCOUNTS_PER_IP = 3;

const FINGERPRINT_PATTERN = /^v1:[a-f0-9]{64}$/;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Records a verified account against its source IP fingerprint.
 *
 * IMPORTANT:
 * - The caller must already have an active PostgreSQL transaction.
 * - The caller owns BEGIN, COMMIT and ROLLBACK.
 * - Call only after email verification has succeeded.
 * - When allowed=false, COMMIT is required to persist the security event.
 */
export async function claimVerifiedRegistrationIpInTransaction({
  client,
  ipFingerprint,
  accountId,
}) {
  if (!client || typeof client.query !== 'function') {
    throw new TypeError('A PostgreSQL transaction client is required');
  }

  if (
    typeof ipFingerprint !== 'string' ||
    !FINGERPRINT_PATTERN.test(ipFingerprint)
  ) {
    throw new TypeError('Invalid registration IP fingerprint');
  }

  if (
    typeof accountId !== 'string' ||
    !UUID_PATTERN.test(accountId)
  ) {
    throw new TypeError('Invalid account UUID');
  }

  // Serialize registration claims for the same fingerprint.
  await client.query(
    `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
    [ipFingerprint],
  );

  const countResult = await client.query(
    `SELECT COUNT(*) AS account_count
     FROM registration_ip_claims
     WHERE ip_fingerprint = $1`,
    [ipFingerprint],
  );

  const verifiedAccountCount = Number(
    countResult.rows?.[0]?.account_count,
  );

  if (!Number.isSafeInteger(verifiedAccountCount) ||
      verifiedAccountCount < 0) {
    throw new Error('Invalid registration IP claim count from database');
  }

  if (verifiedAccountCount >= MAX_VERIFIED_ACCOUNTS_PER_IP) {
    await client.query(
      `INSERT INTO security_events (
         event_type,
         ip_fingerprint,
         account_id,
         details
       )
       VALUES ($1, $2, $3, $4::jsonb)`,
      [
        'registration_ip_limit_reached',
        ipFingerprint,
        accountId,
        JSON.stringify({
          limit: MAX_VERIFIED_ACCOUNTS_PER_IP,
          verified_account_count: verifiedAccountCount,
        }),
      ],
    );

    return {
      allowed: false,
      reason: 'ip_account_limit_reached',
      limit: MAX_VERIFIED_ACCOUNTS_PER_IP,
      verifiedAccountCount,
    };
  }

  const insertResult = await client.query(
    `INSERT INTO registration_ip_claims (
       ip_fingerprint,
       account_id,
       verified_at
     )
     VALUES ($1, $2, NOW())
     RETURNING id, verified_at`,
    [ipFingerprint, accountId],
  );

  return {
    allowed: true,
    limit: MAX_VERIFIED_ACCOUNTS_PER_IP,
    verifiedAccountCount: verifiedAccountCount + 1,
    claim: insertResult.rows?.[0] ?? null,
  };
}
