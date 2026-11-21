const ALLOWED_SCHEMAS = new Set([
  'velzx_central',
  'velzx_central_test',
]);

const ALLOWED_TERMINAL_OUTCOMES = new Set([
  'PROVIDER_REJECTED',
  'RATE_LIMITED',
  'RETRYABLE_ERROR',
  'BILLING_REJECTED',
  'UNKNOWN',
]);

function validateRequestId(value) {
  if (
    typeof value !== 'string' ||
    value.trim().length === 0 ||
    value.length > 256
  ) {
    throw new TypeError('Request ID tidak valid');
  }

  return value;
}

function validatePayloadHash(value) {
  if (
    typeof value !== 'string' ||
    !/^[a-f0-9]{64}$/.test(value)
  ) {
    throw new TypeError('Payload hash tidak valid');
  }

  return value;
}

function validateKeyNumber(value) {
  if (!Number.isInteger(value) || value < 1 || value > 9) {
    throw new TypeError('Nomor email key tidak valid');
  }

  return value;
}

export function createEmailDeliveryRepository(
  pool,
  {
    schema = 'velzx_central',
    leaseSeconds = 120,
  } = {}
) {
  if (!pool || typeof pool.connect !== 'function') {
    throw new TypeError('PostgreSQL pool tidak valid');
  }

  if (!ALLOWED_SCHEMAS.has(schema)) {
    throw new TypeError('Schema database tidak diizinkan');
  }

  if (
    !Number.isInteger(leaseSeconds) ||
    leaseSeconds < 30 ||
    leaseSeconds > 900
  ) {
    throw new TypeError('Lease duration tidak valid');
  }

  const deliveries = `${schema}.email_deliveries`;
  const attempts = `${schema}.email_delivery_attempts`;

  async function transaction(callback) {
    const client = await pool.connect();

    try {
      await client.query('BEGIN');
      const result = await callback(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK').catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }

  async function claim({ requestId, payloadHash }) {
    validateRequestId(requestId);
    validatePayloadHash(payloadHash);

    return transaction(async client => {
      await client.query(
        'SELECT pg_advisory_xact_lock(hashtextextended($1, 0))',
        [requestId]
      );

      const inserted = await client.query(
        `INSERT INTO ${deliveries}
          (request_id, payload_hash, status, lease_expires_at)
         VALUES (
           $1,
           $2,
           'PENDING',
           NOW() + ($3 * INTERVAL '1 second')
         )
         ON CONFLICT (request_id) DO NOTHING
         RETURNING request_id`,
        [requestId, payloadHash, leaseSeconds]
      );

      if (inserted.rowCount === 1) {
        return {
          state: 'CLAIMED',
          requestId,
          attemptAllowed: true,
        };
      }

      const existing = await client.query(
        `SELECT
           request_id,
           payload_hash,
           status,
           successful_key_number,
           provider_email_id,
           attempt_count,
             lease_expires_at,
             next_attempt_at,
             last_error_code
         FROM ${deliveries}
         WHERE request_id = $1
         FOR UPDATE`,
        [requestId]
      );

      const delivery = existing.rows[0];

      if (!delivery) {
        throw new Error('Delivery record tidak ditemukan');
      }

      if (delivery.payload_hash !== payloadHash) {
        throw new Error(
          'Request ID sudah digunakan dengan payload berbeda'
        );
      }

      if (delivery.status !== 'PENDING') {
        return {
          state: delivery.status,
          requestId,
          successfulKeyNumber: delivery.successful_key_number,
          providerEmailId: delivery.provider_email_id,
          attemptCount: delivery.attempt_count,
          lastErrorCode: delivery.last_error_code,
          attemptAllowed: false,
        };
      }

      const timingResult = await client.query(
      `SELECT
         (
           lease_expires_at IS NOT NULL
           AND lease_expires_at > NOW()
         ) AS lease_active,
         (
           lease_expires_at IS NOT NULL
           AND lease_expires_at <= NOW()
         ) AS lease_expired,
         (
           next_attempt_at IS NOT NULL
           AND next_attempt_at > NOW()
         ) AS retry_not_due
       FROM ${deliveries}
       WHERE request_id = $1`,
      [requestId]
    );

    const timing = timingResult.rows[0];

    if (timing?.lease_expired) {
      await client.query(
        `UPDATE ${deliveries}
         SET status = 'UNKNOWN',
             lease_expires_at = NULL,
             next_attempt_at = NULL,
             last_error_code = 'INTERRUPTED_DELIVERY',
             updated_at = NOW()
         WHERE request_id = $1`,
        [requestId]
      );

      return {
        state: 'UNKNOWN',
        requestId,
        lastErrorCode: 'INTERRUPTED_DELIVERY',
        attemptAllowed: false,
      };
    }

    if (timing?.lease_active) {
      return {
        state: 'IN_PROGRESS',
        requestId,
        attemptCount: delivery.attempt_count,
        attemptAllowed: false,
      };
    }

    if (timing?.retry_not_due) {
      return {
        state: 'WAITING_RETRY',
        requestId,
        nextAttemptAt: delivery.next_attempt_at,
        attemptAllowed: false,
      };
    }

    await client.query(
      `UPDATE ${deliveries}
       SET lease_expires_at = NOW() + ($2 * INTERVAL '1 second'),
           next_attempt_at = NULL,
           updated_at = NOW()
       WHERE request_id = $1
         AND status = 'PENDING'`,
      [requestId, leaseSeconds]
    );

    return {
      state: 'CLAIMED',
      requestId,
      attemptCount: delivery.attempt_count,
      attemptAllowed: true,
    };
    });
  }

  async function beginAttempt({ requestId, keyNumber }) {
    validateRequestId(requestId);
    validateKeyNumber(keyNumber);

    const result = await transaction(async client => {
      const selected = await client.query(
        `SELECT status, lease_expires_at,
                (lease_expires_at > NOW()) AS lease_valid
         FROM ${deliveries}
         WHERE request_id = $1
         FOR UPDATE`,
        [requestId]
      );

      const delivery = selected.rows[0];

      if (!delivery || delivery.status !== 'PENDING') {
        throw new Error('Delivery tidak dalam status PENDING');
      }

      if (!delivery.lease_valid) {
        await client.query(
          `UPDATE ${deliveries}
           SET status = 'UNKNOWN',
               lease_expires_at = NULL,
               last_error_code = 'LEASE_EXPIRED',
               updated_at = NOW()
           WHERE request_id = $1`,
          [requestId]
        );

        return { leaseExpired: true };
      }

      const inserted = await client.query(
        `INSERT INTO ${attempts}
           (request_id, key_number, outcome)
         VALUES ($1, $2, 'IN_PROGRESS')
         RETURNING id`,
        [requestId, keyNumber]
      );

      await client.query(
        `UPDATE ${deliveries}
         SET attempt_count = attempt_count + 1,
             lease_expires_at = NOW() + ($2 * INTERVAL '1 second'),
             updated_at = NOW()
         WHERE request_id = $1
           AND status = 'PENDING'`,
        [requestId, leaseSeconds]
      );

      return {
        attemptId: inserted.rows[0].id,
        requestId,
        keyNumber,
      };
    });

    if (result.leaseExpired) {
      throw new Error('Delivery lease sudah kedaluwarsa');
    }

    return result;
  }

  async function finishAttempt({
    attemptId,
    outcome,
    httpStatus = null,
    errorCode = null,
  }) {
    if (
      !Number.isSafeInteger(Number(attemptId)) ||
      Number(attemptId) < 1
    ) {
      throw new TypeError('Attempt ID tidak valid');
    }

    if (
      outcome !== 'AUTH_REJECTED' &&
      !ALLOWED_TERMINAL_OUTCOMES.has(outcome)
    ) {
      throw new TypeError('Outcome percobaan tidak valid');
    }

    if (
      httpStatus !== null &&
      (!Number.isInteger(httpStatus) || httpStatus < 100 || httpStatus > 599)
    ) {
      throw new TypeError('HTTP status tidak valid');
    }

    return transaction(async client => {
      const result = await client.query(
        `SELECT request_id, outcome
         FROM ${attempts}
         WHERE id = $1
         FOR UPDATE`,
        [attemptId]
      );

      const attempt = result.rows[0];

      if (!attempt || attempt.outcome !== 'IN_PROGRESS') {
        throw new Error('Attempt tidak ditemukan atau sudah selesai');
      }

      await client.query(
        `UPDATE ${attempts}
         SET outcome = $2,
             http_status = $3,
             error_code = $4,
             completed_at = NOW()
         WHERE id = $1`,
        [attemptId, outcome, httpStatus, errorCode]
      );

      const definitiveRejection =
        outcome === 'PROVIDER_REJECTED' &&
        httpStatus >= 400 &&
        httpStatus < 500 &&
        httpStatus !== 429;

      if (
        outcome === 'AUTH_REJECTED' ||
        outcome === 'RETRYABLE_ERROR' ||
        definitiveRejection
      ) {
        await client.query(
          `UPDATE ${deliveries}
           SET lease_expires_at = NOW() + ($2 * INTERVAL '1 second'),
               last_error_code = $3,
               updated_at = NOW()
           WHERE request_id = $1
             AND status = 'PENDING'`,
          [attempt.request_id, leaseSeconds, errorCode || outcome]
        );
      } else {
        const status = outcome === 'UNKNOWN' ? 'UNKNOWN' : 'FAILED';

        await client.query(
          `UPDATE ${deliveries}
           SET status = $2,
               lease_expires_at = NULL,
               last_error_code = $3,
               updated_at = NOW()
           WHERE request_id = $1
             AND status = 'PENDING'`,
          [attempt.request_id, status, errorCode || outcome]
        );
      }

      return {
        requestId: attempt.request_id,
        outcome,
      };
    });
  }

  async function scheduleRetry({
    requestId,
    nextAttemptAt,
    errorCode = 'RETRYABLE_ERROR',
    allowNoAttempts = false,
  }) {
    validateRequestId(requestId);

    const retryDate = new Date(nextAttemptAt);
    if (!Number.isFinite(retryDate.getTime())) {
      throw new TypeError('Waktu retry tidak valid');
    }

    if (
      typeof errorCode !== 'string' ||
      errorCode.length === 0 ||
      errorCode.length > 100
    ) {
      throw new TypeError('Kode error retry tidak valid');
    }

    return transaction(async client => {
      const deliveryResult = await client.query(
        `SELECT
           status,
           (lease_expires_at > NOW()) AS lease_active
         FROM ${deliveries}
         WHERE request_id = $1
         FOR UPDATE`,
        [requestId]
      );

      const delivery = deliveryResult.rows[0];

      if (
        !delivery ||
        delivery.status !== 'PENDING' ||
        !delivery.lease_active
      ) {
        throw new Error('Delivery tidak memiliki lease aktif');
      }

      const attemptsResult = await client.query(
        `SELECT
           COUNT(*)::INTEGER AS total,
           COALESCE(
             BOOL_AND(
               outcome IN ('AUTH_REJECTED', 'RETRYABLE_ERROR')
               OR (
                 outcome = 'PROVIDER_REJECTED'
                 AND http_status BETWEEN 400 AND 499
                 AND http_status <> 429
               )
             ),
             FALSE
           ) AS all_retryable,
           COALESCE(BOOL_OR(outcome = 'IN_PROGRESS'), FALSE) AS active
         FROM ${attempts}
         WHERE request_id = $1`,
        [requestId]
      );

      const attemptState = attemptsResult.rows[0];

      const totalAttempts = Number(attemptState.total);

      if (
        !Number.isSafeInteger(totalAttempts) ||
        totalAttempts < 0 ||
        typeof allowNoAttempts !== 'boolean' ||
        (totalAttempts === 0 && allowNoAttempts !== true) ||
        (totalAttempts > 0 && !attemptState.all_retryable) ||
        attemptState.active
      ) {
        throw new Error('Riwayat attempt tidak aman untuk retry');
      }

      const updated = await client.query(
        `UPDATE ${deliveries}
         SET lease_expires_at = NULL,
             next_attempt_at = $2,
             last_error_code = $3,
             updated_at = NOW()
         WHERE request_id = $1
           AND status = 'PENDING'
           AND $2::TIMESTAMPTZ > NOW()
         RETURNING request_id, next_attempt_at`,
        [requestId, retryDate.toISOString(), errorCode]
      );

      if (updated.rowCount !== 1) {
        throw new Error('Gagal menyimpan jadwal retry');
      }

      return {
        state: 'WAITING_RETRY',
        requestId: updated.rows[0].request_id,
        nextAttemptAt: updated.rows[0].next_attempt_at,
      };
    });
  }

  async function completeSuccess({
    requestId,
    attemptId,
    keyNumber,
    providerEmailId,
  }) {
    validateRequestId(requestId);
    validateKeyNumber(keyNumber);

    if (
      typeof providerEmailId !== 'string' ||
      !providerEmailId.trim()
    ) {
      throw new TypeError('Provider email ID wajib diisi');
    }

    return transaction(async client => {
      const deliveryResult = await client.query(
        `SELECT status
         FROM ${deliveries}
         WHERE request_id = $1
         FOR UPDATE`,
        [requestId]
      );

      if (deliveryResult.rows[0]?.status !== 'PENDING') {
        throw new Error('Delivery tidak dapat diselesaikan');
      }

      const attemptResult = await client.query(
        `SELECT request_id, key_number, outcome
         FROM ${attempts}
         WHERE id = $1
         FOR UPDATE`,
        [attemptId]
      );

      const attempt = attemptResult.rows[0];

      if (
        !attempt ||
        attempt.request_id !== requestId ||
        Number(attempt.key_number) !== keyNumber ||
        attempt.outcome !== 'IN_PROGRESS'
      ) {
        throw new Error('Attempt sukses tidak valid');
      }

      await client.query(
        `UPDATE ${attempts}
         SET outcome = 'SUCCESS',
             http_status = 200,
             completed_at = NOW()
         WHERE id = $1`,
        [attemptId]
      );

      await client.query(
        `UPDATE ${deliveries}
         SET status = 'SUCCESS',
             successful_key_number = $2,
             provider_email_id = $3,
             lease_expires_at = NULL,
             last_error_code = NULL,
             updated_at = NOW()
         WHERE request_id = $1`,
        [requestId, keyNumber, providerEmailId]
      );

      return {
        state: 'SUCCESS',
        requestId,
        successfulKeyNumber: keyNumber,
        providerEmailId,
      };
    });
  }


  const QUOTA_STATUSES = new Set([
    'ACTIVE',
    'QUOTA_EXHAUSTED',
    'TEMPORARY_ERROR',
    'INVALID_KEY',
    'UNVERIFIED',
    'DISABLED',
  ]);

  function validateQuotaInput({
    keyNumber,
    status,
    dailyUsed,
    dailyLimit,
    resetsAt,
    cooldownUntil,
    lastErrorCode,
  }) {
    validateKeyNumber(keyNumber);

    if (!QUOTA_STATUSES.has(status)) {
      throw new TypeError('Status kuota tidak valid');
    }

    for (const [name, value] of [
      ['dailyUsed', dailyUsed],
      ['dailyLimit', dailyLimit],
    ]) {
      if (
        value !== null &&
        (!Number.isSafeInteger(value) || value < 0)
      ) {
        throw new TypeError(`${name} tidak valid`);
      }
    }

    for (const [name, value] of [
      ['resetsAt', resetsAt],
      ['cooldownUntil', cooldownUntil],
    ]) {
      if (
        value !== null &&
        (!Number.isFinite(new Date(value).getTime()))
      ) {
        throw new TypeError(`${name} tidak valid`);
      }
    }

    if (
      status === 'QUOTA_EXHAUSTED' &&
      resetsAt === null
    ) {
      throw new TypeError('Waktu reset wajib untuk kuota habis');
    }

    if (
      dailyUsed !== null &&
      dailyLimit !== null &&
      dailyUsed > dailyLimit &&
      status !== 'QUOTA_EXHAUSTED'
    ) {
      throw new TypeError('Pemakaian melebihi limit harus ditandai QUOTA_EXHAUSTED');
    }

    if (
      lastErrorCode !== null &&
      (typeof lastErrorCode !== 'string' || lastErrorCode.length > 100)
    ) {
      throw new TypeError('Kode error kuota tidak valid');
    }
  }

  async function setKeyQuotaState({
    keyNumber,
    status,
    dailyUsed = null,
    dailyLimit = null,
    resetsAt = null,
    cooldownUntil = null,
    lastErrorCode = null,
  }) {
    validateQuotaInput({
      keyNumber,
      status,
      dailyUsed,
      dailyLimit,
      resetsAt,
      cooldownUntil,
      lastErrorCode,
    });

    return transaction(async client => {
      const result = await client.query(
        `INSERT INTO ${schema}.resend_key_quota (
           key_number,
           status,
           daily_used,
           daily_limit,
           resets_at,
           cooldown_until,
           last_checked_at,
           last_error_code,
           updated_at
         )
         VALUES ($1, $2, $3, $4, $5, $6, NOW(), $7, NOW())
         ON CONFLICT (key_number) DO UPDATE SET
           status = EXCLUDED.status,
           daily_used = EXCLUDED.daily_used,
           daily_limit = EXCLUDED.daily_limit,
           resets_at = EXCLUDED.resets_at,
           cooldown_until = EXCLUDED.cooldown_until,
           last_checked_at = NOW(),
           last_error_code = EXCLUDED.last_error_code,
           updated_at = NOW()
         RETURNING *`,
        [
          keyNumber,
          status,
          dailyUsed,
          dailyLimit,
          resetsAt,
          cooldownUntil,
          lastErrorCode,
        ]
      );

      return result.rows[0];
    });
  }

  async function refreshExpiredQuotaKeys() {
    return transaction(async client => {
      const result = await client.query(
        `UPDATE ${schema}.resend_key_quota
         SET status = 'ACTIVE',
             daily_used = 0,
             resets_at = NULL,
             cooldown_until = NULL,
             last_error_code = NULL,
             updated_at = NOW()
         WHERE status = 'QUOTA_EXHAUSTED'
           AND resets_at <= NOW()
         RETURNING key_number`
      );

      return result.rows.map(row => Number(row.key_number));
    });
  }

  async function getKeyQuotaState(keyNumber) {
    validateKeyNumber(keyNumber);

    await refreshExpiredQuotaKeys();

    const result = await pool.query(
      `SELECT *
       FROM ${schema}.resend_key_quota
       WHERE key_number = $1`,
      [keyNumber]
    );

    return result.rows[0] ?? null;
  }

  async function listKeyQuotaStates() {
    await refreshExpiredQuotaKeys();

    const result = await pool.query(
      `SELECT *
       FROM ${schema}.resend_key_quota
       ORDER BY key_number ASC`
    );

    return result.rows;
  }

  return Object.freeze({
    claim,
    setKeyQuotaState,
    refreshExpiredQuotaKeys,
    getKeyQuotaState,
    listKeyQuotaStates,
    beginAttempt,
    finishAttempt,
    scheduleRetry,
    completeSuccess,
  });
}
