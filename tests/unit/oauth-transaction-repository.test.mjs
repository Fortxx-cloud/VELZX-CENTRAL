import test from 'node:test';
import assert from 'node:assert/strict';

import {
  createOAuthTransactionRepository,
} from '../../src/auth/oauth/oauth-transaction-repository.mjs';

const KEY = Buffer.alloc(32, 7);
const BINDING = 'B'.repeat(43);
const VERIFIER = 'V'.repeat(64);
const NONCE = 'N'.repeat(43);

function matchesTable(sql, table) {
  return sql.includes(`velzx_central_test.${table}`)
    || sql.includes(`velzx_central.${table}`);
}

function isInsertInto(sql, table) {
  return sql.trimStart().startsWith('INSERT INTO')
    && matchesTable(sql, table);
}

function createMockPool({
  expired = false,
  nonceHashMismatch = false,
  tamperCiphertext = false,
} = {}) {
  const calls = [];
  let inserted;
  let released = false;
  let consumed = false;

  const client = {
    async query(sql, params = []) {
      calls.push({ sql, params });

      if (['BEGIN', 'COMMIT', 'ROLLBACK'].includes(sql)) {
        return { rowCount: null, rows: [] };
      }

      if (sql.startsWith('SET LOCAL search_path')) {
        return { rowCount: null, rows: [] };
      }

      if (isInsertInto(sql, 'oauth_transactions')) {
        inserted = params;

        return {
          rowCount: 1,
          rows: [{
            expires_at: new Date(Date.now() + 600000),
          }],
        };
      }

      if (
        sql.trimStart().startsWith('SELECT') &&
        sql.includes('SELECT *') &&
        matchesTable(sql, 'oauth_transactions')
      ) {
        if (!inserted) return { rowCount: 0, rows: [] };

        const ciphertext = Buffer.from(inserted[9]);
        if (tamperCiphertext) ciphertext[0] ^= 1;

        return {
          rowCount: 1,
          rows: [{
            id: inserted[0],
            provider: inserted[1],
            state_hash: inserted[2],
            nonce_hash: nonceHashMismatch ? '0'.repeat(64) : inserted[3],
            browser_binding_hash: inserted[4],
            purpose: inserted[5],
            initiating_user_id: inserted[6],
            initiating_session_id: inserted[7],
            secret_iv: inserted[8],
            secret_ciphertext: ciphertext,
            secret_auth_tag: inserted[10],
            is_unexpired: !expired,
            expires_at: new Date(
              expired ? Date.now() - 1000 : Date.now() + 600000,
            ),
            consumed_at: consumed ? new Date() : null,
          }],
        };
      }

      if (
        sql.trimStart().startsWith('UPDATE') &&
        matchesTable(sql, 'oauth_transactions')
      ) {
        consumed = true;
        return { rowCount: 1, rows: [{ id: params[0] }] };
      }

      throw new Error(`Unexpected SQL: ${sql}`);
    },

    release() {
      released = true;
    },
  };

  return {
    pool: {
      async connect() {
        return client;
      },
    },
    calls,
    wasReleased: () => released,
  };
}

function createRepository(pool, options = {}) {
  return createOAuthTransactionRepository(pool, {
    encryptionKey: KEY,
    ...options,
  });
}

test('creates transaction with hashed state and encrypted secrets', async () => {
  const mock = createMockPool();
  const repository = createRepository(mock.pool);

  const result = await repository.create({
    provider: 'google',
    browserBinding: BINDING,
    pkceVerifier: VERIFIER,
    nonce: NONCE,
  });

  assert.match(result.state, /^[A-Za-z0-9_-]{43}$/);

  const insert = mock.calls.find(({ sql }) =>
    isInsertInto(sql, 'oauth_transactions'),
  );

  assert.ok(insert);
  assert.equal(insert.params[2].length, 64);
  assert.notEqual(insert.params[2], result.state);
  assert.equal(insert.params[3].length, 64);
  assert.equal(insert.params[4].length, 64);
  assert.notEqual(insert.params[9].toString(), VERIFIER);
  assert.ok(mock.calls.some(({ sql }) => sql === 'COMMIT'));
  assert.equal(mock.wasReleased(), true);
});

test('consumes transaction once and decrypts PKCE and nonce', async () => {
  const mock = createMockPool();
  const repository = createRepository(mock.pool);

  const created = await repository.create({
    provider: 'google',
    browserBinding: BINDING,
    pkceVerifier: VERIFIER,
    nonce: NONCE,
  });

  const result = await repository.consume({
    provider: 'google',
    state: created.state,
    browserBinding: BINDING,
  });

  assert.equal(result.provider, 'google');
  assert.equal(result.pkceVerifier, VERIFIER);
  assert.equal(result.nonce, NONCE);
  assert.equal(result.purpose, 'login');
  assert.ok(mock.calls.some(({ sql }) =>
    sql.includes('FOR UPDATE'),
  ));
  assert.ok(mock.calls.some(({ sql }) =>
    sql.includes('SET consumed_at = NOW()'),
  ));
});

test('rejects wrong browser binding without consuming transaction', async () => {
  const mock = createMockPool();
  const repository = createRepository(mock.pool);

  const created = await repository.create({
    provider: 'google',
    browserBinding: BINDING,
    pkceVerifier: VERIFIER,
  });

  const result = await repository.consume({
    provider: 'google',
    state: created.state,
    browserBinding: 'X'.repeat(43),
  });

  assert.equal(result, null);
  assert.ok(!mock.calls.some(({ sql }) =>
    sql.includes('SET consumed_at = NOW()'),
  ));
});

test('rejects expired transaction', async () => {
  const mock = createMockPool({ expired: true });
  const repository = createRepository(mock.pool);

  const created = await repository.create({
    provider: 'google',
    browserBinding: BINDING,
    pkceVerifier: VERIFIER,
  });

  const result = await repository.consume({
    provider: 'google',
    state: created.state,
    browserBinding: BINDING,
  });

  assert.equal(result, null);
});

test('rejects nonce hash mismatch and rolls back consumption', async () => {
  const mock = createMockPool({ nonceHashMismatch: true });
  const repository = createRepository(mock.pool);

  const created = await repository.create({
    provider: 'google',
    browserBinding: BINDING,
    pkceVerifier: VERIFIER,
    nonce: NONCE,
  });

  await assert.rejects(
    repository.consume({
      provider: 'google',
      state: created.state,
      browserBinding: BINDING,
    }),
    /nonce integrity check failed/,
  );

  assert.ok(mock.calls.some(({ sql }) => sql === 'ROLLBACK'));
});

test('rejects tampered AES-GCM ciphertext and rolls back consumption', async () => {
  const mock = createMockPool({ tamperCiphertext: true });
  const repository = createRepository(mock.pool);

  const created = await repository.create({
    provider: 'google',
    browserBinding: BINDING,
    pkceVerifier: VERIFIER,
    nonce: NONCE,
  });

  await assert.rejects(
    repository.consume({
      provider: 'google',
      state: created.state,
      browserBinding: BINDING,
    }));

  assert.ok(mock.calls.some(({ sql }) => sql === 'ROLLBACK'));
});

test('rejects malformed state before database connection', async () => {
  let connected = false;

  const repository = createRepository({
    async connect() {
      connected = true;
      throw new Error('Unexpected connection');
    },
  });

  const result = await repository.consume({
    provider: 'google',
    state: 'invalid',
    browserBinding: BINDING,
  });

  assert.equal(result, null);
  assert.equal(connected, false);
});

test('rejects invalid provider and PKCE verifier', async () => {
  const repository = createRepository({
    async connect() {
      throw new Error('Should not connect');
    },
  });

  await assert.rejects(
    repository.create({
      provider: 'unknown',
      browserBinding: BINDING,
      pkceVerifier: VERIFIER,
    }),
    /provider tidak diizinkan/,
  );

  await assert.rejects(
    repository.create({
      provider: 'google',
      browserBinding: BINDING,
      pkceVerifier: 'short',
    }),
    /PKCE verifier tidak valid/,
  );
});

test('requires authenticated identity for account linking', async () => {
  const repository = createRepository({
    async connect() {
      throw new Error('Should not connect');
    },
  });

  await assert.rejects(
    repository.create({
      provider: 'github',
      purpose: 'link',
      browserBinding: BINDING,
      pkceVerifier: VERIFIER,
    }),
    /Identitas sesi account linking tidak valid/,
  );
});

test('rejects encryption key with incorrect length', () => {
  assert.throws(
    () => createOAuthTransactionRepository({}, {
      encryptionKey: Buffer.alloc(16),
    }),
    /PostgreSQL pool tidak valid/,
  );

  assert.throws(
    () => createOAuthTransactionRepository(
      { async connect() {} },
      { encryptionKey: Buffer.alloc(16) },
    ),
    /OAuth encryption key harus 32 byte/,
  );
});


test('uses production schema only when explicitly selected', async () => {
  const mock = createMockPool();
  const repository = createRepository(mock.pool, {
    schema: 'velzx_central',
  });

  await repository.create({
    provider: 'google',
    browserBinding: BINDING,
    pkceVerifier: VERIFIER,
    nonce: NONCE,
  });

  assert.ok(mock.calls.some(({ sql }) =>
    sql === 'SET LOCAL search_path TO velzx_central, pg_catalog'
  ));
  assert.ok(mock.calls.some(({ sql }) =>
    sql.includes('INSERT INTO velzx_central.oauth_transactions')
  ));
  assert.ok(!mock.calls.some(({ sql }) =>
    sql.includes('velzx_central_test.')
  ));
});

test('keeps test schema as the transaction repository default', async () => {
  const mock = createMockPool();
  const repository = createRepository(mock.pool);

  await repository.create({
    provider: 'google',
    browserBinding: BINDING,
    pkceVerifier: VERIFIER,
  });

  assert.ok(mock.calls.some(({ sql }) =>
    sql === 'SET LOCAL search_path TO velzx_central_test, pg_catalog'
  ));
});

test('rejects public schema for OAuth transactions', () => {
  assert.throws(
    () => createOAuthTransactionRepository(
      { async connect() {} },
      { schema: 'public', encryptionKey: KEY },
    ),
    /Schema database tidak diizinkan/,
  );
});
