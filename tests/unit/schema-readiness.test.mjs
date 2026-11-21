import test from 'node:test';
import assert from 'node:assert/strict';

import {
  assertIngressSchemaReady,
  assertOAuthSchemaReady,
} from '../../src/database/schema-readiness.mjs';

const specs = {
  ingress_nonces: {
    columns: {
      nonce: ['character varying', 'NO', 43],
      created_at: ['timestamp with time zone', 'NO', null],
      expires_at: ['timestamp with time zone', 'NO', null],
    },
    constraints: {
      ingress_nonces_pkey: 'p',
      ingress_nonces_nonce_check: 'c',
      ingress_nonces_check: 'c',
    },
    indexes: ['idx_ingress_nonces_expires_at'],
  },
  users: {
    columns: {
      id: ['uuid', 'NO'],
      email_normalized: ['character varying', 'NO', 320],
      password_hash: ['character varying', 'YES', 255],
      email_verified_at: ['timestamp with time zone', 'YES'],
      account_status: ['character varying', 'NO', 24],
      created_at: ['timestamp with time zone', 'NO'],
      updated_at: ['timestamp with time zone', 'NO'],
    },
    constraints: {
      users_pkey: 'p',
      users_email_normalized_key: 'u',
      users_email_normalized_check: 'c',
      users_account_status_check: 'c',
      users_check: 'c',
    },
    indexes: ['idx_users_status_created'],
  },
  user_identities: {
    columns: {
      id: ['uuid', 'NO'],
      user_id: ['uuid', 'NO'],
      provider: ['character varying', 'NO', 16],
      provider_subject: ['character varying', 'NO', 255],
      provider_email: ['character varying', 'YES', 320],
      provider_email_verified: ['boolean', 'NO'],
      created_at: ['timestamp with time zone', 'NO'],
    },
    constraints: {
      user_identities_pkey: 'p',
      user_identities_user_id_fkey: 'f',
      user_identities_provider_provider_subject_key: 'u',
      user_identities_provider_check: 'c',
      user_identities_provider_subject_check: 'c',
      user_identities_check: 'c',
    },
    indexes: ['idx_user_identities_user'],
  },
  sessions: {
    columns: {
      id: ['uuid', 'NO'],
      user_id: ['uuid', 'NO'],
      session_token_hash: ['character varying', 'NO', 64],
      expires_at: ['timestamp with time zone', 'NO'],
      last_seen_at: ['timestamp with time zone', 'YES'],
      revoked_at: ['timestamp with time zone', 'YES'],
      created_at: ['timestamp with time zone', 'NO'],
    },
    constraints: {
      sessions_pkey: 'p',
      sessions_user_id_fkey: 'f',
      sessions_session_token_hash_key: 'u',
      sessions_session_token_hash_check: 'c',
      sessions_check: 'c',
      sessions_check1: 'c',
      sessions_check2: 'c',
    },
    indexes: ['idx_sessions_user_active'],
  },
  oauth_transactions: {
    columns: {
      id: ['uuid', 'NO'],
      provider: ['character varying', 'NO', 16],
      state_hash: ['character varying', 'NO', 64],
      nonce_hash: ['character varying', 'YES', 64],
      browser_binding_hash: ['character varying', 'NO', 64],
      purpose: ['character varying', 'NO', 16],
      initiating_user_id: ['uuid', 'YES'],
      initiating_session_id: ['uuid', 'YES'],
      secret_iv: ['bytea', 'NO'],
      secret_ciphertext: ['bytea', 'NO'],
      secret_auth_tag: ['bytea', 'NO'],
      expires_at: ['timestamp with time zone', 'NO'],
      consumed_at: ['timestamp with time zone', 'YES'],
      created_at: ['timestamp with time zone', 'NO'],
    },
    constraints: {
      oauth_transactions_pkey: 'p',
      oauth_transactions_state_hash_key: 'u',
      oauth_transactions_initiating_user_id_fkey: 'f',
      oauth_transactions_initiating_session_id_fkey: 'f',
      oauth_transactions_provider_check: 'c',
      oauth_transactions_purpose_check: 'c',
      oauth_transactions_state_hash_check: 'c',
      oauth_transactions_nonce_hash_check: 'c',
      oauth_transactions_browser_binding_hash_check: 'c',
      oauth_transactions_secret_iv_check: 'c',
      oauth_transactions_secret_auth_tag_check: 'c',
      oauth_transactions_check: 'c',
      oauth_transactions_check1: 'c',
      oauth_transactions_check2: 'c',
    },
    indexes: [
      'idx_oauth_transactions_expiry',
      'idx_oauth_transactions_user',
    ],
  },
  registration_ip_claims: {
    columns: {
      id: ['bigint', 'NO'],
      ip_fingerprint: ['character varying', 'NO', 67],
      account_id: ['uuid', 'NO'],
      verified_at: ['timestamp with time zone', 'NO'],
      created_at: ['timestamp with time zone', 'NO'],
    },
    constraints: {
      registration_ip_claims_pkey: 'p',
      registration_ip_claims_account_id_key: 'u',
      registration_ip_claims_ip_fingerprint_check: 'c',
    },
    indexes: ['idx_registration_ip_claims_verified'],
  },
  security_events: {
    columns: {
      id: ['bigint', 'NO'],
      event_type: ['text', 'NO'],
      ip_fingerprint: ['character varying', 'YES', 67],
      account_id: ['uuid', 'YES'],
      details: ['jsonb', 'NO'],
      created_at: ['timestamp with time zone', 'NO'],
    },
    constraints: {
      security_events_pkey: 'p',
      security_events_event_type_check: 'c',
      security_events_ip_fingerprint_check: 'c',
    },
    indexes: [
      'idx_security_events_created_at',
      'idx_security_events_fingerprint',
    ],
  },
};


const definitions = {
  ingress_nonces_pkey: 'PRIMARY KEY (nonce)',
  ingress_nonces_nonce_check: "CHECK (nonce::text ~ '^[A-Za-z0-9_-]{43}$'::text)",
  ingress_nonces_check: 'CHECK (expires_at > created_at)',
  users_pkey: 'PRIMARY KEY (id)',
  users_email_normalized_key: 'UNIQUE (email_normalized)',
  users_email_normalized_check: 'CHECK (length(email_normalized::text) >= 3 AND length(email_normalized::text) <= 320 AND email_normalized::text = lower(btrim(email_normalized::text)))',
  users_account_status_check: "CHECK (account_status::text = ANY (ARRAY['pending_verification'::character varying, 'active'::character varying, 'suspended'::character varying, 'disabled'::character varying]::text[]))",
  users_check: "CHECK (account_status::text <> 'active'::text OR email_verified_at IS NOT NULL)",
  user_identities_pkey: 'PRIMARY KEY (id)',
  user_identities_user_id_fkey: 'FOREIGN KEY (user_id) REFERENCES velzx_central_test.users(id) ON DELETE CASCADE',
  user_identities_provider_provider_subject_key: 'UNIQUE (provider, provider_subject)',
  user_identities_provider_check: "CHECK (provider::text = ANY (ARRAY['google'::character varying, 'github'::character varying, 'microsoft'::character varying]::text[]))",
  user_identities_provider_subject_check: 'CHECK (length(provider_subject::text) >= 1 AND length(provider_subject::text) <= 255)',
  user_identities_check: 'CHECK (NOT provider_email_verified OR provider_email IS NOT NULL)',
  sessions_pkey: 'PRIMARY KEY (id)',
  sessions_user_id_fkey: 'FOREIGN KEY (user_id) REFERENCES velzx_central_test.users(id) ON DELETE CASCADE',
  sessions_session_token_hash_key: 'UNIQUE (session_token_hash)',
  sessions_session_token_hash_check: "CHECK (session_token_hash::text ~ '^[a-f0-9]{64}$'::text)",
  sessions_check: 'CHECK (expires_at > created_at)',
  sessions_check1: 'CHECK (revoked_at IS NULL OR revoked_at >= created_at)',
  sessions_check2: 'CHECK (last_seen_at IS NULL OR last_seen_at >= created_at)',
  oauth_transactions_pkey: 'PRIMARY KEY (id)',
  oauth_transactions_state_hash_key: 'UNIQUE (state_hash)',
  oauth_transactions_initiating_user_id_fkey: 'FOREIGN KEY (initiating_user_id) REFERENCES velzx_central_test.users(id) ON DELETE CASCADE',
  oauth_transactions_initiating_session_id_fkey: 'FOREIGN KEY (initiating_session_id) REFERENCES velzx_central_test.sessions(id) ON DELETE CASCADE',
  oauth_transactions_provider_check: "CHECK (provider::text = ANY (ARRAY['google'::character varying, 'github'::character varying, 'microsoft'::character varying]::text[]))",
  oauth_transactions_purpose_check: "CHECK (purpose::text = ANY (ARRAY['login'::character varying, 'link'::character varying]::text[]))",
  oauth_transactions_state_hash_check: "CHECK (state_hash::text ~ '^[a-f0-9]{64}$'::text)",
  oauth_transactions_nonce_hash_check: "CHECK (nonce_hash IS NULL OR nonce_hash::text ~ '^[a-f0-9]{64}$'::text)",
  oauth_transactions_browser_binding_hash_check: "CHECK (browser_binding_hash::text ~ '^[a-f0-9]{64}$'::text)",
  oauth_transactions_secret_iv_check: 'CHECK (octet_length(secret_iv) = 12)',
  oauth_transactions_secret_auth_tag_check: 'CHECK (octet_length(secret_auth_tag) = 16)',
  oauth_transactions_check: 'CHECK (expires_at > created_at)',
  oauth_transactions_check1: 'CHECK (consumed_at IS NULL OR consumed_at >= created_at)',
  oauth_transactions_check2: "CHECK (purpose::text = 'login'::text AND initiating_user_id IS NULL AND initiating_session_id IS NULL OR purpose::text = 'link'::text AND initiating_user_id IS NOT NULL AND initiating_session_id IS NOT NULL)",
  registration_ip_claims_pkey: 'PRIMARY KEY (id)',
  registration_ip_claims_account_id_key: 'UNIQUE (account_id)',
  registration_ip_claims_ip_fingerprint_check: "CHECK (ip_fingerprint::text ~ '^v1:[a-f0-9]{64}$'::text)",
  security_events_pkey: 'PRIMARY KEY (id)',
  security_events_event_type_check: "CHECK (event_type = ANY (ARRAY['registration_ip_limit_reached'::text, 'registration_ip_invalid'::text, 'registration_ip_untrusted_source'::text]))",
  security_events_ip_fingerprint_check: "CHECK (ip_fingerprint IS NULL OR ip_fingerprint::text ~ '^v1:[a-f0-9]{64}$'::text)",
};

function createMetadata() {
  const columns = [];
  const constraints = [];
  const indexes = [];

  for (const [tableName, spec] of Object.entries(specs)) {
    for (const [columnName, definition] of Object.entries(spec.columns)) {
      columns.push({
        table_name: tableName,
        column_name: columnName,
        data_type: definition[0],
        is_nullable: definition[1],
        character_maximum_length: definition[2] ?? null,
      });
    }

    for (const [constraintName, constraintType] of Object.entries(spec.constraints)) {
      constraints.push({
        table_name: tableName,
        constraint_name: constraintName,
        constraint_type: constraintType,
        definition: definitions[constraintName],
      });
    }

    for (const indexName of spec.indexes) {
      indexes.push({
        table_name: tableName,
        index_name: indexName,
      });
    }
  }

  return { columns, constraints, indexes };
}

function createMockPool(metadata = createMetadata()) {
  const calls = [];

  return {
    calls,
    async query(sql, params) {
      calls.push({ sql, params });

      if (sql.includes('information_schema.columns')) {
        return { rows: metadata.columns };
      }

      if (sql.includes('pg_constraint')) {
        return { rows: metadata.constraints };
      }

      if (sql.includes('pg_indexes')) {
        return { rows: metadata.indexes };
      }

      throw new Error('Query metadata tidak dikenal');
    },
  };
}

test('schema ingress lengkap diterima', async () => {
  const pool = createMockPool();

  assert.equal(await assertIngressSchemaReady(pool), true);
  assert.equal(pool.calls.length, 3);
  assert.ok(pool.calls.every(call =>
    call.params[0] === 'velzx_central'
  ));
});

test('schema OAuth lengkap diterima', async () => {
  const pool = createMockPool();

  assert.equal(await assertOAuthSchemaReady(pool), true);
  assert.equal(pool.calls.length, 3);
});

test('schema ingress yang hilang ditolak', async () => {
  const metadata = createMetadata();
  metadata.columns = metadata.columns.filter(
    row => row.table_name !== 'ingress_nonces',
  );

  await assert.rejects(
    assertIngressSchemaReady(createMockPool(metadata)),
    /tabel ingress_nonces tidak ditemukan/,
  );
});

test('tabel OAuth yang hilang ditolak', async () => {
  const metadata = createMetadata();
  metadata.columns = metadata.columns.filter(
    row => row.table_name !== 'oauth_transactions',
  );

  await assert.rejects(
    assertOAuthSchemaReady(createMockPool(metadata)),
    /tabel oauth_transactions tidak ditemukan/,
  );
});

test('kolom wajib yang hilang ditolak', async () => {
  const metadata = createMetadata();
  metadata.columns = metadata.columns.filter(
    row => !(row.table_name === 'users'
      && row.column_name === 'email_normalized'),
  );

  await assert.rejects(
    assertOAuthSchemaReady(createMockPool(metadata)),
    /users\.email_normalized tidak ditemukan/,
  );
});

test('tipe data kolom yang salah ditolak', async () => {
  const metadata = createMetadata();
  const column = metadata.columns.find(
    row => row.table_name === 'sessions'
      && row.column_name === 'session_token_hash',
  );
  column.data_type = 'text';

  await assert.rejects(
    assertOAuthSchemaReady(createMockPool(metadata)),
    /sessions\.session_token_hash tipe data tidak sesuai/,
  );
});

test('nullability kolom yang salah ditolak', async () => {
  const metadata = createMetadata();
  const column = metadata.columns.find(
    row => row.table_name === 'user_identities'
      && row.column_name === 'provider_email',
  );
  column.is_nullable = 'NO';

  await assert.rejects(
    assertOAuthSchemaReady(createMockPool(metadata)),
    /user_identities\.provider_email nullability tidak sesuai/,
  );
});

test('unique constraint penting yang hilang ditolak', async () => {
  const metadata = createMetadata();
  metadata.constraints = metadata.constraints.filter(
    row => row.constraint_name
      !== 'user_identities_provider_provider_subject_key',
  );

  await assert.rejects(
    assertOAuthSchemaReady(createMockPool(metadata)),
    /constraint user_identities\.user_identities_provider_provider_subject_key tidak ditemukan/,
  );
});

test('check constraint keamanan yang hilang ditolak', async () => {
  const metadata = createMetadata();
  metadata.constraints = metadata.constraints.filter(
    row => row.constraint_name !== 'oauth_transactions_secret_iv_check',
  );

  await assert.rejects(
    assertOAuthSchemaReady(createMockPool(metadata)),
    /constraint oauth_transactions\.oauth_transactions_secret_iv_check tidak ditemukan/,
  );
});

test('indeks penting yang hilang ditolak', async () => {
  const metadata = createMetadata();
  metadata.indexes = metadata.indexes.filter(
    row => row.index_name !== 'idx_registration_ip_claims_verified',
  );

  await assert.rejects(
    assertOAuthSchemaReady(createMockPool(metadata)),
    /index registration_ip_claims\.idx_registration_ip_claims_verified tidak ditemukan/,
  );
});


test('definisi CHECK yang salah ditolak', async () => {
  const metadata = createMetadata();
  const constraint = metadata.constraints.find(
    row => row.constraint_name === 'users_check',
  );
  constraint.definition = 'CHECK (account_status IS NOT NULL)';

  await assert.rejects(
    assertOAuthSchemaReady(createMockPool(metadata)),
    /constraint users\.users_check definisi tidak sesuai/,
  );
});

test('definisi FOREIGN KEY yang salah ditolak', async () => {
  const metadata = createMetadata();
  const constraint = metadata.constraints.find(
    row => row.constraint_name === 'sessions_user_id_fkey',
  );
  constraint.definition =
    'FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL';

  await assert.rejects(
    assertOAuthSchemaReady(createMockPool(metadata)),
    /constraint sessions\.sessions_user_id_fkey definisi tidak sesuai/,
  );
});

test('definisi UNIQUE yang salah ditolak', async () => {
  const metadata = createMetadata();
  const constraint = metadata.constraints.find(
    row => row.constraint_name === 'users_email_normalized_key',
  );
  constraint.definition = 'UNIQUE (account_status)';

  await assert.rejects(
    assertOAuthSchemaReady(createMockPool(metadata)),
    /constraint users\.users_email_normalized_key definisi tidak sesuai/,
  );
});

test('nonce hash constraint wajib tersedia', async () => {
  const metadata = createMetadata();
  metadata.constraints = metadata.constraints.filter(
    row => row.constraint_name !== 'oauth_transactions_nonce_hash_check',
  );

  await assert.rejects(
    assertOAuthSchemaReady(createMockPool(metadata)),
    /constraint oauth_transactions\.oauth_transactions_nonce_hash_check tidak ditemukan/,
  );
});

test('pool PostgreSQL yang tidak valid ditolak', async () => {
  await assert.rejects(
    assertIngressSchemaReady(null),
    /Pool PostgreSQL tidak valid/,
  );
});

test('kegagalan membaca metadata ditangani secara fail-closed', async () => {
  const pool = {
    async query() {
      throw new Error('detail internal database');
    },
  };

  await assert.rejects(
    assertIngressSchemaReady(pool),
    error => {
      assert.match(error.message, /Ingress: gagal membaca metadata/);
      assert.doesNotMatch(error.message, /detail internal database/);
      return true;
    },
  );
});
