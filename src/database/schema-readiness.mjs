const SCHEMA = 'velzx_central';

const C = (type, nullable = false, maxLength = null) => ({
  type, nullable, maxLength,
});

const CHECK = 'c';
const PRIMARY = 'p';
const UNIQUE = 'u';
const FOREIGN = 'f';

const CONTRACT = {
  ingress_nonces: {
    columns: {
      nonce: C('character varying', false, 43),
      created_at: C('timestamp with time zone'),
      expires_at: C('timestamp with time zone'),
    },
    constraints: {
      ingress_nonces_pkey: [PRIMARY, 'primarykey(nonce)'],
      ingress_nonces_nonce_check: [CHECK, "check(nonce~'^[A-Za-z0-9_-]{43}$')"],
      ingress_nonces_check: [CHECK, 'check(expires_at>created_at)'],
    },
    indexes: ['idx_ingress_nonces_expires_at'],
  },

  users: {
    columns: {
      id: C('uuid'),
      email_normalized: C('character varying', false, 320),
      password_hash: C('character varying', true, 255),
      email_verified_at: C('timestamp with time zone', true),
      account_status: C('character varying', false, 24),
      created_at: C('timestamp with time zone'),
      updated_at: C('timestamp with time zone'),
    },
    constraints: {
      users_pkey: [PRIMARY, 'primarykey(id)'],
      users_email_normalized_key: [UNIQUE, 'unique(email_normalized)'],
      users_email_normalized_check: [
        CHECK,
        'check(length(email_normalized)>=3andlength(email_normalized)<=320andemail_normalized=lower(btrim(email_normalized)))',
      ],
      users_account_status_check: [
        CHECK,
        "check(account_status=any(array['pending_verification','active','suspended','disabled']))",
      ],
      users_check: [
        CHECK,
        "check(account_status<>'active'oremail_verified_atisnotnull)",
      ],
    },
    indexes: ['idx_users_status_created'],
  },

  user_identities: {
    columns: {
      id: C('uuid'),
      user_id: C('uuid'),
      provider: C('character varying', false, 16),
      provider_subject: C('character varying', false, 255),
      provider_email: C('character varying', true, 320),
      provider_email_verified: C('boolean'),
      created_at: C('timestamp with time zone'),
    },
    constraints: {
      user_identities_pkey: [PRIMARY, 'primarykey(id)'],
      user_identities_user_id_fkey: [
        FOREIGN,
        'foreignkey(user_id)referencesusers(id)ondeletecascade',
      ],
      user_identities_provider_provider_subject_key: [
        UNIQUE,
        'unique(provider,provider_subject)',
      ],
      user_identities_provider_check: [
        CHECK,
        "check(provider=any(array['google','github','microsoft']))",
      ],
      user_identities_provider_subject_check: [
        CHECK,
        'check(length(provider_subject)>=1andlength(provider_subject)<=255)',
      ],
      user_identities_check: [
        CHECK,
        'check(notprovider_email_verifiedorprovider_emailisnotnull)',
      ],
    },
    indexes: ['idx_user_identities_user'],
  },

  sessions: {
    columns: {
      id: C('uuid'),
      user_id: C('uuid'),
      session_token_hash: C('character varying', false, 64),
      expires_at: C('timestamp with time zone'),
      last_seen_at: C('timestamp with time zone', true),
      revoked_at: C('timestamp with time zone', true),
      created_at: C('timestamp with time zone'),
    },
    constraints: {
      sessions_pkey: [PRIMARY, 'primarykey(id)'],
      sessions_user_id_fkey: [
        FOREIGN,
        'foreignkey(user_id)referencesusers(id)ondeletecascade',
      ],
      sessions_session_token_hash_key: [
        UNIQUE,
        'unique(session_token_hash)',
      ],
      sessions_session_token_hash_check: [
        CHECK,
        "check(session_token_hash~'^[a-f0-9]{64}$')",
      ],
      sessions_check: [CHECK, 'check(expires_at>created_at)'],
      sessions_check1: [
        CHECK,
        'check(revoked_atisnullorrevoked_at>=created_at)',
      ],
      sessions_check2: [
        CHECK,
        'check(last_seen_atisnullorlast_seen_at>=created_at)',
      ],
    },
    indexes: ['idx_sessions_user_active'],
  },

  oauth_transactions: {
    columns: {
      id: C('uuid'),
      provider: C('character varying', false, 16),
      state_hash: C('character varying', false, 64),
      nonce_hash: C('character varying', true, 64),
      browser_binding_hash: C('character varying', false, 64),
      purpose: C('character varying', false, 16),
      initiating_user_id: C('uuid', true),
      initiating_session_id: C('uuid', true),
      secret_iv: C('bytea'),
      secret_ciphertext: C('bytea'),
      secret_auth_tag: C('bytea'),
      expires_at: C('timestamp with time zone'),
      consumed_at: C('timestamp with time zone', true),
      created_at: C('timestamp with time zone'),
    },
    constraints: {
      oauth_transactions_pkey: [PRIMARY, 'primarykey(id)'],
      oauth_transactions_state_hash_key: [
        UNIQUE,
        'unique(state_hash)',
      ],
      oauth_transactions_initiating_user_id_fkey: [
        FOREIGN,
        'foreignkey(initiating_user_id)referencesusers(id)ondeletecascade',
      ],
      oauth_transactions_initiating_session_id_fkey: [
        FOREIGN,
        'foreignkey(initiating_session_id)referencessessions(id)ondeletecascade',
      ],
      oauth_transactions_provider_check: [
        CHECK,
        "check(provider=any(array['google','github','microsoft']))",
      ],
      oauth_transactions_purpose_check: [
        CHECK,
        "check(purpose=any(array['login','link']))",
      ],
      oauth_transactions_state_hash_check: [
        CHECK,
        "check(state_hash~'^[a-f0-9]{64}$')",
      ],
      oauth_transactions_nonce_hash_check: [
        CHECK,
        "check(nonce_hashisnullornonce_hash~'^[a-f0-9]{64}$')",
      ],
      oauth_transactions_browser_binding_hash_check: [
        CHECK,
        "check(browser_binding_hash~'^[a-f0-9]{64}$')",
      ],
      oauth_transactions_secret_iv_check: [
        CHECK,
        'check(octet_length(secret_iv)=12)',
      ],
      oauth_transactions_secret_auth_tag_check: [
        CHECK,
        'check(octet_length(secret_auth_tag)=16)',
      ],
      oauth_transactions_check: [
        CHECK,
        'check(expires_at>created_at)',
      ],
      oauth_transactions_check1: [
        CHECK,
        'check(consumed_atisnullorconsumed_at>=created_at)',
      ],
      oauth_transactions_check2: [
        CHECK,
        "check(purpose='login'andinitiating_user_idisnullandinitiating_session_idisnullorpurpose='link'andinitiating_user_idisnotnullandinitiating_session_idisnotnull)",
      ],
    },
    indexes: [
      'idx_oauth_transactions_expiry',
      'idx_oauth_transactions_user',
    ],
  },

  registration_ip_claims: {
    columns: {
      id: C('bigint'),
      ip_fingerprint: C('character varying', false, 67),
      account_id: C('uuid'),
      verified_at: C('timestamp with time zone'),
      created_at: C('timestamp with time zone'),
    },
    constraints: {
      registration_ip_claims_pkey: [PRIMARY, 'primarykey(id)'],
      registration_ip_claims_account_id_key: [
        UNIQUE,
        'unique(account_id)',
      ],
      registration_ip_claims_ip_fingerprint_check: [
        CHECK,
        "check(ip_fingerprint~'^v1:[a-f0-9]{64}$')",
      ],
    },
    indexes: ['idx_registration_ip_claims_verified'],
  },

  security_events: {
    columns: {
      id: C('bigint'),
      event_type: C('text'),
      ip_fingerprint: C('character varying', true, 67),
      account_id: C('uuid', true),
      details: C('jsonb'),
      created_at: C('timestamp with time zone'),
    },
    constraints: {
      security_events_pkey: [PRIMARY, 'primarykey(id)'],
      security_events_event_type_check: [
        CHECK,
        "check(event_type=any(array['registration_ip_limit_reached','registration_ip_invalid','registration_ip_untrusted_source']))",
      ],
      security_events_ip_fingerprint_check: [
        CHECK,
        "check(ip_fingerprintisnullorip_fingerprint~'^v1:[a-f0-9]{64}$')",
      ],
    },
    indexes: [
      'idx_security_events_created_at',
      'idx_security_events_fingerprint',
    ],
  },
};

const INGRESS_TABLES = ['ingress_nonces'];
const OAUTH_TABLES = [
  'users',
  'user_identities',
  'sessions',
  'oauth_transactions',
  'registration_ip_claims',
  'security_events',
];

function normalizeDefinition(value) {
  const literals = [];

  const protectedSql = String(value).replace(
    /'(?:''|[^'])*'/g,
    literal => {
      const index = literals.push(literal) - 1;
      return `§literal${index}§`;
    },
  );

  let normalized = protectedSql
    .toLowerCase()
    .replace(/::(?:character varying|text)(?:\[\])?/g, '')
    .replace(/velzx_central(?:_test)?\./g, '')
    .replace(/\s+/g, '');

  normalized = normalized.replace(
    /§literal(\d+)§/g,
    (_, index) => literals[Number(index)],
  );

  return normalized;
}

async function readMetadata(pool) {
  const [columns, constraints, indexes] = await Promise.all([
    pool.query(
      `SELECT table_name, column_name, data_type, is_nullable,
              character_maximum_length
       FROM information_schema.columns
       WHERE table_schema = $1`,
      [SCHEMA],
    ),
    pool.query(
      `SELECT c.relname AS table_name,
              con.conname AS constraint_name,
              con.contype AS constraint_type,
              pg_get_constraintdef(con.oid, true) AS definition
       FROM pg_constraint con
       JOIN pg_class c ON c.oid = con.conrelid
       JOIN pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = $1`,
      [SCHEMA],
    ),
    pool.query(
      `SELECT tablename AS table_name, indexname AS index_name
       FROM pg_indexes
       WHERE schemaname = $1`,
      [SCHEMA],
    ),
  ]);

  return {
    columns: columns.rows,
    constraints: constraints.rows,
    indexes: indexes.rows,
  };
}

function validateTables(metadata, tableNames) {
  const errors = [];

  for (const tableName of tableNames) {
    const spec = CONTRACT[tableName];
    const tableColumns = metadata.columns.filter(
      row => row.table_name === tableName,
    );

    if (tableColumns.length === 0) {
      errors.push(`tabel ${tableName} tidak ditemukan`);
      continue;
    }

    for (const [columnName, expected] of Object.entries(spec.columns)) {
      const actual = tableColumns.find(
        row => row.column_name === columnName,
      );

      if (!actual) {
        errors.push(`${tableName}.${columnName} tidak ditemukan`);
        continue;
      }

      if (actual.data_type !== expected.type) {
        errors.push(`${tableName}.${columnName} tipe data tidak sesuai`);
      }

      if ((actual.is_nullable === 'YES') !== expected.nullable) {
        errors.push(`${tableName}.${columnName} nullability tidak sesuai`);
      }

      if (
        expected.maxLength !== null
        && Number(actual.character_maximum_length) !== expected.maxLength
      ) {
        errors.push(`${tableName}.${columnName} panjang kolom tidak sesuai`);
      }
    }

    for (const [name, [type, definition]] of Object.entries(spec.constraints)) {
      const actual = metadata.constraints.find(
        row => row.table_name === tableName
          && row.constraint_name === name,
      );

      if (!actual) {
        errors.push(`constraint ${tableName}.${name} tidak ditemukan`);
        continue;
      }

      if (actual.constraint_type !== type) {
        errors.push(`constraint ${tableName}.${name} tipe tidak sesuai`);
        continue;
      }

      if (normalizeDefinition(actual.definition) !== definition) {
        errors.push(`constraint ${tableName}.${name} definisi tidak sesuai`);
      }
    }

    for (const name of spec.indexes) {
      const actual = metadata.indexes.find(
        row => row.table_name === tableName && row.index_name === name,
      );

      if (!actual) {
        errors.push(`index ${tableName}.${name} tidak ditemukan`);
      }
    }
  }

  return errors;
}

async function assertReady(pool, tableNames, label) {
  if (!pool || typeof pool.query !== 'function') {
    throw new TypeError('Pool PostgreSQL tidak valid');
  }

  let metadata;

  try {
    metadata = await readMetadata(pool);
  } catch {
    throw new Error(`${label}: gagal membaca metadata schema produksi`);
  }

  const errors = validateTables(metadata, tableNames);

  if (errors.length > 0) {
    throw new Error(
      `${label}: schema ${SCHEMA} tidak siap: ${errors.join('; ')}`,
    );
  }

  return true;
}

export function assertIngressSchemaReady(pool) {
  return assertReady(pool, INGRESS_TABLES, 'Ingress');
}

export function assertOAuthSchemaReady(pool) {
  return assertReady(pool, OAUTH_TABLES, 'OAuth');
}
