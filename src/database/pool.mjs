import pg from 'pg';

const { Pool } = pg;

export function createDatabasePool(env = process.env) {
  const connectionString = env.DATABASE_URL?.trim();

  if (!connectionString) {
    throw new Error('DATABASE_URL wajib dikonfigurasi');
  }

  let parsed;

  try {
    parsed = new URL(connectionString);
  } catch {
    throw new Error('DATABASE_URL tidak valid');
  }

  if (
    parsed.protocol !== 'postgres:' &&
    parsed.protocol !== 'postgresql:'
  ) {
    throw new Error('DATABASE_URL harus menggunakan PostgreSQL');
  }

  const pool = new Pool({
    connectionString,
    max: 10,
    connectionTimeoutMillis: 5000,
    idleTimeoutMillis: 30000,
    application_name: 'velzx-central',
  });

  // Jangan mencatat connection string atau kredensial.
  pool.on('error', () => {
    console.error('Unexpected PostgreSQL pool error');
  });

  return pool;
}
