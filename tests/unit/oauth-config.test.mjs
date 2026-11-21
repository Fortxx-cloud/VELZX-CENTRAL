import test from 'node:test';
import assert from 'node:assert/strict';

import { loadOAuthConfig } from '../../src/config/oauth.mjs';

const encryptionKey = Buffer.alloc(32, 7).toString('base64url');

function completeEnv() {
  return {
    GOOGLE_CLIENT_ID: 'google-client-id',
    GOOGLE_CLIENT_SECRET: 'google-client-secret',
    GOOGLE_REDIRECT_URI: 'https://central.example/auth/oauth/google/callback',

    GITHUB_CLIENT_ID: 'github-client-id',
    GITHUB_CLIENT_SECRET: 'github-client-secret',
    GITHUB_REDIRECT_URI: 'https://central.example/auth/oauth/github/callback',

    MICROSOFT_CLIENT_ID: 'microsoft-client-id',
    MICROSOFT_CLIENT_SECRET: 'microsoft-client-secret',
    MICROSOFT_REDIRECT_URI: 'https://central.example/auth/oauth/microsoft/callback',

    OAUTH_TRANSACTION_ENCRYPTION_KEY: encryptionKey,
    REGISTRATION_IP_PEPPER: 'p'.repeat(32),
  };
}

function googleOnlyEnv() {
  const env = completeEnv();

  for (const name of [
    'GITHUB_CLIENT_ID',
    'GITHUB_CLIENT_SECRET',
    'GITHUB_REDIRECT_URI',
    'MICROSOFT_CLIENT_ID',
    'MICROSOFT_CLIENT_SECRET',
    'MICROSOFT_REDIRECT_URI',
  ]) {
    delete env[name];
  }

  return env;
}

test('OAuth nonaktif jika seluruh provider kosong', () => {
  assert.equal(loadOAuthConfig({}), null);
});

test('konfigurasi lengkap menghasilkan tiga provider dan key 32 byte', () => {
  const config = loadOAuthConfig(completeEnv());

  assert.equal(config.encryptionKey.length, 32);
  assert.equal(config.microsoft.tenantId, 'common');
  assert.equal(config.google.clientId, 'google-client-id');
  assert.equal(config.github.clientId, 'github-client-id');
});

test('Google dapat aktif tanpa GitHub dan Microsoft', () => {
  const config = loadOAuthConfig(googleOnlyEnv());

  assert.equal(config.google.clientId, 'google-client-id');
  assert.equal(config.github, null);
  assert.equal(config.microsoft, null);
});

test('GitHub dapat aktif secara independen', () => {
  const env = completeEnv();

  for (const name of [
    'GOOGLE_CLIENT_ID',
    'GOOGLE_CLIENT_SECRET',
    'GOOGLE_REDIRECT_URI',
    'MICROSOFT_CLIENT_ID',
    'MICROSOFT_CLIENT_SECRET',
    'MICROSOFT_REDIRECT_URI',
  ]) {
    delete env[name];
  }

  const config = loadOAuthConfig(env);

  assert.equal(config.google, null);
  assert.equal(config.github.clientId, 'github-client-id');
  assert.equal(config.microsoft, null);
});

test('Microsoft dapat aktif secara independen', () => {
  const env = completeEnv();

  for (const name of [
    'GOOGLE_CLIENT_ID',
    'GOOGLE_CLIENT_SECRET',
    'GOOGLE_REDIRECT_URI',
    'GITHUB_CLIENT_ID',
    'GITHUB_CLIENT_SECRET',
    'GITHUB_REDIRECT_URI',
  ]) {
    delete env[name];
  }

  const config = loadOAuthConfig(env);

  assert.equal(config.google, null);
  assert.equal(config.github, null);
  assert.equal(config.microsoft.clientId, 'microsoft-client-id');
});

test('provider parsial dinonaktifkan jika tidak ada provider lengkap', () => {
  const env = {
    GOOGLE_CLIENT_ID: 'configured',
    GOOGLE_CLIENT_SECRET: 'google-secret',
  };

  assert.equal(loadOAuthConfig(env), null);
});

test('provider lengkap tetap aktif ketika provider lain parsial', () => {
  const env = googleOnlyEnv();
  env.GITHUB_CLIENT_ID = 'partial-github-client';

  const config = loadOAuthConfig(env);

  assert.equal(config.google.clientId, 'google-client-id');
  assert.equal(config.github, null);
  assert.equal(config.microsoft, null);
});

test('provider independen tetap mewajibkan encryption key', () => {
  const env = googleOnlyEnv();
  delete env.OAUTH_TRANSACTION_ENCRYPTION_KEY;

  assert.throws(
    () => loadOAuthConfig(env),
    /OAUTH_TRANSACTION_ENCRYPTION_KEY/,
  );
});

test('provider independen tetap mewajibkan IP pepper', () => {
  const env = googleOnlyEnv();
  delete env.REGISTRATION_IP_PEPPER;

  assert.throws(
    () => loadOAuthConfig(env),
    /REGISTRATION_IP_PEPPER/,
  );
});

test('encryption key dengan panjang tidak sesuai ditolak', () => {
  const env = googleOnlyEnv();
  env.OAUTH_TRANSACTION_ENCRYPTION_KEY = 'short';

  assert.throws(
    () => loadOAuthConfig(env),
    /Base64URL 32 byte/,
  );
});

test('registration IP pepper yang terlalu pendek ditolak', () => {
  const env = googleOnlyEnv();
  env.REGISTRATION_IP_PEPPER = 'short';

  assert.throws(
    () => loadOAuthConfig(env),
    /REGISTRATION_IP_PEPPER/,
  );
});

test('redirect URI HTTP ditolak', () => {
  const env = googleOnlyEnv();
  env.GOOGLE_REDIRECT_URI =
    'http://central.example/auth/oauth/google/callback';

  assert.throws(
    () => loadOAuthConfig(env),
    /google redirect URI/,
  );
});

test('redirect URI dengan path callback provider lain ditolak', () => {
  const env = googleOnlyEnv();
  env.GOOGLE_REDIRECT_URI =
    'https://central.example/auth/oauth/github/callback';

  assert.throws(
    () => loadOAuthConfig(env),
    /google redirect URI/,
  );
});

test('Microsoft tenant yang tidak valid ditolak', () => {
  const env = completeEnv();
  env.MICROSOFT_TENANT_ID = 'invalid-tenant';

  assert.throws(
    () => loadOAuthConfig(env),
    /MICROSOFT_TENANT_ID/,
  );
});

test('kredensial provider yang hanya berisi spasi dianggap tidak tersedia', () => {
  const env = googleOnlyEnv();
  env.GOOGLE_CLIENT_SECRET = '   ';

  assert.equal(loadOAuthConfig(env), null);
});

test('registration IP pepper yang hanya berisi spasi ditolak', () => {
  const env = googleOnlyEnv();
  env.REGISTRATION_IP_PEPPER = '   ';

  assert.throws(
    () => loadOAuthConfig(env),
    /REGISTRATION_IP_PEPPER/,
  );
});
