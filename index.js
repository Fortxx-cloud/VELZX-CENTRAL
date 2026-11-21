import { createCentralServer } from './src/http/server.mjs';
import { createDatabasePool } from './src/database/pool.mjs';
import {
  assertIngressSchemaReady,
  assertOAuthSchemaReady,
} from './src/database/schema-readiness.mjs';

import { loadOAuthConfig } from './src/config/oauth.mjs';

import { createGoogleOAuthProvider } from './src/auth/oauth/providers/google.mjs';
import { createGitHubOAuthProvider } from './src/auth/oauth/providers/github.mjs';
import { createMicrosoftOAuthProvider } from './src/auth/oauth/providers/microsoft.mjs';

import { createOAuthTransactionRepository } from './src/auth/oauth/oauth-transaction-repository.mjs';
import { createOAuthAccountRepository } from './src/auth/oauth/oauth-account-repository.mjs';
import { createOAuthService } from './src/auth/oauth/oauth-service.mjs';

import { createSessionRepository } from './src/auth/session/session-repository.mjs';
import { createOAuthRouteHandler } from './src/http/routes/oauth-routes.mjs';
import { createAuthRouteHandler } from './src/http/routes/auth-routes.mjs';

const port = Number(process.env.SERVER_PORT || 3000);

if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error('SERVER_PORT tidak valid');
}

const PRODUCTION_SCHEMA = 'velzx_central';


function createOAuthHandler(pool, config, sessionRepository, publicOrigin) {
  if (!config) {
    console.log('OAuth belum dikonfigurasi; endpoint OAuth tidak aktif');
    return null;
  }

  const providers = {};

  if (config.google) {
    providers.google = createGoogleOAuthProvider(config.google);
  }

  if (config.github) {
    providers.github = createGitHubOAuthProvider(config.github);
  }

  if (config.microsoft) {
    providers.microsoft = createMicrosoftOAuthProvider(config.microsoft);
  }

  const transactionRepository = createOAuthTransactionRepository(pool, {
    schema: PRODUCTION_SCHEMA,
    encryptionKey: config.encryptionKey,
    ttlSeconds: 600,
  });

  const accountRepository = createOAuthAccountRepository(pool, {
    schema: PRODUCTION_SCHEMA,
  });

  const oauthService = createOAuthService({
    providers,
    accountRepository,
    transactionRepository,
    sessionRepository,
    registrationIpPepper: config.registrationIpPepper,
  });

  if (!publicOrigin) {
    throw new Error('APP_ORIGIN wajib dikonfigurasi ketika OAuth aktif');
  }

  return createOAuthRouteHandler({
    oauthService,
    publicOrigin,
  });
}

const oauthConfig = loadOAuthConfig(process.env);
const pool = createDatabasePool();

let oauthRouteHandler = null;
let authRouteHandler = null;

try {
  await assertIngressSchemaReady(pool);
  console.log('Ingress database schema validated');

  if (oauthConfig) {
    await assertOAuthSchemaReady(pool);

    const sessionRepository = createSessionRepository(pool, {
      schema: PRODUCTION_SCHEMA,
    });

    const publicOrigin = process.env.APP_ORIGIN?.trim();

    oauthRouteHandler = createOAuthHandler(
      pool,
      oauthConfig,
      sessionRepository,
      publicOrigin,
    );

    authRouteHandler = createAuthRouteHandler({
      sessionRepository,
      publicOrigin,
    });

    console.log('OAuth provider configuration validated');
    console.log('Authentication API initialized');
  }
} catch (error) {
  await pool.end();
  throw error;
}

const server = createCentralServer({
  pool,
  oauthRouteHandler,
  authRouteHandler,
});

server.listen(port, '0.0.0.0', () => {
  console.log(`VELZX AI Central listening on port ${port}`);
});

let shuttingDown = false;

function shutdown() {
  if (shuttingDown) return;
  shuttingDown = true;

  server.close(async (error) => {
    if (error) {
      console.error('HTTP server shutdown failed');
      process.exitCode = 1;
    }

    try {
      await pool.end();
    } catch {
      console.error('PostgreSQL pool shutdown failed');
      process.exitCode = 1;
    }

    if (!error && process.exitCode !== 1) {
      console.log('VELZX AI Central stopped');
    }
  });
}

process.once('SIGTERM', shutdown);
process.once('SIGINT', shutdown);
