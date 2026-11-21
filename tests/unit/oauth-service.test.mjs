import test from 'node:test';
import assert from 'node:assert/strict';

import {
  createOAuthService,
  OAuthServiceError,
  SESSION_TTL_SECONDS,
} from '../../src/auth/oauth/oauth-service.mjs';

const USER_ID = '11111111-1111-4111-8111-111111111111';
const SESSION_ID = '22222222-2222-4222-8222-222222222222';
const SESSION_TOKEN = 's'.repeat(43);
const BINDING = 'b'.repeat(43);
const PEPPER = 'p'.repeat(40);
const NOW = Date.parse('2026-11-20T00:00:00.000Z');

function createHarness({
  existing = null,
  identity = {},
  transaction = {},
  session = null,
  registrationResult = null,
  linkResult = null,
} = {}) {
  const calls = [];

  const providerIdentity = {
    provider: 'google',
    providerSubject: 'google-subject-123',
    email: 'user@gmail.com',
    emailVerified: true,
    providerEmailVerified: true,
    registrationEligible: true,
    ...identity,
  };

  const tx = {
    id: 'transaction-id',
    provider: 'google',
    purpose: 'login',
    initiatingUserId: null,
    initiatingSessionId: null,
    pkceVerifier: 'v'.repeat(43),
    nonce: 'n'.repeat(43),
    ...transaction,
  };

  const providers = {};

  for (const provider of ['google', 'github', 'microsoft']) {
    providers[provider] = {
      async createAuthorizationUrl(args) {
        calls.push({ method: 'createAuthorizationUrl', provider, args });
        return `https://identity.example/${provider}/authorize`;
      },
      async exchangeAuthorizationCode(args) {
        calls.push({ method: 'exchangeAuthorizationCode', provider, args });
        return { ...providerIdentity, provider };
      },
    };
  }

  const accountRepository = {
    async findUserByIdentity(args) {
      calls.push({ method: 'findUserByIdentity', args });
      return existing;
    },
    async createOAuthAccount(args) {
      calls.push({ method: 'createOAuthAccount', args });
      return registrationResult ?? {
        created: true,
        user: { id: USER_ID, email: 'user@gmail.com', accountStatus: 'active' },
        session: {
          id: SESSION_ID,
          token: 'new-session-token',
          expiresAt: new Date(NOW + SESSION_TTL_SECONDS * 1000),
        },
      };
    },
    async linkOAuthIdentity(args) {
      calls.push({ method: 'linkOAuthIdentity', args });
      return linkResult ?? {
        linked: true,
        identity: { id: 'identity-id', provider: 'google' },
      };
    },
  };

  const transactionRepository = {
    async create(args) {
      calls.push({ method: 'transactionCreate', args });
      return {
        id: 'transaction-id',
        state: 't'.repeat(43),
        expiresAt: new Date(NOW + 600000),
      };
    },
    async consume(args) {
      calls.push({ method: 'transactionConsume', args });
      return tx;
    },
  };

  const sessionRepository = {
    async findActiveSession(args) {
      calls.push({ method: 'findActiveSession', args });
      return session ?? {
        session: { id: SESSION_ID },
        user: { id: USER_ID, accountStatus: 'active' },
      };
    },
    async createSessionForUser(args) {
      calls.push({ method: 'createSessionForUser', args });
      return {
        id: SESSION_ID,
        userId: args.userId,
        token: 'created-session-token',
        expiresAt: args.sessionExpiresAt,
      };
    },
  };

  const service = createOAuthService({
    providers,
    accountRepository,
    transactionRepository,
    sessionRepository,
    registrationIpPepper: PEPPER,
    clock: () => NOW,
  });

  return {
    service,
    calls,
    providers,
    accountRepository,
    transactionRepository,
    sessionRepository,
  };
}

test('uses a seven-day absolute session lifetime', () => {
  assert.equal(SESSION_TTL_SECONDS, 604800);
});

test('starts Google login with PKCE, nonce, and a login transaction', async () => {
  const { service, calls } = createHarness();

  const result = await service.startLogin({
    provider: 'google',
    browserBinding: BINDING,
  });

  assert.equal(
    result.authorizationUrl,
    'https://identity.example/google/authorize',
  );
  assert.match(result.state, /^[A-Za-z0-9_-]{43}$/);

  const transaction = calls.find(
    (call) => call.method === 'transactionCreate',
  );

  assert.equal(transaction.args.provider, 'google');
  assert.equal(transaction.args.purpose, 'login');
  assert.equal(transaction.args.browserBinding, BINDING);
  assert.match(transaction.args.pkceVerifier, /^[A-Za-z0-9_-]{43}$/);
  assert.match(transaction.args.nonce, /^[A-Za-z0-9_-]{43}$/);
});

test('starts GitHub login without an OIDC nonce', async () => {
  const { service, calls } = createHarness();

  await service.startLogin({
    provider: 'github',
    browserBinding: BINDING,
  });

  const transaction = calls.find(
    (call) => call.method === 'transactionCreate',
  );

  assert.equal(transaction.args.provider, 'github');
  assert.equal(transaction.args.nonce, null);
});

test('rejects unsupported providers', async () => {
  const { service } = createHarness();

  await assert.rejects(
    service.startLogin({
      provider: 'unknown',
      browserBinding: BINDING,
    }),
    (error) => error.code === 'unsupported_provider',
  );
});

test('linked active identity logs in without an IP claim', async () => {
  const existing = {
    user: {
      id: USER_ID,
      email: 'user@gmail.com',
      accountStatus: 'active',
    },
    identity: { provider: 'google', subject: 'google-subject-123' },
  };

  const { service, calls } = createHarness({ existing });

  const result = await service.completeLogin({
    provider: 'google',
    code: 'authorization-code',
    state: 't'.repeat(43),
    browserBinding: BINDING,
    clientIp: '203.0.113.10',
  });

  assert.equal(result.authenticated, true);
  assert.equal(result.created, false);
  assert.equal(result.user.id, USER_ID);

  const createSession = calls.find(
    (call) => call.method === 'createSessionForUser',
  );

  assert.equal(createSession.args.userId, USER_ID);
  assert.equal(
    createSession.args.sessionExpiresAt.getTime(),
    NOW + SESSION_TTL_SECONDS * 1000,
  );

  assert.equal(
    calls.some((call) => call.method === 'createOAuthAccount'),
    false,
  );
});

test('rejects linked identities whose Central account is inactive', async () => {
  const { service } = createHarness({
    existing: {
      user: { id: USER_ID, accountStatus: 'suspended' },
      identity: { provider: 'google' },
    },
  });

  await assert.rejects(
    service.completeLogin({
      provider: 'google',
      code: 'authorization-code',
      state: 't'.repeat(43),
      browserBinding: BINDING,
      clientIp: '203.0.113.10',
    }),
    (error) => error.code === 'account_unavailable',
  );
});

test('registers a new account only with eligible verified provider email', async () => {
  const { service, calls } = createHarness();

  const result = await service.completeLogin({
    provider: 'google',
    code: 'authorization-code',
    state: 't'.repeat(43),
    browserBinding: BINDING,
    clientIp: '203.0.113.10',
  });

  assert.equal(result.authenticated, true);
  assert.equal(result.created, true);

  const registration = calls.find(
    (call) => call.method === 'createOAuthAccount',
  );

  assert.equal(registration.args.provider, 'google');
  assert.equal(registration.args.email, 'user@gmail.com');
  assert.equal(registration.args.providerEmailVerified, true);
  assert.match(registration.args.ipFingerprint, /^v1:[a-f0-9]{64}$/);
  assert.equal(
    registration.args.sessionExpiresAt.getTime(),
    NOW + SESSION_TTL_SECONDS * 1000,
  );
});

test('does not register an identity without verified email eligibility', async () => {
  const { service, calls } = createHarness({
    transaction: { provider: 'github' },
    identity: {
      email: null,
      emailVerified: false,
      providerEmailVerified: false,
      registrationEligible: false,
    },
  });

  await assert.rejects(
    service.completeLogin({
      provider: 'github',
      code: 'authorization-code',
      state: 't'.repeat(43),
      browserBinding: BINDING,
      clientIp: '203.0.113.10',
    }),
    (error) => error.code === 'registration_not_eligible',
  );

  assert.equal(
    calls.some((call) => call.method === 'createOAuthAccount'),
    false,
  );
});

test('maps registration IP limit rejection to a safe service error', async () => {
  const { service } = createHarness({
    registrationResult: {
      created: false,
      reason: 'ip_account_limit_reached',
    },
  });

  await assert.rejects(
    service.completeLogin({
      provider: 'google',
      code: 'authorization-code',
      state: 't'.repeat(43),
      browserBinding: BINDING,
      clientIp: '203.0.113.10',
    }),
    (error) => error.code === 'registration_ip_limit_reached',
  );
});

test('starts account linking only for an active Central session', async () => {
  const { service, calls } = createHarness();

  const result = await service.startLink({
    provider: 'github',
    browserBinding: BINDING,
    sessionToken: SESSION_TOKEN,
  });

  assert.equal(
    result.authorizationUrl,
    'https://identity.example/github/authorize',
  );

  const transaction = calls.find(
    (call) => call.method === 'transactionCreate',
  );

  assert.equal(transaction.args.purpose, 'link');
  assert.equal(transaction.args.initiatingUserId, USER_ID);
  assert.equal(transaction.args.initiatingSessionId, SESSION_ID);
  assert.equal(transaction.args.nonce, null);
});

test('rejects account linking without an active session', async () => {
  const { service } = createHarness({ session: null });

  const harness = createHarness({
    session: null,
  });

  harness.sessionRepository.findActiveSession = async () => null;

  await assert.rejects(
    harness.service.startLink({
      provider: 'google',
      browserBinding: BINDING,
      sessionToken: SESSION_TOKEN,
    }),
    (error) => error.code === 'authentication_required',
  );
});

test('completes account linking after revalidating the exact session', async () => {
  const { service, calls } = createHarness({
    transaction: {
      purpose: 'link',
      initiatingUserId: USER_ID,
      initiatingSessionId: SESSION_ID,
    },
    identity: {
      email: null,
      emailVerified: false,
      providerEmailVerified: false,
      registrationEligible: false,
    },
  });

  const result = await service.completeLink({
    provider: 'google',
    code: 'authorization-code',
    state: 't'.repeat(43),
    browserBinding: BINDING,
    sessionToken: SESSION_TOKEN,
  });

  assert.equal(result.linked, true);
  assert.equal(result.userId, USER_ID);

  const link = calls.find(
    (call) => call.method === 'linkOAuthIdentity',
  );

  assert.equal(link.args.userId, USER_ID);
  assert.equal(link.args.sessionId, SESSION_ID);
  assert.equal(link.args.providerEmail, null);
  assert.equal(link.args.providerEmailVerified, false);

  assert.equal(
    calls.some((call) => call.method === 'createOAuthAccount'),
    false,
  );

  assert.equal(
    calls.some((call) => call.method === 'createSessionForUser'),
    false,
  );
});

test('rejects account linking when the initiating session changes', async () => {
  const { service } = createHarness({
    transaction: {
      purpose: 'link',
      initiatingUserId: USER_ID,
      initiatingSessionId: SESSION_ID,
    },
    session: {
      session: { id: '33333333-3333-4333-8333-333333333333' },
      user: { id: USER_ID, accountStatus: 'active' },
    },
  });

  await assert.rejects(
    service.completeLink({
      provider: 'google',
      code: 'authorization-code',
      state: 't'.repeat(43),
      browserBinding: BINDING,
      sessionToken: SESSION_TOKEN,
    }),
    (error) => error.code === 'session_mismatch',
  );
});

test('rejects invalid or expired OAuth transactions', async () => {
  const harness = createHarness();

  harness.transactionRepository.consume = async () => null;

  await assert.rejects(
    harness.service.completeLogin({
      provider: 'google',
      code: 'authorization-code',
      state: 't'.repeat(43),
      browserBinding: BINDING,
      clientIp: '203.0.113.10',
    }),
    (error) => error.code === 'invalid_oauth_transaction',
  );
});

test('rejects callback when transaction purpose does not match login', async () => {
  const { service } = createHarness({
    transaction: {
      purpose: 'link',
      initiatingUserId: USER_ID,
      initiatingSessionId: SESSION_ID,
    },
  });

  await assert.rejects(
    service.completeLogin({
      provider: 'google',
      code: 'authorization-code',
      state: 't'.repeat(43),
      browserBinding: BINDING,
      clientIp: '203.0.113.10',
    }),
    (error) => error.code === 'invalid_oauth_purpose',
  );
});

test('rejects callback when transaction provider differs', async () => {
  const { service } = createHarness({
    transaction: { provider: 'github' },
  });

  await assert.rejects(
    service.completeLogin({
      provider: 'google',
      code: 'authorization-code',
      state: 't'.repeat(43),
      browserBinding: BINDING,
      clientIp: '203.0.113.10',
    }),
    (error) => error.code === 'invalid_oauth_transaction',
  );
});

test('maps account identity conflict without exposing database details', async () => {
  const { service } = createHarness({
    registrationResult: {
      created: false,
      reason: 'identity_conflict',
    },
  });

  await assert.rejects(
    service.completeLogin({
      provider: 'google',
      code: 'authorization-code',
      state: 't'.repeat(43),
      browserBinding: BINDING,
      clientIp: '203.0.113.10',
    }),
    (error) => error.code === 'account_conflict',
  );
});

test('rejects link callback when transaction purpose is login', async () => {
  const { service } = createHarness();

  await assert.rejects(
    service.completeLink({
      provider: 'google',
      code: 'authorization-code',
      state: 't'.repeat(43),
      browserBinding: BINDING,
      sessionToken: SESSION_TOKEN,
    }),
    (error) => error.code === 'invalid_oauth_purpose',
  );
});

test('does not allow an invalid session TTL', () => {
  const harness = createHarness();

  assert.throws(
    () => createOAuthService({
      providers: harness.providers,
      accountRepository: harness.accountRepository,
      transactionRepository: harness.transactionRepository,
      sessionRepository: harness.sessionRepository,
      registrationIpPepper: PEPPER,
      sessionTtlSeconds: 3600,
    }),
    /TTL 7 hari/,
  );
});

test('exports a safe OAuth service error type', () => {
  const error = new OAuthServiceError('test_code', 'Pesan aman');

  assert.equal(error.name, 'OAuthServiceError');
  assert.equal(error.code, 'test_code');
});


test('completeCallback consumes a login transaction exactly once', async () => {
  const { service, calls } = createHarness();

  const result = await service.completeCallback({
    provider: 'google',
    code: 'authorization-code',
    state: 't'.repeat(43),
    browserBinding: BINDING,
    clientIp: '203.0.113.10',
  });

  assert.equal(result.authenticated, true);
  assert.equal(result.created, true);
  assert.equal(
    calls.filter((call) => call.method === 'transactionConsume').length,
    1,
  );
  assert.equal(
    calls.filter((call) => call.method === 'exchangeAuthorizationCode').length,
    1,
  );
});

test('completeCallback consumes a link transaction exactly once', async () => {
  const { service, calls } = createHarness({
    transaction: {
      purpose: 'link',
      initiatingUserId: USER_ID,
      initiatingSessionId: SESSION_ID,
    },
    identity: {
      email: null,
      emailVerified: false,
      providerEmailVerified: false,
      registrationEligible: false,
    },
  });

  const result = await service.completeCallback({
    provider: 'google',
    code: 'authorization-code',
    state: 't'.repeat(43),
    browserBinding: BINDING,
    sessionToken: SESSION_TOKEN,
  });

  assert.equal(result.linked, true);
  assert.equal(result.userId, USER_ID);
  assert.equal(
    calls.filter((call) => call.method === 'transactionConsume').length,
    1,
  );
  assert.equal(
    calls.some((call) => call.method === 'createOAuthAccount'),
    false,
  );
});

test('completeCallback rejects an unsupported transaction purpose', async () => {
  const { service, calls } = createHarness({
    transaction: { purpose: 'unknown' },
  });

  await assert.rejects(
    service.completeCallback({
      provider: 'google',
      code: 'authorization-code',
      state: 't'.repeat(43),
      browserBinding: BINDING,
      clientIp: '203.0.113.10',
    }),
    (error) => error.code === 'invalid_oauth_purpose',
  );

  assert.equal(
    calls.filter((call) => call.method === 'transactionConsume').length,
    1,
  );
  assert.equal(
    calls.some((call) => call.method === 'findUserByIdentity'),
    false,
  );
  assert.equal(
    calls.some((call) => call.method === 'linkOAuthIdentity'),
    false,
  );
});


test('accepts independently configured OAuth providers', async () => {
  for (const provider of ['google', 'github', 'microsoft']) {
    const harness = createHarness();

    const service = createOAuthService({
      providers: {
        [provider]: harness.providers[provider],
      },
      accountRepository: harness.accountRepository,
      transactionRepository: harness.transactionRepository,
      sessionRepository: harness.sessionRepository,
      registrationIpPepper: PEPPER,
      clock: () => NOW,
    });

    const result = await service.startLogin({
      provider,
      browserBinding: BINDING,
    });

    assert.equal(result.provider, provider);
    assert.match(result.authorizationUrl, new RegExp(`/${provider}/authorize$`));
  }
});

test('rejects an empty OAuth provider configuration', () => {
  const harness = createHarness();

  assert.throws(
    () => createOAuthService({
      providers: {},
      accountRepository: harness.accountRepository,
      transactionRepository: harness.transactionRepository,
      sessionRepository: harness.sessionRepository,
      registrationIpPepper: PEPPER,
      clock: () => NOW,
    }),
    /Minimal satu OAuth provider harus dikonfigurasi/,
  );
});

test('rejects unsupported configured OAuth providers', () => {
  const harness = createHarness();

  assert.throws(
    () => createOAuthService({
      providers: {
        google: harness.providers.google,
        custom: harness.providers.google,
      },
      accountRepository: harness.accountRepository,
      transactionRepository: harness.transactionRepository,
      sessionRepository: harness.sessionRepository,
      registrationIpPepper: PEPPER,
      clock: () => NOW,
    }),
    (error) => error.code === 'unsupported_provider',
  );
});

test('rejects an incomplete configured OAuth provider', () => {
  const harness = createHarness();

  assert.throws(
    () => createOAuthService({
      providers: {
        google: {
          createAuthorizationUrl: async () => 'https://identity.example/google/authorize',
        },
      },
      accountRepository: harness.accountRepository,
      transactionRepository: harness.transactionRepository,
      sessionRepository: harness.sessionRepository,
      registrationIpPepper: PEPPER,
      clock: () => NOW,
    }),
    /Implementasi provider google tidak valid/,
  );
});
