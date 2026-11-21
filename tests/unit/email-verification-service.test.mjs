import test from 'node:test';
import assert from 'node:assert/strict';

import {
  createEmailVerificationService,
} from '../../src/users/email-verification-service.mjs';

import {
  createIpFingerprint,
} from '../../src/security/ip-fingerprint.mjs';

const pepper = 'test-registration-pepper-0123456789-abcdefghijklmnopqrstuvwxyz';

test('uses verified ingress IP to generate registration fingerprint', async () => {
  let received;

  const repository = {
    async verifyEmailToken(params) {
      received = params;
      return { verified: true };
    },
  };

  const service = createEmailVerificationService({
    repository,
    env: { REGISTRATION_IP_PEPPER: pepper },
  });

  const result = await service.verifyEmailToken({
    verificationToken: 'test-token',
    ingressVerification: {
      accepted: true,
      clientIp: '192.0.2.10',
    },
  });

  assert.deepEqual(result, { verified: true });
  assert.equal(received.verificationToken, 'test-token');
  assert.equal(
    received.ipFingerprint,
    createIpFingerprint({
      ip: '192.0.2.10',
      pepper,
    }),
  );
});

test('does not use client-supplied IP or fingerprint', async () => {
  let received;

  const repository = {
    async verifyEmailToken(params) {
      received = params;
      return { verified: true };
    },
  };

  const service = createEmailVerificationService({
    repository,
    env: { REGISTRATION_IP_PEPPER: pepper },
  });

  await service.verifyEmailToken({
    verificationToken: 'test-token',
    clientIp: '198.51.100.99',
    ipFingerprint: 'v1:attacker-controlled',
    ingressVerification: {
      accepted: true,
      clientIp: '192.0.2.10',
    },
  });

  assert.equal(
    received.ipFingerprint,
    createIpFingerprint({
      ip: '192.0.2.10',
      pepper,
    }),
  );
  assert.notEqual(received.ipFingerprint, 'v1:attacker-controlled');
});

test('rejects missing or unaccepted ingress verification', async () => {
  let repositoryCalled = false;

  const service = createEmailVerificationService({
    repository: {
      async verifyEmailToken() {
        repositoryCalled = true;
      },
    },
    env: { REGISTRATION_IP_PEPPER: pepper },
  });

  for (const ingressVerification of [
    undefined,
    null,
    {},
    { accepted: false, clientIp: '192.0.2.10' },
    { accepted: true },
    { accepted: true, clientIp: 123 },
  ]) {
    await assert.rejects(
      service.verifyEmailToken({
        verificationToken: 'test-token',
        ingressVerification,
      }),
      /Verifikasi ingress tidak valid/,
    );
  }

  assert.equal(repositoryCalled, false);
});

test('fails closed when registration IP pepper is missing', async () => {
  let repositoryCalled = false;

  const service = createEmailVerificationService({
    repository: {
      async verifyEmailToken() {
        repositoryCalled = true;
      },
    },
    env: {},
  });

  assert.throws(
    () => createIpFingerprint({
      ip: '192.0.2.10',
      pepper: undefined,
    }),
  );

  await assert.rejects(
    service.verifyEmailToken({
      verificationToken: 'test-token',
      ingressVerification: {
        accepted: true,
        clientIp: '192.0.2.10',
      },
    }),
  );

  assert.equal(repositoryCalled, false);
});

test('rejects invalid ingress IP before calling repository', async () => {
  let repositoryCalled = false;

  const service = createEmailVerificationService({
    repository: {
      async verifyEmailToken() {
        repositoryCalled = true;
      },
    },
    env: { REGISTRATION_IP_PEPPER: pepper },
  });

  await assert.rejects(
    service.verifyEmailToken({
      verificationToken: 'test-token',
      ingressVerification: {
        accepted: true,
        clientIp: 'not-an-ip-address',
      },
    }),
  );

  assert.equal(repositoryCalled, false);
});
