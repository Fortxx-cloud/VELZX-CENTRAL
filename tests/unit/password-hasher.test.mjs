import test from 'node:test';
import assert from 'node:assert/strict';

import {
  hashPassword,
  verifyPassword,
} from '../../src/auth/password-hasher.mjs';

test('password hash verifies the original password', async () => {
  const password = 'Correct-Horse-Battery-2026!';
  const hash = await hashPassword(password);

  assert.equal(await verifyPassword(password, hash), true);
});

test('different password does not verify', async () => {
  const hash = await hashPassword('Correct-Horse-Battery-2026!');

  assert.equal(
    await verifyPassword('Different-Horse-Battery-2026!', hash),
    false,
  );
});

test('same password produces different salted hashes', async () => {
  const password = 'Correct-Horse-Battery-2026!';

  const first = await hashPassword(password);
  const second = await hashPassword(password);

  assert.notEqual(first, second);
  assert.equal(await verifyPassword(password, first), true);
  assert.equal(await verifyPassword(password, second), true);
});

test('rejects passwords shorter than 12 characters', async () => {
  await assert.rejects(
    hashPassword('short'),
    TypeError,
  );
});

test('rejects passwords longer than 128 characters', async () => {
  await assert.rejects(
    hashPassword('a'.repeat(129)),
    TypeError,
  );
});

test('rejects malformed stored hashes safely', async () => {
  assert.equal(
    await verifyPassword(
      'Correct-Horse-Battery-2026!',
      'invalid-hash',
    ),
    false,
  );
});

test('rejects unsupported hash parameters', async () => {
  assert.equal(
    await verifyPassword(
      'Correct-Horse-Battery-2026!',
      'scrypt$N=16384,r=8,p=1$YWJj$YWJj',
    ),
    false,
  );
});
