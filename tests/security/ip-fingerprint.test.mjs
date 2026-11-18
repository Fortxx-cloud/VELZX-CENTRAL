import test from 'node:test';
import assert from 'node:assert/strict';

import {
  normalizeIpAddress,
  createIpFingerprint,
} from '../../src/security/ip-fingerprint.mjs';

const pepper = 'test-pepper-0123456789-abcdefghijklmnopqrstuvwxyz';

test('normalizes IPv4', () => {
  assert.equal(
    normalizeIpAddress('192.0.2.10'),
    '192.0.2.10',
  );
});

test('normalizes compressed and expanded IPv6 identically', () => {
  assert.equal(
    normalizeIpAddress('2001:db8::1'),
    normalizeIpAddress('2001:0db8:0000:0000:0000:0000:0000:0001'),
  );
});

test('normalizes IPv4-mapped IPv6 to IPv4', () => {
  assert.equal(
    normalizeIpAddress('::ffff:192.0.2.10'),
    '192.0.2.10',
  );
});

test('rejects invalid IP addresses', () => {
  assert.throws(() => normalizeIpAddress('not-an-ip'));
  assert.throws(() => normalizeIpAddress('192.0.2.999'));
  assert.throws(() => normalizeIpAddress('2001:db8::1%eth0'));
});

test('generates deterministic fingerprints', () => {
  assert.equal(
    createIpFingerprint({ ip: '192.0.2.10', pepper }),
    createIpFingerprint({ ip: '192.0.2.10', pepper }),
  );
});

test('equivalent IPv6 forms produce identical fingerprints', () => {
  assert.equal(
    createIpFingerprint({ ip: '2001:db8::1', pepper }),
    createIpFingerprint({
      ip: '2001:0db8:0000:0000:0000:0000:0000:0001',
      pepper,
    }),
  );
});

test('different IPs produce different fingerprints', () => {
  assert.notEqual(
    createIpFingerprint({ ip: '192.0.2.10', pepper }),
    createIpFingerprint({ ip: '192.0.2.11', pepper }),
  );
});

test('different peppers produce different fingerprints', () => {
  assert.notEqual(
    createIpFingerprint({ ip: '192.0.2.10', pepper }),
    createIpFingerprint({ ip: '192.0.2.10', pepper: 'another-test-pepper-0123456789-abcdefghijklmnopqrstuvwxyz' }),
  );
});

test('rejects missing or weak pepper', () => {
  assert.throws(() => createIpFingerprint({
    ip: '192.0.2.10',
    pepper: '',
  }));

  assert.throws(() => createIpFingerprint({
    ip: '192.0.2.10',
    pepper: 'too-short',
  }));
});

test('fingerprint does not expose raw IP', () => {
  const result = createIpFingerprint({
    ip: '192.0.2.10',
    pepper,
  });

  assert.match(result, /^v1:[a-f0-9]{64}$/);
  assert.equal(result.includes('192.0.2.10'), false);
});

test('normalizes IPv6 addresses in the same /64 subnet identically', () => {
  assert.equal(
    normalizeIpAddress('2001:db8:abcd:12:1111:2222:3333:4444'),
    normalizeIpAddress('2001:db8:abcd:12:aaaa:bbbb:cccc:dddd'),
  );

  assert.equal(
    normalizeIpAddress('2001:db8:abcd:12:1111:2222:3333:4444'),
    '2001:0db8:abcd:0012::/64',
  );
});

test('different IPv6 /64 subnets remain distinct', () => {
  assert.notEqual(
    createIpFingerprint({
      ip: '2001:db8:abcd:12::1',
      pepper,
    }),
    createIpFingerprint({
      ip: '2001:db8:abcd:13::1',
      pepper,
    }),
  );
});

test('IPv6 addresses in the same /64 produce identical fingerprints', () => {
  assert.equal(
    createIpFingerprint({
      ip: '2001:db8:abcd:12::1',
      pepper,
    }),
    createIpFingerprint({
      ip: '2001:db8:abcd:12:ffff:eeee:dddd:cccc',
      pepper,
    }),
  );
});
