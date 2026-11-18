import { createHmac } from 'node:crypto';
import { isIP } from 'node:net';

export function normalizeIpAddress(input) {
  if (typeof input !== 'string') {
    throw new TypeError('IP address must be a string');
  }

  const ip = input.trim();

  if (isIP(ip) === 4) {
    return ip;
  }

  if (isIP(ip) !== 6 || ip.includes('%')) {
    throw new Error('Invalid IP address');
  }

  let address = ip.toLowerCase();

  // Convert an embedded IPv4 tail into two IPv6 groups.
  if (address.includes('.')) {
    const lastColon = address.lastIndexOf(':');
    const ipv4 = address.slice(lastColon + 1);

    if (isIP(ipv4) !== 4) {
      throw new Error('Invalid embedded IPv4 address');
    }

    const octets = ipv4.split('.').map(Number);
    const high = ((octets[0] << 8) | octets[1]).toString(16);
    const low = ((octets[2] << 8) | octets[3]).toString(16);

    address = `${address.slice(0, lastColon + 1)}${high}:${low}`;
  }

  const halves = address.split('::');

  if (halves.length > 2) {
    throw new Error('Invalid IPv6 compression');
  }

  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1]
    ? halves[1].split(':')
    : [];

  const groups = halves.length === 2
    ? [...left, ...Array(8 - left.length - right.length).fill('0'), ...right]
    : left;

  if (
    groups.length !== 8 ||
    groups.some(group => !/^[0-9a-f]{1,4}$/.test(group))
  ) {
    throw new Error('Invalid IPv6 address');
  }

  const normalized = groups.map(group => group.padStart(4, '0'));

  // Treat IPv4-mapped IPv6 as the equivalent IPv4 address.
  if (
    normalized.slice(0, 5).every(group => group === '0000') &&
    normalized[5] === 'ffff'
  ) {
    const high = Number.parseInt(normalized[6], 16);
    const low = Number.parseInt(normalized[7], 16);

    return [
      high >> 8,
      high & 255,
      low >> 8,
      low & 255,
    ].join('.');
  }

  // Group all IPv6 addresses in the same /64 subnet together.
  return `${normalized.slice(0, 4).join(':')}::/64`;
}

export function createIpFingerprint({
  ip,
  pepper,
}) {
  if (typeof pepper !== 'string' || Buffer.byteLength(pepper) < 32) {
    throw new Error('Registration IP pepper must contain at least 32 bytes');
  }

  const normalizedIp = normalizeIpAddress(ip);

  const digest = createHmac('sha256', pepper)
    .update('velzx-central:registration-ip:v1\0')
    .update(normalizedIp)
    .digest('hex');

  return `v1:${digest}`;
}
