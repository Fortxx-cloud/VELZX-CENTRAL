import {
  randomBytes,
  scrypt as scryptCallback,
  timingSafeEqual,
} from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(scryptCallback);

const PARAMETERS = Object.freeze({
  N: 32768,
  r: 8,
  p: 1,
  keyLength: 64,
  maxmem: 64 * 1024 * 1024,
});

const SALT_LENGTH = 16;
const MIN_PASSWORD_LENGTH = 12;
const MAX_PASSWORD_LENGTH = 128;

function validatePassword(password) {
  if (typeof password !== 'string') {
    throw new TypeError('Password harus berupa string');
  }

  const length = [...password].length;
  const bytes = Buffer.byteLength(password, 'utf8');

  if (
    length < MIN_PASSWORD_LENGTH ||
    length > MAX_PASSWORD_LENGTH ||
    bytes > 1024
  ) {
    throw new TypeError(
      `Password harus ${MIN_PASSWORD_LENGTH}-${MAX_PASSWORD_LENGTH} karakter`,
    );
  }
}

function encode(value) {
  return value.toString('base64url');
}

function decode(value) {
  if (
    typeof value !== 'string' ||
    !/^[A-Za-z0-9_-]+$/.test(value)
  ) {
    throw new TypeError('Format password hash tidak valid');
  }

  const decoded = Buffer.from(value, 'base64url');

  if (decoded.toString('base64url') !== value) {
    throw new TypeError('Encoding password hash tidak valid');
  }

  return decoded;
}

export async function hashPassword(password) {
  validatePassword(password);

  const salt = randomBytes(SALT_LENGTH);

  const derivedKey = await scrypt(
    password,
    salt,
    PARAMETERS.keyLength,
    {
      N: PARAMETERS.N,
      r: PARAMETERS.r,
      p: PARAMETERS.p,
      maxmem: PARAMETERS.maxmem,
    },
  );

  return [
    'scrypt',
    `N=${PARAMETERS.N},r=${PARAMETERS.r},p=${PARAMETERS.p}`,
    encode(salt),
    encode(derivedKey),
  ].join('$');
}

export async function verifyPassword(password, storedHash) {
  validatePassword(password);

  if (typeof storedHash !== 'string') {
    return false;
  }

  const parts = storedHash.split('$');

  if (parts.length !== 4 || parts[0] !== 'scrypt') {
    return false;
  }

  if (parts[1] !== 'N=32768,r=8,p=1') {
    return false;
  }

  try {
    const salt = decode(parts[2]);
    const expected = decode(parts[3]);

    if (
      salt.length !== SALT_LENGTH ||
      expected.length !== PARAMETERS.keyLength
    ) {
      return false;
    }

    const actual = await scrypt(
      password,
      salt,
      PARAMETERS.keyLength,
      {
        N: PARAMETERS.N,
        r: PARAMETERS.r,
        p: PARAMETERS.p,
        maxmem: PARAMETERS.maxmem,
      },
    );

    return timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}
