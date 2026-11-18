import {
  createHash,
  createHmac,
  timingSafeEqual,
} from 'node:crypto';

const SIGNATURE_PATTERN = /^[a-f0-9]{64}$/;
const HASH_PATTERN = /^[a-f0-9]{64}$/;
const NONCE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const TIMESTAMP_PATTERN = /^\d{10}$/;

function validateSecret(secret) {
  if (
    typeof secret !== 'string' ||
    Buffer.byteLength(secret, 'utf8') < 32
  ) {
    throw new Error(
      'CENTRAL_INGRESS_SECRET must contain at least 32 bytes',
    );
  }
}

export function hashIngressBody(body) {
  if (
    typeof body !== 'string' &&
    !Buffer.isBuffer(body) &&
    !(body instanceof Uint8Array)
  ) {
    throw new TypeError('Ingress body must be bytes or a string');
  }

  return createHash('sha256')
    .update(body)
    .digest('hex');
}

export function buildIngressCanonicalRequest({
  method,
  pathname,
  search = '',
  timestamp,
  nonce,
  bodyHash,
  clientIp,
}) {
  if (
    typeof method !== 'string' ||
    !/^[A-Za-z]+$/.test(method)
  ) {
    throw new Error('Invalid ingress HTTP method');
  }

  if (
    typeof pathname !== 'string' ||
    !pathname.startsWith('/') ||
    /[\r\n]/.test(pathname)
  ) {
    throw new Error('Invalid ingress pathname');
  }

  if (
    typeof search !== 'string' ||
    (search !== '' && !search.startsWith('?')) ||
    /[\r\n]/.test(search)
  ) {
    throw new Error('Invalid ingress query string');
  }

  if (
    typeof timestamp !== 'string' ||
    !TIMESTAMP_PATTERN.test(timestamp)
  ) {
    throw new Error('Invalid ingress timestamp');
  }

  if (
    typeof nonce !== 'string' ||
    !NONCE_PATTERN.test(nonce)
  ) {
    throw new Error('Invalid ingress nonce');
  }

  if (
    typeof bodyHash !== 'string' ||
    !HASH_PATTERN.test(bodyHash)
  ) {
    throw new Error('Invalid ingress body hash');
  }

  if (
    typeof clientIp !== 'string' ||
    clientIp.length < 1 ||
    clientIp.length > 64 ||
    /[\r\n\s]/.test(clientIp)
  ) {
    throw new Error('Invalid ingress client IP');
  }

  return [
    'VELZX-INGRESS-V1',
    method.toUpperCase(),
    `${pathname}${search}`,
    timestamp,
    nonce,
    bodyHash,
    clientIp,
  ].join('\n');
}

export function createIngressSignature({
  secret,
  ...request
}) {
  validateSecret(secret);

  const canonical = buildIngressCanonicalRequest(request);

  return createHmac('sha256', secret)
    .update(canonical, 'utf8')
    .digest('hex');
}

export function verifyIngressSignature({
  secret,
  signature,
  nowSeconds = Math.floor(Date.now() / 1000),
  maxSkewSeconds = 60,
  ...request
}) {
  validateSecret(secret);

  if (
    !Number.isSafeInteger(nowSeconds) ||
    !Number.isSafeInteger(maxSkewSeconds) ||
    maxSkewSeconds < 0
  ) {
    throw new Error('Invalid ingress clock configuration');
  }

  if (
    typeof signature !== 'string' ||
    !SIGNATURE_PATTERN.test(signature)
  ) {
    return false;
  }

  if (
    typeof request.timestamp !== 'string' ||
    !TIMESTAMP_PATTERN.test(request.timestamp)
  ) {
    return false;
  }

  const timestamp = Number(request.timestamp);

  if (Math.abs(nowSeconds - timestamp) > maxSkewSeconds) {
    return false;
  }

  try {
    const expected = createIngressSignature({
      secret,
      ...request,
    });

    return timingSafeEqual(
      Buffer.from(expected, 'hex'),
      Buffer.from(signature, 'hex'),
    );
  } catch {
    return false;
  }
}
