import { isIP } from 'node:net';

import {
  hashIngressBody,
  verifyIngressSignature,
} from '../../security/ingress-signature.mjs';

import {
  claimIngressNonce,
} from '../../security/ingress-nonce-repository.mjs';

const HEADER_NAMES = {
  timestamp: 'x-velzx-timestamp',
  nonce: 'x-velzx-nonce',
  clientIp: 'x-velzx-client-ip',
  bodyHash: 'x-velzx-body-sha256',
  signature: 'x-velzx-signature',
};

function readSingleHeader(req, name) {
  const values = req.headersDistinct?.[name];

  if (Array.isArray(values)) {
    return values.length === 1 ? values[0] : null;
  }

  const value = req.headers[name];

  return typeof value === 'string' ? value : null;
}

export function createIngressVerifier({
  pool,
  env = process.env,
  maxSkewSeconds = 60,
}) {
  if (!pool || typeof pool.query !== 'function') {
    throw new TypeError('PostgreSQL pool is required for ingress');
  }

  const secret = env.CENTRAL_INGRESS_SECRET;

  if (
    typeof secret !== 'string' ||
    Buffer.byteLength(secret, 'utf8') < 32
  ) {
    throw new Error(
      'CENTRAL_INGRESS_SECRET wajib tersedia dan minimal 32 bytes',
    );
  }

  if (
    !Number.isSafeInteger(maxSkewSeconds) ||
    maxSkewSeconds < 1 ||
    maxSkewSeconds > 300
  ) {
    throw new Error('Invalid ingress timestamp window');
  }

  return async function verifyIngress({ req, rawBody }) {
    const headers = {};

    for (const [key, name] of Object.entries(HEADER_NAMES)) {
      headers[key] = readSingleHeader(req, name);

      if (!headers[key]) {
        return { accepted: false, status: 401 };
      }
    }

    if (isIP(headers.clientIp) === 0) {
      return { accepted: false, status: 401 };
    }

    const target = req.url ?? '/';

    if (!target.startsWith('/') || target.startsWith('//')) {
      return { accepted: false, status: 401 };
    }

    let parsedTarget;

    try {
      parsedTarget = new URL(target, 'http://central.invalid');
    } catch {
      return { accepted: false, status: 401 };
    }

    const nowSeconds = Math.floor(Date.now() / 1000);
    const bodyHash = hashIngressBody(rawBody);

    if (bodyHash !== headers.bodyHash) {
      return { accepted: false, status: 401 };
    }

    const valid = verifyIngressSignature({
      secret,
      signature: headers.signature,
      method: req.method ?? '',
      pathname: parsedTarget.pathname,
      search: parsedTarget.search,
      timestamp: headers.timestamp,
      nonce: headers.nonce,
      bodyHash,
      clientIp: headers.clientIp,
      nowSeconds,
      maxSkewSeconds,
    });

    if (!valid) {
      return { accepted: false, status: 401 };
    }

    // Retensi dibuat cukup panjang agar nonce tidak terhapus
    // selama timestamp request masih mungkin diterima.
    const expiresAt = new Date(
      (Number(headers.timestamp) + maxSkewSeconds + 60) * 1000,
    );

    const claim = await claimIngressNonce({
      client: pool,
      nonce: headers.nonce,
      expiresAt,
      schema: 'velzx_central',
    });

    if (!claim.accepted) {
      return { accepted: false, status: 409 };
    }

    return {
      accepted: true,
      clientIp: headers.clientIp,
    };
  };
}
