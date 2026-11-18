const MAX_BODY_BYTES = 1024 * 1024;

const INTERNAL_HEADERS = [
  'x-velzx-timestamp',
  'x-velzx-nonce',
  'x-velzx-client-ip',
  'x-velzx-body-sha256',
  'x-velzx-signature',
];

const HOP_BY_HOP_HEADERS = [
  'host',
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'content-length',
  'cf-connecting-ip',
  'x-real-ip',
];

function jsonResponse(status, message) {
  return new Response(
    JSON.stringify({ status: 'error', message }),
    {
      status,
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
      },
    },
  );
}

function validateOrigin(value) {
  if (typeof value !== 'string' || !value) {
    throw new Error('CENTRAL_ORIGIN is required');
  }

  const url = new URL(value);

  if (
    url.protocol !== 'https:' ||
    url.username ||
    url.password ||
    url.pathname !== '/' ||
    url.search ||
    url.hash
  ) {
    throw new Error('CENTRAL_ORIGIN must be an HTTPS origin without a path');
  }

  return url.origin;
}

function validateSecret(secret) {
  if (
    typeof secret !== 'string' ||
    new TextEncoder().encode(secret).length < 32
  ) {
    throw new Error('Invalid ingress configuration');
  }

  return secret;
}

function validateClientIp(ip) {
  if (
    typeof ip !== 'string' ||
    ip.length < 1 ||
    ip.length > 64 ||
    /[\s\r\n]/.test(ip)
  ) {
    return false;
  }

  // IPv4 validation.
  const ipv4 = ip.split('.');
  if (ipv4.length === 4) {
    return ipv4.every((part) =>
      /^(0|[1-9]\d{0,2})$/.test(part) &&
      Number(part) <= 255
    );
  }

  // IPv6 validation through URL parser.
  if (!ip.includes(':') || ip.includes('%')) {
    return false;
  }

  try {
    const parsed = new URL(`http://[${ip}]/`);
    return parsed.hostname.startsWith('[');
  } catch {
    return false;
  }
}

async function readBoundedBody(request) {
  if (!request.body) {
    return new Uint8Array();
  }

  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();

      if (done) break;

      total += value.byteLength;

      if (total > MAX_BODY_BYTES) {
        await reader.cancel();
        throw new Error('BODY_TOO_LARGE');
      }

      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const body = new Uint8Array(total);
  let offset = 0;

  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return body;
}

function toHex(bytes) {
  return Array.from(bytes, (byte) =>
    byte.toString(16).padStart(2, '0')
  ).join('');
}

function toBase64Url(bytes) {
  let binary = '';

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

async function sha256(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return toHex(new Uint8Array(digest));
}

async function createHmac(secret, canonical) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );

  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(canonical),
  );

  return toHex(new Uint8Array(signature));
}

async function createNonce() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return toBase64Url(bytes);
}

function createForwardHeaders(requestHeaders) {
  const headers = new Headers(requestHeaders);

  for (const name of INTERNAL_HEADERS) {
    headers.delete(name);
  }

  for (const name of HOP_BY_HOP_HEADERS) {
    headers.delete(name);
  }

  // Do not forward untrusted client-supplied proxy identity headers.
  for (const name of [...headers.keys()]) {
    if (name.toLowerCase().startsWith('x-forwarded-')) {
      headers.delete(name);
    }
  }

  return headers;
}

async function handleRequest(request, env) {
  let origin;
  let secret;

  try {
    origin = validateOrigin(env.CENTRAL_ORIGIN);
    secret = validateSecret(env.CENTRAL_INGRESS_SECRET);
  } catch {
    return jsonResponse(503, 'Ingress configuration unavailable');
  }

  const incomingUrl = new URL(request.url);

  // Reject ambiguous paths before constructing the origin URL.
  if (
    !incomingUrl.pathname.startsWith('/') ||
    incomingUrl.pathname.startsWith('//') ||
    /[\r\n]/.test(incomingUrl.pathname + incomingUrl.search)
  ) {
    return jsonResponse(400, 'Invalid request target');
  }

  const targetUrl = new URL(
    incomingUrl.pathname + incomingUrl.search,
    origin,
  );

  // Defense in depth: forwarding must never change the configured origin.
  if (targetUrl.origin !== origin) {
    return jsonResponse(400, 'Invalid request target');
  }

  const headers = createForwardHeaders(request.headers);

  // Health check remains unsigned and publicly accessible.
  if (
    request.method === 'GET' &&
    incomingUrl.pathname === '/health' &&
    incomingUrl.search === ''
  ) {
    try {
      return await fetch(targetUrl.toString(), {
        method: 'GET',
        headers,
        redirect: 'manual',
      });
    } catch {
      return jsonResponse(502, 'Central origin unavailable');
    }
  }

  let body;

  try {
    body = await readBoundedBody(request);
  } catch (error) {
    if (error.message === 'BODY_TOO_LARGE') {
      return jsonResponse(413, 'Request body too large');
    }

    return jsonResponse(400, 'Invalid request body');
  }

  const clientIp = request.headers.get('CF-Connecting-IP');

  if (!validateClientIp(clientIp)) {
    return jsonResponse(401, 'Invalid client IP');
  }

  try {
    const timestamp = String(Math.floor(Date.now() / 1000));
    const nonce = await createNonce();
    const bodyHash = await sha256(body);

    const canonical = [
      'VELZX-INGRESS-V1',
      request.method.toUpperCase(),
      `${incomingUrl.pathname}${incomingUrl.search}`,
      timestamp,
      nonce,
      bodyHash,
      clientIp,
    ].join('\n');

    const signature = await createHmac(secret, canonical);

    headers.set('X-Velzx-Timestamp', timestamp);
    headers.set('X-Velzx-Nonce', nonce);
    headers.set('X-Velzx-Client-IP', clientIp);
    headers.set('X-Velzx-Body-SHA256', bodyHash);
    headers.set('X-Velzx-Signature', signature);

    const init = {
      method: request.method,
      headers,
      redirect: 'manual',
    };

    if (request.method !== 'GET' && request.method !== 'HEAD') {
      init.body = body;
    }

    return await fetch(targetUrl.toString(), init);
  } catch {
    return jsonResponse(502, 'Ingress forwarding failed');
  }
}

export default {
  async fetch(request, env) {
    return handleRequest(request, env);
  },
};
