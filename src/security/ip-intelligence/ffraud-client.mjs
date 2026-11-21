import { isIP } from 'node:net';
import { URL } from 'node:url';

const API_BASE_URL = 'https://api.ffraud.com/public/ip/';
const MAX_RESPONSE_BYTES = 64 * 1024;
const MIN_DATA_COMPLETENESS = 0.6;

const SIGNAL_FIELDS = [
  'vpn',
  'proxy',
  'tor',
  'is_residential_proxy',
];

function unavailable(reason) {
  return {
    decision: 'unavailable',
    reason,
    source: 'ffraud',
  };
}

function challenge(reason, data = {}) {
  return {
    decision: 'challenge',
    reason,
    source: 'ffraud',
    ...data,
  };
}

function isValidTimeout(value) {
  return Number.isSafeInteger(value) && value >= 100 && value <= 30000;
}

function canonicalIp(value) {
  if (typeof value !== 'string' || isIP(value) === 0) {
    return null;
  }

  try {
    const host = isIP(value) === 6 ? `[${value}]` : value;
    return new URL(`http://${host}/`).hostname.toLowerCase();
  } catch {
    return null;
  }
}

async function readBoundedResponse(response) {
  if (!response.body || typeof response.body.getReader !== 'function') {
    return { error: 'provider_response_unreadable' };
  }

  const reader = response.body.getReader();
  const chunks = [];
  let totalBytes = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();

      if (done) break;

      if (!(value instanceof Uint8Array)) {
        return { error: 'provider_response_unreadable' };
      }

      totalBytes += value.byteLength;

      if (totalBytes > MAX_RESPONSE_BYTES) {
        try {
          await reader.cancel();
        } catch {}
        return { error: 'provider_response_too_large' };
      }

      chunks.push(value);
    }
  } catch {
    return { error: 'provider_response_unreadable' };
  } finally {
    reader.releaseLock();
  }

  const combined = new Uint8Array(totalBytes);
  let offset = 0;

  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }

  try {
    return {
      body: new TextDecoder('utf-8', { fatal: true }).decode(combined),
    };
  } catch {
    return { error: 'provider_invalid_json' };
  }
}

export function createFfraudClient({
  fetchImpl = globalThis.fetch,
  timeoutMs = 5000,
} = {}) {
  if (typeof fetchImpl !== 'function') {
    throw new TypeError('FFraud fetch implementation tidak valid');
  }

  if (!isValidTimeout(timeoutMs)) {
    throw new TypeError('FFraud timeout harus 100–30000 ms');
  }

  async function inspectIp({ ingressVerification } = {}) {
    if (
      !ingressVerification ||
      ingressVerification.accepted !== true ||
      typeof ingressVerification.clientIp !== 'string'
    ) {
      throw new TypeError('Verifikasi ingress tidak valid');
    }

    const normalizedInput = ingressVerification.clientIp.trim();

    if (isIP(normalizedInput) === 0) {
      throw new TypeError('Alamat IP tidak valid');
    }
    let response;

    try {
      response = await fetchImpl(
        `${API_BASE_URL}${encodeURIComponent(normalizedInput)}`,
        {
          method: 'GET',
          headers: {
            accept: 'application/json',
          },
          signal: AbortSignal.timeout(timeoutMs),
          redirect: 'error',
        },
      );
    } catch {
      return unavailable('provider_unreachable');
    }

    if (response.status === 429) {
      return unavailable('provider_rate_limited');
    }

    if (!response.ok) {
      return unavailable('provider_http_error');
    }

    const boundedBody = await readBoundedResponse(response);

    if (boundedBody.error) {
      return unavailable(boundedBody.error);
    }

    const rawBody = boundedBody.body;

    let data;

    try {
      data = JSON.parse(rawBody);
    } catch {
      return unavailable('provider_invalid_json');
    }

    if (
      !data ||
      typeof data !== 'object' ||
      Array.isArray(data) ||
      data.success !== true
    ) {
      return unavailable('provider_invalid_response');
    }

    const requestedIp = canonicalIp(normalizedInput);
    const returnedIp = canonicalIp(data.ip);

    if (!requestedIp || !returnedIp || requestedIp !== returnedIp) {
      return unavailable('provider_ip_mismatch');
    }

    const confidence =
      typeof data.confidence === 'string'
        ? data.confidence.toLowerCase()
        : null;

    const dataCompleteness = data.data_completeness;

    const signals = {};

    for (const field of SIGNAL_FIELDS) {
      signals[field] =
        typeof data[field] === 'boolean'
          ? data[field]
          : null;
    }

    const resultMetadata = {
      confidence,
      dataCompleteness:
        typeof dataCompleteness === 'number' &&
        Number.isFinite(dataCompleteness)
          ? dataCompleteness
          : null,
      signals,
    };

    const hasIncompleteSignals = SIGNAL_FIELDS.some(
      (field) => signals[field] === null,
    );

    if (hasIncompleteSignals) {
      return challenge(
        'classification_fields_incomplete',
        resultMetadata,
      );
    }

    const hasSufficientEvidence =
      confidence === 'high' &&
      typeof dataCompleteness === 'number' &&
      Number.isFinite(dataCompleteness) &&
      dataCompleteness >= MIN_DATA_COMPLETENESS &&
      dataCompleteness <= 1;

    const detectedSignals = SIGNAL_FIELDS.filter(
      (field) => signals[field] === true,
    );

    if (detectedSignals.length > 0) {
      if (!hasSufficientEvidence) {
        return challenge(
          'suspicious_signal_without_sufficient_evidence',
          resultMetadata,
        );
      }

      return {
        decision: 'block',
        reason: 'confirmed_proxy_vpn_or_tor_signal',
        source: 'ffraud',
        ...resultMetadata,
      };
    }

    if (!hasSufficientEvidence) {
      return challenge(
        'insufficient_classification_evidence',
        resultMetadata,
      );
    }

    // Hosting/datacenter alone is not a blocking signal.
    return {
      decision: 'allow',
      reason: 'no_prohibited_connection_signal',
      source: 'ffraud',
      ...resultMetadata,
    };
  }

  return Object.freeze({
    inspectIp,
  });
}
