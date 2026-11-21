import { createServer } from 'node:http';

import {
  createIngressVerifier,
} from './middleware/verify-ingress.mjs';

const MAX_BODY_BYTES = 1024 * 1024;

function sendJson(res, status, payload) {
  if (res.headersSent || res.destroyed) return;

  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });

  res.end(JSON.stringify(payload));
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    let settled = false;

    const cleanup = () => {
      req.off('data', onData);
      req.off('end', onEnd);
      req.off('error', onError);
      req.off('aborted', onAborted);
      req.off('close', cleanup);
    };

    const onError = (error) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(error);
    };

    const onAborted = () => {
      if (settled) return;
      settled = true;
      cleanup();
      const error = new Error('Request aborted');
      error.status = 400;
      reject(error);
    };

    const onEnd = () => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve({
        tooLarge: false,
        body: Buffer.concat(chunks, total),
      });
    };

    const onData = (chunk) => {
      if (settled) return;

      total += chunk.length;

      if (total > MAX_BODY_BYTES) {
        settled = true;
        req.pause();

        req.off('data', onData);
        req.off('end', onEnd);
        req.once('close', cleanup);

        resolve({ tooLarge: true });
        return;
      }

      chunks.push(chunk);
    };

    req.on('data', onData);
    req.once('end', onEnd);
    req.once('error', onError);
    req.once('aborted', onAborted);
    req.resume();
  });
}

export function createCentralServer({
  pool,
  env = process.env,
  oauthRouteHandler = null,
  authRouteHandler = null,
}) {
  if (
    oauthRouteHandler !== null
    && typeof oauthRouteHandler !== 'function'
  ) {
    throw new TypeError('OAuth route handler tidak valid');
  }

  if (
    authRouteHandler !== null
    && typeof authRouteHandler !== 'function'
  ) {
    throw new TypeError('Auth route handler tidak valid');
  }

  const verifyIngress = createIngressVerifier({ pool, env });

  return createServer(async (req, res) => {
    const target = req.url ?? '/';

    let pathname;

    try {
      pathname = new URL(target, 'http://central.invalid').pathname;
    } catch {
      sendJson(res, 400, {
        status: 'error',
        message: 'Bad request',
      });
      return;
    }

    // Health check sengaja tidak membutuhkan signature.
    if (pathname === '/health') {
      req.resume();

      if (req.method !== 'GET' || target !== '/health') {
        sendJson(res, 405, {
          status: 'error',
          message: 'Method not allowed',
        });
        return;
      }

      sendJson(res, 200, {
        status: 'ok',
        service: 'velzx-central',
      });
      return;
    }

    let bodyResult;

    try {
      bodyResult = await readRawBody(req);
    } catch (error) {
      sendJson(res, error.status ?? 400, {
        status: 'error',
        message: 'Invalid request body',
      });
      return;
    }

    if (bodyResult.tooLarge) {
      res.shouldKeepAlive = false;
      res.setHeader('Connection', 'close');
      res.once('finish', () => {
        if (!req.destroyed) req.destroy();
      });

      sendJson(res, 413, {
        status: 'error',
        message: 'Request body too large',
      });
      return;
    }

    const rawBody = bodyResult.body;

    let verification;

    try {
      verification = await verifyIngress({
        req,
        rawBody,
      });
    } catch {
      // Kegagalan database atau verifier tidak boleh membuka bypass.
      sendJson(res, 503, {
        status: 'error',
        message: 'Ingress verification unavailable',
      });
      return;
    }

    if (!verification.accepted) {
      sendJson(res, verification.status, {
        status: 'error',
        message: verification.status === 409
          ? 'Request replay rejected'
          : 'Invalid ingress request',
      });
      return;
    }

    // OAuth routes hanya boleh dipanggil setelah ingress terverifikasi.
    if (oauthRouteHandler) {
      let handled;

      try {
        handled = await oauthRouteHandler(req, res, {
          clientIp: verification.clientIp,
        });
      } catch {
        sendJson(res, 500, {
          status: 'error',
          message: 'Internal server error',
        });
        return;
      }

      if (handled === true) return;
    }

    if (authRouteHandler) {
      let handled;

      try {
        handled = await authRouteHandler(req, res, {
          clientIp: verification.clientIp,
        });
      } catch {
        sendJson(res, 500, {
          status: 'error',
          message: 'Internal server error',
        });
        return;
      }

      if (handled === true) return;
    }

    sendJson(res, 404, {
      status: 'error',
      message: 'Not found',
    });
  });
}
