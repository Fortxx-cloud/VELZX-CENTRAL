import { randomBytes } from 'node:crypto';
import { OAuthServiceError } from '../../auth/oauth/oauth-service.mjs';

const PROVIDERS = new Set(['google', 'github', 'microsoft']);

const SESSION_COOKIE = '__Host-velzx_session';
const BINDING_COOKIE_PREFIX = '__Host-velzx_oauth_';

const SESSION_MAX_AGE = 7 * 24 * 60 * 60;
const BINDING_MAX_AGE = 600;

function sendJson(res, status, payload) {
  if (res.headersSent || res.destroyed) return;

  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Pragma': 'no-cache',
    'X-Content-Type-Options': 'nosniff',
  });

  res.end(JSON.stringify(payload));
}

function appendSetCookie(res, cookies) {
  const current = res.getHeader('Set-Cookie');
  const values = current
    ? Array.isArray(current) ? current : [current]
    : [];

  res.setHeader('Set-Cookie', [...values, ...cookies]);
}

function serializeCookie(name, value, maxAge) {
  return [
    `${name}=${value}`,
    'Path=/',
    'HttpOnly',
    'Secure',
    'SameSite=Lax',
    `Max-Age=${maxAge}`,
  ].join('; ');
}

function parseCookies(header) {
  const result = new Map();

  if (typeof header !== 'string') return result;

  for (const part of header.split(';')) {
    const separator = part.indexOf('=');
    if (separator < 1) continue;

    const name = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();

    if (!result.has(name)) result.set(name, value);
  }

  return result;
}

function validState(state) {
  return typeof state === 'string'
    && /^[A-Za-z0-9_-]{43}$/.test(state);
}

function safeProviderError(error) {
  if (error instanceof OAuthServiceError) {
    const known = new Set([
      'unsupported_provider',
      'invalid_authorization_code',
      'invalid_oauth_transaction',
      'invalid_oauth_purpose',
      'registration_not_eligible',
      'registration_ip_limit_reached',
      'account_conflict',
      'account_unavailable',
      'authentication_required',
      'session_mismatch',
      'identity_conflict',
      'link_failed',
      'session_creation_failed',
    ]);

    if (known.has(error.code)) {
      return {
        status: error.code === 'authentication_required' ? 401 : 400,
        code: error.code,
        message: 'OAuth request tidak dapat diselesaikan',
      };
    }
  }

  return {
    status: 400,
    code: 'oauth_failed',
    message: 'OAuth request tidak dapat diselesaikan',
  };
}

function validateAuthorizationUrl(value, provider) {
  let url;

  try {
    url = new URL(value);
  } catch {
    throw new Error('OAuth authorization URL tidak valid');
  }

  const baseValid = (
    url.protocol === 'https:'
    && !url.username
    && !url.password
    && !url.port
    && !url.hash
  );

  const allowedEndpoint = {
    google: (
      url.hostname === 'accounts.google.com'
      && url.pathname === '/o/oauth2/v2/auth'
    ),
    github: (
      url.hostname === 'github.com'
      && url.pathname === '/login/oauth/authorize'
    ),
    microsoft: (
      url.hostname === 'login.microsoftonline.com'
      && /^\/(?:common|organizations|consumers|[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})\/oauth2\/v2\.0\/authorize$/.test(url.pathname)
    ),
  };

  if (!baseValid || allowedEndpoint[provider] !== true) {
    throw new Error('OAuth authorization endpoint tidak diizinkan');
  }

  return url;
}

function redirect(res, destination) {
  if (res.headersSent || res.destroyed) return;

  res.writeHead(302, {
    Location: destination,
    'Cache-Control': 'no-store',
    'Referrer-Policy': 'no-referrer',
  });

  res.end();
}

export function createOAuthRouteHandler({
  oauthService,
  publicOrigin = null,
}) {
  if (
    !oauthService
    || typeof oauthService.startLogin !== 'function'
    || typeof oauthService.startLink !== 'function'
    || typeof oauthService.completeCallback !== 'function'
  ) {
    throw new TypeError('OAuth service tidak valid');
  }

  let normalizedOrigin = null;

  if (publicOrigin !== null) {
    const parsed = new URL(publicOrigin);

    if (
      parsed.protocol !== 'https:'
      || parsed.username
      || parsed.password
      || parsed.pathname !== '/'
      || parsed.search
      || parsed.hash
    ) {
      throw new TypeError('Public origin OAuth tidak valid');
    }

    normalizedOrigin = parsed.origin;
  }

  return async function handleOAuthRoute(req, res, { clientIp } = {}) {
    const target = req.url ?? '/';
    let url;

    try {
      url = new URL(target, 'http://central.invalid');
    } catch {
      return false;
    }

    const match = url.pathname.match(
      /^\/auth\/oauth\/([^/]+)(?:\/(start|callback))?$|^\/auth\/oauth\/([^/]+)\/link\/start$/,
    );

    if (!match) return false;

    const provider = match[1] ?? match[3];
    const action = match[3] ? 'link-start' : match[2] ?? 'start';

    if (!PROVIDERS.has(provider)) {
      sendJson(res, 404, {
        status: 'error',
        code: 'unsupported_provider',
        message: 'OAuth provider tidak didukung',
      });
      return true;
    }

    try {
      if (action === 'start' && req.method === 'GET') {
        if (!normalizedOrigin) {
          sendJson(res, 503, {
            status: 'error',
            code: 'oauth_origin_not_configured',
            message: 'OAuth belum tersedia',
          });
          return true;
        }

        const browserBinding = randomBytes(32).toString('base64url');
        const result = await oauthService.startLogin({
          provider,
          browserBinding,
        });

        if (
          !result
          || result.provider !== provider
          || !validState(result.state)
          || typeof result.authorizationUrl !== 'string'
        ) {
          throw new Error('OAuth start result invalid');
        }

        const authorizationUrl = validateAuthorizationUrl(
          result.authorizationUrl,
          provider,
        );

        const cookieName = `${BINDING_COOKIE_PREFIX}${result.state}`;

        appendSetCookie(res, [
          serializeCookie(cookieName, browserBinding, BINDING_MAX_AGE),
        ]);

        redirect(res, authorizationUrl.toString());
        return true;
      }

      if (action === 'callback' && req.method === 'GET') {
        const state = url.searchParams.get('state');
        const code = url.searchParams.get('code');

        if (!validState(state) || !code || code.length > 2048) {
          sendJson(res, 400, {
            status: 'error',
            code: 'invalid_oauth_callback',
            message: 'OAuth callback tidak valid',
          });
          return true;
        }

        const cookieName = `${BINDING_COOKIE_PREFIX}${state}`;
        const cookies = parseCookies(req.headers.cookie);
        const browserBinding = cookies.get(cookieName);

        if (
          typeof browserBinding !== 'string'
          || !/^[A-Za-z0-9_-]{43,128}$/.test(browserBinding)
        ) {
          sendJson(res, 400, {
            status: 'error',
            code: 'invalid_oauth_transaction',
            message: 'OAuth transaction tidak valid',
          });
          return true;
        }

        if (!normalizedOrigin) {
          sendJson(res, 503, {
            status: 'error',
            code: 'oauth_origin_not_configured',
            message: 'OAuth belum tersedia',
          });
          return true;
        }

        const sessionToken = cookies.get(SESSION_COOKIE) ?? null;

        const result = await oauthService.completeCallback({
          provider,
          code,
          state,
          browserBinding,
          clientIp,
          sessionToken,
        });

        const clearBindingCookie = serializeCookie(
          cookieName,
          '',
          0,
        );

        if (result?.authenticated === true) {
          if (
            typeof result.session?.token !== 'string'
            || !/^[A-Za-z0-9_-]{43}$/.test(result.session.token)
          ) {
            throw new Error('OAuth session result invalid');
          }

          appendSetCookie(res, [
            clearBindingCookie,
            serializeCookie(
              SESSION_COOKIE,
              result.session.token,
              SESSION_MAX_AGE,
            ),
          ]);

          sendJson(res, 200, {
            status: 'ok',
            authenticated: true,
            created: result.created === true,
          });

          return true;
        }

        if (result?.linked === true) {
          appendSetCookie(res, [clearBindingCookie]);

          sendJson(res, 200, {
            status: 'ok',
            linked: true,
          });

          return true;
        }

        throw new Error('OAuth callback result invalid');
      }

      if (action === 'link-start' && req.method === 'POST') {
        if (!normalizedOrigin) {
          sendJson(res, 503, {
            status: 'error',
            code: 'oauth_origin_not_configured',
            message: 'Account linking belum tersedia',
          });
          return true;
        }

        if (req.headers.origin !== normalizedOrigin) {
          sendJson(res, 403, {
            status: 'error',
            code: 'origin_rejected',
            message: 'Origin tidak diizinkan',
          });
          return true;
        }

        const cookies = parseCookies(req.headers.cookie);
        const sessionToken = cookies.get(SESSION_COOKIE);

        if (
          typeof sessionToken !== 'string'
          || !/^[A-Za-z0-9_-]{43}$/.test(sessionToken)
        ) {
          sendJson(res, 401, {
            status: 'error',
            code: 'authentication_required',
            message: 'Session aktif diperlukan',
          });
          return true;
        }

        const browserBinding = randomBytes(32).toString('base64url');

        const result = await oauthService.startLink({
          provider,
          browserBinding,
          sessionToken,
        });

        if (
          !result
          || result.provider !== provider
          || !validState(result.state)
          || typeof result.authorizationUrl !== 'string'
        ) {
          throw new Error('OAuth link start result invalid');
        }

        const authorizationUrl = validateAuthorizationUrl(
          result.authorizationUrl,
          provider,
        );

        const cookieName = `${BINDING_COOKIE_PREFIX}${result.state}`;

        appendSetCookie(res, [
          serializeCookie(cookieName, browserBinding, BINDING_MAX_AGE),
        ]);

        redirect(res, authorizationUrl.toString());
        return true;
      }

      sendJson(res, 405, {
        status: 'error',
        code: 'method_not_allowed',
        message: 'Method not allowed',
      });

      return true;
    } catch (error) {
      const safe = safeProviderError(error);

      sendJson(res, safe.status, {
        status: 'error',
        code: safe.code,
        message: safe.message,
      });

      return true;
    }
  };
}
