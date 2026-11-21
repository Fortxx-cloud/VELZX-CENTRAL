const SESSION_COOKIE = '__Host-velzx_session';
const SESSION_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

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

function sendNoContent(res, { clearCookie = false } = {}) {
  if (res.headersSent || res.destroyed) return;

  const headers = {
    'Cache-Control': 'no-store',
    'Pragma': 'no-cache',
    'X-Content-Type-Options': 'nosniff',
  };

  if (clearCookie) {
    headers['Set-Cookie'] = [
      `${SESSION_COOKIE}=`,
      'Path=/',
      'HttpOnly',
      'Secure',
      'SameSite=Lax',
      'Max-Age=0',
    ].join('; ');
  }

  res.writeHead(204, headers);
  res.end();
}

function readSessionToken(header) {
  if (typeof header !== 'string') return null;

  let found = false;
  let invalid = false;
  let token = null;

  for (const part of header.split(';')) {
    const item = part.trim();
    if (!item) continue;

    const separator = item.indexOf('=');
    const name = separator === -1
      ? item
      : item.slice(0, separator).trim();

    if (name !== SESSION_COOKIE) continue;

    if (found) return null;
    found = true;

    if (separator < 1) {
      invalid = true;
      continue;
    }

    const value = item.slice(separator + 1).trim();

    if (!SESSION_TOKEN_PATTERN.test(value)) {
      invalid = true;
    } else {
      token = value;
    }
  }

  return found && !invalid ? token : null;
}

function sendAuthenticationRequired(res) {
  sendJson(res, 401, {
    status: 'error',
    code: 'authentication_required',
    message: 'Session aktif diperlukan',
  });
}

export function createAuthRouteHandler({
  sessionRepository,
  publicOrigin,
}) {
  if (
    !sessionRepository
    || typeof sessionRepository.findActiveSession !== 'function'
    || typeof sessionRepository.listActiveSessions !== 'function'
    || typeof sessionRepository.revokeSession !== 'function'
    || typeof sessionRepository.revokeSessionById !== 'function'
  ) {
    throw new TypeError('Session repository tidak valid');
  }

  if (typeof publicOrigin !== 'string' || !publicOrigin) {
    throw new TypeError('Public origin Auth tidak valid');
  }

  let normalizedOrigin;

  try {
    const parsed = new URL(publicOrigin);

    if (
      parsed.protocol !== 'https:'
      || parsed.username
      || parsed.password
      || parsed.pathname !== '/'
      || parsed.search
      || parsed.hash
    ) {
      throw new TypeError('Public origin Auth tidak valid');
    }

    normalizedOrigin = parsed.origin;
  } catch {
    throw new TypeError('Public origin Auth tidak valid');
  }

  return async function handleAuthRoute(req, res) {
    const target = req.url ?? '/';
    let pathname;

    try {
      pathname = new URL(target, 'http://central.invalid').pathname;
    } catch {
      return false;
    }

    const isMe = pathname === '/api/v1/me';
    const isLogout = pathname === '/api/v1/auth/logout';
    const isSessions = pathname === '/api/v1/auth/sessions';
    const sessionMatch = pathname.match(
      /^\/api\/v1\/auth\/sessions\/([^/]+)$/,
    );

    if (!isMe && !isLogout && !isSessions && !sessionMatch) {
      return false;
    }

    const expectedMethod = isMe || isSessions
      ? 'GET'
      : isLogout
        ? 'POST'
        : 'DELETE';

    if (req.method !== expectedMethod) {
      sendJson(res, 405, {
        status: 'error',
        code: 'method_not_allowed',
        message: 'Method not allowed',
      });
      return true;
    }

    if (
      (isLogout || sessionMatch)
      && req.headers.origin !== normalizedOrigin
    ) {
      sendJson(res, 403, {
        status: 'error',
        code: 'origin_rejected',
        message: 'Origin tidak diizinkan',
      });
      return true;
    }

    const token = readSessionToken(req.headers.cookie);

    if (isLogout) {
      if (token) {
        await sessionRepository.revokeSession({ token });
      }

      sendNoContent(res, { clearCookie: true });
      return true;
    }

    if (!token) {
      sendAuthenticationRequired(res);
      return true;
    }

    const active = await sessionRepository.findActiveSession({ token });

    if (!active) {
      sendAuthenticationRequired(res);
      return true;
    }

    if (isMe) {
      sendJson(res, 200, {
        status: 'ok',
        user: {
          id: active.user.id,
          email: active.user.email,
          accountStatus: active.user.accountStatus,
          emailVerified: active.user.emailVerified,
        },
      });
      return true;
    }

    if (isSessions) {
      const sessions = await sessionRepository.listActiveSessions({
        userId: active.user.id,
      });

      sendJson(res, 200, {
        status: 'ok',
        sessions: sessions.map((session) => ({
          id: session.id,
          createdAt: session.createdAt,
          expiresAt: session.expiresAt,
          current: session.id === active.session.id,
        })),
      });
      return true;
    }

    const sessionId = sessionMatch[1];

    if (!UUID_PATTERN.test(sessionId)) {
      sendJson(res, 404, {
        status: 'error',
        code: 'session_not_found',
        message: 'Session tidak ditemukan',
      });
      return true;
    }

    const revoked = await sessionRepository.revokeSessionById({
      sessionId,
      userId: active.user.id,
    });

    if (!revoked) {
      sendJson(res, 404, {
        status: 'error',
        code: 'session_not_found',
        message: 'Session tidak ditemukan',
      });
      return true;
    }

    sendNoContent(res, {
      clearCookie: sessionId === active.session.id,
    });

    return true;
  };
}
