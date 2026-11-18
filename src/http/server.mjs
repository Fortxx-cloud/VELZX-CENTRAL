import { createServer } from 'node:http';

export function createCentralServer() {
  return createServer((req, res) => {
    const pathname = new URL(
      req.url ?? '/',
      'http://localhost'
    ).pathname;

    if (pathname === '/health') {
      if (req.method !== 'GET') {
        res.writeHead(405, {
          'Content-Type': 'application/json; charset=utf-8',
          'Cache-Control': 'no-store',
        });
        res.end(JSON.stringify({
          status: 'error',
          message: 'Method not allowed',
        }));
        return;
      }

      res.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
      });

      res.end(JSON.stringify({
        status: 'ok',
        service: 'velzx-central',
      }));
      return;
    }

    res.writeHead(404, {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
    });

    res.end(JSON.stringify({
      status: 'error',
      message: 'Not found',
    }));
  });
}
