import { createCentralServer } from './src/http/server.mjs';
import { createDatabasePool } from './src/database/pool.mjs';

const port = Number(process.env.SERVER_PORT || 3000);

if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error('SERVER_PORT tidak valid');
}

const pool = createDatabasePool();
const server = createCentralServer({ pool });

server.listen(port, '0.0.0.0', () => {
  console.log(`VELZX AI Central listening on port ${port}`);
});

let shuttingDown = false;

function shutdown() {
  if (shuttingDown) return;
  shuttingDown = true;

  server.close(async (error) => {
    if (error) {
      console.error('HTTP server shutdown failed');
      process.exitCode = 1;
    }

    try {
      await pool.end();
    } catch {
      console.error('PostgreSQL pool shutdown failed');
      process.exitCode = 1;
    }

    if (!error && process.exitCode !== 1) {
      console.log('VELZX AI Central stopped');
    }
  });
}

process.once('SIGTERM', shutdown);
process.once('SIGINT', shutdown);
