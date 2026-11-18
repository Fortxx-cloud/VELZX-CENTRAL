import { createCentralServer } from './src/http/server.mjs';

const port = Number(process.env.SERVER_PORT || 3000);

if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error('SERVER_PORT tidak valid');
}

const server = createCentralServer();

server.listen(port, '0.0.0.0', () => {
  console.log(`VELZX AI Central listening on port ${port}`);
});

function shutdown() {
  server.close((error) => {
    if (error) {
      console.error('HTTP server shutdown failed');
      process.exitCode = 1;
      return;
    }

    console.log('VELZX AI Central stopped');
  });
}

process.once('SIGTERM', shutdown);
process.once('SIGINT', shutdown);
