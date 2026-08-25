import * as http from 'http';

const PORT = 9001;

const server = http.createServer((req, res) => {
  if (req.url === '/ping') {
    res.writeHead(200);
    res.end('pong\n');
    return;
  }

  const chunks: Buffer[] = [];
  req.on('data', chunk => chunks.push(chunk));
  req.on('end', () => {
    const body = Buffer.concat(chunks).toString();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      echo: 'Lattice Echo Service',
      method: req.method,
      url: req.url,
      headers: req.headers,
      body,
    }, null, 2));
  });
});

const BIND_HOST = process.env.LATTICE_SERVICE_BIND_HOST ?? '127.0.0.1';

server.listen(PORT, BIND_HOST, () => {
  console.log(`lp://echo.lattice backend listening on http://${BIND_HOST}:${PORT}`);
});
