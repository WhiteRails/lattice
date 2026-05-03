import * as http from 'http';
import * as https from 'https';
import * as url from 'url';

const PORT = 9004;

const server = http.createServer((req, res) => {
  if (req.url === '/ping') {
    res.writeHead(200);
    res.end('pong\n');
    return;
  }

  // The request URL comes in as something like /web.read?url=https://docs.github.com
  const parsed = url.parse(req.url || '', true);
  
  if (parsed.pathname?.startsWith('/web.read')) {
    const targetUrl = parsed.query.url as string;
    if (!targetUrl) {
      res.writeHead(400);
      res.end(JSON.stringify({ error: 'Missing target url' }));
      return;
    }
    
    // Minimal proxy implementation
    const target = url.parse(targetUrl);
    const client = target.protocol === 'https:' ? https : http;
    
    const proxyReq = client.request(targetUrl, { method: 'GET' }, (proxyRes) => {
      res.writeHead(proxyRes.statusCode || 200, proxyRes.headers);
      proxyRes.pipe(res);
    });
    
    proxyReq.on('error', (err) => {
      res.writeHead(502);
      res.end(JSON.stringify({ error: 'Failed to fetch target', detail: err.message }));
    });
    
    proxyReq.end();
  } else {
    res.writeHead(403);
    res.end(JSON.stringify({ status: 'blocked', reason: 'Browser proxy only supports GET web.read in this test' }));
  }
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`lp://browser.lattice backend listening on http://127.0.0.1:${PORT}`);
});
