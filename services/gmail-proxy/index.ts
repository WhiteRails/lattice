import * as http from 'http';

const PORT = 9003;

const server = http.createServer((req, res) => {
  if (req.url === '/ping') {
    res.writeHead(200);
    res.end('pong\n');
    return;
  }

  res.writeHead(200, { 'Content-Type': 'application/json' });
  
  if (req.url?.startsWith('/email.draft')) {
    res.end(JSON.stringify({ status: 'draft_created', draft_id: 'draft_991' }));
  } else if (req.url?.startsWith('/email.send')) {
    // Note: the proxy should normally return 202 pending approval.
    // If it reaches here, the policy allowed it.
    res.end(JSON.stringify({ status: 'sent', message_id: 'msg_882' }));
  } else {
    res.end(JSON.stringify({ status: 'unknown_endpoint', url: req.url }));
  }
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`lp://gmail.lattice backend listening on http://127.0.0.1:${PORT}`);
});
