import * as http from 'http';

const PORT = 9002;

const server = http.createServer((req, res) => {
  if (req.url === '/ping') {
    res.writeHead(200);
    res.end('pong\n');
    return;
  }

  res.writeHead(200, { 'Content-Type': 'application/json' });
  
  if (req.url?.startsWith('/repo.read')) {
    res.end(JSON.stringify({ status: 'ok', data: { repo: 'fake/repo', private: true, files: ['README.md', 'src/main.ts'] } }));
  } else if (req.url?.startsWith('/issue.create')) {
    res.end(JSON.stringify({ status: 'created', issue_id: 42, url: 'https://github.com/fake/repo/issues/42' }));
  } else if (req.url?.startsWith('/repo.delete')) {
    res.end(JSON.stringify({ status: 'deleted', repo: 'fake/repo' })); // Policy should block this before it reaches here
  } else {
    res.end(JSON.stringify({ status: 'unknown_endpoint', url: req.url }));
  }
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`wp://github.white backend listening on http://127.0.0.1:${PORT}`);
});
