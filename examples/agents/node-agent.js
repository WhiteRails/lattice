const http = require('http');
const crypto = require('crypto');

// Read HTTP_PROXY from environment
const proxy = process.env.HTTP_PROXY;
if (!proxy) {
  console.error('Error: HTTP_PROXY environment variable is not set.');
  console.error('This agent must be run inside the Lattice sandbox.');
  process.exit(1);
}

console.log(`[Agent] Starting up. Using proxy: ${proxy}`);

const proxyUrl = new URL(proxy);
const privateKey = process.env.LATTICE_AGENT_PRIVATE_KEY;
if (!privateKey) {
  console.error('Error: LATTICE_AGENT_PRIVATE_KEY environment variable is not set.');
  process.exit(1);
}

function signRequest({ method, host, path, body = '' }) {
  const timestamp = new Date().toISOString();
  const bodyHash = crypto.createHash('sha256').update(body).digest('hex');
  const payload = [
    method.toUpperCase(),
    host,
    path,
    timestamp,
    bodyHash,
  ].join('\n');
  const signature = crypto.sign(null, Buffer.from(payload), privateKey).toString('base64');
  return { timestamp, signature };
}

function makeRequest(targetUrl, method = 'GET') {
  return new Promise((resolve, reject) => {
    const target = new URL(targetUrl);
    const auth = signRequest({
      method,
      host: target.host,
      path: target.pathname + target.search,
    });
    const options = {
      hostname: proxyUrl.hostname,
      port: proxyUrl.port,
      path: target.pathname + target.search,
      method: method,
      headers: {
        Host: target.host,
        'x-lattice-agent': process.env.LATTICE_AGENT,
        'x-lattice-timestamp': auth.timestamp,
        'x-lattice-signature': auth.signature,
      }
    };

    console.log(`\n[Agent] Trying to ${method} ${targetUrl} ...`);
    const req = http.request(options, (res) => {
      console.log(`[Agent] Response Status: ${res.statusCode}`);
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          // Try to pretty-print if JSON
          console.log(`[Agent] Response Body: ${JSON.stringify(JSON.parse(data), null, 2)}`);
        } catch {
          console.log(`[Agent] Response Body: ${data.slice(0, 200)}...`);
        }
        resolve();
      });
    });

    req.on('error', (err) => {
      console.error(`[Agent] Request failed: ${err.message}`);
      resolve(); // resolve anyway so we can continue demo
    });

    req.end();
  });
}

async function main() {
  // 1. Try an allowed resource
  await makeRequest('http://echo.lattice/echo.ping?foo=bar');

  // 2. Try an external internet resource (should be blocked by default policy)
  await makeRequest('http://example.com');
  
  // 3. Try GitHub allowed endpoint
  await makeRequest('http://github.lattice/repo.read?repo=acme/core');

  console.log('\n[Agent] Finished tasks.');
}

main();
