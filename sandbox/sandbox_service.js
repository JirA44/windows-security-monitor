const http = require('http');
const fs = require('fs');
const path = require('path');
const port = Number(process.argv[2] || 18250);
const root = process.argv[3] || __dirname;
const pidFile = path.join(root, 'sandbox.pid');
fs.mkdirSync(root, { recursive: true });
fs.writeFileSync(pidFile, String(process.pid));
let requests = 0;
const server = http.createServer((req, res) => {
  requests++;
  if (req.url === '/health') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', requests }));
    return;
  }
  if (req.url === '/echo') {
    let body = '';
    req.on('data', (chunk) => { if (body.length < 4096) body += chunk; });
    req.on('end', () => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, length: body.length }));
    });
    return;
  }
  res.writeHead(404, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ error: 'not_found' }));
});
server.on('error', () => process.exit(1));
server.listen(port, '127.0.0.1', () => {
  console.log('sandbox listening on 127.0.0.1:' + port + ' pid=' + process.pid);
});
process.on('SIGTERM', () => { server.close(() => process.exit(0)); });
setTimeout(() => { try { server.close(() => process.exit(0)); } catch (e) { process.exit(1); } }, 15 * 60 * 1000).unref();
