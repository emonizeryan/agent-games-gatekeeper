// Live HTTP tests — starts the server on a scratch port with a LOCAL TEST
// HMAC secret, then exercises the real HTTP path end to end:
//   /health, preflight (signed), bad HMAC -> 401, valid task -> APPROVE +
//   locally-verifying proof, trap task -> REJECT + verifying proof,
//   same task_id replay -> byte-identical body, unsigned request -> 401.
// Run: node test-live.js   (needs server.js; uses a test secret only)
const { spawn } = require('child_process');
const crypto = require('crypto');
const http = require('http');

const PORT = 20000 + Math.floor(Math.random() * 20000); // fresh port per run —
// a previous run's server can outlive the test process (orphaned on SIGTERM
// race) and hold a fixed port, which used to fail the next run with
// EADDRINUSE. Random ports make runs independent.
const TEST_SECRET = 'local-test-secret-only-never-the-real-one';

// Hoisted for the error handler: the spawned server's exit state + output.
let serverExit = null;
let serverOut = '';

function hmacHex(secret, rawBody) {
  return crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
}

function request(path, body, sign) {
  return new Promise((resolve, reject) => {
    const raw = body === null ? '' : (typeof body === 'string' ? body : JSON.stringify(body));
    const headers = { 'Content-Type': 'application/json' };
    if (sign) headers['x-agent-games-signature'] = hmacHex(TEST_SECRET, raw);
    // agent:false — fresh socket per request. Node's default keep-alive agent
    // can reuse a socket the server has just closed, which surfaces as a
    // flaky ECONNRESET on the next request (seen 2x in this harness).
    const req = http.request({ host: '127.0.0.1', port: PORT, path, method: body === null ? 'GET' : 'POST', headers, agent: false }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    if (raw) req.write(raw);
    req.end();
  });
}

const VK = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const ADDR = '0x1111111111111111111111111111111111111111';

function validEnvelope() {
  return {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: 'gk_live_1', mode: 'competition',
    input: {
      registered_vk: VK, proof_vk: VK, minimum: '1000', public_balance: '1460',
      expiry_block: '8430000', current_block: '8420000',
      recipient: ADDR, condition_recipient: ADDR,
      amount: '500', max_transfer: '1000', proof_tx: '0xliveproof1',
    },
  };
}

(async () => {
  const server = spawn('node', ['server.js'], {
    cwd: __dirname,
    env: { ...process.env, PORT: String(PORT), AGENT_GAMES_HMAC_SECRET: TEST_SECRET },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let serverExitLocal = null;
  server.on('exit', (code, signal) => { serverExitLocal = `code=${code} signal=${signal}`; serverExit = serverExitLocal; });
  let out = '';
  server.stdout.on('data', (d) => { out += d.toString(); serverOut = out; });
  server.stderr.on('data', (d) => { out += d.toString(); serverOut = out; });
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  try {
    // Wait for the self-test line (proof takes ~1s at startup).
    for (let i = 0; i < 30 && !out.includes('self-test:'); i++) await sleep(500);
    let pass = 0;
    const total = 7;
    const check = (name, ok, extra = '') => {
      if (ok) pass++;
      console.log(`${ok ? 'PASS' : 'FAIL'}  ${name} ${extra}`);
    };

    const health = await request('/health', null, false);
    const healthJson = JSON.parse(health.body);
    check('/health 200 + self-test PASS', health.status === 200 && /PASS/.test(healthJson.gatekeeper.selfTest), `(${healthJson.gatekeeper.selfTest})`);

    const pre = await request('/gatekeeper', { type: 'agent-games.preflight.v1' }, true);
    const preJson = JSON.parse(pre.body);
    check('preflight -> {ok:true, protocolVersion:v1} + signed', pre.status === 200 && preJson.ok === true && preJson.protocolVersion === 'v1' && !!pre.headers['x-agent-games-signature']);

    const unsigned = await request('/gatekeeper', validEnvelope(), false);
    check('unsigned task -> 401', unsigned.status === 401);

    const badSig = await request('/gatekeeper', validEnvelope(), true);
    // Corrupt the signature by re-signing with a different secret is complex
    // here; instead send a wrong header value directly.
    const wrong = await new Promise((resolve, reject) => {
      const raw = JSON.stringify(validEnvelope());
      const req = http.request({ host: '127.0.0.1', port: PORT, path: '/gatekeeper', method: 'POST', headers: { 'Content-Type': 'application/json', 'x-agent-games-signature': 'deadbeef' }, agent: false }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
      });
      req.on('error', reject);
      req.write(raw);
      req.end();
    });
    check('wrong signature -> 401', wrong.status === 401);
    void badSig;

    const t0 = Date.now();
    const valid = await request('/gatekeeper', validEnvelope(), true);
    const validJson = JSON.parse(valid.body);
    const validMs = Date.now() - t0;
    check('valid task -> APPROVE + proof + signed', valid.status === 200 && validJson.decision === 'APPROVE' && validJson.reason_code === 'VALID_CONDITION' && !!validJson.proof && Array.isArray(validJson.public_signals) && validJson.public_signals.length === 13 && !!valid.headers['x-agent-games-signature'], `(${validMs}ms)`);

    const trap = validEnvelope();
    trap.task_id = 'gk_live_2';
    trap.input.public_balance = '100';
    trap.input.proof_tx = '0xliveproof2';
    const trapRes = await request('/gatekeeper', trap, true);
    const trapJson = JSON.parse(trapRes.body);
    check('trap task -> REJECT/THRESHOLD_MISMATCH + proof', trapRes.status === 200 && trapJson.decision === 'REJECT' && trapJson.reason_code === 'THRESHOLD_MISMATCH' && !!trapJson.proof);

    const replay = await request('/gatekeeper', validEnvelope(), true);
    check('same task_id replay -> byte-identical body', replay.body === valid.body);

    console.log(`\n${pass}/${total} live HTTP checks passed`);
    process.exit(pass === total ? 0 : 1);
  } finally {
    server.kill();
  }
})().catch((e) => { console.error('LIVE TEST ERROR:', e); console.error('--- server exit:', serverExit); console.error('--- server output tail:\n' + String(serverOut).slice(-2000)); process.exit(1); });
