// Proof Gatekeeper — HTTP server (plain Node http, no framework).
//   POST /gatekeeper  — signed task envelopes from the Agent Games platform
//   GET  /health      — readiness: HMAC configured? self-test result?
//   GET  /            — service info
//
// Protocol (from the official event page + field guide):
//   - Every inbound POST is HMAC-verified over the RAW body against the
//     `x-agent-games-signature` header BEFORE parsing (401 on mismatch).
//   - Preflight {"type":"agent-games.preflight.v1"} is answered
//     {ok:true, protocolVersion:"v1"}, signed.
//   - Responses carry {decision, reason_code, proof_tx, proof, public_signals}
//     and are signed with x-agent-games-signature over the raw response body.
//     PROOF_REUSED responses carry NO proof (the platform excludes them from
//     the reliability bonus — there is nothing new to prove).
//   - Fail closed everywhere: bad task -> REJECT; proof generation fails ->
//     return the decision WITHOUT a proof (never crash, never hang, never
//     approve what cannot be proven); unhandled error -> 500, not a timeout.
//   - Idempotency: responses are cached by task_id; a platform retry of the
//     same task returns the byte-identical cached body.
//   - This server never signs a transaction, never spends anything, never
//     touches a wallet or a seed. It only judges tasks.
const fs = require('fs');
const path = require('path');
const http = require('http');
const { verifyBody, signBody } = require('./shared/hmac');
const { decide } = require('./gatekeeper/decide');
const { proveDecision } = require('./gatekeeper/prove');
const snark = require('./shared/snark');

// ---- tiny .env loader (no dependency) ----
(function loadEnv() {
  try {
    for (const line of fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split('\n')) {
      const m = /^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/.exec(line);
      if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^['"]|['"]$/g, '');
    }
  } catch { /* no .env — environment variables only */ }
})();

const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || '0.0.0.0';
const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const HMAC_FORMAT = process.env.AGENT_GAMES_HMAC_FORMAT || 'hex';
const TASK_ID_MODE = process.env.GATEKEEPER_TASK_ID_MODE || 'keccak';

const responseCache = new Map(); // task_id -> { status, body } (byte-identical replays)
let selfTestResult = 'pending';

function sendJson(res, status, obj, sign) {
  const body = JSON.stringify(obj);
  const headers = { 'Content-Type': 'application/json' };
  if (sign && HMAC_SECRET) headers['x-agent-games-signature'] = signBody(HMAC_SECRET, body, HMAC_FORMAT);
  res.writeHead(status, headers);
  res.end(body);
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function inboundOk(rawBody, req) {
  if (!HMAC_SECRET) {
    console.warn('[warn] AGENT_GAMES_HMAC_SECRET is not set — inbound HMAC is NOT verified. Set it before going live.');
    return true;
  }
  return verifyBody(HMAC_SECRET, rawBody, req.headers['x-agent-games-signature'], HMAC_FORMAT);
}

async function handleGatekeeper(envelope) {
  // The platform envelope nests the task fields under `input`, but `task_id`
  // lives at the TOP level of the envelope (see the event page's sample
  // payload). Merge it in so decide()/prove() see the real task id — the
  // circuit's taskId signal and the proof-reuse seen-set both key on it.
  const task = { ...(envelope.input || envelope), task_id: envelope.task_id ?? (envelope.input || {}).task_id ?? '' };
  const taskId = String(task.task_id || '');
  if (taskId && responseCache.has(taskId)) return responseCache.get(taskId);

  const required = ['registered_vk', 'proof_vk', 'minimum', 'public_balance', 'expiry_block', 'current_block', 'recipient', 'condition_recipient', 'amount', 'max_transfer'];
  for (const field of required) {
    if (task[field] === undefined || task[field] === null || task[field] === '') {
      const out = { status: 200, body: { decision: 'REJECT', reason_code: 'INVALID_TASK', proof_tx: String(task.proof_tx || '') } };
      if (taskId) responseCache.set(taskId, out);
      return out;
    }
  }

  const { decision, reason_code } = decide(task);
  const proofTx = String(task.proof_tx || '');
  const base = { decision, reason_code, proof_tx: proofTx };

  if (reason_code === 'PROOF_REUSED') {
    const out = { status: 200, body: base };
    if (taskId) responseCache.set(taskId, out);
    return out;
  }

  try {
    const { proof, publicSignals } = await proveDecision(task, decision, TASK_ID_MODE);
    const out = { status: 200, body: { ...base, proof, public_signals: publicSignals } };
    if (taskId) responseCache.set(taskId, out);
    return out;
  } catch (e) {
    // The circuit refused the decision (logic/circuit mismatch) — return the
    // decision WITHOUT a proof rather than crashing or hanging. Loud log so
    // a mismatch is noticed immediately.
    console.error('[gatekeeper] proof generation FAILED for', decision, reason_code, ':', e.message);
    const out = { status: 200, body: base };
    if (taskId) responseCache.set(taskId, out);
    return out;
  }
}

async function selfTest() {
  try {
    const task = {
      task_id: 'gk_selftest_1',
      registered_vk: '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0',
      proof_vk: '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0',
      minimum: '1000', public_balance: '1460', expiry_block: '8430000', current_block: '8420000',
      recipient: '0x1111111111111111111111111111111111111111',
      condition_recipient: '0x1111111111111111111111111111111111111111',
      amount: '500', max_transfer: '1000', proof_tx: '0xselftest',
    };
    const { decision } = decide(task);
    const { proof, publicSignals } = await proveDecision(task, decision, TASK_ID_MODE);
    const ok = await snark.verify(proof, publicSignals);
    selfTestResult = ok && decision === 'APPROVE' ? 'PASS (APPROVE proof verifies locally)' : 'FAIL';
  } catch (e) {
    selfTestResult = 'FAIL: ' + e.message;
  }
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'GET' && req.url === '/health') {
      return sendJson(res, 200, {
        ok: true,
        gatekeeper: { hmacConfigured: !!HMAC_SECRET, taskIdMode: TASK_ID_MODE, selfTest: selfTestResult },
        uptimeSec: Math.floor(process.uptime()),
      });
    }
    if (req.method === 'GET' && req.url === '/') {
      return sendJson(res, 200, { service: 'agent-games-gatekeeper', track: 'proof-gatekeeper', endpoints: ['POST /gatekeeper', 'GET /health'] });
    }
    if (req.method !== 'POST' || req.url !== '/gatekeeper') {
      return sendJson(res, 404, { error: 'not found' });
    }
    const rawBody = await readRawBody(req);
    if (!inboundOk(rawBody, req)) {
      console.warn('[warn] HMAC mismatch on /gatekeeper');
      return sendJson(res, 401, { error: 'bad signature' });
    }
    let envelope;
    try {
      envelope = JSON.parse(rawBody.toString('utf8'));
    } catch {
      return sendJson(res, 400, { error: 'invalid JSON' });
    }
    if (envelope && envelope.type === 'agent-games.preflight.v1') {
      return sendJson(res, 200, { ok: true, protocolVersion: 'v1' }, true);
    }
    const result = await handleGatekeeper(envelope);
    return sendJson(res, result.status, result.body, true);
  } catch (e) {
    console.error('[server] unhandled error:', e);
    return sendJson(res, 500, { error: 'internal error' });
  }
});

server.listen(PORT, HOST, async () => {
  console.log(`[server] listening on ${HOST}:${server.address().port} (POST /gatekeeper, GET /health)`);
  console.log(`[server] HMAC secret: ${HMAC_SECRET ? 'configured' : 'NOT SET (inbound verification disabled)'}`);
  console.log(`[server] taskId mode: ${TASK_ID_MODE}`);
  await selfTest();
  console.log(`[server] self-test: ${selfTestResult}`);
});

server.on('error', (e) => {
  console.error(`[server] FATAL: cannot listen on ${HOST}:${PORT} — ${e.code || e.message}`);
  process.exit(1);
});
