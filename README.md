# Proof Gatekeeper — zkVerify Agent Games Season 01

A public HTTPS endpoint that judges proof-backed transfer tasks and proves
every decision with a Groth16 zero-knowledge proof. Built for the **Proof
Gatekeeper** track of zkVerify Agent Games Season 01
(21 Oct – 21 Nov 2026; 100,000 VFY per track, 50k / 30k / 20k top 3).

The platform POSTs a signed task envelope; the server verifies the HMAC,
decides **APPROVE** or **REJECT** from a deterministic 7-trap checklist,
generates a Groth16 proof of that decision with the tournament's own
circuit, and returns the signed decision — all inside the 60-second window.

## How it works

1. **Verify first.** Every inbound POST is HMAC-SHA256-verified over the RAW
   body against the `x-agent-games-signature` header, before parsing. Bad
   signature → 401, no work done.
2. **Decide, fail closed.** First failing trap wins; any failure → REJECT.
   Only a task that survives every check gets APPROVE. When in doubt, REJECT
   (a wrong APPROVE costs −6, a wrong REJECT only −3).
   - `VK_SUBSTITUTION` — proof_vk != registered_vk
   - `PROOF_REUSED` — proof_tx already seen under a *different* task_id
     (a retry of the same task_id is NOT a reuse)
   - `THRESHOLD_MISMATCH` — public_balance < minimum
   - `EXPIRED_CONDITION` — current_block >= expiry_block (expiry is STRICT)
   - `RECIPIENT_MISMATCH` — recipient != condition_recipient
   - `AMOUNT_OVERFLOW` — amount > max_transfer
   - else `VALID_CONDITION` → APPROVE
   - Boundaries: balance == minimum and amount == max are VALID;
     current == expiry is EXPIRED.
3. **Prove the decision.** Groth16 proof (BN128, Circom 2.x) via snarkjs
   0.7.6 with the tournament's own circuit. APPROVE = decision `1`,
   REJECT = decision `0`. If proof generation fails on an APPROVE, the
   server fails closed to REJECT. Reused-proof tasks get NO proof (the
   platform excludes them from the reliability bonus).
4. **Sign the response.** Every response carries its own
   `x-agent-games-signature` over the raw body. Preflight
   (`{"type":"agent-games.preflight.v1"}`) is answered
   `{ok:true, protocolVersion:"v1"}`, signed.
5. **Stay idempotent.** Responses are cached by task_id; a platform retry
   returns the byte-identical cached body.

The server never signs a transaction, never spends anything, never touches
a wallet or a seed. It only judges tasks.

## Circuit files (official, hash-verified)

Downloaded from the official site — never a third-party copy:

| File | URL | Size | SHA-256 |
|---|---|---|---|
| `gatekeeper.wasm` | https://agentgames.zkverify.io/circuits/gatekeeper.wasm | 1,755,820 | `be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f` |
| `gatekeeper_final.zkey` | https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey | 309,750 | `adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d` |

Registered verification-key hash (from the site's own `/api/circuit-info`):
`0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`.
Exported VK from the downloaded zkey: Groth16, curve bn128, 13 public
signals — matches. Re-download and re-check the hashes if you ever replace
these files.

## Run locally

```bash
npm install
cp .env.example .env   # the example secret is a LOCAL TEST SECRET ONLY
npm test               # 12-case harness + 7 live HTTP checks (see below)
npm start              # serves POST /gatekeeper + GET /health on :8080
```

`GET /health` reports HMAC configured? taskId mode? self-test result?
(The server runs a proof self-test at startup: a valid APPROVE proof,
verified locally.)

## Verified results (measured 2026-11-16 on this VM)

- **Harness `node gatekeeper/test.js`: 12/12 passed** — event-page sample
  → APPROVE + verifying proof; all 6 trap varieties → REJECT with the
  correct reason code + verifying proof; 4 boundary cases; PROOF_REUSED
  detection; same-task retry is not a reuse. First proof ~6s (wasm load),
  subsequent proofs 1.2–2.8s each — far inside the 60s deadline.
- **Live HTTP `node test-live.js`: 7/7 passed** — /health self-test PASS,
  preflight signed, unsigned → 401, wrong signature → 401, valid task →
  APPROVE + proof (13 public signals) + signed, trap task → REJECT +
  proof, same-task replay → byte-identical body.
- **Wrong decisions are unprovable by construction:** asking the circuit to
  prove decision `1` on trap inputs fails witness generation
  (`Assert Failed`, `GatekeeperEvaluation_79` line 102) — the circuit is
  the referee.

## Deploy (user-side — no cloud account was created here)

**Option A — Railway (recommended, what other competitors used):**
1. Push this repo to GitHub (public).
2. Railway → New Project → Deploy from GitHub repo → pick this repo.
   Railway detects the Dockerfile; no build config needed.
3. In Railway → Variables, add:
   - `AGENT_GAMES_HMAC_SECRET` = the secret from the dashboard
     ("Rotate Secret") — see Registration step 3 below.
   - `GATEKEEPER_TASK_ID_MODE` = `keccak` (default; change only if a
     practice task's proof is rejected).
4. Railway gives a public URL like
   `https://<name>.up.railway.app` — the gatekeeper endpoint is
   `https://<name>.up.railway.app/gatekeeper`.
5. `GET /health` on that URL must show the self-test PASS before you
   register the endpoint.

**Option B — Docker on any VPS:**
```bash
docker build -t gatekeeper .
docker run -d -p 8080:8080 -e AGENT_GAMES_HMAC_SECRET='<secret>' gatekeeper
```
Put it behind HTTPS (Caddy/Nginx + a domain). The platform requires a
public HTTPS URL.

**Option C — your own PC:** `npm start` + a tunnel (Cloudflare Tunnel
with your own account). Note: free tunnels were measured BLOCKED from the
VM this was built on (tunnelmole 502, trycloudflare 403), so deploy from
an unrestricted host, not this VM.

## Registration (user-side, in the browser)

Do these BEFORE a round opens — entries lock while a round is open.
Round 4 opens **today 16 Nov 17:30 WIB** (ends 03:30 WIB); Round 5 opens
17 Nov 17:30 WIB. If the endpoint is not registered + preflighted before
17:30, Round 4 is missed — aim for Round 5 instead.

1. **Sign in** at https://agentgames.zkverify.io — sign-in is SIWE
   (EIP-4361, an EIP-191 personal signature from your wallet in the
   browser). Claim your handle. **Do NOT use the ref link
   `?ref=GBDJFT2D`** — its ownership is unverified; register from the
   clean site URL.
2. **Link GitHub** in the dashboard — prize eligibility requires a
   connected GitHub account. (Another competitor hit an OAuth-callback
   issue here; if the link does not land, retry the flow in a fresh
   browser session.)
3. **Register the endpoint:** dashboard → Endpoints → add
   `https://<your-host>/gatekeeper` (full handler path, HTTPS).
4. **Rotate Secret** in the dashboard → paste it as
   `AGENT_GAMES_HMAC_SECRET` in Railway Variables (or `.env` on a VPS)
   → redeploy/restart. Without it, inbound HMAC is not verified and the
   preflight fails with "The endpoint must return signed protocol-v1 JSON".
5. **Preflight + practice task** in the dashboard. Preflight confirms the
   HMAC format (if it rejects, set `AGENT_GAMES_HMAC_FORMAT=sha256=` and
   redeploy). The practice task confirms the `taskId` mapping — if its
   proof is rejected, switch `GATEKEEPER_TASK_ID_MODE` to `numeric` or
   `hex` and redeploy, then re-run practice. Do at least one practice
   task: entry requires it.
6. **Play.** Once the dashboard marks the agent HEALTHY and entered, the
   platform sends 8 signed tasks per round on its own schedule. Nothing
   else to click — each decision carries its proof.

## Scoring (from the official event page)

Correct APPROVE or correct REJECT (verified): **+12** each. Wrong
APPROVE: **−6**. Wrong REJECT: **−3**. Timeout: **−2**. Missing/invalid
proof: **−2**. Reliability bonus: **+0 to +5**, pro-rated by the share of
provable tasks whose proof verified. 8 rounds, 8 tasks per agent per
round, scores cumulative. Rounds 1–3 are already played (we are late);
Rounds 4–8 remain (max 5 × 8 × 12 = 480 + bonus).

## Known limits / open items

- **taskId mapping is unconfirmed.** The envelope's `task_id` is a string;
  the circuit needs a field element. Default `keccak256(task_id) mod p`.
  Confirm against a practice task; switch `GATEKEEPER_TASK_ID_MODE` if
  the platform rejects the proof.
- **HMAC format is an assumption** (lowercase hex HMAC-SHA256). The docs
  do not state it explicitly. Preflight is the verification step; the
  `sha256=` fallback exists for a reason.
- **Proof-reuse seen-set is in-memory.** A server restart clears it, so a
  restart mid-round could miss a reuse. Rounds are daily and short; keep
  the server up for the whole round window (17:30–03:30 WIB).
- **VK-hash reproduction gap (reported by other builders):** the site's
  published registered-VK hash (`0x6b79c6…d77b0`) could not be reproduced
  from the exported verification key with 12 serialization variants. Our
  proofs verify against the key exported from the official proving key, so
  the artifacts are self-consistent — but the platform re-verifies against
  *its* registered key, so the practice task is the real check.
- **No Steal the VFY agent here.** That track's entries locked once Swiss
  pairing started (Nov 13–17) — out of scope by design.

## Files

```
server.js                  entry point (POST /gatekeeper, GET /health, GET /)
gatekeeper/decide.js       7-trap checklist + proof_tx seen-set
gatekeeper/prove.js        circuit input mapping, taskId mapping
gatekeeper/test.js         harness: 7 traps + boundaries + reuse (12 cases)
shared/field.js            BN128 field helpers, keccak256 mod p
shared/hmac.js             HMAC-SHA256 verify/sign (timing-safe)
shared/snark.js            snarkjs wrapper (prove / verify)
circuits/                  OFFICIAL wasm + zkey (hashes above)
test-live.js               HTTP-level tests vs a local server (7 checks)
.env.example               env template (TEST secret only — never the real one)
Dockerfile / railway.json  deploy files
```
