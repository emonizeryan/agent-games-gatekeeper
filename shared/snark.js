// snarkjs wrapper for the official gatekeeper circuit (Groth16 / BN128).
// Circuit files live in ../circuits/ — downloaded from the OFFICIAL site:
//   https://agentgames.zkverify.io/circuits/gatekeeper.wasm
//   https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey
// Verified SHA-256 (2026-11-16):
//   gatekeeper.wasm       be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f
//   gatekeeper_final.zkey adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d
const path = require('path');
const snarkjs = require('snarkjs');

const WASM_PATH = path.join(__dirname, '..', 'circuits', 'gatekeeper.wasm');
const ZKEY_PATH = path.join(__dirname, '..', 'circuits', 'gatekeeper_final.zkey');

let cachedVk = null;

async function verificationKey() {
  if (!cachedVk) cachedVk = await snarkjs.zKey.exportVerificationKey(ZKEY_PATH);
  return cachedVk;
}

// Generate a Groth16 proof for `input`. Throws when witness calculation fails
// — i.e. the inputs violate the circuit (a decision that does not match the
// circuit's own evaluation of the task). Callers must fail closed on throw.
async function prove(input) {
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM_PATH, ZKEY_PATH);
  return { proof, publicSignals };
}

async function verify(proof, publicSignals) {
  const vk = await verificationKey();
  return snarkjs.groth16.verify(vk, publicSignals, proof);
}

module.exports = { WASM_PATH, ZKEY_PATH, verificationKey, prove, verify };
