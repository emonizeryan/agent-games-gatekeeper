// Proof Gatekeeper — Groth16 proof generation for a decision.
// Circuit inputs (recovered by probing the official wasm's input table;
// 13 public signals, template GatekeeperEvaluation_79, 647 witness signals):
//   registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
//   currentBlock, recipient, conditionRecipient, amount, maxTransfer,
//   decision (1 = APPROVE, 0 = REJECT), taskId, salt (private).
// Public signals (13): [bindingHash, registeredVkHash, proofVkHash, minimum,
//   publicBalance, expiryBlock, currentBlock, recipient, conditionRecipient,
//   amount, maxTransfer, decision, taskId]. Signal [0] is a salt-dependent
//   binding hash the platform cannot recompute; the other 12 are the task
//   fields, which the platform checks against the envelope.
//
// taskId mapping (OPEN — confirm against a practice task):
//   The envelope's task_id is a string like "gk_24_9d1"; the circuit needs a
//   field element. Default: keccak256(task_id as UTF-8) mod FIELD_PRIME.
//   Alternatives (GATEKEEPER_TASK_ID_MODE): "numeric" (digits of the suffix
//   as a decimal number), "hex" (hex chars of the suffix as a number).
//   If a practice task's proof is rejected, switch the mode and retry — the
//   mapping is this one function, no other code changes needed.
const crypto = require('crypto');
const { modField, keccakModField } = require('../shared/field');
const snark = require('../shared/snark');

function taskIdToField(taskId, mode) {
  const id = String(taskId || '');
  if (mode === 'numeric') {
    const digits = id.replace(/\D/g, '');
    return digits ? modField(BigInt(digits)) : 0n;
  }
  if (mode === 'hex') {
    const hex = id.replace(/[^0-9a-fA-F]/g, '');
    return hex ? modField(BigInt('0x' + hex)) : 0n;
  }
  return keccakModField([Buffer.from(id, 'utf8')]);
}

function buildCircuitInput(task, decision, taskIdMode) {
  const salt = '0x' + crypto.randomBytes(32).toString('hex');
  return {
    registeredVkHash: String(task.registered_vk),
    proofVkHash: String(task.proof_vk),
    minimum: String(task.minimum),
    publicBalance: String(task.public_balance),
    expiryBlock: String(task.expiry_block),
    currentBlock: String(task.current_block),
    recipient: String(task.recipient),
    conditionRecipient: String(task.condition_recipient),
    amount: String(task.amount),
    maxTransfer: String(task.max_transfer),
    decision: decision === 'APPROVE' ? '1' : '0',
    taskId: taskIdToField(task.task_id, taskIdMode).toString(),
    salt,
  };
}

async function proveDecision(task, decision, taskIdMode) {
  const input = buildCircuitInput(task, decision, taskIdMode);
  return snark.prove(input);
}

module.exports = { taskIdToField, buildCircuitInput, proveDecision };
