// Proof Gatekeeper — deterministic decision logic.
// The official circuit is the referee: it enforces that the decision matches
// its own evaluation of the task inputs, so this module must implement
// EXACTLY the circuit's checks. A wrong decision fails witness generation.
//
// Checks, first failing trap wins (reason_code = trap name):
//   VK_SUBSTITUTION   proof_vk != registered_vk
//   PROOF_REUSED      proof_tx already seen under a DIFFERENT task_id
//   THRESHOLD_MISMATCH public_balance < minimum
//   EXPIRED_CONDITION current_block >= expiry_block (expiry is STRICT)
//   RECIPIENT_MISMATCH recipient != condition_recipient (case-insensitive)
//   AMOUNT_OVERFLOW   amount > max_transfer
//   else VALID_CONDITION -> APPROVE
//
// Boundaries (verified against the circuit in gatekeeper/test.js):
//   - public_balance == minimum is VALID (threshold is inclusive).
//   - amount == max_transfer is VALID (cap is inclusive).
//   - current_block == expiry_block is EXPIRED (valid only while
//     current_block < expiry_block).
//   - A platform retry of the SAME task_id is NOT a reuse; the same
//     proof_tx under another task_id IS a reuse.
// The seen-set lives in memory; a server restart clears it. That matches the
// platform's round model (8 tasks per round, fresh rounds daily), but a
// restart mid-round could miss a reuse — see README "Known limits".
const seenProofs = new Map(); // proof_tx (lowercased) -> task_id

function decide(input) {
  const registeredVk = String(input.registered_vk || '').toLowerCase();
  const proofVk = String(input.proof_vk || '').toLowerCase();
  const minimum = BigInt(input.minimum);
  const balance = BigInt(input.public_balance);
  const expiry = BigInt(input.expiry_block);
  const current = BigInt(input.current_block);
  const recipient = String(input.recipient || '').toLowerCase();
  const conditionRecipient = String(input.condition_recipient || '').toLowerCase();
  const amount = BigInt(input.amount);
  const cap = BigInt(input.max_transfer);
  const proofTx = String(input.proof_tx || '').toLowerCase();
  const taskId = String(input.task_id || '');

  if (proofVk !== registeredVk) return { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION' };

  if (proofTx) {
    const previousTask = seenProofs.get(proofTx);
    if (previousTask !== undefined && previousTask !== taskId) {
      return { decision: 'REJECT', reason_code: 'PROOF_REUSED' };
    }
    if (previousTask === undefined) seenProofs.set(proofTx, taskId);
  }

  if (balance < minimum) return { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH' };
  if (current >= expiry) return { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION' };
  if (recipient !== conditionRecipient) return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH' };
  if (amount > cap) return { decision: 'REJECT', reason_code: 'AMOUNT_OVERFLOW' };

  return { decision: 'APPROVE', reason_code: 'VALID_CONDITION' };
}

function resetSeen() {
  seenProofs.clear();
}

module.exports = { decide, resetSeen, seenProofs };
