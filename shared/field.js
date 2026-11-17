// Field helpers for the BN128 (alt_bn128) prime field — the field of the
// official Agent Games gatekeeper circuit. Only what the gatekeeper needs:
// reduce values mod p, keccak256 (for the taskId mapping), hex helpers.
const { keccak_256 } = require('js-sha3');

const FIELD_PRIME = BigInt(
  '21888242871839275222246405745257275088548364400416034343698204186575808495617'
);

// Any int-like value (hex "0x..", decimal string, number, BigInt) -> field element.
function modField(x) {
  let v;
  if (typeof x === 'bigint') v = x;
  else if (typeof x === 'number') v = BigInt(x);
  else if (typeof x === 'string' && x.startsWith('0x')) v = BigInt(x);
  else v = BigInt(x);
  const r = v % FIELD_PRIME;
  return r < 0n ? r + FIELD_PRIME : r;
}

function keccakHex(buffers) {
  return '0x' + keccak_256(Buffer.concat(buffers));
}

// keccak256 of the concatenated buffers, reduced mod the field prime.
function keccakModField(buffers) {
  return modField(BigInt(keccakHex(buffers)));
}

module.exports = { FIELD_PRIME, modField, keccakHex, keccakModField };
