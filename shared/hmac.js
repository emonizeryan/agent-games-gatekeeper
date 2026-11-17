// HMAC-SHA256 for the Agent Games envelope protocol.
// The platform signs every inbound task with the secret issued at registration
// ("Rotate Secret" in the dashboard) and puts the signature in the
// `x-agent-games-signature` header, computed over the RAW request body.
// We verify it BEFORE parsing JSON, and sign every response the same way.
//
// Encoding is not stated explicitly in the official docs; the standard
// assumption is a lowercase hex HMAC-SHA256 of the raw body. If the platform
// rejects the preflight, flip AGENT_GAMES_HMAC_FORMAT to `sha256=` to use
// the `sha256=<hex>` form instead. Preflight is the verification step.
const crypto = require('crypto');

function hmacHex(secret, rawBody) {
  return crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
}

function signBody(secret, rawBody, format) {
  const hex = hmacHex(secret, rawBody);
  return format === 'sha256=' ? 'sha256=' + hex : hex;
}

function verifyBody(secret, rawBody, headerValue, format) {
  if (!secret || !headerValue) return false;
  const expected = signBody(secret, rawBody, format);
  const a = Buffer.from(expected);
  const b = Buffer.from(String(headerValue));
  if (a.length !== b.length) return false;
  try {
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

module.exports = { hmacHex, signBody, verifyBody };
