// totp.js
// RFC 6238 TOTP (SHA-1 by default)
export async function totpNow(secretBase32, step = 30, digits = 6) {
  const key = base32ToBytes(secretBase32.replace(/\s+/g, '').toUpperCase());
  const counter = Math.floor(Date.now() / 1000 / step);
  const msg = new ArrayBuffer(8);
  new DataView(msg).setUint32(4, counter, false);

  const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const hmac = new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, msg));

  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = ((hmac[offset] & 0x7f) << 24 | (hmac[offset + 1] & 0xff) << 16 |
                (hmac[offset + 2] & 0xff) << 8 | (hmac[offset + 3] & 0xff)) % (10 ** digits);
  return code.toString().padStart(digits, '0');
}

function base32ToBytes(b32) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of b32) {
    const val = alphabet.indexOf(c);
    if (val < 0) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  const out = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return new Uint8Array(out);
}
