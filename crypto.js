// crypto.js
function bufToBase64(buf) { return btoa(String.fromCharCode(...new Uint8Array(buf))); }
function base64ToBuf(b64) {
  const bin = atob(b64); const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}

export async function deriveMasterKey(passphrase, saltB64, params = null) {
  const enc = new TextEncoder();
  const salt = saltB64 ? base64ToBuf(saltB64) : crypto.getRandomValues(new Uint8Array(16)).buffer;
  const iter = params?.iter ?? 400000;

  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(passphrase), { name: 'PBKDF2' }, false, ['deriveKey', 'deriveBits']
  );
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' },
    keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );

  // Verifier (HKDF -> HMAC-like bits)
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' },
    keyMaterial, 128
  );
  const verifier = bufToBase64(bits);

  return {
    key,
    salt: bufToBase64(salt),
    params: { algo: 'PBKDF2', iter },
    verifier
  };
}

export async function wrapItemKey(masterKey, itemKey) {
  // Simplified: encrypt a random 32-byte key under masterKey
  const rawItemKey = await crypto.subtle.exportKey('raw', itemKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, masterKey, rawItemKey);
  return JSON.stringify({ iv: bufToBase64(iv.buffer), ct: bufToBase64(ct) });
}

export async function unwrapItemKey(masterKey, wrappedJson) {
  const { iv, ct } = JSON.parse(wrappedJson);
  const raw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: base64ToBuf(iv) }, masterKey, base64ToBuf(ct));
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

export async function encryptItem(itemKey, payload, itemId) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const aad = `eagide:${itemId ?? 'new'}:${Date.now()}`;
  const plaintext = enc.encode(JSON.stringify(payload));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(aad) },
    itemKey, plaintext
  );
  return { ciphertext: bufToBase64(ciphertext), iv: bufToBase64(iv.buffer), aad };
}

export async function decryptItem(itemKey, ciphertextB64, ivB64, aad) {
  const dec = new TextDecoder();
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64ToBuf(ivB64), additionalData: new TextEncoder().encode(aad) },
    itemKey, base64ToBuf(ciphertextB64)
  );
  return JSON.parse(dec.decode(pt));
}
