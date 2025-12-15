// crypto.js
// Utilitaires de chiffrement: PBKDF2/SHA-256 + AES-GCM + enveloppe de clés
function bufToBase64(buf) { return btoa(String.fromCharCode(...new Uint8Array(buf))); }
function base64ToBuf(b64) {
  const bin = atob(b64); const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}

export async function deriveMasterKey(passphrase, saltB64 = null, params = null) {
  const enc = new TextEncoder();
  const salt = saltB64 ? base64ToBuf(saltB64) : crypto.getRandomValues(new Uint8Array(16)).buffer;
  const iter = params?.iter ?? 400000;

  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(passphrase), { name: 'PBKDF2' }, false, ['deriveKey', 'deriveBits']);
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' },
    keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );

  // Verifier: bits dérivés, stockés côté serveur pour vérifier la passphrase
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' },
    keyMaterial, 128
  );
  const verifier = bufToBase64(bits);

  return { key, salt: bufToBase64(salt), params: { algo: 'PBKDF2', iter }, verifier };
}

export async function verifyKey(localVerifierB64, serverVerifierB64) {
  // Comparaison "constante" côté JS (limite: JS ne garantit pas temps constant)
  if (!localVerifierB64 || !serverVerifierB64) return false;
  if (localVerifierB64.length !== serverVerifierB64.length) return false;
  let diff = 0;
  for (let i = 0; i < localVerifierB64.length; i++) diff |= localVerifierB64.charCodeAt(i) ^ serverVerifierB64.charCodeAt(i);
  return diff === 0;
}

export async function wrapItemKey(masterKey, itemKey) {
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

// Générateur de mots de passe
export function genPassword(opts = {}) {
  const length = opts.length ?? 20;
  const useUpper = opts.upper ?? true;
  const useLower = opts.lower ?? true;
  const useDigits = opts.digits ?? true;
  const useSymbols = opts.symbols ?? true;
  const excludeLookalikes = opts.excludeLookalikes ?? true;

  let upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ'; // sans I/O
  let lower = 'abcdefghijkmnopqrstuvwxyz'; // sans l
  let digits = excludeLookalikes ? '23456789' : '0123456789';
  let symbols = '!@#$%^&*()-_=+[]{};:,.?/';

  let alphabet = '';
  if (useUpper) alphabet += upper;
  if (useLower) alphabet += lower;
  if (useDigits) alphabet += digits;
  if (useSymbols) alphabet += symbols;

  const out = [];
  const arr = new Uint32Array(length);
  crypto.getRandomValues(arr);
  for (let i = 0; i < length; i++) out.push(alphabet[arr[i] % alphabet.length]);
  return out.join('');
}

// Évaluation simple de force (heuristique)
export function scorePassword(pwd) {
  let score = 0;
  if (!pwd || pwd.length < 8) return { score: 0, label: 'faible' };
  if (pwd.length >= 12) score += 1;
  if (/[A-Z]/.test(pwd)) score += 1;
  if (/[a-z]/.test(pwd)) score += 1;
  if (/\d/.test(pwd)) score += 1;
  if (/[^A-Za-z0-9]/.test(pwd)) score += 1;

  if (score >= 5) return { score, label: 'bon' };
  if (score >= 3) return { score, label: 'moyen' };
  return { score, label: 'faible' };
}
