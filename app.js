// app.js
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

import { deriveMasterKey, wrapItemKey, unwrapItemKey, encryptItem, decryptItem } from './crypto.js';
import { renderList, renderEditor } from './ui.js';
import { totpNow } from './totp.js';

const supabase = createClient('https://YOUR_PROJECT.supabase.co', 'PUBLIC_ANON_KEY');

const state = {
  session: null,
  vault: null,        // vault row with salts and params
  masterKey: null,    // CryptoKey (not persisted)
  items: [],          // decrypted item models
  clipboardTimer: null
};

const loginMicrosoft = document.getElementById('loginMicrosoft');
const loginGoogle = document.getElementById('loginGoogle');
const logoutBtn = document.getElementById('logout');

loginMicrosoft.onclick = async () => {
  await supabase.auth.signInWithOAuth({ provider: 'azure' });
};
loginGoogle.onclick = async () => {
  await supabase.auth.signInWithOAuth({ provider: 'google' });
};

logoutBtn.onclick = async () => {
  await supabase.auth.signOut();
  lockAndReset();
};

supabase.auth.onAuthStateChange(async (event, session) => {
  state.session = session;
  document.getElementById('app').classList.toggle('hidden', !session);
  document.getElementById('logout').classList.toggle('hidden', !session);
  document.getElementById('loginMicrosoft').classList.toggle('hidden', !!session);
  document.getElementById('loginGoogle').classList.toggle('hidden', !!session);
  if (!session) return;

  const { data } = await supabase.from('vaults').select('*').eq('owner_uid', session.user.id).limit(1).single();
  state.vault = data || null;
  document.getElementById('createVaultBtn').classList.toggle('hidden', !!data);
});

document.getElementById('createVaultBtn').onclick = async () => {
  const pass = document.getElementById('passphrase').value;
  const kdf = await deriveMasterKey(pass); // returns { key, salt, params, verifier }
  state.masterKey = kdf.key;
  const { data, error } = await supabase.from('vaults').insert({
    owner_uid: state.session.user.id,
    kdf_salt: kdf.salt,
    kdf_params: kdf.params,
    key_verifier: kdf.verifier
  }).select().single();
  if (error) return alert('Erreur de création du coffre.');
  state.vault = data;
  await loadItems();
};

document.getElementById('unlockBtn').onclick = async () => {
  const pass = document.getElementById('passphrase').value;
  if (!state.vault) return alert('Aucun coffre. Créez-le d’abord.');
  const kdf = await deriveMasterKey(pass, state.vault.kdf_salt, state.vault.kdf_params);
  state.masterKey = kdf.key;
  // Optionally verify
  // compare kdf.verifier === vault.key_verifier (constant-time)
  await loadItems();
};

async function loadItems() {
  const { data, error } = await supabase.from('items')
    .select('id, kind, title, tags_hashed, enc_key_wrapped, enc_blob, iv, aad, version, updated_at')
    .eq('vault_id', state.vault.id)
    .order('updated_at', { ascending: false });
  if (error) return alert('Erreur de chargement.');
  const items = [];
  for (const row of data) {
    const itemKey = await unwrapItemKey(state.masterKey, row.enc_key_wrapped);
    const payload = await decryptItem(itemKey, row.enc_blob, row.iv, row.aad);
    items.push({ ...row, payload });
  }
  state.items = items;
  document.getElementById('unlock').classList.add('hidden');
  document.getElementById('vault').classList.remove('hidden');
  renderList(state.items, onEdit, onCopy, onReveal);
}

function onEdit(item) { renderEditor(item, saveItem, deleteItem); }

async function saveItem(model) {
  const itemKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const wrapped = await wrapItemKey(state.masterKey, itemKey);
  const { ciphertext, iv, aad } = await encryptItem(itemKey, model.payload, model.id);
  const row = {
    vault_id: state.vault.id,
    kind: model.kind,
    title: model.title,
    tags_hashed: model.tags,
    enc_key_wrapped: wrapped,
    enc_blob: ciphertext,
    iv, aad
  };
  if (model.id) {
    await supabase.from('items').update(row).eq('id', model.id);
  } else {
    await supabase.from('items').insert(row);
  }
  await loadItems();
}

async function deleteItem(item) {
  await supabase.from('items').delete().eq('id', item.id);
  await loadItems();
}

function onCopy(text) {
  navigator.clipboard.writeText(text);
  const timerMs = 15000;
  clearTimeout(state.clipboardTimer);
  state.clipboardTimer = setTimeout(async () => {
    try {
      await navigator.clipboard.writeText('');
    } catch {}
  }, timerMs);
}

function onReveal(node) { node.classList.toggle('revealed'); }

function lockAndReset() {
  state.masterKey = null;
  state.items = [];
  document.getElementById('vault').classList.add('hidden');
  document.getElementById('unlock').classList.remove('hidden');
}
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
// ui.js
export function renderList(items, onEdit, onCopy, onReveal) {
  const list = document.getElementById('list');
  list.innerHTML = '';
  for (const it of items) {
    const card = document.createElement('div');
    card.className = 'card';
    const title = document.createElement('h3');
    title.textContent = it.title;
    const meta = document.createElement('div');
    meta.className = 'meta';
    meta.textContent = `${it.kind} • ${new Date(it.updated_at).toLocaleString()}`;
    const actions = document.createElement('div');

    if (it.kind === 'login') {
      const user = document.createElement('div');
      user.innerHTML = `<span class="muted">Utilisateur</span>: ${it.payload.username}`;
      const pass = document.createElement('div');
      const secret = document.createElement('span');
      secret.className = 'secret';
      secret.textContent = it.payload.password;
      const reveal = document.createElement('button');
      reveal.textContent = 'Afficher';
      reveal.onclick = () => onReveal(secret);
      const copy = document.createElement('button');
      copy.className = 'copyBtn';
      copy.textContent = 'Copier';
      copy.onclick = () => onCopy(it.payload.password);
      pass.appendChild(secret); pass.appendChild(reveal); pass.appendChild(copy);
      actions.appendChild(user); actions.appendChild(pass);
    }

    const edit = document.createElement('button');
    edit.textContent = 'Modifier';
    edit.onclick = () => onEdit(it);

    card.appendChild(title);
    card.appendChild(meta);
    card.appendChild(actions);
    card.appendChild(edit);
    list.appendChild(card);
  }
}

export function renderEditor(item, onSave, onDelete) {
  const panel = document.getElementById('editor');
  panel.classList.remove('hidden');
  panel.innerHTML = '';

  const kindSel = field('Type', select(['login','note','totp','card','identity','custom'], item?.kind || 'login'));
  const title = field('Titre', input('text', item?.title || ''));
  let body = document.createElement('div');

  const model = { id: item?.id, kind: kindSel.input.value, title: title.input.value, tags: [], payload: {} };

  const renderBody = () => {
    body.innerHTML = '';
    switch (kindSel.input.value) {
      case 'login':
        const u = field('Utilisateur', input('text', item?.payload?.username || ''));
        const p = field('Mot de passe', input('password', item?.payload?.password || ''));
        body.append(u.el, p.el);
        model.payload = { username: u.input.value, password: p.input.value };
        break;
      case 'note':
        const n = field('Note', textarea(item?.payload?.note || ''));
        body.append(n.el);
        model.payload = { note: n.input.value };
        break;
      case 'totp':
        const s = field('Secret (Base32)', input('text', item?.payload?.secret || ''));
        body.append(s.el);
        model.payload = { secret: s.input.value };
        break;
      default:
        const j = field('JSON', textarea(JSON.stringify(item?.payload || {}, null, 2)));
        body.append(j.el);
        model.payload = JSON.parse(j.input.value || '{}');
    }
  };
  renderBody();
  kindSel.input.onchange = renderBody;

  const save = button('Enregistrer', async () => { await onSave(model); panel.classList.add('hidden'); });
  const del = item ? button('Supprimer', async () => { await onDelete(item); panel.classList.add('hidden'); }) : null;

  panel.append(kindSel.el, title.el, body, save, ...(del ? [del] : []));

  function field(label, inputEl) {
    const el = document.createElement('div'); const l = document.createElement('label');
    l.textContent = label; el.append(l); el.append(inputEl); return { el, input: inputEl };
  }
  function input(type, value) { const i = document.createElement('input'); i.type = type; i.value = value; return i; }
  function textarea(value) { const t = document.createElement('textarea'); t.value = value; return t; }
  function select(opts, value) {
    const s = document.createElement('select'); for (const o of opts) {
      const opt = document.createElement('option'); opt.value = o; opt.textContent = o;
      if (o === value) opt.selected = true; s.append(opt);
    } return s;
  }
  function button(text, cb) { const b = document.createElement('button'); b.textContent = text; b.onclick = cb; return b; }
}
