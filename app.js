// app.js
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

import { deriveMasterKey, wrapItemKey, unwrapItemKey, encryptItem, decryptItem } from './crypto.js';
import { renderList, renderEditor } from './ui.js';
import { totpNow } from './totp.js';

const supabase = createClient('https://nlnlyssdyxhrzfyrzxbm.supabase.co', 'sb_publishable_0_GAx_3WxLEVo9ctBuSCeA_lylUUc3M');

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
