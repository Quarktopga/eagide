// app.js
import { createClient } from 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/+esm';
import { deriveMasterKey, verifyKey, wrapItemKey, unwrapItemKey, encryptItem, decryptItem, genPassword, scorePassword } from './crypto.js';
import { renderList, renderEditor, renderGenerator, renderAudit } from './ui.js';

// Remplace ces valeurs par celles de ton projet Supabase
const SUPABASE_URL = 'https://YOUR_PROJECT.supabase.co';
const SUPABASE_ANON_KEY = 'YOUR_PUBLIC_ANON_KEY';

const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

const $ = (id) => document.getElementById(id);

const state = {
  session: null,
  vault: null,
  masterKey: null,       // CryptoKey
  items: [],             // {id, kind, title, payload, ...}
  clipboardTimer: null
};

function computeRedirectTo() {
  return window.location.origin + window.location.pathname;
}

function setStatus(msg) { $('status').textContent = msg || ''; }

document.addEventListener('DOMContentLoaded', () => {
  attachHandlers();
  initAuthListener();
  sanityCheck();
});

function attachHandlers() {
  $('btn-google').addEventListener('click', async (e) => {
    e.preventDefault(); setStatus('Redirection vers Google…');
    await supabase.auth.signInWithOAuth({ provider: 'google', options: { redirectTo: computeRedirectTo() } })
      .catch(err => { console.error(err); alert('Erreur OAuth Google. Voir console.'); });
  });

  $('btn-microsoft').addEventListener('click', async (e) => {
    e.preventDefault(); setStatus('Redirection vers Microsoft…');
    await supabase.auth.signInWithOAuth({ provider: 'azure', options: { redirectTo: computeRedirectTo() } })
      .catch(err => { console.error(err); alert('Erreur OAuth Microsoft. Voir console.'); });
  });

  $('btn-logout').addEventListener('click', async () => {
    await supabase.auth.signOut();
    lockAndReset();
    setStatus('Déconnecté.');
  });

  $('unlockBtn').addEventListener('click', unlockVault);
  $('createVaultBtn').addEventListener('click', createVault);
  $('quickLock').addEventListener('click', lockAndReset);
  $('newItem').addEventListener('click', () => renderEditor(null, saveItem, deleteItem));
  $('generator').addEventListener('click', () => renderGenerator(onGenerate));
  $('search').addEventListener('input', onSearch);
}

function initAuthListener() {
  supabase.auth.onAuthStateChange(async (event, session) => {
    console.log('Auth event:', event);
    state.session = session || null;

    const isSignedIn = !!state.session;
    $('btn-logout').classList.toggle('hidden', !isSignedIn);
    $('btn-google').classList.toggle('hidden', isSignedIn);
    $('btn-microsoft').classList.toggle('hidden', isSignedIn);
    $('welcome').classList.toggle('hidden', isSignedIn);
    $('unlock').classList.toggle('hidden', !isSignedIn);

    if (!isSignedIn) {
      setStatus('Veuillez vous connecter.');
      return;
    }

    const { data, error } = await supabase.from('vaults').select('*').eq('owner_uid', state.session.user.id).limit(1).single();
    if (error && error.code !== 'PGRST116') { // single() no rows
      console.error('Erreur lecture vault:', error);
      setStatus('Erreur de lecture coffre.');
      return;
    }
    state.vault = data || null;
    $('createVaultBtn').classList.toggle('hidden', !!state.vault);

    setStatus('Connecté. Déverrouillez votre coffre.');
  });
}

async function sanityCheck() {
  try {
    const { error } = await supabase.from('vaults').select('id').limit(1);
    if (error && !String(error.message || '').includes('relation')) {
      console.warn('Sanity check:', error.message);
    }
  } catch (err) {
    console.error('Supabase init error:', err);
    setStatus('Erreur d’initialisation Supabase (URL ou clé publique).');
  }
}

async function createVault() {
  const pass = $('passphrase').value;
  if (!pass) return alert('Entrez une phrase secrète.');
  const kdf = await deriveMasterKey(pass);
  state.masterKey = kdf.key;

  const { data, error } = await supabase.from('vaults').insert({
    owner_uid: state.session.user.id,
    kdf_salt: kdf.salt,
    kdf_params: kdf.params,
    key_verifier: kdf.verifier
  }).select().single();

  if (error) {
    console.error(error);
    return alert('Erreur de création du coffre.');
  }
  state.vault = data;
  await loadItems();
}

async function unlockVault() {
  if (!state.vault) return alert('Aucun coffre. Créez-le d’abord.');
  const pass = $('passphrase').value;
  if (!pass) return alert('Entrez votre phrase secrète.');

  const kdf = await deriveMasterKey(pass, state.vault.kdf_salt, state.vault.kdf_params);
  const ok = await verifyKey(kdf.verifier, state.vault.key_verifier);
  if (!ok) return alert('Phrase secrète invalide.');

  state.masterKey = kdf.key;
  await loadItems();
}

async function loadItems() {
  const { data, error } = await supabase.from('items')
    .select('id, kind, title, tags_hashed, enc_key_wrapped, enc_blob, iv, aad, version, updated_at')
    .eq('vault_id', state.vault.id)
    .order('updated_at', { ascending: false });

  if (error) { console.error(error); return alert('Erreur de chargement.'); }

  const items = [];
  for (const row of data) {
    try {
      const itemKey = await unwrapItemKey(state.masterKey, row.enc_key_wrapped);
      const payload = await decryptItem(itemKey, row.enc_blob, row.iv, row.aad);
      items.push({ ...row, payload });
    } catch (e) {
      console.warn('Élément illisible (clé/INTÉGRITÉ):', row.id, e);
    }
  }
  state.items = items;

  $('unlock').classList.add('hidden');
  $('vault').classList.remove('hidden');

  renderList(state.items, onEdit, onCopy, onReveal);
  renderAudit(state.items);
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
    tags_hashed: model.tags || [],
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
    try { await navigator.clipboard.writeText(''); } catch {}
  }, timerMs);
}

function onReveal(node) { node.classList.toggle('revealed'); }

function lockAndReset() {
  state.masterKey = null;
  state.items = [];
  $('vault').classList.add('hidden');
  $('unlock').classList.remove('hidden');
}

function onSearch(e) {
  const q = e.target.value.toLowerCase();
  const filtered = state.items.filter(it =>
    it.title.toLowerCase().includes(q) ||
    (it.payload?.username || '').toLowerCase().includes(q)
  );
  renderList(filtered, onEdit, onCopy, onReveal);
}

function onGenerate(options) {
  const pwd = genPassword(options);
  const score = scorePassword(pwd);
  return { pwd, score };
}
