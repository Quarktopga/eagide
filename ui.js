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
      user.innerHTML = `<span class="muted">Utilisateur</span>: ${escapeHtml(it.payload.username || '')}`;
      const pass = document.createElement('div');
      const secret = document.createElement('span');
      secret.className = 'secret';
      secret.textContent = it.payload.password || '';
      const reveal = document.createElement('button');
      reveal.textContent = 'Afficher';
      reveal.onclick = () => onReveal(secret);
      const copy = document.createElement('button');
      copy.className = 'copyBtn';
      copy.textContent = 'Copier';
      copy.onclick = () => onCopy(it.payload.password || '');
      pass.appendChild(secret); pass.appendChild(reveal); pass.appendChild(copy);
      actions.appendChild(user); actions.appendChild(pass);
    } else if (it.kind === 'note') {
      const note = document.createElement('div');
      note.textContent = (it.payload.note || '').slice(0, 120);
      actions.appendChild(note);
    } else if (it.kind === 'totp') {
      const totp = document.createElement('div');
      totp.className = 'muted';
      totp.textContent = 'Code TOTP calculé localement (à venir).';
      actions.appendChild(totp);
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
      case 'login': {
        const u = field('Utilisateur', input('text', item?.payload?.username || ''));
        const p = field('Mot de passe', input('password', item?.payload?.password || ''));
        body.append(u.el, p.el);
        model.payload = { username: u.input.value, password: p.input.value };
        break;
      }
      case 'note': {
        const n = field('Note', textarea(item?.payload?.note || ''));
        body.append(n.el);
        model.payload = { note: n.input.value };
        break;
      }
      case 'totp': {
        const s = field('Secret (Base32)', input('text', item?.payload?.secret || ''));
        body.append(s.el);
        model.payload = { secret: s.input.value };
        break;
      }
      default: {
        const j = field('JSON', textarea(JSON.stringify(item?.payload || {}, null, 2)));
        body.append(j.el);
        try { model.payload = JSON.parse(j.input.value || '{}'); } catch { model.payload = {}; }
      }
    }
  };
  renderBody();
  kindSel.input.onchange = () => { model.kind = kindSel.input.value; renderBody(); };
  title.input.oninput = () => { model.title = title.input.value; };

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

export function renderGenerator(onGenerate) {
  const panel = document.getElementById('generatorPanel');
  panel.classList.remove('hidden');
  panel.innerHTML = '';

  const len = field('Longueur', input('number', '20')); len.input.min = '8'; len.input.max = '128';
  const upper = checkbox('Majuscules', true);
  const lower = checkbox('Minuscules', true);
  const digits = checkbox('Chiffres', true);
  const symbols = checkbox('Symboles', true);
  const lookalikes = checkbox('Exclure les caractères ambigus (I, O, l, 0)', true);

  const out = document.createElement('div'); out.className = 'fields';
  const pwdOut = input('text', ''); pwdOut.readOnly = true;
  const copy = button('Copier', () => navigator.clipboard.writeText(pwdOut.value));
  const strength = document.createElement('div'); strength.className = 'strength';
  const bar = document.createElement('div'); bar.className = 'strength-bar'; const fill = document.createElement('div'); bar.appendChild(fill);
  strength.append(bar);

  const genBtn = button('Générer', () => {
    const { pwd, score } = onGenerate({
      length: Number(len.input.value),
      upper: upper.input.checked,
      lower: lower.input.checked,
      digits: digits.input.checked,
      symbols: symbols.input.checked,
      excludeLookalikes: lookalikes.input.checked,
    });
    pwdOut.value = pwd;
    strength.classList.remove('ok', 'good');
    if (score.label === 'bon') strength.classList.add('good');
    else if (score.label === 'moyen') strength.classList.add('ok');
    fill.style.width = score.label === 'bon' ? '80%' : score.label === 'moyen' ? '50%' : '20%';
  });

  panel.append(len.el, upper.el, lower.el, digits.el, symbols.el, lookalikes.el, genBtn, out, pwdOut, copy, strength);

  function field(label, inputEl) {
    const el = document.createElement('div'); const l = document.createElement('label');
    l.textContent = label; el.append(l); el.append(inputEl); return { el, input: inputEl };
  }
  function input(type, value) { const i = document.createElement('input'); i.type = type; i.value = value; return i; }
  function checkbox(label, checked) {
    const wrap = document.createElement('div');
    const l = document.createElement('label'); const c = document.createElement('input'); c.type = 'checkbox'; c.checked = checked;
    l.textContent = label; wrap.append(l); wrap.append(c); return { el: wrap, input: c };
  }
  function button(text, cb) { const b = document.createElement('button'); b.textContent = text; b.onclick = cb; return b; }
}

export function renderAudit(items) {
  const target = document.getElementById('audit');
  const reused = new Map();
  let weak = 0;
  for (const it of items) {
    if (it.kind === 'login') {
      const pwd = it.payload.password || '';
      const hash = simpleHash(pwd);
      reused.set(hash, (reused.get(hash) || 0) + 1);
      if ((pwd.length < 12) || !(/[A-Z]/.test(pwd) && /[a-z]/.test(pwd) && /\d/.test(pwd))) weak++;
    }
  }
  const reuseCount = [...reused.values()].filter(n => n > 1).length;
  target.textContent = `Audit: ${weak} mot(s) de passe faibles · ${reuseCount} cas de réutilisation`;
}

function simpleHash(str) {
  let h = 0; for (let i = 0; i < str.length; i++) h = (h * 31 + str.charCodeAt(i)) >>> 0;
  return h.toString(16);
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
