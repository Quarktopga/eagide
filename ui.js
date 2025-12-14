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
