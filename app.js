(() => {
  // Relay publik gratis berbasis pub/sub HTTP. Bisa diganti dengan server ntfy sendiri.
  const SERVER = 'https://ntfy.sh';
  const MAX_BODY = 3800; // batas ntfy 4096 byte

  const $ = (s) => document.querySelector(s);
  const home = $('#home'), room = $('#room');
  const nameInput = $('#nameInput'), codeInput = $('#codeInput');
  const messagesEl = $('#messages'), textInput = $('#textInput');
  const statusDot = $('#statusDot');

  const enc = new TextEncoder(), dec = new TextDecoder();
  let state = { code: null, topic: null, key: null, es: null, seen: new Set() };

  // ---------- util ----------
  const clientId = (() => {
    let id = localStorage.getItem('tr-cid');
    if (!id) { id = crypto.randomUUID(); localStorage.setItem('tr-cid', id); }
    return id;
  })();

  nameInput.value = localStorage.getItem('tr-name') || '';
  nameInput.addEventListener('input', () => localStorage.setItem('tr-name', nameInput.value.trim()));

  function toast(msg) {
    const t = $('#toast');
    t.textContent = msg;
    t.classList.add('show');
    clearTimeout(toast._t);
    toast._t = setTimeout(() => t.classList.remove('show'), 1800);
  }

  const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
  const b64 = (bytes) => btoa(String.fromCharCode(...bytes));
  const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

  function normalize(code) {
    return code.toLowerCase().replace(/[^a-z0-9]/g, '');
  }

  function randomCode() {
    const alphabet = 'abcdefghjkmnpqrstuvwxyz23456789'; // tanpa karakter yang mirip
    const bytes = crypto.getRandomValues(new Uint8Array(10));
    const s = [...bytes].map((b) => alphabet[b % alphabet.length]).join('');
    return s.slice(0, 5) + '-' + s.slice(5);
  }

  // ---------- crypto ----------
  async function deriveKeys(code) {
    const norm = normalize(code);
    const hash = await crypto.subtle.digest('SHA-256', enc.encode('topic:' + norm));
    const topic = 'tr-' + hex(hash).slice(0, 32); // kode asli tidak pernah dikirim ke server
    const base = await crypto.subtle.importKey('raw', enc.encode(norm), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: enc.encode('textroom-v1'), iterations: 100000, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
    return { topic, key };
  }

  async function encrypt(obj) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv }, state.key, enc.encode(JSON.stringify(obj))
    ));
    const out = new Uint8Array(iv.length + ct.length);
    out.set(iv); out.set(ct, iv.length);
    return b64(out);
  }

  async function decrypt(str) {
    const raw = unb64(str);
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: raw.slice(0, 12) }, state.key, raw.slice(12)
    );
    return JSON.parse(dec.decode(pt));
  }

  // ---------- room ----------
  async function joinRoom(rawCode) {
    const code = rawCode.trim();
    if (normalize(code).length < 4) { toast('Kode room minimal 4 karakter'); return; }
    leaveRoom(true);

    const { topic, key } = await deriveKeys(code);
    state = { code, topic, key, es: null, seen: new Set() };

    $('#roomCode').textContent = code;
    messagesEl.innerHTML = '<div class="empty">Belum ada pesan. Kirim yang pertama!</div>';
    home.classList.add('hidden');
    room.classList.remove('hidden');
    history.replaceState(null, '', '#' + encodeURIComponent(code));
    connect();
    textInput.focus();
  }

  function connect() {
    statusDot.className = 'dot';
    const es = new EventSource(`${SERVER}/${state.topic}/sse?since=all`);
    state.es = es;
    es.onopen = () => (statusDot.className = 'dot on');
    es.onerror = () => (statusDot.className = 'dot off'); // EventSource reconnect otomatis
    es.onmessage = async (ev) => {
      try {
        const m = JSON.parse(ev.data);
        if (m.event !== 'message' || state.seen.has(m.id)) return;
        state.seen.add(m.id);
        const payload = await decrypt(m.message);
        addMessage(payload, m.time);
      } catch (_) { /* bukan pesan valid / kunci salah -> abaikan */ }
    };
  }

  function leaveRoom(silent) {
    if (state.es) state.es.close();
    state = { code: null, topic: null, key: null, es: null, seen: new Set() };
    if (!silent) {
      room.classList.add('hidden');
      home.classList.remove('hidden');
      history.replaceState(null, '', location.pathname);
    }
  }

  // ---------- render ----------
  function linkify(container, text) {
    const re = /(https?:\/\/[^\s<>"]+)/g;
    text.split(re).forEach((part, i) => {
      if (i % 2 === 1) {
        const a = document.createElement('a');
        a.href = part; a.textContent = part; a.target = '_blank'; a.rel = 'noopener noreferrer';
        container.appendChild(a);
      } else if (part) {
        container.appendChild(document.createTextNode(part));
      }
    });
  }

  function addMessage(p, unixTime) {
    const empty = messagesEl.querySelector('.empty');
    if (empty) empty.remove();

    const nearBottom = messagesEl.scrollHeight - messagesEl.scrollTop - messagesEl.clientHeight < 120;

    const wrap = document.createElement('div');
    wrap.className = 'msg' + (p.cid === clientId ? ' mine' : '');

    const meta = document.createElement('div');
    meta.className = 'meta';
    const time = new Date(unixTime * 1000).toLocaleTimeString('id-ID', { hour: '2-digit', minute: '2-digit' });
    meta.append(document.createTextNode(`${p.from || 'Anonim'} · ${time}`));
    const copy = document.createElement('button');
    copy.className = 'copy'; copy.type = 'button'; copy.textContent = 'Salin';
    copy.onclick = () => navigator.clipboard.writeText(p.text).then(() => toast('Tersalin'));
    meta.appendChild(copy);

    const body = document.createElement('div');
    body.className = 'body';
    linkify(body, p.text);

    wrap.append(meta, body);
    messagesEl.appendChild(wrap);
    if (nearBottom || p.cid === clientId) messagesEl.scrollTop = messagesEl.scrollHeight;
  }

  // ---------- kirim ----------
  async function send() {
    const text = textInput.value.trim();
    if (!text || !state.topic) return;
    const body = await encrypt({ text, from: nameInput.value.trim() || 'Anonim', cid: clientId });
    if (body.length > MAX_BODY) { toast('Teks terlalu panjang (maks ± 2.500 karakter)'); return; }
    try {
      const res = await fetch(`${SERVER}/${state.topic}`, { method: 'POST', body });
      if (!res.ok) throw new Error(res.status);
      textInput.value = '';
      autosize();
    } catch (e) {
      toast('Gagal kirim, cek koneksi');
    }
  }

  function autosize() {
    textInput.style.height = 'auto';
    textInput.style.height = Math.min(textInput.scrollHeight, 140) + 'px';
  }

  // ---------- event ----------
  $('#newBtn').onclick = () => joinRoom(randomCode());
  $('#joinForm').onsubmit = (e) => { e.preventDefault(); joinRoom(codeInput.value); };
  $('#leaveBtn').onclick = () => leaveRoom(false);
  $('#copyLink').onclick = () => {
    const url = location.origin + location.pathname + '#' + encodeURIComponent(state.code);
    navigator.clipboard.writeText(url).then(() => toast('Link room tersalin'));
  };
  $('#sendForm').onsubmit = (e) => { e.preventDefault(); send(); };
  textInput.addEventListener('input', autosize);
  textInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); }
  });

  // Auto-join dari link (#kode)
  if (location.hash.length > 1) joinRoom(decodeURIComponent(location.hash.slice(1)));
})();
