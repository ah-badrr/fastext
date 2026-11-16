(() => {
  // Relay publik gratis berbasis pub/sub HTTP. Bisa diganti dengan server ntfy sendiri.
  const SERVER = 'https://ntfy.sh';
  const MAX_BODY = 3800; // batas ntfy 4096 byte (payload base64 per potongan)
  const CHUNK_TTL = 60000; // gabungkan potongan selama maks 60 detik
  const MAX_CHARS = 50000; // batas praktis teks per pesan (±20potongan x 2500 karakter)

  const $ = (s) => document.querySelector(s);
  const home = $('#home'), room = $('#room');
  const nameInput = $('#nameInput'), codeInput = $('#codeInput');
  const messagesEl = $('#messages'), textInput = $('#textInput');
  const statusDot = $('#statusDot');

  const enc = new TextEncoder(), dec = new TextDecoder();
  let state = { code: null, topic: null, key: null, es: null, seen: new Set(), pending: new Map() };

  // ---------- pemotongan pesan panjang ----------
  // Batas ntfy ±4096 byte per request, dan ciphertext AES-GCM tidak bisa
  // dipotong-potong sembarangan. Jadi teks dipecah DULU (per karakter), tiap
  // potongan dienkripsi & dikirim sebagai satu POST terpisah, lalu penerima
  // menggabungkannya kembali menjadi satu pesan utuh.

  // Estimasi panjang payload base64 (iv+ciphertext+tag) untuk JSON sepanjang n byte.
  const b64LenForBytes = (n) => Math.ceil((12 + n + 16) / 3) * 4;
  const bytesOf = (s) => enc.encode(s).length;

  // Cari ukuran potongan terbesar (<= hi) yang payload-nya masih < MAX_BODY,
  // termasuk overhead JSON pembungkusnya ({text, from, cid, mid, part, total}).
  function fitChunkSize(text, metaBytes, lo, hi) {
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (b64LenForBytes(bytesOf(text.slice(0, mid)) + metaBytes) < MAX_BODY) lo = mid;
      else hi = mid - 1;
    }
    return Math.max(lo, 1);
  }

  function splitText(text, metaBytes) {
    const parts = [];
    let rest = text;
    while (bytesOf(rest) + metaBytes >= MAX_BODY) {
      const size = fitChunkSize(rest, metaBytes, 1, rest.length);
      // jangan potong pasangan surrogate (emoji/karakter Unicode di atas U+FFFF)
      const last = rest.charCodeAt(size - 1);
      const cut = (last >= 0xd800 && last <= 0xdbff) ? size - 1 : size;
      parts.push(rest.slice(0, cut));
      rest = rest.slice(cut);
    }
    if (rest) parts.push(rest);
    return parts;
  }

  async function sendMessageChunks(parts, from, msgId, total) {
    for (let i = 0; i < parts.length; i++) {
      const body = await encrypt({
        text: parts[i], from, cid: clientId,
        ...(total > 1 ? { mid: msgId, part: i, total } : {})
      });
      if (body.length > MAX_BODY) throw new Error('chunk terlalu besar');
      const res = await fetch(`${SERVER}/${state.topic}`, { method: 'POST', body });
      if (!res.ok) throw new Error(res.status);
    }
  }

  // Hitung potongan dengan asumsi JSON pembungkus paling buruk (paling panjang),
  // lalu verifikasi payload asli tiap potongan — perkecil & ulangi jika kebesaran.
  async function buildParts(text, from) {
    let metaBytes = 256 + clientId.length + from.length;
    for (;;) {
      const parts = splitText(text, metaBytes);
      const msgId = crypto.randomUUID();
      // total bisa bertambah saat potongan dikecilkan -> pakai angka terburuk: 999
      const worstTotal = String(Math.max(parts.length, 999));
      try {
        for (const p of parts) {
          const body = await encrypt({
            text: p, from, cid: clientId,
            ...(parts.length > 1 ? { mid: msgId, part: 999, total: worstTotal } : {})
          });
          if (body.length > MAX_BODY) throw new Error('over');
        }
        return parts;
      } catch (_) {
        if (metaBytes <= 64) throw new Error('split gagal');
        metaBytes *= 2; // conservative: perkecil ukuran potongan
      }
    }
  }

  // Kumpulkan potongan-potongan dari satu pesan panjang, gabung saat lengkap.
  function collectPart(p, unixTime) {
    const { mid, part, total } = p;
    let buf = state.pending.get(mid);
    if (!buf) {
      buf = new Array(total);
      state.pending.set(mid, buf);
      setTimeout(() => {
        if (state.pending.get(mid) === buf) state.pending.delete(mid);
      }, CHUNK_TTL);
    }
    if (part >= total) return; // data rusak
    buf[part] = p.text;
    if (buf.every((x) => x !== undefined)) {
      state.pending.delete(mid);
      addMessage({ text: buf.join(''), from: p.from, cid: p.cid }, unixTime);
    }
  }

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
    state = { code, topic, key, es: null, seen: new Set(), pending: new Map() };

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
        if (typeof payload.mid === 'string' && Number.isInteger(payload.part)) {
          collectPart(payload, m.time); // bagian dari pesan panjang -> tunggu lengkap
        } else {
          addMessage(payload, m.time);
        }
      } catch (_) { /* bukan pesan valid / kunci salah -> abaikan */ }
    };
  }

  function leaveRoom(silent) {
    if (state.es) state.es.close();
    state = { code: null, topic: null, key: null, es: null, seen: new Set(), pending: new Map() };
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
  let sending = false;
  async function send() {
    const text = textInput.value.trim();
    if (!text || !state.topic || sending) return;
    if (text.length > MAX_CHARS) {
      toast(`Teks terlalu panjang (maks ${MAX_CHARS.toLocaleString('id-ID')} karakter)`);
      return;
    }
    const from = nameInput.value.trim() || 'Anonim';
    sending = true;
    $('#sendBtn').disabled = true;
    try {
      const parts = await buildParts(text, from);
      if (parts.length === 1) {
        // pesan pendek: kirim sekali saja tanpa metadata chunk (hemat kuota)
        const body = await encrypt({ text, from, cid: clientId });
        const res = await fetch(`${SERVER}/${state.topic}`, { method: 'POST', body });
        if (!res.ok) throw new Error(res.status);
      } else {
        await sendMessageChunks(parts, from, crypto.randomUUID(), parts.length);
      }
      textInput.value = '';
      autosize();
      updateCounter();
      if (parts.length > 1) toast(`Terkirim dalam ${parts.length} potongan`);
    } catch (e) {
      toast('Gagal kirim, cek koneksi');
    } finally {
      sending = false;
      $('#sendBtn').disabled = false;
    }
  }

  function autosize() {
    textInput.style.height = 'auto';
    textInput.style.height = Math.min(textInput.scrollHeight, 140) + 'px';
  }

  // penghitung karakter realtime (muncul saat mendekati batas)
  const counterEl = $('#charCount');
  function updateCounter() {
    const n = textInput.value.trim().length;
    if (n < MAX_CHARS * 0.8) { counterEl.textContent = ''; return; }
    const k = (v) => v.toLocaleString('id-ID');
    counterEl.textContent = `${k(n)} / ${k(MAX_CHARS)} karakter`;
    counterEl.classList.toggle('warn', n > MAX_CHARS);
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
  textInput.addEventListener('input', () => { autosize(); updateCounter(); });
  textInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); }
  });

  // Auto-join dari link (#kode)
  if (location.hash.length > 1) joinRoom(decodeURIComponent(location.hash.slice(1)));
})();
