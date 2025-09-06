// MES Pro+
// - Chunked transfer with progress bars (up to very large files)
// - Text, images, files, voice messages with stronger disguise (robot / simple pitch)
// - Local persistence; "End chat" button
// Security: demo-level AES-GCM with PBKDF2 key; server relays only.

const qs = new URLSearchParams(location.hash.slice(1));
const pathParts = location.pathname.split('/').filter(Boolean);
let roomId = pathParts[0] === 'room' ? pathParts[1] : null;

const els = {
  statusDot: document.getElementById('statusDot'),
  statusText: document.getElementById('statusText'),
  onlineCount: document.getElementById('onlineCount'),
  createRoom: document.getElementById('createRoom'),
  copyInvite: document.getElementById('copyInvite'),
  endChat: document.getElementById('endChat'),
  nickname: document.getElementById('nickname'),
  input: document.getElementById('input'),
  send: document.getElementById('send'),
  messages: document.getElementById('messages'),
  fileInput: document.getElementById('fileInput'),
  voiceBtn: document.getElementById('voiceBtn'),
  voiceEffect: document.getElementById('voiceEffect'),
};

let ws = null;
let key = null;
let secretB = null;
let saltB = null;
let meId = randomId(6);

// local persistence
function storageKey(room){ return `MES_${room}`; }
let historyCache = [];
let assembling = new Map(); // fileId -> { total, got, chunks:[], meta }
const CHUNK_SIZE = 256 * 1024; // 256 KiB

init().catch(console.error);

async function init() {
  if (roomId) {
    const saved = localStorage.getItem(storageKey(roomId));
    if (saved) {
      try {
        historyCache = JSON.parse(saved);
        for (const item of historyCache) renderMessage(item, item.sender === meId, true);
      } catch(_) {}
    }
  }

  const fromHashK = qs.get('k');
  const fromHashS = qs.get('s');
  if (!fromHashK || !fromHashS || !roomId) {
    setOffline();
  } else {
    secretB = base64urlToBytes(fromHashK);
    saltB = base64urlToBytes(fromHashS);
    key = await deriveKey(secretB, saltB);
    connect();
  }

  els.createRoom.onclick = async () => {
    roomId = randomId(12);
    secretB = crypto.getRandomValues(new Uint8Array(32));
    saltB = crypto.getRandomValues(new Uint8Array(16));
    key = await deriveKey(secretB, saltB);
    const url = `${location.origin}/room/${roomId}#k=${bytesToBase64url(secretB)}&s=${bytesToBase64url(saltB)}`;
    history.pushState({}, '', url);
    historyCache = [];
    localStorage.removeItem(storageKey(roomId));
    connect();
  };

  els.copyInvite.onclick = async () => {
    if (!roomId || !secretB || !saltB) return alert('Сначала создайте комнату');
    const url = `${location.origin}/room/${roomId}#k=${bytesToBase64url(secretB)}&s=${bytesToBase64url(saltB)}`;
    await navigator.clipboard.writeText(url);
    notify('Ссылка скопирована');
  };

  els.endChat.onclick = () => {
    if (!roomId) return;
    localStorage.removeItem(storageKey(roomId));
    location.href = `${location.origin}/room/${roomId}`;
  };

  els.send.onclick = sendText;
  els.input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendText(); }
  });

  els.fileInput.addEventListener('change', handleFiles);
  els.voiceBtn.addEventListener('click', handleVoice);
}

function setOnline(){ els.statusDot.classList.add('online'); els.statusText.textContent='online'; }
function setOffline(){ els.statusDot.classList.remove('online'); els.statusText.textContent='offline'; }

function notify(txt) {
  const li = document.createElement('li');
  li.className = 'meta';
  li.textContent = txt;
  els.messages.appendChild(li);
  els.messages.scrollTop = els.messages.scrollHeight;
}

function randomId(n) {
  const arr = crypto.getRandomValues(new Uint8Array(n));
  const alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let out=''; for (let b of arr) out += alphabet[b % alphabet.length];
  return out;
}

async function deriveKey(secretBytes, saltBytes) {
  const keyMaterial = await crypto.subtle.importKey('raw', secretBytes, {name: 'PBKDF2'}, false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {name: 'PBKDF2', salt: saltBytes, iterations: 200_000, hash: 'SHA-256'},
    keyMaterial,
    {name: 'AES-GCM', length: 256},
    false,
    ['encrypt', 'decrypt']
  );
}

function connect() {
  if (!roomId) return;
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const wsUrl = `${proto}://${location.host}/ws/${roomId}`;
  ws = new WebSocket(wsUrl);

  ws.onopen = () => { setOnline(); notify(`Подключено к комнате ${roomId}`); };
  ws.onclose = () => { setOffline(); notify('Соединение закрыто'); };
  ws.onerror = () => { setOffline(); notify('Ошибка соединения'); };

  ws.onmessage = async (ev) => {
    let dataStr = typeof ev.data === 'string' ? ev.data : await ev.data.text();
    try {
      const data = JSON.parse(dataStr);
      if (data && data._control === 'online') {
        els.onlineCount.textContent = String(data.count);
        return;
      }
    } catch(_) {}

    // Encrypted packet
    try {
      const packet = JSON.parse(dataStr);
      if (!packet.ct || !packet.iv) return;
      const iv = base64urlToBytes(packet.iv);
      const ct = base64urlToBytes(packet.ct);
      const dec = await crypto.subtle.decrypt({name: 'AES-GCM', iv}, key, ct);
      const str = new TextDecoder().decode(new Uint8Array(dec));
      const msg = JSON.parse(str);
      onDecryptedMessage(msg);
    } catch(e) {
      // ignore
    }
  };
}

function onDecryptedMessage(msg){
  if (msg.kind === 'chunk') {
    const id = msg.fileId;
    if (!assembling.has(id)) {
      assembling.set(id, { total: msg.total, got: 0, chunks: new Array(msg.total), meta: msg.meta });
    }
    const entry = assembling.get(id);
    entry.chunks[msg.seq] = msg.data; // base64url string
    entry.got++;
    updateProgress(id, entry.got / entry.total, false);
    if (entry.got === entry.total) {
      // assemble
      const b64 = entry.chunks.join('');
      const bytes = base64urlToBytes(b64);
      const meta = entry.meta;
      const kind = meta.kind;
      const payload = {
        id: id,
        kind: kind,
        sender: msg.sender,
        nick: msg.nick,
        ts: msg.ts,
        name: meta.name,
        mime: meta.mime,
        size: meta.size,
        data: b64
      };
      addMessage(payload, false);
      assembling.delete(id);
    }
    return;
  }
  // regular messages (text)
  addMessage(msg, false);
}

function nowPayloadBase(type, extra={}){
  return {
    id: crypto.randomUUID(),
    kind: type, // 'text' | 'image' | 'file' | 'audio' | 'chunk'
    sender: meId,
    nick: els.nickname.value.trim().slice(0, 24) || 'anon',
    ts: Date.now(),
    ...extra,
  };
}

async function encryptAndSend(payload) {
  if (!ws || ws.readyState !== WebSocket.OPEN) { notify('Нет соединения'); return; }
  const bytes = new TextEncoder().encode(JSON.stringify(payload));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({name: 'AES-GCM', iv}, key, bytes);
  const packet = { iv: bytesToBase64url(iv), ct: bytesToBase64url(new Uint8Array(ct)) };
  ws.send(JSON.stringify(packet));
}

async function sendText() {
  const text = els.input.value.trim();
  if (!text) return;
  els.input.value = '';
  const payload = nowPayloadBase('text', { text });
  addMessage(payload, true);
  await encryptAndSend(payload);
}

async function handleFiles(ev){
  const files = Array.from(ev.target.files || []);
  ev.target.value = '';
  for (const file of files) {
    await sendLargeBlob(file, file.type.startsWith('image/') ? 'image' : 'file');
  }
}

async function sendLargeBlob(file, kind){
  const arrayBuf = await file.arrayBuffer();
  const bytes = new Uint8Array(arrayBuf);
  const b64 = bytesToBase64url(bytes);
  const fileId = crypto.randomUUID();
  const chunkLen = CHUNK_SIZE * 4 // base64 grows; keep UI chunking by raw byte size
  const total = Math.ceil(b64.length / chunkLen);
  const meta = { name: file.name, mime: file.type || 'application/octet-stream', size: file.size, kind };

  // optimistic placeholder with progress
  createProgressCard(fileId, meta, true);
  for (let i=0, seq=0; i < b64.length; i += chunkLen, seq++) {
    const part = b64.slice(i, i + chunkLen);
    const chunkMsg = nowPayloadBase('chunk', {
      fileId, seq, total, meta, data: part
    });
    updateProgress(fileId, (seq+1)/total, true);
    await encryptAndSend(chunkMsg);
  }
  // After last chunk, render final message locally
  const donePayload = nowPayloadBase(kind, { name: meta.name, mime: meta.mime, size: meta.size, data: b64 });
  donePayload.id = fileId;
  addMessage(donePayload, true);
  removeProgressCard(fileId);
}

function createProgressCard(id, meta, mine){
  const li = document.createElement('li');
  li.className = 'msg' + (mine ? ' me' : '');
  li.id = `progress-${id}`;
  const metaDiv = document.createElement('div');
  metaDiv.className = 'meta';
  metaDiv.textContent = `${els.nickname.value || 'anon'} • отправка ${meta.name}…`;
  const body = document.createElement('div');
  body.innerHTML = `<div class="file">${meta.name} (${prettySize(meta.size)})</div>
    <div class="progress"><span style="width:0%"></span></div>`;
  li.appendChild(metaDiv); li.appendChild(body);
  els.messages.appendChild(li);
  els.messages.scrollTop = els.messages.scrollHeight;
}
function updateProgress(id, frac, mine){
  const el = document.getElementById(`progress-${id}`);
  if (!el) return;
  const bar = el.querySelector('.progress>span');
  if (bar) bar.style.width = `${(Math.min(1, Math.max(0, frac))*100).toFixed(1)}%`;
}
function removeProgressCard(id){
  const el = document.getElementById(`progress-${id}`);
  if (el && el.parentNode) el.parentNode.removeChild(el);
}

// Voice recording with stronger disguise.
// We collect raw PCM via ScriptProcessor, then post-process:
// - robot: ring modulation + distortion
// - chipmunk: speed up 1.5x (higher pitch)
// - deep: slow 0.8x (lower pitch)
// Encoded as WAV (PCM16).

let recStream=null, recCtx=null, spNode=null, pcmL=[];

async function handleVoice(){
  if (spNode) { // stop
    stopRecording();
    return;
  }
  try {
    recStream = await navigator.mediaDevices.getUserMedia({audio: true});
    recCtx = new (window.AudioContext || window.webkitAudioContext)();
    const source = recCtx.createMediaStreamSource(recStream);
    spNode = recCtx.createScriptProcessor(4096, 1, 1);
    source.connect(spNode); spNode.connect(recCtx.destination);
    pcmL = [];
    spNode.onaudioprocess = (e) => {
      const ch = e.inputBuffer.getChannelData(0);
      pcmL.push(new Float32Array(ch));
    };
    els.voiceBtn.textContent = '🔴';
    notify('Запись начата… Нажмите ещё раз, чтобы остановить.');
  } catch(e){
    console.error(e); notify('Не удалось начать запись');
  }
}

async function stopRecording(){
  els.voiceBtn.textContent = '🎙️';
  spNode.disconnect(); spNode = null;
  recStream.getTracks().forEach(t => t.stop());
  const rate = recCtx.sampleRate;
  recCtx.close();
  // Join PCM
  let total = 0; for (const b of pcmL) total += b.length;
  const pcm = new Float32Array(total);
  let off=0; for (const b of pcmL) { pcm.set(b, off); off += b.length; }

  // Apply effect
  const mode = els.voiceEffect.value;
  let processed = pcm, outRate = rate;
  if (mode === 'robot') {
    processed = ringModulate(pcm, rate, 35); // 35 Hz ring modulation
    processed = softClip(processed, 2.5);
  } else if (mode === 'chipmunk') {
    const factor = 1.5;
    processed = resample(pcm, rate, rate*factor);
    outRate = rate; // we resampled then will encode at original rate -> higher pitch & shorter
  } else if (mode === 'deep') {
    const factor = 0.8;
    processed = resample(pcm, rate, rate*factor);
    outRate = rate;
  }

  // Encode WAV (PCM16)
  const wav = pcmToWav(processed, outRate);
  const bytes = new Uint8Array(wav);
  const b64 = bytesToBase64url(bytes);
  const payload = nowPayloadBase('audio', {
    name: `voice-${new Date().toISOString().replace(/[:.]/g,'-')}.wav`,
    mime: 'audio/wav',
    size: bytes.byteLength,
    data: b64
  });
  addMessage(payload, true);
  await encryptAndSend(payload);
}

// DSP helpers
function ringModulate(pcm, rate, freq){
  const out = new Float32Array(pcm.length);
  for (let i=0;i<pcm.length;i++){
    const mod = Math.sin(2*Math.PI*freq*(i/rate));
    out[i] = pcm[i]*mod;
  }
  return out;
}
function softClip(pcm, amount){
  const out = new Float32Array(pcm.length);
  for (let i=0;i<pcm.length;i++){
    const x = pcm[i]*amount;
    out[i] = Math.tanh(x);
  }
  return out;
}
function resample(pcm, inRate, outRate){
  const ratio = outRate / inRate;
  const n = Math.floor(pcm.length * (1/ratio));
  const out = new Float32Array(n);
  for (let i=0;i<n;i++){
    const srcIndex = i*ratio;
    const i0 = Math.floor(srcIndex);
    const i1 = Math.min(pcm.length-1, i0+1);
    const frac = srcIndex - i0;
    out[i] = pcm[i0]*(1-frac) + pcm[i1]*frac;
  }
  return out;
}
function pcmToWav(pcm, sampleRate){
  // 16-bit PCM mono
  const bytesPerSample = 2;
  const blockAlign = bytesPerSample * 1;
  const byteRate = sampleRate * blockAlign;
  const dataSize = pcm.length * bytesPerSample;
  const buffer = new ArrayBuffer(44 + dataSize);
  const dv = new DataView(buffer);
  let p = 0;
  function writeStr(s){ for (let i=0;i<s.length;i++) dv.setUint8(p++, s.charCodeAt(i)); }
  function writeU32(v){ dv.setUint32(p, v, true); p+=4; }
  function writeU16(v){ dv.setUint16(p, v, true); p+=2; }

  writeStr('RIFF'); writeU32(36 + dataSize); writeStr('WAVE');
  writeStr('fmt '); writeU32(16); writeU16(1); writeU16(1);
  writeU32(sampleRate); writeU32(byteRate); writeU16(blockAlign); writeU16(16);
  writeStr('data'); writeU32(dataSize);
  // samples
  let offset = 44;
  for (let i=0;i<pcm.length;i++){
    let s = Math.max(-1, Math.min(1, pcm[i]));
    dv.setInt16(offset, s < 0 ? s*0x8000 : s*0x7FFF, true);
    offset += 2;
  }
  return buffer;
}

function addMessage(msg, mine=false){
  historyCache.push(msg);
  try { localStorage.setItem(storageKey(roomId), JSON.stringify(historyCache).slice(0, 4_000_000)); } catch(_) {}

  renderMessage(msg, mine, false);
  els.messages.scrollTop = els.messages.scrollHeight;
}

function renderMessage(msg, mine=false, restoring=false){
  const li = document.createElement('li');
  li.className = 'msg' + (mine ? ' me' : '');
  const meta = document.createElement('div');
  meta.className = 'meta';
  const d = new Date(msg.ts || Date.now());
  meta.textContent = `${msg.nick || 'anon'} • ${d.toLocaleTimeString()}`;
  const body = document.createElement('div');

  if (msg.kind === 'text') {
    body.textContent = msg.text || '';
  } else if (msg.kind === 'image') {
    const bytes = base64urlToBytes(msg.data);
    const blob = new Blob([bytes], {type: msg.mime || 'image/*'});
    const img = document.createElement('img');
    img.className = 'preview';
    img.src = URL.createObjectURL(blob);
    img.alt = msg.name || 'image';
    body.appendChild(img);

    const a = document.createElement('a');
    a.href = img.src; a.download = msg.name || 'image';
    a.textContent = `Скачать (${prettySize(msg.size)})`;
    a.className = 'file';
    body.appendChild(a);
  } else if (msg.kind === 'audio') {
    const bytes = base64urlToBytes(msg.data);
    const blob = new Blob([bytes], {type: msg.mime || 'audio/wav'});
    const url = URL.createObjectURL(blob);
    const audio = document.createElement('audio');
    audio.controls = true; audio.src = url;
    body.appendChild(audio);

    const a = document.createElement('a');
    a.href = url; a.download = msg.name || 'voice.wav';
    a.textContent = `Скачать голосовое (${prettySize(msg.size)})`;
    a.className = 'file';
    body.appendChild(a);
  } else if (msg.kind === 'file') {
    const bytes = base64urlToBytes(msg.data);
    const blob = new Blob([bytes], {type: msg.mime || 'application/octet-stream'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = msg.name || 'file.bin';
    a.textContent = `${msg.name || 'файл'} (${prettySize(msg.size)})`;
    body.appendChild(a);
  } else {
    body.textContent = '[неизвестный тип]';
  }

  li.appendChild(meta); li.appendChild(body);
  els.messages.appendChild(li);
}

function prettySize(n){
  if (!n && n !== 0) return '';
  const kb = 1024, mb = kb*1024;
  if (n >= mb) return (n/mb).toFixed(2) + ' MB';
  if (n >= kb) return (n/kb).toFixed(1) + ' KB';
  return n + ' B';
}

function bytesToBase64url(bytes) {
  let bin = '';
  for (let b of bytes) bin += String.fromCharCode(b);
  let b64 = btoa(bin).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  return b64;
}
function base64urlToBytes(s) {
  s = (s || '').replace(/-/g,'+').replace(/_/g,'/');
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  const bin = atob(s + pad);
  const out = new Uint8Array(bin.length);
  for (let i=0;i<bin.length;i++) out[i] = bin.charCodeAt(i);
  return out;
}
