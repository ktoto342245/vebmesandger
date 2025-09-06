// Create floating orbs
function createCyberOrbs() {
  const container = document.getElementById('orbs');
  for (let i = 0; i < 30; i++) {
    const orb = document.createElement('div');
    orb.className = 'orb';
    orb.style.left = Math.random() * 100 + '%';
    orb.style.animationDelay = Math.random() * 15 + 's';
    orb.style.animationDuration = (Math.random() * 8 + 10) + 's';
    container.appendChild(orb);
  }
}

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
  createCyberOrbs();
  
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
    notify('🔗 Квантовая ссылка-приглашение скопирована в буфер обмена');
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

function notify(msg) {
  // Create a simple notification
  const notification = document.createElement('div');
  notification.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    background: linear-gradient(135deg, var(--red-neon), var(--red-bright));
    color: white;
    padding: 16px 24px;
    border-radius: 12px;
    box-shadow: 0 8px 30px rgba(255, 10, 92, 0.4);
    z-index: 10000;
    font-weight: 600;
    animation: slideIn 0.3s ease;
  `;
  notification.textContent = msg;
  document.body.appendChild(notification);
  
  setTimeout(() => {
    notification.style.animation = 'slideOut 0.3s ease forwards';
    setTimeout(() => notification.remove(), 300);
  }, 3000);
}

function randomId(len) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < len; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

function base64urlToBytes(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return new Uint8Array([...atob(str)].map(c => c.charCodeAt(0)));
}

function bytesToBase64url(bytes) {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

async function deriveKey(secret, salt) {
  const keyMaterial = await crypto.subtle.importKey('raw', secret, { name: 'PBKDF2' }, false, ['deriveKey']);
  return await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encrypt(data) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
  const result = new Uint8Array(iv.length + encrypted.byteLength);
  result.set(iv, 0);
  result.set(new Uint8Array(encrypted), iv.length);
  return result;
}

async function decrypt(encryptedData) {
  const iv = encryptedData.slice(0, 12);
  const data = encryptedData.slice(12);
  return await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
}

function setOffline() {
  els.statusDot.classList.remove('online');
  els.statusText.textContent = 'OFFLINE';
  els.onlineCount.textContent = '0';
}

function setOnline(count = 1) {
  els.statusDot.classList.add('online');
  els.statusText.textContent = 'ONLINE';
  els.onlineCount.textContent = count.toString();
}

function connect() {
  if (!roomId || !key) return;
  
  const wsUrl = `wss://${location.host}/ws/${roomId}`;
  ws = new WebSocket(wsUrl);
  
  ws.onopen = () => {
    console.log('Connected to room:', roomId);
    setOnline();
  };
  
  ws.onclose = () => {
    console.log('Disconnected');
    setOffline();
    setTimeout(() => connect(), 3000);
  };
  
  ws.onerror = (error) => {
    console.error('WebSocket error:', error);
    setOffline();
  };
  
  ws.onmessage = handleMessage;
}

async function handleMessage(event) {
  try {
    const data = JSON.parse(event.data);
    
    if (data.type === 'online_count') {
      setOnline(data.count);
      return;
    }
    
    if (data.type === 'chunk') {
      await handleChunk(data);
      return;
    }
    
    if (data.encrypted) {
      const encryptedBytes = base64urlToBytes(data.encrypted);
      const decryptedBytes = await decrypt(encryptedBytes);
      const decryptedText = new TextDecoder().decode(decryptedBytes);
      const message = JSON.parse(decryptedText);
      
      const isSelf = message.sender === meId;
      renderMessage(message, isSelf);
      
      if (!isSelf) {
        historyCache.push(message);
        localStorage.setItem(storageKey(roomId), JSON.stringify(historyCache));
      }
    }
  } catch (error) {
    console.error('Error handling message:', error);
  }
}

async function handleChunk(data) {
  const { fileId, chunkIndex, totalChunks, chunkData, meta } = data;
  
  if (!assembling.has(fileId)) {
    assembling.set(fileId, { 
      total: totalChunks, 
      got: 0, 
      chunks: new Array(totalChunks),
      meta 
    });
  }
  
  const assembly = assembling.get(fileId);
  assembly.chunks[chunkIndex] = base64urlToBytes(chunkData);
  assembly.got++;
  
  // Update progress
  const progress = Math.round((assembly.got / assembly.total) * 100);
  updateProgress(fileId, progress);
  
  if (assembly.got === assembly.total) {
    // Reconstruct file
    const totalSize = assembly.chunks.reduce((sum, chunk) => sum + chunk.length, 0);
    const fileData = new Uint8Array(totalSize);
    let offset = 0;
    
    for (const chunk of assembly.chunks) {
      fileData.set(chunk, offset);
      offset += chunk.length;
    }
    
    // Decrypt file data
    const decryptedData = await decrypt(fileData);
    
    // Create message
    const message = {
      id: fileId,
      sender: assembly.meta.sender,
      nickname: assembly.meta.nickname,
      timestamp: assembly.meta.timestamp,
      type: 'file',
      filename: assembly.meta.filename,
      size: assembly.meta.size,
      mimeType: assembly.meta.mimeType,
      data: bytesToBase64url(new Uint8Array(decryptedData))
    };
    
    const isSelf = message.sender === meId;
    renderMessage(message, isSelf);
    
    if (!isSelf) {
      historyCache.push(message);
      localStorage.setItem(storageKey(roomId), JSON.stringify(historyCache));
    }
    
    assembling.delete(fileId);
  }
}

function updateProgress(fileId, progress) {
  const progressElement = document.querySelector(`[data-file-id="${fileId}"] .loading-progress`);
  if (progressElement) {
    progressElement.style.width = progress + '%';
  }
}

async function sendText() {
  const text = els.input.value.trim();
  if (!text || !ws || ws.readyState !== WebSocket.OPEN) return;
  
  const message = {
    id: randomId(8),
    sender: meId,
    nickname: els.nickname.value.trim() || 'Анонимный',
    timestamp: Date.now(),
    type: 'text',
    text
  };
  
  await sendMessage(message);
  renderMessage(message, true);
  
  historyCache.push(message);
  localStorage.setItem(storageKey(roomId), JSON.stringify(historyCache));
  
  els.input.value = '';
}

async function sendMessage(message) {
  const messageJson = JSON.stringify(message);
  const messageBytes = new TextEncoder().encode(messageJson);
  const encryptedBytes = await encrypt(messageBytes);
  const encryptedB64 = bytesToBase64url(encryptedBytes);
  
  ws.send(JSON.stringify({ encrypted: encryptedB64 }));
}

function renderMessage(message, isSelf, isHistory = false) {
  const li = document.createElement('li');
  li.className = `message ${isSelf ? 'me' : ''}`;
  
  if (message.type === 'meta') {
    li.className = 'message meta';
    li.innerHTML = `<div class="message-text">${message.text}</div>`;
  } else {
    const time = new Date(message.timestamp).toLocaleTimeString('ru-RU', { 
      hour: '2-digit', 
      minute: '2-digit' 
    });
    
    let content = '';
    if (message.type === 'text') {
      content = `
        <div class="message-header">${message.nickname} • ${time}</div>
        <div class="message-text">${escapeHtml(message.text)}</div>
      `;
    } else if (message.type === 'file') {
      content = renderFileContent(message, time);
    }
    
    li.innerHTML = content;
  }
  
  els.messages.appendChild(li);
  
  if (!isHistory) {
    li.scrollIntoView({ behavior: 'smooth' });
  }
}

function renderFileContent(message, time) {
  const { filename, mimeType, size, data } = message;
  
  let fileContent = '';
  
  if (mimeType.startsWith('image/')) {
    fileContent = `<img src="data:${mimeType};base64,${data}" alt="${filename}" class="preview-img">`;
  } else if (mimeType.startsWith('audio/')) {
    fileContent = `<audio controls class="audio-element"><source src="data:${mimeType};base64,${data}" type="${mimeType}"></audio>`;
  } else {
    const blob = new Blob([base64urlToBytes(data)], { type: mimeType });
    const url = URL.createObjectURL(blob);
    fileContent = `
      <div class="file-preview-box">
        <a href="${url}" download="${filename}" class="file-link">${filename}</a>
        <div style="font-size: 12px; color: var(--text-muted); margin-top: 5px;">
          ${formatFileSize(size)}
        </div>
      </div>
    `;
  }
  
  return `
    <div class="message-header">${message.nickname} • ${time}</div>
    <div class="message-text">${fileContent}</div>
  `;
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function formatFileSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1024 * 1024 * 1024) return (bytes / 1024 / 1024).toFixed(1) + ' MB';
  return (bytes / 1024 / 1024 / 1024).toFixed(1) + ' GB';
}

async function handleFiles(event) {
  const files = Array.from(event.target.files);
  if (!files.length || !ws || ws.readyState !== WebSocket.OPEN) return;
  
  for (const file of files) {
    await sendFile(file);
  }
  
  event.target.value = '';
}

async function sendFile(file) {
  const fileId = randomId(12);
  const reader = new FileReader();
  
  reader.onload = async () => {
    const fileData = new Uint8Array(reader.result);
    const encryptedData = await encrypt(fileData);
    
    const totalChunks = Math.ceil(encryptedData.length / CHUNK_SIZE);
    const meta = {
      sender: meId,
      nickname: els.nickname.value.trim() || 'Анонимный',
      timestamp: Date.now(),
      filename: file.name,
      size: file.size,
      mimeType: file.type
    };
    
    // Show progress message
    const progressMessage = {
      id: fileId,
      sender: meId,
      nickname: meta.nickname,
      timestamp: meta.timestamp,
      type: 'progress',
      filename: file.name
    };
    
    renderProgressMessage(progressMessage);
    
    // Send chunks
    for (let i = 0; i < totalChunks; i++) {
      const start = i * CHUNK_SIZE;
      const end = Math.min(start + CHUNK_SIZE, encryptedData.length);
      const chunk = encryptedData.slice(start, end);
      
      const chunkData = {
        type: 'chunk',
        fileId,
        chunkIndex: i,
        totalChunks,
        chunkData: bytesToBase64url(chunk),
        meta: i === 0 ? meta : undefined
      };
      
      ws.send(JSON.stringify(chunkData));
      
      // Update progress
      const progress = Math.round(((i + 1) / totalChunks) * 100);
      updateProgress(fileId, progress);
      
      // Small delay to prevent overwhelming
      if (i % 10 === 0) {
        await new Promise(resolve => setTimeout(resolve, 10));
      }
    }
  };
  
  reader.readAsArrayBuffer(file);
}

function renderProgressMessage(message) {
  const li = document.createElement('li');
  li.className = 'message me';
  li.setAttribute('data-file-id', message.id);
  
  const time = new Date(message.timestamp).toLocaleTimeString('ru-RU', { 
    hour: '2-digit', 
    minute: '2-digit' 
  });
  
  li.innerHTML = `
    <div class="message-header">${message.nickname} • ${time}</div>
    <div class="message-text">
      📤 Отправка файла: ${message.filename}
      <div class="loading-bar">
        <div class="loading-progress" style="width: 0%"></div>
      </div>
    </div>
  `;
  
  els.messages.appendChild(li);
  li.scrollIntoView({ behavior: 'smooth' });
}

// Voice recording functionality
let mediaRecorder = null;
let recordedChunks = [];

async function handleVoice() {
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    alert('Запись голоса не поддерживается в вашем браузере');
    return;
  }
  
  if (mediaRecorder && mediaRecorder.state === 'recording') {
    mediaRecorder.stop();
    return;
  }
  
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    mediaRecorder = new MediaRecorder(stream);
    recordedChunks = [];
    
    mediaRecorder.ondataavailable = (event) => {
      if (event.data.size > 0) {
        recordedChunks.push(event.data);
      }
    };
    
    mediaRecorder.onstop = async () => {
      const blob = new Blob(recordedChunks, { type: 'audio/webm' });
      await processVoiceRecording(blob);
      
      // Stop all tracks
      stream.getTracks().forEach(track => track.stop());
      
      els.voiceBtn.classList.remove('recording');
    };
    
    mediaRecorder.start();
    els.voiceBtn.classList.add('recording');
    
  } catch (error) {
    console.error('Error accessing microphone:', error);
    alert('Не удалось получить доступ к микрофону');
  }
}

async function processVoiceRecording(blob) {
  const effect = els.voiceEffect.value;
  
  if (effect === 'none') {
    await sendVoiceMessage(blob);
    return;
  }
  
  try {
    const audioContext = new (window.AudioContext || window.webkitAudioContext)();
    const arrayBuffer = await blob.arrayBuffer();
    const audioBuffer = await audioContext.decodeAudioData(arrayBuffer);
    
    let processedBuffer;
    
    switch (effect) {
      case 'robot':
        processedBuffer = applyRobotEffect(audioBuffer, audioContext);
        break;
      case 'chipmunk':
        processedBuffer = applyPitchEffect(audioBuffer, audioContext, 1.5);
        break;
      case 'deep':
        processedBuffer = applyPitchEffect(audioBuffer, audioContext, 0.7);
        break;
      default:
        processedBuffer = audioBuffer;
    }
    
    const processedBlob = await audioBufferToBlob(processedBuffer, audioContext);
    await sendVoiceMessage(processedBlob);
    
  } catch (error) {
    console.error('Error processing audio:', error);
    await sendVoiceMessage(blob);
  }
}

function applyRobotEffect(audioBuffer, audioContext) {
  const outputBuffer = audioContext.createBuffer(
    audioBuffer.numberOfChannels,
    audioBuffer.length,
    audioBuffer.sampleRate
  );
  
  for (let channel = 0; channel < audioBuffer.numberOfChannels; channel++) {
    const inputData = audioBuffer.getChannelData(channel);
    const outputData = outputBuffer.getChannelData(channel);
    
    for (let i = 0; i < inputData.length; i++) {
      outputData[i] = Math.sign(inputData[i]) * Math.pow(Math.abs(inputData[i]), 0.5);
    }
  }
  
  return outputBuffer;
}

function applyPitchEffect(audioBuffer, audioContext, pitchFactor) {
  const newLength = Math.floor(audioBuffer.length / pitchFactor);
  const outputBuffer = audioContext.createBuffer(
    audioBuffer.numberOfChannels,
    newLength,
    audioBuffer.sampleRate
  );
  
  for (let channel = 0; channel < audioBuffer.numberOfChannels; channel++) {
    const inputData = audioBuffer.getChannelData(channel);
    const outputData = outputBuffer.getChannelData(channel);
    
    for (let i = 0; i < newLength; i++) {
      const sourceIndex = Math.floor(i * pitchFactor);
      if (sourceIndex < inputData.length) {
        outputData[i] = inputData[sourceIndex];
      }
    }
  }
  
  return outputBuffer;
}

async function audioBufferToBlob(audioBuffer, audioContext) {
  const offlineContext = new OfflineAudioContext(
    audioBuffer.numberOfChannels,
    audioBuffer.length,
    audioBuffer.sampleRate
  );
  
  const source = offlineContext.createBufferSource();
  source.buffer = audioBuffer;
  source.connect(offlineContext.destination);
  source.start();
  
  const renderedBuffer = await offlineContext.startRendering();
  
  // Convert to WAV format
  const length = renderedBuffer.length;
  const numberOfChannels = renderedBuffer.numberOfChannels;
  const sampleRate = renderedBuffer.sampleRate;
  const buffer = new ArrayBuffer(44 + length * numberOfChannels * 2);
  const view = new DataView(buffer);
  
  // WAV header
  const writeString = (offset, string) => {
    for (let i = 0; i < string.length; i++) {
      view.setUint8(offset + i, string.charCodeAt(i));
    }
  };
  
  writeString(0, 'RIFF');
  view.setUint32(4, 36 + length * numberOfChannels * 2, true);
  writeString(8, 'WAVE');
  writeString(12, 'fmt ');
  view.setUint32(16, 16, true);
  view.setUint16(20, 1, true);
  view.setUint16(22, numberOfChannels, true);
  view.setUint32(24, sampleRate, true);
  view.setUint32(28, sampleRate * numberOfChannels * 2, true);
  view.setUint16(32, numberOfChannels * 2, true);
  view.setUint16(34, 16, true);
  writeString(36, 'data');
  view.setUint32(40, length * numberOfChannels * 2, true);
  
  // PCM data
  let offset = 44;
  for (let i = 0; i < length; i++) {
    for (let channel = 0; channel < numberOfChannels; channel++) {
      const sample = Math.max(-1, Math.min(1, renderedBuffer.getChannelData(channel)[i]));
      view.setInt16(offset, sample * 0x7FFF, true);
      offset += 2;
    }
  }
  
  return new Blob([buffer], { type: 'audio/wav' });
}

async function sendVoiceMessage(blob) {
  const file = new File([blob], `voice_${Date.now()}.wav`, { type: 'audio/wav' });
  await sendFile(file);
}

// CSS animations for notifications
const style = document.createElement('style');
style.textContent = `
  @keyframes slideIn {
    from {
      transform: translateX(100%);
      opacity: 0;
    }
    to {
      transform: translateX(0);
      opacity: 1;
    }
  }
  
  @keyframes slideOut {
    from {
      transform: translateX(0);
      opacity: 1;
    }
    to {
      transform: translateX(100%);
      opacity: 0;
    }
  }
`;
document.head.appendChild(style);
