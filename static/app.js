/**
 * Aegis Defender Pro - Frontend Controller & Telemetry Engine
 * Powers real-time scanning, shield toggling, quarantine management, and audio telemetry.
 */

// Global State
let currentTab = 'dashboard';
let scanPollingInterval = null;
let telemetryPollingInterval = null;
let lastKnownEventCount = 0;
let inspectedFilePath = null;
let inspectedResult = null;

// Synthesizer Audio Context for Cyber Sound Effects (Web Audio API)
let audioCtx = null;

function initAudio() {
  if (!audioCtx) {
    const AudioContext = window.AudioContext || window.webkitAudioContext;
    if (AudioContext) {
      audioCtx = new AudioContext();
    }
  }
}

function playSound(type) {
  try {
    initAudio();
    if (!audioCtx) return;

    if (audioCtx.state === 'suspended') {
      audioCtx.resume();
    }

    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.connect(gain);
    gain.connect(audioCtx.destination);

    const now = audioCtx.currentTime;

    if (type === 'click') {
      osc.type = 'sine';
      osc.frequency.setValueAtTime(800, now);
      osc.frequency.exponentialRampToValueAtTime(400, now + 0.05);
      gain.gain.setValueAtTime(0.08, now);
      gain.gain.linearRampToValueAtTime(0.001, now + 0.05);
      osc.start(now);
      osc.stop(now + 0.05);
    } else if (type === 'threat') {
      // Urgent cyber dual-tone alarm
      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(650, now);
      osc.frequency.setValueAtTime(850, now + 0.08);
      osc.frequency.setValueAtTime(650, now + 0.16);
      gain.gain.setValueAtTime(0.18, now);
      gain.gain.linearRampToValueAtTime(0.001, now + 0.28);
      osc.start(now);
      osc.stop(now + 0.28);
    } else if (type === 'success') {
      osc.type = 'triangle';
      osc.frequency.setValueAtTime(520, now);
      osc.frequency.exponentialRampToValueAtTime(880, now + 0.12);
      gain.gain.setValueAtTime(0.1, now);
      gain.gain.linearRampToValueAtTime(0.001, now + 0.15);
      osc.start(now);
      osc.stop(now + 0.15);
    }
  } catch (e) {
    // Audio non-fatal
  }
}

// Toast Notifications
function showToast(title, message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;

  let icon = '🛡️';
  if (type === 'threat') icon = '🚨';
  if (type === 'success') icon = '✅';

  toast.innerHTML = `
    <div class="toast-icon">${icon}</div>
    <div class="toast-content">
      <div class="toast-title">${title}</div>
      <div class="toast-msg">${message}</div>
    </div>
  `;

  container.appendChild(toast);
  if (type === 'threat') playSound('threat');

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';
    setTimeout(() => toast.remove(), 300);
  }, 4500);
}

// Tab Switching
function switchTab(tabId) {
  playSound('click');
  currentTab = tabId;

  document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));

  const targetPane = document.getElementById(`tab-${tabId}`);
  const targetNavBtn = document.getElementById(`nav-btn-${tabId}`);

  if (targetPane) targetPane.classList.add('active');
  if (targetNavBtn) targetNavBtn.classList.add('active');

  const heading = document.getElementById('page-heading');
  const titles = {
    persistence: 'MITRE ATT&CK Persistence Hunter',
    network: 'Zero-Trust Network & Socket Guard',
    dashboard: 'Cyber Defense Dashboard',
    scanner: 'Deep Threat Scanner & Sandbox',
    shield: 'Real-Time Filesystem Shield',
    quarantine: 'Encrypted Quarantine Vault',
    processes: 'Process & Memory Behavior Guard',
    intel: 'Threat Intelligence Database',
    lab: 'Antivirus Verification & EICAR Lab'
  };
  if (heading && titles[tabId]) {
    heading.textContent = titles[tabId];
  }

  // Load specific tab data on switch
    if (tabId === 'persistence') loadPersistenceAudit();
  if (tabId === 'network') loadNetworkConnections();
  if (tabId === 'quarantine') loadQuarantine();
  if (tabId === 'processes') loadProcesses();
  if (tabId === 'intel') loadThreatIntel();
  if (tabId === 'shield') loadShieldStatus();
}

// Fetch & Update System Status
async function updateSystemStatus() {
  try {
    const res = await fetch('/api/status');
    if (!res.ok) return;
    const data = await res.json();

    // OS Pill
    const osElem = document.getElementById('sidebar-os-info');
    if (osElem) osElem.textContent = `${data.os} ${data.architecture}`;

    // Quarantine count
    const qCountElem = document.getElementById('stat-quarantine-count');
    const qBadgeElem = document.getElementById('nav-quarantine-count');
    const vaultCount = document.getElementById('vault-total-count');
    if (qCountElem) qCountElem.textContent = data.quarantine_count;
    if (qBadgeElem) qBadgeElem.textContent = data.quarantine_count;
    if (vaultCount) vaultCount.textContent = data.quarantine_count;

    // Signatures loaded
    const sigElem = document.getElementById('stat-signatures-count');
    const globalSig = document.getElementById('global-sig-count');
    if (sigElem) sigElem.textContent = data.signatures_loaded;
    if (globalSig) globalSig.textContent = `${data.signatures_loaded} Rules`;

    // Shield status
    const shieldSwitch = document.getElementById('toggle-shield-switch');
    const shieldStatusText = document.getElementById('stat-shield-status');
    const globalStatus = document.getElementById('global-status-pill');
    const shieldBtnMain = document.getElementById('btn-toggle-shield-main');

    if (shieldSwitch) shieldSwitch.checked = data.is_protected;
    if (shieldStatusText) shieldStatusText.textContent = data.is_protected ? 'Active' : 'Disabled';
    if (globalStatus) {
      globalStatus.textContent = data.is_protected ? 'SHIELD ARMED' : 'SHIELD DISABLED';
      globalStatus.className = `telemetry-value ${data.is_protected ? 'active' : ''}`;
    }
    if (shieldBtnMain) {
      shieldBtnMain.textContent = `Shield: ${data.is_protected ? 'Active' : 'Disabled'}`;
      shieldBtnMain.className = data.is_protected ? 'btn-primary' : 'btn-danger';
    }

  } catch (err) {
    console.error('Status fetch error:', err);
  }
}

// Poll Real-Time Shield Events
async function fetchShieldEvents() {
  try {
    const res = await fetch('/api/shield/events');
    if (!res.ok) return;
    const events = await res.json();

    // Check for newly intercepted threats
    if (events.length > lastKnownEventCount && lastKnownEventCount > 0) {
      const latest = events[0];
      if (latest && latest.is_threat) {
        showToast('Malware Intercepted!', `${latest.threat_name} isolated from ${latest.file_name}`, 'threat');
      }
    }
    lastKnownEventCount = events.length;

    renderRecentEvents(events);
    renderShieldTabEvents(events);
    renderLabEvents(events);
  } catch (err) {
    console.error('Events error:', err);
  }
}

function renderRecentEvents(events) {
  const tbody = document.getElementById('dashboard-recent-events-tbody');
  if (!tbody) return;

  if (events.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="table-empty">Awaiting filesystem activity...</td></tr>';
    return;
  }

  tbody.innerHTML = events.slice(0, 8).map(ev => {
    const badgeClass = ev.is_threat ? (ev.severity === 'Critical' ? 'critical' : 'high') : 'clean';
    return `
      <tr>
        <td>${ev.timestamp}</td>
        <td><strong>${ev.file_name}</strong><br><small style="color:var(--text-dim);">${ev.file_path}</small></td>
        <td>${ev.is_threat ? ev.threat_name : 'Verified Clean'}</td>
        <td><span class="badge-threat ${badgeClass}">${ev.severity || 'Clean'}</span></td>
        <td><span class="code-snippet">${ev.action_taken}</span></td>
      </tr>
    `;
  }).join('');
}

function renderShieldTabEvents(events) {
  const tbody = document.getElementById('shield-events-tbody');
  if (!tbody) return;

  if (events.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="table-empty">No filesystem interceptions yet.</td></tr>';
    return;
  }

  tbody.innerHTML = events.map(ev => {
    const badgeClass = ev.is_threat ? (ev.severity === 'Critical' ? 'critical' : 'high') : 'clean';
    return `
      <tr>
        <td>${ev.timestamp}</td>
        <td><strong>${ev.file_name}</strong><br><small style="color:var(--text-dim);">${ev.file_path}</small></td>
        <td>${ev.is_threat ? ev.threat_name : 'Passed Security Audit'}</td>
        <td><span class="badge-threat ${badgeClass}">${ev.severity || 'Clean'}</span></td>
        <td><span class="code-snippet">${ev.action_taken}</span></td>
      </tr>
    `;
  }).join('');
}

function renderLabEvents(events) {
  const tbody = document.getElementById('lab-test-results-tbody');
  if (!tbody) return;

  const testEvents = events.filter(e => e.file_name.includes('eicar') || e.file_name.includes('mock_'));
  if (testEvents.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" class="table-empty">Ready. Click a test button above to verify detection.</td></tr>';
    return;
  }

  tbody.innerHTML = testEvents.slice(0, 5).map(ev => `
    <tr>
      <td>${ev.timestamp}</td>
      <td><strong>${ev.file_name}</strong></td>
      <td><span class="badge-threat critical">${ev.threat_name}</span></td>
      <td><span class="stat-badge success">${ev.action_taken}</span></td>
    </tr>
  `).join('');
}

// Toggle Real-Time Shield
async function toggleRealtimeShield() {
  playSound('click');
  try {
    const res = await fetch('/api/shield/toggle', { method: 'POST' });
    const data = await res.json();
    showToast(
      'Real-Time Shield',
      data.is_active ? 'Continuous filesystem monitoring activated.' : 'Shield disabled. Computer may be unprotected.',
      data.is_active ? 'success' : 'threat'
    );
    updateSystemStatus();
  } catch (err) {
    showToast('Error', 'Failed to toggle shield', 'threat');
  }
}

// Shield Watched Folders
async function loadShieldStatus() {
  try {
    const res = await fetch('/api/shield/status');
    const data = await res.json();
    const list = document.getElementById('watched-dirs-list');
    if (!list) return;

    list.innerHTML = data.watch_directories.map(d => `
      <div class="watched-dir-item">
        <span>📁 ${d}</span>
        <button onclick="removeWatchedDirectory('${encodeURIComponent(d)}')">&times;</button>
      </div>
    `).join('');
  } catch (err) {
    console.error('Shield status error:', err);
  }
}

async function addWatchedDirectory() {
  const input = document.getElementById('input-new-dir');
  const path = input.value.trim();
  if (!path) return;

  try {
    const res = await fetch('/api/shield/add-dir', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path })
    });
    const data = await res.json();
    if (data.success) {
      showToast('Directory Added', `Now monitoring: ${path}`, 'success');
      input.value = '';
      loadShieldStatus();
    } else {
      showToast('Invalid Path', data.error || 'Directory does not exist', 'threat');
    }
  } catch (err) {
    showToast('Error', 'Failed to add directory', 'threat');
  }
}

async function removeWatchedDirectory(encodedPath) {
  const path = decodeURIComponent(encodedPath);
  try {
    const res = await fetch('/api/shield/remove-dir', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path })
    });
    const data = await res.json();
    if (data.success) {
      showToast('Directory Removed', `Stopped monitoring: ${path}`, 'info');
      loadShieldStatus();
    }
  } catch (err) {
    showToast('Error', 'Failed to remove directory', 'threat');
  }
}

// Scanning Engine
function launchQuickScan() {
  switchTab('scanner');
  startScan('quick');
}

async function startScan(type) {
  playSound('click');
  const panel = document.getElementById('live-scan-panel');
  if (panel) panel.style.display = 'block';

  document.getElementById('scan-exec-type').textContent = `${type.toUpperCase()} SCAN`;
  document.getElementById('scan-exec-status').textContent = 'Initializing engine...';

  try {
    const res = await fetch('/api/scan/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type })
    });
    const data = await res.json();
    if (data.success) {
      showToast('Scan Launched', `Starting ${type} scan...`, 'info');
      if (scanPollingInterval) clearInterval(scanPollingInterval);
      scanPollingInterval = setInterval(pollScanProgress, 800);
    } else {
      showToast('Scan Busy', data.error || 'A scan is already active', 'threat');
    }
  } catch (err) {
    showToast('Error', 'Failed to launch scan', 'threat');
  }
}

async function startCustomScan(e) {
  if (e) e.stopPropagation();
  const input = document.getElementById('custom-scan-path');
  const path = input.value.trim();
  if (!path) {
    showToast('Missing Path', 'Please enter a directory path to scan', 'threat');
    return;
  }

  const panel = document.getElementById('live-scan-panel');
  if (panel) panel.style.display = 'block';
  document.getElementById('scan-exec-type').textContent = 'CUSTOM SCAN';

  try {
    const res = await fetch('/api/scan/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 'custom', custom_path: path })
    });
    const data = await res.json();
    if (data.success) {
      showToast('Custom Scan', `Scanning path: ${path}`, 'info');
      if (scanPollingInterval) clearInterval(scanPollingInterval);
      scanPollingInterval = setInterval(pollScanProgress, 800);
    } else {
      showToast('Error', data.error, 'threat');
    }
  } catch (err) {
    showToast('Error', 'Failed to start custom scan', 'threat');
  }
}

async function pollScanProgress() {
  try {
    const res = await fetch('/api/scan/progress');
    const job = await res.json();

    const bar = document.getElementById('scan-progress-bar');
    const perc = document.getElementById('scan-progress-percentage');
    const counts = document.getElementById('scan-progress-counts');
    const currPath = document.getElementById('scan-current-filepath');
    const statusText = document.getElementById('scan-exec-status');

    if (job.status === 'running') {
      statusText.textContent = `Scanning in progress... (${job.scanned_files} files inspected, ${job.elapsed_seconds || 0}s)`;
    }

    if (bar) bar.style.width = `${Math.max(job.progress_percent, job.status === 'running' ? 5 : 0)}%`;
    if (perc) perc.textContent = `${job.progress_percent}%`;
    if (counts) counts.textContent = `${job.scanned_files} files inspected • ${job.threats_found} threats found`;
    if (currPath) currPath.textContent = job.current_file || 'Inspecting filesystem...';

    // Update session scanned stat
    const sessionStat = document.getElementById('stat-files-scanned');
    if (sessionStat) sessionStat.textContent = job.scanned_files;

    if (job.status === 'completed') {
      clearInterval(scanPollingInterval);
      statusText.textContent = 'Scan Completed Successfully!';
      if (bar) bar.style.width = '100%';
      if (perc) perc.textContent = '100%';
      if (job.threats_found > 0) {
        showToast('Threats Intercepted!', `${job.threats_found} threat(s) neutralized and quarantined.`, 'threat');
      } else {
        showToast('Scan Clean', 'No malware detected. System is secure.', 'success');
      }
      updateSystemStatus();
      loadScanHistory();
    } else if (job.status === 'cancelled') {
      clearInterval(scanPollingInterval);
      statusText.textContent = 'Scan Cancelled.';
    }
  } catch (err) {
    console.error('Progress poll error:', err);
  }
}

async function cancelScan() {
  playSound('click');
  try {
    await fetch('/api/scan/cancel', { method: 'POST' });
    showToast('Scan Cancelled', 'Active scan stopped by user', 'info');
  } catch (err) {
    console.error('Cancel error:', err);
  }
}

async function loadScanHistory() {
  try {
    const res = await fetch('/api/scan/history');
    const history = await res.json();
    const tbody = document.getElementById('scan-history-tbody');
    if (!tbody) return;

    if (history.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" class="table-empty">No scan runs recorded yet.</td></tr>';
      return;
    }

    tbody.innerHTML = history.map(item => `
      <tr>
        <td>${item.timestamp}</td>
        <td><strong>${item.type.toUpperCase()}</strong></td>
        <td>${item.scanned_files}</td>
        <td><span class="badge-threat ${item.threats_found > 0 ? 'critical' : 'clean'}">${item.threats_found} Threats</span></td>
        <td>${item.duration_sec}s</td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('History load error:', err);
  }
}

// Drag & Drop Instant File Sandbox
function setupDragAndDrop() {
  const dropZone = document.getElementById('drop-zone');
  if (!dropZone) return;

  ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, e => {
      e.preventDefault();
      e.stopPropagation();
    }, false);
  });

  ['dragenter', 'dragover'].forEach(eventName => {
    dropZone.addEventListener(eventName, () => dropZone.classList.add('dragover'), false);
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, () => dropZone.classList.remove('dragover'), false);
  });

  dropZone.addEventListener('drop', e => {
    const dt = e.dataTransfer;
    const files = dt.files;
    if (files.length > 0) {
      inspectDroppedFile(files[0]);
    }
  });
}

function handleFilePicked(e) {
  const files = e.target.files;
  if (files && files.length > 0) {
    inspectDroppedFile(files[0]);
  }
}

async function inspectDroppedFile(file) {
  playSound('click');
  const card = document.getElementById('inspection-result-card');
  if (card) card.style.display = 'block';

  document.getElementById('inspection-file-name').textContent = file.name;
  document.getElementById('inspect-size').textContent = `${(file.size / 1024).toFixed(2)} KB`;
  document.getElementById('inspect-details').textContent = 'Analyzing byte structures, hashes, and heuristic patterns...';

  // Read file bytes in browser for hashing & entropy
  const reader = new FileReader();
  reader.onload = async function(event) {
    const buffer = event.target.result;
    const uint8 = new Uint8Array(buffer);

    // Compute Web Crypto SHA-256
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const sha256Hex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    // Compute Shannon Entropy
    let counts = new Array(256).fill(0);
    for (let i = 0; i < uint8.length; i++) counts[uint8[i]]++;
    let entropy = 0;
    const len = uint8.length;
    for (let i = 0; i < 256; i++) {
      if (counts[i] > 0) {
        let p = counts[i] / len;
        entropy -= p * Math.log2(p);
      }
    }
    entropy = entropy.toFixed(3);

    document.getElementById('inspect-sha256').textContent = sha256Hex;
    document.getElementById('inspect-entropy').textContent = `${entropy} / 8.0`;

    // Check against EICAR string or known test patterns in content
    const textSample = new TextDecoder('utf-8', { fatal: false }).decode(uint8.slice(0, 10000));
    const isEicar = textSample.includes('EICAR-STANDARD-ANTIVIRUS-TEST-FILE');
    const isReverseShell = textSample.includes('/bin/sh') && textSample.includes('/dev/tcp');

    const verdictBadge = document.getElementById('inspection-verdict-badge');
    const btnQuarantine = document.getElementById('btn-quarantine-inspected');

    if (isEicar || isReverseShell || entropy > 7.85) {
      verdictBadge.className = 'verdict-badge threat';
      verdictBadge.textContent = 'MALICIOUS DETECTED';
      document.getElementById('inspect-method').textContent = isEicar ? 'EICAR Test Signature' : (isReverseShell ? 'Heuristic Reverse Shell' : 'High Entropy Encrypted Payload');
      document.getElementById('inspect-details').textContent = isEicar ? 'Harmless EICAR test file identified. Immediate quarantine advised.' : 'Potentially dangerous payload pattern detected.';
      if (btnQuarantine) btnQuarantine.style.display = 'inline-block';
      showToast('File Inspection', `High risk signature found in ${file.name}`, 'threat');
    } else {
      verdictBadge.className = 'verdict-badge clean';
      verdictBadge.textContent = 'CLEAN';
      document.getElementById('inspect-method').textContent = 'Zero Risk Signatures Match';
      document.getElementById('inspect-details').textContent = 'File passed static entropy analysis and signature inspection with no malicious indicators.';
      if (btnQuarantine) btnQuarantine.style.display = 'none';
      showToast('File Verified', `${file.name} is clean.`, 'success');
    }
  };
  reader.readAsArrayBuffer(file);
}

// Quarantine Vault Operations
async function loadQuarantine() {
  try {
    const res = await fetch('/api/quarantine');
    const items = await res.json();
    const tbody = document.getElementById('quarantine-tbody');
    if (!tbody) return;

    if (items.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="table-empty">Quarantine vault is empty. No active threats isolated.</td></tr>';
      return;
    }

    tbody.innerHTML = items.map(item => `
      <tr>
        <td>${item.timestamp}</td>
        <td><strong>${item.file_name}</strong><br><small style="color:var(--text-dim);">${item.original_path}</small></td>
        <td><span class="badge-threat critical">${item.threat_name}</span></td>
        <td><span class="badge-threat high">${item.severity}</span></td>
        <td><span class="code-snippet">${item.sha256 ? item.sha256.substring(0, 16) + '...' : 'N/A'}</span></td>
        <td>
          <button class="btn-secondary" style="padding: 4px 8px; font-size: 11px; margin-right: 6px;" onclick="restoreQuarantined('${item.id}')">Restore</button>
          <button class="btn-danger" style="padding: 4px 8px; font-size: 11px;" onclick="shredQuarantined('${item.id}')">Shred</button>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('Quarantine load error:', err);
  }
}

async function restoreQuarantined(id) {
  playSound('click');
  try {
    const res = await fetch('/api/quarantine/restore', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id })
    });
    const data = await res.json();
    if (data.success) {
      showToast('File Restored', 'Threat unscrambled and restored to original path.', 'success');
      loadQuarantine();
      updateSystemStatus();
    } else {
      showToast('Restore Failed', 'Unable to restore file.', 'threat');
    }
  } catch (err) {
    showToast('Error', 'Failed to restore file', 'threat');
  }
}

async function shredQuarantined(id) {
  playSound('click');
  if (!confirm('Are you sure you want to permanently zero-overwrite and shred this threat?')) return;

  try {
    const res = await fetch('/api/quarantine/shred', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id })
    });
    const data = await res.json();
    if (data.success) {
      showToast('Threat Shredded', 'File zero-wiped and permanently eliminated.', 'info');
      loadQuarantine();
      updateSystemStatus();
    } else {
      showToast('Shred Failed', 'Unable to destroy file.', 'threat');
    }
  } catch (err) {
    showToast('Error', 'Failed to shred file', 'threat');
  }
}

// Process Guard Operations
async function loadProcesses() {
  const tbody = document.getElementById('processes-tbody');
  if (!tbody) return;

  tbody.innerHTML = '<tr><td colspan="6" class="table-empty">Auditing running processes and checking memory hooks...</td></tr>';

  try {
    const res = await fetch('/api/processes');
    const procs = await res.json();

    if (procs.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="table-empty">No processes returned.</td></tr>';
      return;
    }

    tbody.innerHTML = procs.slice(0, 50).map(p => {
      const riskClass = p.risk === 'Critical' ? 'critical' : (p.risk === 'High' ? 'high' : (p.risk === 'Medium' ? 'medium' : 'clean'));
      return `
        <tr>
          <td><span class="code-snippet">${p.pid}</span></td>
          <td><strong>${p.name}</strong></td>
          <td><span class="badge-threat ${riskClass}">${p.risk}</span></td>
          <td>${p.cpu || 0.0}%</td>
          <td><div style="max-width: 380px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: var(--font-mono); font-size: 11px;">${p.command}</div></td>
          <td>
            <button class="btn-danger" style="padding: 4px 8px; font-size: 11px;" onclick="killProcess(${p.pid})">Terminate</button>
          </td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    tbody.innerHTML = '<tr><td colspan="6" class="table-empty">Failed to query process table.</td></tr>';
  }
}

async function killProcess(pid) {
  playSound('click');
  if (!confirm(`Terminate process PID ${pid}?`)) return;

  try {
    const res = await fetch('/api/processes/kill', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pid })
    });
    const data = await res.json();
    if (data.success) {
      showToast('Process Terminated', `PID ${pid} successfully ended.`, 'success');
      loadProcesses();
    } else {
      showToast('Termination Failed', data.error || 'Insufficient privileges', 'threat');
    }
  } catch (err) {
    showToast('Error', 'Failed to terminate process', 'threat');
  }
}

// Threat Intelligence Database
async function loadThreatIntel() {
  try {
    const res = await fetch('/api/database');
    const db = await res.json();

    // Render Hashes
    const hashesTbody = document.getElementById('intel-hashes-tbody');
    if (hashesTbody) {
      hashesTbody.innerHTML = Object.entries(db.hashes).map(([h, info]) => `
        <tr>
          <td><strong>${info.name}</strong></td>
          <td>${info.category || info.type}</td>
          <td><span class="badge-threat ${info.severity === 'Critical' ? 'critical' : 'high'}">${info.severity}</span></td>
          <td><span class="code-snippet">${h.substring(0, 16)}...</span></td>
        </tr>
      `).join('');
    }

    // Render Rules
    const rulesTbody = document.getElementById('intel-rules-tbody');
    if (rulesTbody) {
      rulesTbody.innerHTML = db.rules.map(r => `
        <tr>
          <td><strong>${r.id}</strong><br><small style="color:var(--text-dim);">${r.name}</small></td>
          <td>${r.description}</td>
          <td><span class="badge-threat ${r.severity === 'Critical' ? 'critical' : 'high'}">${r.severity}</span></td>
        </tr>
      `).join('');
    }
  } catch (err) {
    console.error('Intel load error:', err);
  }
}

function openAddRuleModal() {
  document.getElementById('add-rule-modal').style.display = 'flex';
}

function closeAddRuleModal() {
  document.getElementById('add-rule-modal').style.display = 'none';
}

function toggleRuleInputs() {
  const type = document.getElementById('modal-rule-type').value;
  document.getElementById('group-hash-input').style.display = type === 'hash' ? 'flex' : 'none';
  document.getElementById('group-regex-input').style.display = type === 'regex' ? 'flex' : 'none';
}

async function submitCustomRule() {
  const type = document.getElementById('modal-rule-type').value;
  const name = document.getElementById('modal-rule-name').value.trim();
  const severity = document.getElementById('modal-rule-severity').value;

  if (!name) {
    alert('Please enter a threat name');
    return;
  }

  try {
    if (type === 'hash') {
      const hash = document.getElementById('modal-hash-value').value.trim();
      if (!hash) {
        alert('Please enter a hash value');
        return;
      }
      const res = await fetch('/api/database/add-hash', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hash, name, severity })
      });
      const data = await res.json();
      if (data.success) {
        showToast('Signature Added', `Registered hash signature for ${name}`, 'success');
        closeAddRuleModal();
        loadThreatIntel();
        updateSystemStatus();
      }
    } else {
      const pattern = document.getElementById('modal-regex-pattern').value.trim();
      if (!pattern) {
        alert('Please enter a regex pattern');
        return;
      }
      const res = await fetch('/api/database/add-rule', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, pattern, severity })
      });
      const data = await res.json();
      if (data.success) {
        showToast('Rule Added', `Registered regex heuristic rule ${name}`, 'success');
        closeAddRuleModal();
        loadThreatIntel();
        updateSystemStatus();
      }
    }
  } catch (err) {
    showToast('Error', 'Failed to save signature', 'threat');
  }
}

// EICAR Test Lab Functions
async function generateEicarTest() {
  playSound('click');
  try {
    const res = await fetch('/api/test/generate-eicar', { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      showToast('EICAR Sample Created', 'Harmless test file written. Real-Time Shield will intercept in ~1 sec!', 'info');
      setTimeout(fetchShieldEvents, 1200);
      setTimeout(updateSystemStatus, 1500);
    } else {
      showToast('Error', data.error, 'threat');
    }
  } catch (err) {
    showToast('Error', 'Failed to trigger test', 'threat');
  }
}

async function generateHeuristicTest() {
  playSound('click');
  try {
    const res = await fetch('/api/test/generate-test-threat', { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      showToast('Mock Script Dropped', 'Reverse-shell test string written. Real-Time Shield will intercept in ~1 sec!', 'info');
      setTimeout(fetchShieldEvents, 1200);
      setTimeout(updateSystemStatus, 1500);
    } else {
      showToast('Error', data.error, 'threat');
    }
  } catch (err) {
    showToast('Error', 'Failed to trigger test', 'threat');
  }
}

function refreshDashboard() {
  playSound('click');
  updateSystemStatus();
  fetchShieldEvents();
  showToast('Refreshed', 'Telemetry updated.', 'info');
}

// Initialization on DOM Ready
document.addEventListener('DOMContentLoaded', () => {
  setupDragAndDrop();
  updateSystemStatus();
  fetchShieldEvents();
  loadScanHistory();

  // Periodic Telemetry Loop
  telemetryPollingInterval = setInterval(() => {
    updateSystemStatus();
    fetchShieldEvents();
  }, 2500);
});
