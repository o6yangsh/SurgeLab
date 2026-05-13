// Navigation Logic
const navBtns = document.querySelectorAll('.nav-btn');
const views = document.querySelectorAll('.view');

navBtns.forEach(btn => {
  btn.addEventListener('click', () => {
    navBtns.forEach(b => b.classList.remove('active'));
    views.forEach(v => v.classList.remove('active'));
    
    btn.classList.add('active');
    const target = btn.getAttribute('data-target');
    document.getElementById(target).classList.add('active');
  });
});

// Engine Control Logic
const btnStart = document.getElementById('btn-start');
const btnStop = document.getElementById('btn-stop');
const statusDot = document.getElementById('status-dot');
const statusText = document.getElementById('status-text');
const logConsole = document.getElementById('log-console');

function addLog(msg) {
  const div = document.createElement('div');
  div.textContent = msg;
  logConsole.appendChild(div);
  logConsole.scrollTop = logConsole.scrollHeight;
}

if (window.electronAPI) {
  window.electronAPI.onSingboxLog((log) => addLog(log));
}

btnStart.addEventListener('click', async () => {
  btnStart.disabled = true;
  const mode = document.getElementById('mode-select').value;
  
  // Default routing rule to send traffic to the first imported proxy
  const activeOutbound = profiles.length > 0 ? profiles[0].name : 'direct';
  const currentRules = [{ domain_suffix: ['google.com'], outbound: activeOutbound }, { geosite: 'cn', outbound: 'direct' }];
  const currentDns = { local: '223.5.5.5', remote: 'https://cloudflare-dns.com/dns-query' };
  
  const compiledObj = ProfileCompiler.compile(profiles, currentRules, currentDns, mode);
  const configJson = JSON.stringify(compiledObj, null, 2);
  
  if (window.electronAPI) {
    const res = await window.electronAPI.startSingbox(configJson);
    if (res.status === 'running') {
      btnStop.disabled = false;
      statusDot.className = 'dot running';
      statusText.textContent = 'Running';
    } else {
      btnStart.disabled = false;
    }
  } else {
    // Mock for browser
    setTimeout(() => {
      btnStop.disabled = false;
      statusDot.className = 'dot running';
      statusText.textContent = 'Running';
      addLog('[INFO] Mock sing-box started on 127.0.0.1');
    }, 500);
  }
});

btnStop.addEventListener('click', async () => {
  btnStop.disabled = true;
  if (window.electronAPI) {
    await window.electronAPI.stopSingbox();
  }
  btnStart.disabled = false;
  statusDot.className = 'dot stopped';
  statusText.textContent = 'Stopped';
  addLog('[INFO] Engine stopped');
});

// URI Import & Profile parsing (Mock logic for prototype)
const btnImport = document.getElementById('btn-import');
const uriInput = document.getElementById('uri-input');
const nodeList = document.getElementById('node-list');
let profiles = [];

function renderProfiles() {
  nodeList.innerHTML = '';
  profiles.forEach(p => {
    const div = document.createElement('div');
    div.className = 'node-item';
    
    // Mask password logic
    const maskedPass = '*'.repeat(8);

    div.innerHTML = `
      <span class="type">${p.type.toUpperCase()}</span>
      <div style="font-weight: 600;">${p.name || p.server}</div>
      <div style="font-size: 12px; color: var(--text-muted)">${p.server}:${p.port}</div>
      <div style="font-size: 12px; color: var(--text-muted)">Pass: ${maskedPass}</div>
    `;
    nodeList.appendChild(div);
  });
}

btnImport.addEventListener('click', () => {
  const uri = uriInput.value.trim();
  if (!uri) return;
  
  try {
    const parsedNode = URIParser.parse(uri);
    profiles.push(parsedNode);
    renderProfiles();
    addLog(`[INFO] Imported ${parsedNode.type} node: ${parsedNode.name}`);
    uriInput.value = '';
  } catch (err) {
    addLog(`[ERROR] Failed to parse URI: ${err.message}`);
  }
});

// Rule Preview
const btnPreview = document.getElementById('btn-preview');
const previewInput = document.getElementById('preview-input');
const previewResult = document.getElementById('preview-result');

btnPreview.addEventListener('click', () => {
  const val = previewInput.value.trim();
  if (!val) return;
  if (val.includes('google')) {
    previewResult.textContent = `Match: Rule(domain: google.com) -> PROXY (vless)`;
    previewResult.style.color = 'var(--primary)';
  } else {
    previewResult.textContent = `Match: Rule(FINAL) -> DIRECT`;
    previewResult.style.color = 'var(--text-muted)';
  }
});

// Export Logic
const btnExportConfig = document.getElementById('btn-export-config');
const btnExportProfile = document.getElementById('btn-export-profile');

function triggerDownload(filename, text) {
  const element = document.createElement('a');
  element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(text));
  element.setAttribute('download', filename);
  element.style.display = 'none';
  document.body.appendChild(element);
  element.click();
  document.body.removeChild(element);
}

btnExportConfig.addEventListener('click', () => {
  const mode = document.getElementById('mode-select').value;
  // Mock rules and dns for export
  const mockRules = [{ domain_suffix: ['google.com'], outbound: 'PROXY' }];
  const mockDns = { local: '223.5.5.5', remote: 'https://cloudflare-dns.com/dns-query' };
  
  const config = ProfileCompiler.compile(profiles, mockRules, mockDns, mode);
  triggerDownload('sing-box.json', JSON.stringify(config, null, 2));
  addLog('[INFO] Exported sing-box.json');
});

btnExportProfile.addEventListener('click', () => {
  const redacted = ProfileCompiler.redactProfile(profiles);
  triggerDownload('redacted-profiles.json', JSON.stringify(redacted, null, 2));
  addLog('[INFO] Exported redacted profiles');
});
