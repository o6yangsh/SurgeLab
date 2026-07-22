const navBtns = document.querySelectorAll('.nav-btn');
const views = document.querySelectorAll('.view');

navBtns.forEach(btn => {
  btn.addEventListener('click', () => {
    navBtns.forEach(item => item.classList.remove('active'));
    views.forEach(view => view.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById(btn.dataset.target).classList.add('active');
  });
});

const btnStart = document.getElementById('btn-start');
const btnStop = document.getElementById('btn-stop');
const statusDot = document.getElementById('status-dot');
const statusText = document.getElementById('status-text');
const logConsole = document.getElementById('log-console');
const nodeList = document.getElementById('node-list');
const ruleList = document.getElementById('rule-list');
let profiles = [];
let rules = [
  { id: 'private-direct', type: 'ip_is_private', value: true, outbound: 'direct', enabled: true },
  { id: 'geosite-cn-direct', type: 'rule_set', value: 'geosite-cn', outbound: 'direct', enabled: true },
  { id: 'geoip-cn-direct', type: 'rule_set', value: 'geoip-cn', outbound: 'direct', enabled: true }
];

function addLog(message) {
  const line = document.createElement('div');
  line.textContent = message;
  logConsole.appendChild(line);
  while (logConsole.children.length > 500) logConsole.removeChild(logConsole.firstChild);
  logConsole.scrollTop = logConsole.scrollHeight;
}

function currentDns() {
  return {
    local: document.getElementById('local-dns-input').value.trim() || '223.5.5.5',
    remote: document.getElementById('remote-dns-input').value.trim() || 'https://cloudflare-dns.com/dns-query',
    fakeIpEnabled: document.getElementById('fake-ip-checkbox').checked
  };
}

function validateDns(settings) {
  try {
    const isIpv4 = value => {
      const parts = value.split('.');
      return parts.length === 4 && parts.every(part => /^\d{1,3}$/.test(part) && Number(part) <= 255);
    };
    if (!isIpv4(settings.local) && !/^(udp|tcp|tls|quic):\/\//i.test(settings.local)) {
      throw new Error('Local DNS must be an IPv4 address or a udp/tcp/tls/quic URL.');
    }
    if (!/^https:\/\//i.test(settings.remote) && !/^(tls|quic):\/\//i.test(settings.remote)) {
      throw new Error('Remote DNS must use HTTPS, TLS, or QUIC.');
    }
    return true;
  } catch (error) {
    addLog(`[ERROR] ${error.message}`);
    return false;
  }
}

function renderProfiles() {
  nodeList.innerHTML = '';
  profiles.forEach((profile, index) => {
    const item = document.createElement('div');
    item.className = 'node-item';

    const type = document.createElement('span');
    type.className = 'type';
    type.textContent = profile.type.toUpperCase();
    item.appendChild(type);

    const name = document.createElement('div');
    name.style.fontWeight = '600';
    name.style.paddingRight = '25px';
    name.textContent = profile.name || profile.server;
    item.appendChild(name);

    const address = document.createElement('div');
    address.style.fontSize = '12px';
    address.style.color = 'var(--text-muted)';
    address.textContent = `${profile.server}:${profile.port}`;
    item.appendChild(address);

    const secret = document.createElement('div');
    secret.style.fontSize = '12px';
    secret.style.color = 'var(--text-muted)';
    secret.textContent = 'Credential: ********';
    item.appendChild(secret);

    const remove = document.createElement('button');
    remove.className = 'delete-btn';
    remove.textContent = '✕';
    remove.setAttribute('aria-label', `Delete ${profile.name || profile.server}`);
    remove.addEventListener('click', async () => {
      const [deleted] = profiles.splice(index, 1);
      renderProfiles();
      addLog(`[INFO] Deleted node: ${deleted.name || deleted.server}`);
      if (window.electronAPI) {
        const result = await window.electronAPI.saveProfiles(profiles);
        if (!result.success) {
          profiles.splice(index, 0, deleted);
          renderProfiles();
          addLog(`[ERROR] Profile changes were not saved: ${result.message}`);
        }
      }
    });
    item.appendChild(remove);
    nodeList.appendChild(item);
  });
}

function renderRules() {
  ruleList.innerHTML = '';
  rules.forEach((rawRule, index) => {
    const rule = RuleEngine.normalizeRule(rawRule);
    const item = document.createElement('div');
    item.className = 'rule-item';

    const type = document.createElement('span');
    type.textContent = rule.type.replaceAll('_', ' ').toUpperCase();
    item.appendChild(type);

    const value = document.createElement('code');
    value.textContent = Array.isArray(rule.value) ? rule.value.join(', ') : String(rule.value);
    item.appendChild(value);

    const target = document.createElement('span');
    target.className = 'badge';
    target.textContent = rule.outbound.toUpperCase();
    item.appendChild(target);

    const actions = document.createElement('div');
    actions.className = 'rule-actions';
    [['↑', -1], ['↓', 1]].forEach(([label, offset]) => {
      const move = document.createElement('button');
      move.className = 'btn btn-secondary';
      move.textContent = label;
      move.disabled = index + offset < 0 || index + offset >= rules.length;
      move.addEventListener('click', () => moveRule(index, offset));
      actions.appendChild(move);
    });
    const remove = document.createElement('button');
    remove.className = 'btn btn-danger';
    remove.textContent = 'Delete';
    remove.addEventListener('click', () => {
      rules.splice(index, 1);
      persistRules();
    });
    actions.appendChild(remove);
    item.appendChild(actions);
    ruleList.appendChild(item);
  });
}

async function persistRules() {
  renderRules();
  if (window.electronAPI) {
    const result = await window.electronAPI.saveRules(rules);
    if (!result.success) addLog(`[ERROR] Rules were not saved: ${result.message}`);
  }
}

function moveRule(index, offset) {
  const next = index + offset;
  if (next < 0 || next >= rules.length) return;
  [rules[index], rules[next]] = [rules[next], rules[index]];
  persistRules();
}

if (window.electronAPI) {
  window.electronAPI.onSingboxLog(addLog);
  window.electronAPI.onSingboxStatus(status => {
    if (status !== 'stopped') return;
    btnStart.disabled = false;
    btnStop.disabled = true;
    statusDot.className = 'dot stopped';
    statusText.textContent = 'Stopped';
    document.getElementById('engine-status-detail').textContent = 'Engine stopped unexpectedly.';
  });
  Promise.all([window.electronAPI.loadProfiles(), window.electronAPI.loadRules()])
    .then(([savedProfiles, savedRules]) => {
      profiles = Array.isArray(savedProfiles) ? savedProfiles : [];
      if (Array.isArray(savedRules) && savedRules.length) rules = savedRules;
      renderProfiles();
      renderRules();
      addLog(`[INFO] Loaded ${profiles.length} profiles and ${rules.length} routing rules.`);
    })
    .catch(error => addLog(`[ERROR] Failed to load saved data: ${error.message}`));
} else {
  renderProfiles();
  renderRules();
}

btnStart.addEventListener('click', async () => {
  btnStart.disabled = true;
  const mode = document.getElementById('mode-select').value;
  const dns = currentDns();
  if (!validateDns(dns)) {
    btnStart.disabled = false;
    return;
  }
  try {
    const config = ProfileCompiler.compile(profiles, rules, dns, mode);
    if (!window.electronAPI) {
      btnStop.disabled = false;
      statusDot.className = 'dot running';
      statusText.textContent = 'Running';
      addLog('[INFO] Browser preview compiled successfully.');
      return;
    }
    const result = await window.electronAPI.startSingbox(JSON.stringify(config, null, 2));
    if (result.status !== 'running') throw new Error(result.message || 'Failed to start sing-box.');
    btnStop.disabled = false;
    statusDot.className = 'dot running';
    statusText.textContent = 'Running';
    document.getElementById('engine-status-detail').textContent = `Running in ${mode === 'tun' ? 'TUN' : 'System Proxy'} mode | PID: ${result.pid}`;
  } catch (error) {
    btnStart.disabled = false;
    document.getElementById('engine-status-detail').textContent = error.message;
    addLog(`[ERROR] ${error.message}`);
  }
});

btnStop.addEventListener('click', async () => {
  btnStop.disabled = true;
  if (window.electronAPI) await window.electronAPI.stopSingbox();
  btnStart.disabled = false;
  statusDot.className = 'dot stopped';
  statusText.textContent = 'Stopped';
  addLog('[INFO] Engine stopped.');
});

document.getElementById('btn-import').addEventListener('click', async () => {
  const input = document.getElementById('uri-input');
  if (!input.value.trim()) return;
  try {
    const imported = URIParser.parseMany(input.value);
    const previousLength = profiles.length;
    profiles.push(...imported);
    renderProfiles();
    if (window.electronAPI) {
      const result = await window.electronAPI.saveProfiles(profiles);
      if (!result.success) {
        profiles.splice(previousLength);
        renderProfiles();
        throw new Error(`Secure storage failed: ${result.message}`);
      }
    }
    input.value = '';
    addLog(`[INFO] Imported ${imported.length} node(s).`);
  } catch (error) {
    addLog(`[ERROR] Import failed: ${error.message}`);
  }
});

document.getElementById('btn-add-rule').addEventListener('click', () => {
  const type = document.getElementById('rule-type').value;
  const valueInput = document.getElementById('rule-value');
  const value = valueInput.value.trim();
  if (!value) {
    addLog('[ERROR] A rule value is required.');
    return;
  }
  if (type === 'rule_set' && !['geosite-cn', 'geoip-cn'].includes(value)) {
    addLog('[ERROR] Supported remote rule sets are geosite-cn and geoip-cn.');
    return;
  }
  rules.push({
    id: `rule-${Date.now()}`,
    type,
    value: value.includes(',') ? value.split(',').map(item => item.trim()).filter(Boolean) : value,
    outbound: document.getElementById('rule-outbound').value,
    enabled: true
  });
  valueInput.value = '';
  persistRules();
});

document.getElementById('btn-preview').addEventListener('click', () => {
  const input = document.getElementById('preview-input').value.trim();
  if (!input) return;
  const result = RuleEngine.match(input, rules, { final: profiles.length ? 'proxy' : 'direct' });
  if (!profiles.length && result.outbound === 'proxy') result.outbound = 'direct';
  const output = document.getElementById('preview-result');
  if (result.matched) {
    output.textContent = `Rule ${result.index + 1} (${result.rule.type}: ${result.rule.value}) → ${result.outbound.toUpperCase()}`;
    output.style.color = result.outbound === 'reject' ? 'var(--danger)' : 'var(--primary)';
  } else {
    output.textContent = `No locally previewable rule matched → FINAL ${result.outbound.toUpperCase()}`;
    output.style.color = 'var(--text-muted)';
  }
});

function triggerDownload(filename, text) {
  const link = document.createElement('a');
  link.href = `data:text/plain;charset=utf-8,${encodeURIComponent(text)}`;
  link.download = filename;
  link.style.display = 'none';
  document.body.appendChild(link);
  link.click();
  link.remove();
}

document.getElementById('btn-export-config').addEventListener('click', () => {
  try {
    const config = ProfileCompiler.compile(profiles, rules, currentDns(), document.getElementById('mode-select').value);
    triggerDownload('sing-box.json', JSON.stringify(config, null, 2));
    addLog('[INFO] Exported sing-box.json.');
  } catch (error) {
    addLog(`[ERROR] Export failed: ${error.message}`);
  }
});

document.getElementById('btn-export-profile').addEventListener('click', () => {
  triggerDownload('redacted-profiles.json', JSON.stringify(ProfileCompiler.redactProfile(profiles), null, 2));
  addLog('[INFO] Exported redacted profiles.');
});

document.getElementById('btn-open-logs').addEventListener('click', async () => {
  if (!window.electronAPI) return addLog('[INFO] Log file is available in the desktop app.');
  const result = await window.electronAPI.openLogFile();
  if (!result.success) addLog(`[ERROR] ${result.message}`);
});

document.getElementById('btn-export-logs').addEventListener('click', async () => {
  if (!window.electronAPI) return addLog('[INFO] Log export is available in the desktop app.');
  const result = await window.electronAPI.exportLogFile();
  if (result.success) addLog(`[INFO] Logs exported to ${result.filePath}`);
  else if (!result.cancelled) addLog(`[ERROR] ${result.message}`);
});

document.getElementById('btn-test-latency').addEventListener('click', async event => {
  const output = document.getElementById('latency-result');
  if (!profiles.length) {
    output.textContent = 'Import at least one node first.';
    return;
  }
  if (!window.electronAPI) {
    output.textContent = 'Latency testing is available in the desktop app.';
    return;
  }
  event.currentTarget.disabled = true;
  output.textContent = 'Testing TCP connection latency…';
  try {
    const results = await window.electronAPI.testLatencies(profiles.map(profile => ({
      name: profile.name,
      server: profile.server,
      port: profile.port
    })));
    output.textContent = results.map(result => result.success
      ? `${result.name}: ${result.latency} ms`
      : `${result.name}: failed (${result.error})`).join('\n');
    output.style.whiteSpace = 'pre-line';
  } catch (error) {
    output.textContent = `Latency test failed: ${error.message}`;
  } finally {
    event.currentTarget.disabled = false;
  }
});

document.getElementById('btn-test-dns').addEventListener('click', async event => {
  const output = document.getElementById('dns-test-result');
  const localDns = document.getElementById('local-dns-input').value.trim();
  const server = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(localDns) ? localDns : '223.5.5.5';
  if (!window.electronAPI) {
    output.textContent = 'DNS testing is available in the desktop app.';
    return;
  }
  event.currentTarget.disabled = true;
  output.textContent = 'Resolving…';
  try {
    const result = await window.electronAPI.testDns({
      domain: document.getElementById('dns-test-domain').value.trim(),
      server
    });
    output.textContent = result.success
      ? `${result.addresses.join(', ')} via ${result.server} (${result.latency} ms)`
      : `DNS test failed: ${result.error}`;
  } finally {
    event.currentTarget.disabled = false;
  }
});

function isPublicIceAddress(address) {
  if (!address || address.endsWith('.local')) return false;
  if (/^10\./.test(address) || /^192\.168\./.test(address) || /^127\./.test(address)) return false;
  const match = address.match(/^172\.(\d+)\./);
  if (match && Number(match[1]) >= 16 && Number(match[1]) <= 31) return false;
  if (/^(169\.254\.|::1$|f[cd][0-9a-f]{2}:|fe80:)/i.test(address)) return false;
  return true;
}

document.getElementById('btn-test-webrtc').addEventListener('click', async event => {
  const output = document.getElementById('webrtc-result');
  event.currentTarget.disabled = true;
  output.textContent = 'Collecting WebRTC ICE candidates…';
  const peer = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
  const candidates = new Set();
  try {
    peer.createDataChannel('surgelab-diagnostic');
    peer.onicecandidate = ({ candidate }) => {
      if (!candidate || !candidate.candidate) return;
      const parts = candidate.candidate.split(' ');
      if (parts[4]) candidates.add(parts[4]);
    };
    await peer.setLocalDescription(await peer.createOffer());
    await new Promise(resolve => {
      const timeout = setTimeout(resolve, 5000);
      peer.addEventListener('icegatheringstatechange', () => {
        if (peer.iceGatheringState === 'complete') {
          clearTimeout(timeout);
          resolve();
        }
      });
    });
    const all = [...candidates];
    const publicAddresses = all.filter(isPublicIceAddress);
    output.textContent = publicAddresses.length
      ? `Potential public-IP leak: ${publicAddresses.join(', ')}`
      : `No public ICE address detected${all.length ? ` (candidates: ${all.join(', ')})` : ''}.`;
    output.style.color = publicAddresses.length ? 'var(--danger)' : 'var(--success)';
  } catch (error) {
    output.textContent = `WebRTC test failed: ${error.message}`;
  } finally {
    peer.close();
    event.currentTarget.disabled = false;
  }
});
