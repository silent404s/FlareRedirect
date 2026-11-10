/**
 * FlareRedirect Web Dashboard Engine (Ultra-Fast Client-side Controller).
 * Handles instant in-memory search, pagination for 5,000+ domains, multi-account operations,
 * live redirect check workers, and bulk redirect execution.
 */

// Global State
let allZones = [];
let targetsMap = {};
let redirectChecksMap = {};
let selectedZoneIds = new Set();
let filteredZones = [];
let accountsList = [];
let activeAccount = null;

let currentPage = 1;
let pageSize = 50;
let activeScanTaskId = null;
let scanPollInterval = null;

// DOM Elements Cache
const DOM = {
  activeAccountBadge: document.getElementById('activeAccountBadge'),
  activeAccountText: document.getElementById('activeAccountText'),
  openAccountsBtn: document.getElementById('openAccountsBtn'),

  // KPIs
  kpiTotalDomains: document.getElementById('kpiTotalDomains'),
  kpiSingleRedirects: document.getElementById('kpiSingleRedirects'),
  kpiMultipleRedirects: document.getElementById('kpiMultipleRedirects'),
  kpiNoRedirects: document.getElementById('kpiNoRedirects'),
  kpiAccountsCount: document.getElementById('kpiAccountsCount'),

  // Tracer
  quickTraceInput: document.getElementById('quickTraceInput'),
  quickTraceBtn: document.getElementById('quickTraceBtn'),
  quickTraceOutput: document.getElementById('quickTraceOutput'),

  // Toolbar & Filters
  domainCountBadge: document.getElementById('domainCountBadge'),
  searchInput: document.getElementById('searchInput'),
  accountFilter: document.getElementById('accountFilter'),
  statusFilter: document.getElementById('statusFilter'),
  redirectFilter: document.getElementById('redirectFilter'),

  // Action Buttons
  checkLiveBtn: document.getElementById('checkLiveBtn'),
  openBulkBtn: document.getElementById('openBulkBtn'),
  deleteSelectedBtn: document.getElementById('deleteSelectedBtn'),
  cleanCacheBtn: document.getElementById('cleanCacheBtn'),
  refreshCfBtn: document.getElementById('refreshCfBtn'),

  // Progress Banner
  progressCard: document.getElementById('progressCard'),
  progressTitle: document.getElementById('progressTitle'),
  progressBarFill: document.getElementById('progressBarFill'),
  cancelCheckBtn: document.getElementById('cancelCheckBtn'),

  // Table & Pagination
  selectAllCheckbox: document.getElementById('selectAllCheckbox'),
  domainsTableBody: document.getElementById('domainsTableBody'),
  emptyState: document.getElementById('emptyState'),
  pageSizeSelect: document.getElementById('pageSizeSelect'),
  firstPageBtn: document.getElementById('firstPageBtn'),
  prevPageBtn: document.getElementById('prevPageBtn'),
  nextPageBtn: document.getElementById('nextPageBtn'),
  lastPageBtn: document.getElementById('lastPageBtn'),
  pageIndicator: document.getElementById('pageIndicator'),
  pageRangeInfo: document.getElementById('pageRangeInfo'),

  // Toast Container
  toastContainer: document.getElementById('toastContainer'),

  // Modals
  bulkModal: document.getElementById('bulkModal'),
  bulkDomainsInput: document.getElementById('bulkDomainsInput'),
  bulkTargetInput: document.getElementById('bulkTargetInput'),
  bulkPreservePath: document.getElementById('bulkPreservePath'),
  executeBulkBtn: document.getElementById('executeBulkBtn'),

  singleModal: document.getElementById('singleModal'),
  singleModalDomain: document.getElementById('singleModalDomain'),
  singleModalZoneId: document.getElementById('singleModalZoneId'),
  singleModalAccountId: document.getElementById('singleModalAccountId'),
  singleTargetInput: document.getElementById('singleTargetInput'),
  singleModalAccountInfo: document.getElementById('singleModalAccountInfo'),
  saveSingleRedirectBtn: document.getElementById('saveSingleRedirectBtn'),
  deleteSingleRedirectBtn: document.getElementById('deleteSingleRedirectBtn'),

  accountsModal: document.getElementById('accountsModal'),
  newAccountLabel: document.getElementById('newAccountLabel'),
  newAccountAuthMethod: document.getElementById('newAccountAuthMethod'),
  newAccountToken: document.getElementById('newAccountToken'),
  newAccountGlobalKey: document.getElementById('newAccountGlobalKey'),
  newAccountEmail: document.getElementById('newAccountEmail'),
  saveNewAccountBtn: document.getElementById('saveNewAccountBtn'),
  accountsTableBody: document.getElementById('accountsTableBody'),
};

// --- INIT ---
document.addEventListener('DOMContentLoaded', () => {
  initEventListeners();
  loadStatus();
  loadDomains();
});

function initEventListeners() {
  // Search & Filters
  DOM.searchInput.addEventListener('input', () => {
    currentPage = 1;
    filterAndRender();
  });
  DOM.accountFilter.addEventListener('change', () => {
    currentPage = 1;
    filterAndRender();
  });
  DOM.statusFilter.addEventListener('change', () => {
    currentPage = 1;
    filterAndRender();
  });
  DOM.redirectFilter.addEventListener('change', () => {
    currentPage = 1;
    filterAndRender();
  });

  // Pagination Controls
  DOM.pageSizeSelect.addEventListener('change', (e) => {
    pageSize = parseInt(e.target.value, 10);
    currentPage = 1;
    renderCurrentPage();
  });
  DOM.firstPageBtn.addEventListener('click', () => {
    currentPage = 1;
    renderCurrentPage();
  });
  DOM.prevPageBtn.addEventListener('click', () => {
    if (currentPage > 1) {
      currentPage--;
      renderCurrentPage();
    }
  });
  DOM.nextPageBtn.addEventListener('click', () => {
    const totalPages = getTotalPages();
    if (currentPage < totalPages) {
      currentPage++;
      renderCurrentPage();
    }
  });
  DOM.lastPageBtn.addEventListener('click', () => {
    currentPage = getTotalPages();
    renderCurrentPage();
  });

  // Select All Checkbox
  DOM.selectAllCheckbox.addEventListener('change', (e) => {
    const checked = e.target.checked;
    if (checked) {
      filteredZones.forEach(z => selectedZoneIds.add(z.id));
    } else {
      filteredZones.forEach(z => selectedZoneIds.delete(z.id));
    }
    renderCurrentPage();
  });

  // Quick Tracer
  DOM.quickTraceBtn.addEventListener('click', executeQuickTrace);
  DOM.quickTraceInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') executeQuickTrace();
  });

  // Action Buttons
  DOM.checkLiveBtn.addEventListener('click', startLiveRedirectCheck);
  DOM.cancelCheckBtn.addEventListener('click', cancelLiveRedirectCheck);
  DOM.openBulkBtn.addEventListener('click', openBulkModal);
  DOM.executeBulkBtn.addEventListener('click', executeBulkRedirect);
  DOM.deleteSelectedBtn.addEventListener('click', deleteSelectedRedirects);
  DOM.cleanCacheBtn.addEventListener('click', cleanStaleCache);
  DOM.refreshCfBtn.addEventListener('click', refreshFromCloudflare);

  // Single Modal Actions
  DOM.saveSingleRedirectBtn.addEventListener('click', saveSingleRedirect);
  DOM.deleteSingleRedirectBtn.addEventListener('click', () => saveSingleRedirect(true));

  // Accounts Modal
  DOM.openAccountsBtn.addEventListener('click', openAccountsModal);
  DOM.saveNewAccountBtn.addEventListener('click', addNewAccount);
}

// --- API DATA LOADERS ---

async function loadStatus() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    accountsList = data.accounts || [];
    activeAccount = data.active_account;

    if (activeAccount && activeAccount.label) {
      DOM.activeAccountText.textContent = `👤 ${activeAccount.label}`;
    } else {
      DOM.activeAccountText.textContent = 'Belum Terhubung';
    }

    DOM.kpiAccountsCount.textContent = accountsList.length;

    // Refresh Account Filter Dropdown
    const currentVal = DOM.accountFilter.value;
    DOM.accountFilter.innerHTML = '<option value="all">Semua Akun</option>';
    accountsList.forEach(acc => {
      const opt = document.createElement('option');
      opt.value = acc.label;
      opt.textContent = `👤 ${acc.label} (${acc.domain_count} Domain)`;
      DOM.accountFilter.appendChild(opt);
    });
    DOM.accountFilter.value = currentVal || 'all';
  } catch (err) {
    showToast('Gagal memuat status sistem: ' + err.message, true);
  }
}

async function loadDomains() {
  try {
    const res = await fetch('/api/domains');
    const data = await res.json();
    allZones = data.zones || [];
    targetsMap = data.targets || {};
    redirectChecksMap = data.redirect_checks || {};

    updateKpis();
    filterAndRender();
    showToast(`Berhasil memuat ${allZones.length} domain dari cache lokal.`);
  } catch (err) {
    showToast('Gagal mengambil daftar domain: ' + err.message, true);
  }
}

function updateKpis() {
  DOM.kpiTotalDomains.textContent = allZones.length.toLocaleString();

  let single = 0;
  let multiple = 0;
  let none = 0;

  allZones.forEach(z => {
    const chk = redirectChecksMap[z.name.toLowerCase()];
    if (chk) {
      if (chk.is_multiple || (chk.hops && chk.hops > 1)) {
        multiple++;
      } else if (chk.hops === 1) {
        single++;
      } else if (!chk.has_redirect && !chk.error) {
        none++;
      }
    }
  });

  DOM.kpiSingleRedirects.textContent = single.toLocaleString();
  DOM.kpiMultipleRedirects.textContent = multiple.toLocaleString();
  DOM.kpiNoRedirects.textContent = none.toLocaleString();
}

// --- FILTER & PAGINATION ENGINE ---

function filterAndRender() {
  const query = DOM.searchInput.value.trim().toLowerCase();
  const selectedAccount = DOM.accountFilter.value.toLowerCase();
  const selectedStatus = DOM.statusFilter.value.toLowerCase();
  const selectedRedirect = DOM.redirectFilter.value;

  filteredZones = allZones.filter(z => {
    // Search query match
    if (query && !z.name.toLowerCase().includes(query)) {
      return false;
    }
    // Account match
    if (selectedAccount !== 'all' && (z.account_label || '').toLowerCase() !== selectedAccount) {
      return false;
    }
    // Status CF match
    if (selectedStatus !== 'all' && (z.status || '').toLowerCase() !== selectedStatus) {
      return false;
    }
    // Redirect Status match
    const chk = redirectChecksMap[z.name.toLowerCase()];
    if (selectedRedirect === 'multiple') {
      if (!chk || !(chk.is_multiple || (chk.hops && chk.hops > 1))) return false;
    } else if (selectedRedirect === 'single') {
      if (!chk || chk.hops !== 1) return false;
    } else if (selectedRedirect === 'none') {
      if (!chk || chk.has_redirect || chk.error) return false;
    } else if (selectedRedirect === 'error') {
      if (!chk || !chk.error) return false;
    } else if (selectedRedirect === 'untested') {
      if (chk) return false;
    }

    return true;
  });

  DOM.domainCountBadge.textContent = `${filteredZones.length.toLocaleString()} Domain`;
  renderCurrentPage();
}

function getTotalPages() {
  if (pageSize === 0 || filteredZones.length === 0) return 1;
  return Math.max(1, Math.ceil(filteredZones.length / pageSize));
}

function renderCurrentPage() {
  const total = filteredZones.length;
  const totalPages = getTotalPages();

  if (currentPage > totalPages) currentPage = totalPages;
  if (currentPage < 1) currentPage = 1;

  if (total === 0) {
    DOM.domainsTableBody.innerHTML = '';
    DOM.emptyState.style.display = 'block';
    DOM.pageIndicator.textContent = 'Halaman 0 dari 0';
    DOM.pageRangeInfo.textContent = 'Menampilkan 0 - 0 dari 0 Domain';
    DOM.firstPageBtn.disabled = true;
    DOM.prevPageBtn.disabled = true;
    DOM.nextPageBtn.disabled = true;
    DOM.lastPageBtn.disabled = true;
    return;
  }

  DOM.emptyState.style.display = 'none';

  let startIdx = 0;
  let endIdx = total;
  let pageItems = filteredZones;

  if (pageSize > 0) {
    startIdx = (currentPage - 1) * pageSize;
    endIdx = Math.min(startIdx + pageSize, total);
    pageItems = filteredZones.slice(startIdx, endIdx);
  }

  // Update Navigation Controls
  DOM.pageIndicator.textContent = `Halaman ${currentPage} dari ${totalPages}`;
  DOM.pageRangeInfo.textContent = `Menampilkan ${(startIdx + 1).toLocaleString()} - ${endIdx.toLocaleString()} dari ${total.toLocaleString()} Domain`;
  DOM.firstPageBtn.disabled = (currentPage === 1);
  DOM.prevPageBtn.disabled = (currentPage === 1);
  DOM.nextPageBtn.disabled = (currentPage === totalPages);
  DOM.lastPageBtn.disabled = (currentPage === totalPages);

  // Render Table Rows with DocumentFragment for 60fps rendering
  const fragment = document.createDocumentFragment();

  pageItems.forEach(z => {
    const tr = document.createElement('tr');

    // 0. Checkbox
    const tdChk = document.createElement('td');
    tdChk.style.textAlign = 'center';
    const chk = document.createElement('input');
    chk.type = 'checkbox';
    chk.checked = selectedZoneIds.has(z.id);
    chk.addEventListener('change', (e) => {
      if (e.target.checked) {
        selectedZoneIds.add(z.id);
      } else {
        selectedZoneIds.delete(z.id);
      }
    });
    tdChk.appendChild(chk);
    tr.appendChild(tdChk);

    // 1. Domain Name
    const tdName = document.createElement('td');
    tdName.className = 'domain-col';
    tdName.textContent = z.name;
    tr.appendChild(tdName);

    // 2. CF Account
    const tdAcc = document.createElement('td');
    tdAcc.className = 'account-col' + (z.is_connected ? '' : ' disconnected');
    tdAcc.textContent = z.is_connected ? z.account_label : `⚠️ ${z.account_label} (Terputus)`;
    tdAcc.title = z.is_connected ? `Akun: ${z.account_label}` : `Akun '${z.account_label}' tidak terhubung!`;
    tr.appendChild(tdAcc);

    // 3. Status CF
    const tdStatus = document.createElement('td');
    tdStatus.style.textAlign = 'center';
    const isAct = (z.status || '').toLowerCase() === 'active';
    const statusPill = document.createElement('span');
    statusPill.className = `pill ${isAct ? 'pill-success' : 'pill-warning'}`;
    statusPill.textContent = (z.status || 'UNKNOWN').toUpperCase();
    tdStatus.appendChild(statusPill);
    tr.appendChild(tdStatus);

    // 4. Target Live Redirect Badge
    const tdTarget = document.createElement('td');
    const chkData = redirectChecksMap[z.name.toLowerCase()];

    if (chkData) {
      const hops = chkData.hops || 0;
      const target = chkData.target_url || '';
      const code = chkData.status_code || '';
      const isMult = chkData.is_multiple || hops > 1;

      if (isMult) {
        const pill = document.createElement('span');
        pill.className = 'pill pill-warning';
        pill.textContent = `⚠️ [${code} • ${hops}x] ${target}`;
        pill.title = `PERINGATAN: Terdeteksi ${hops}x Pengalihan! Rantai: ${chkData.chain ? chkData.chain.join(' → ') : target}`;
        tdTarget.appendChild(pill);
      } else if (hops === 1) {
        const pill = document.createElement('span');
        pill.className = 'pill pill-success';
        pill.textContent = `✅ [${code || 301}] ${target}`;
        pill.title = `Normal 1x Redirect: ${target}`;
        tdTarget.appendChild(pill);
      } else if (chkData.error) {
        const pill = document.createElement('span');
        pill.className = 'pill pill-danger';
        pill.textContent = `✕ ${chkData.error}`;
        tdTarget.appendChild(pill);
      } else {
        const pill = document.createElement('span');
        pill.className = 'pill pill-neutral';
        pill.textContent = `○ ${code || 200} OK (Tanpa Redirect)`;
        tdTarget.appendChild(pill);
      }
    } else {
      const curTarget = targetsMap[z.id];
      if (curTarget) {
        const pill = document.createElement('span');
        pill.className = 'pill pill-neutral';
        pill.style.color = '#38bdf8';
        pill.textContent = `[CF Rule] ${curTarget}`;
        pill.title = 'Target dari aturan lokal (belum diperiksa live)';
        tdTarget.appendChild(pill);
      } else {
        tdTarget.innerHTML = '<span style="color: var(--text-subtle);">- (Belum dicek)</span>';
      }
    }
    tr.appendChild(tdTarget);

    // 5. Actions
    const tdActions = document.createElement('td');
    tdActions.style.textAlign = 'right';
    const actionWrap = document.createElement('div');
    actionWrap.className = 'row-actions';
    actionWrap.style.justifyContent = 'flex-end';

    const redirectBtn = document.createElement('button');
    redirectBtn.className = 'btn btn-primary btn-icon';
    redirectBtn.textContent = '⚡ Redirect';
    redirectBtn.addEventListener('click', () => openSingleModal(z));
    actionWrap.appendChild(redirectBtn);

    const checkBtn = document.createElement('button');
    checkBtn.className = 'btn btn-secondary btn-icon';
    checkBtn.textContent = '🔍';
    checkBtn.title = 'Uji live redirect domain ini sekarang';
    checkBtn.addEventListener('click', () => checkSingleDomain(z));
    actionWrap.appendChild(checkBtn);

    const delBtn = document.createElement('button');
    delBtn.className = 'btn btn-secondary btn-icon';
    delBtn.textContent = '🗑️';
    delBtn.title = 'Hapus semua redirect untuk domain ini';
    delBtn.addEventListener('click', () => deleteDomainRedirects(z));
    actionWrap.appendChild(delBtn);

    tdActions.appendChild(actionWrap);
    tr.appendChild(tdActions);

    fragment.appendChild(tr);
  });

  DOM.domainsTableBody.innerHTML = '';
  DOM.domainsTableBody.appendChild(fragment);
}

// --- SINGLE & LIVE TRACER ---

async function executeQuickTrace() {
  const raw = DOM.quickTraceInput.value.trim();
  if (!raw) {
    showToast('Ketik domain yang ingin diuji terlebih dahulu.', true);
    return;
  }

  DOM.quickTraceBtn.disabled = true;
  DOM.quickTraceOutput.style.display = 'block';
  DOM.quickTraceOutput.innerHTML = '<span style="color: var(--accent);">🔍 Menghubungi server...</span>';

  try {
    const res = await fetch('/api/redirect/trace-single', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain: raw })
    });
    const data = await res.json();
    redirectChecksMap[raw.toLowerCase()] = data;

    if (data.is_multiple || data.hops > 1) {
      DOM.quickTraceOutput.innerHTML = `<span class="pill pill-warning">⚠️ [${data.status_code || 301} • ${data.hops}x] ${data.target_url}</span>`;
      showToast(`⚠️ Domain '${raw}' terdeteksi ${data.hops}x Redirects!`, true);
    } else if (data.hops === 1) {
      DOM.quickTraceOutput.innerHTML = `<span class="pill pill-success">✅ [${data.status_code || 301}] ${data.target_url}</span>`;
      showToast(`✅ Domain '${raw}' normal 1x redirect ke ${data.target_url}`);
    } else if (data.error) {
      DOM.quickTraceOutput.innerHTML = `<span class="pill pill-danger">✕ Error: ${data.error}</span>`;
      showToast(`Gagal memeriksa '${raw}': ${data.error}`, true);
    } else {
      DOM.quickTraceOutput.innerHTML = `<span class="pill pill-neutral">○ 200 OK (Tanpa Redirect)</span>`;
      showToast(`○ Domain '${raw}' aktif tanpa redirect.`);
    }

    updateKpis();
    filterAndRender();
  } catch (err) {
    DOM.quickTraceOutput.innerHTML = `<span class="pill pill-danger">✕ Error: ${err.message}</span>`;
    showToast('Gagal memeriksa domain: ' + err.message, true);
  } finally {
    DOM.quickTraceBtn.disabled = false;
  }
}

async function checkSingleDomain(zone) {
  showToast(`Memeriksa live redirect '${zone.name}'...`);
  try {
    const res = await fetch('/api/redirect/trace-single', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain: zone.name })
    });
    const data = await res.json();
    redirectChecksMap[zone.name.toLowerCase()] = data;
    updateKpis();
    renderCurrentPage();

    if (data.is_multiple || data.hops > 1) {
      showToast(`⚠️ '${zone.name}' terdeteksi ${data.hops}x Redirects!`, true);
    } else if (data.hops === 1) {
      showToast(`✅ '${zone.name}' normal 1x redirect (${data.status_code}) ke ${data.target_url}`);
    } else if (data.error) {
      showToast(`✕ '${zone.name}': ${data.error}`, true);
    } else {
      showToast(`○ '${zone.name}': 200 OK (Tanpa Redirect)`);
    }
  } catch (err) {
    showToast(`Gagal memeriksa '${zone.name}': ` + err.message, true);
  }
}

// --- CONCURRENT BATCH LIVE REDIRECT CHECKER ---

async function startLiveRedirectCheck() {
  if (activeScanTaskId) {
    showToast('Pengecekan live redirect sedang berlangsung.', true);
    return;
  }

  // Use selected domains if any, else use all filtered
  let targetDomains = [];
  if (selectedZoneIds.size > 0) {
    targetDomains = allZones.filter(z => selectedZoneIds.has(z.id)).map(z => z.name);
  } else {
    targetDomains = filteredZones.map(z => z.name);
  }

  if (targetDomains.length === 0) {
    showToast('Tidak ada domain yang dapat diperiksa.', true);
    return;
  }

  if (targetDomains.length > 50) {
    const ok = confirm(`Mulai pengecekan live redirect untuk ${targetDomains.length} domain?\n\nPengecekan berjalan otomatis di background secara multi-threaded (cepat dan tidak membuat lag).`);
    if (!ok) return;
  }

  DOM.checkLiveBtn.disabled = true;
  DOM.progressCard.style.display = 'flex';
  DOM.progressBarFill.style.width = '0%';
  DOM.progressTitle.textContent = `Memulai pengecekan ${targetDomains.length} domain...`;

  try {
    const res = await fetch('/api/redirect/check-live', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domains: targetDomains })
    });
    const data = await res.json();

    if (data.task_id) {
      activeScanTaskId = data.task_id;
      scanPollInterval = setInterval(pollScanProgress, 600);
    }
  } catch (err) {
    DOM.progressCard.style.display = 'none';
    DOM.checkLiveBtn.disabled = false;
    showToast('Gagal memulai pengecekan: ' + err.message, true);
  }
}

async function pollScanProgress() {
  if (!activeScanTaskId) return;

  try {
    const res = await fetch(`/api/redirect/check-live/status?task_id=${activeScanTaskId}`);
    if (res.status === 404) {
      clearInterval(scanPollInterval);
      activeScanTaskId = null;
      return;
    }
    const task = await res.json();

    const current = task.current || 0;
    const total = task.total || 1;
    const pct = Math.round((current / total) * 100);

    DOM.progressBarFill.style.width = `${pct}%`;
    DOM.progressTitle.textContent = `Mengecek ${current}/${total} domain (${pct}%) — ${task.current_domain || ''}`;

    // Incremental merge
    if (task.results) {
      Object.assign(redirectChecksMap, task.results);
      if (current % 25 === 0) {
        updateKpis();
        renderCurrentPage();
      }
    }

    if (task.status === 'completed' || task.status === 'error') {
      clearInterval(scanPollInterval);
      activeScanTaskId = null;
      DOM.progressCard.style.display = 'none';
      DOM.checkLiveBtn.disabled = false;

      updateKpis();
      filterAndRender();

      if (task.status === 'completed') {
        showToast(`Pengecekan live selesai! Total ${total} domain berhasil diperiksa.`);
      } else {
        showToast('Pengecekan dihentikan dengan catatan error.', true);
      }
    }
  } catch (err) {
    // Ignore transient poll network errors
  }
}

function cancelLiveRedirectCheck() {
  if (scanPollInterval) clearInterval(scanPollInterval);
  activeScanTaskId = null;
  DOM.progressCard.style.display = 'none';
  DOM.checkLiveBtn.disabled = false;
  showToast('Pengecekan live redirect dihentikan.');
}

// --- BULK REDIRECT ---

function openBulkModal() {
  let prefillDomains = [];
  if (selectedZoneIds.size > 0) {
    prefillDomains = allZones.filter(z => selectedZoneIds.has(z.id)).map(z => z.name);
  }
  DOM.bulkDomainsInput.value = prefillDomains.join('\n');
  DOM.bulkModal.style.display = 'flex';
}

async function executeBulkRedirect() {
  const text = DOM.bulkDomainsInput.value.trim();
  const targetUrl = DOM.bulkTargetInput.value.trim();
  const preservePath = DOM.bulkPreservePath.checked;

  if (!text) {
    alert('Masukkan daftar domain terlebih dahulu.');
    return;
  }
  if (!targetUrl) {
    alert('Masukkan URL tujuan redirect terlebih dahulu.');
    return;
  }

  const rawLines = text.split('\n').map(l => l.trim()).filter(l => l.length > 0);
  const items = [];
  const unconnectedDomains = [];

  rawLines.forEach(raw => {
    // clean protocol and paths
    const cleanHost = raw.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').toLowerCase();
    const zone = allZones.find(z => z.name.toLowerCase() === cleanHost);

    if (zone) {
      if (!zone.is_connected) {
        unconnectedDomains.push(`${cleanHost} (${zone.account_label})`);
      } else {
        items.push({
          zone_id: zone.id,
          source: cleanHost,
          target: targetUrl,
          account_id: zone.account_id,
          account_label: zone.account_label
        });
      }
    } else {
      unconnectedDomains.push(`${cleanHost} (Zona tidak ditemukan)`);
    }
  });

  if (unconnectedDomains.length > 0) {
    const proceed = confirm(`Peringatan: ${unconnectedDomains.length} domain berikut tidak memiliki akun Cloudflare yang terhubung:\n\n${unconnectedDomains.slice(0, 10).join('\n')}\n\nApakah Anda ingin tetap memproses ${items.length} domain yang valid?`);
    if (!proceed) return;
  }

  if (items.length === 0) {
    alert('Tidak ada domain valid yang siap dieksekusi.');
    return;
  }

  DOM.executeBulkBtn.disabled = true;
  DOM.executeBulkBtn.textContent = 'Memproses...';

  try {
    const res = await fetch('/api/redirect/bulk', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ items, preserve_path: preservePath })
    });
    const data = await res.json();

    if (data.success !== undefined) {
      closeModal('bulkModal');
      showToast(`Bulk Redirect Berhasil: ${data.success} berhasil, ${data.failed} gagal.`);
      loadDomains();
    } else {
      alert('Gagal mengeksekusi: ' + (data.error || 'Unknown error'));
    }
  } catch (err) {
    alert('Error saat mengirim request: ' + err.message);
  } finally {
    DOM.executeBulkBtn.disabled = false;
    DOM.executeBulkBtn.textContent = '⚡ Terapkan Redirect Massal';
  }
}

// --- SINGLE REDIRECT MODAL ---

function openSingleModal(zone) {
  if (!zone.is_connected) {
    alert(`Perhatian: Domain '${zone.name}' terdaftar pada akun '${zone.account_label}' yang saat ini tidak terhubung.\n\nSilakan hubungkan akun '${zone.account_label}' di menu Kelola Akun terlebih dahulu.`);
    return;
  }

  DOM.singleModalDomain.textContent = zone.name;
  DOM.singleModalZoneId.value = zone.id;
  DOM.singleModalAccountId.value = zone.account_id || '';
  DOM.singleTargetInput.value = targetsMap[zone.id] || '';
  DOM.singleModalAccountInfo.textContent = `Akun Pemilik: 👤 ${zone.account_label} (Terhubung)`;
  DOM.singleModal.style.display = 'flex';
}

async function saveSingleRedirect(isDelete = false) {
  const zoneId = DOM.singleModalZoneId.value;
  const source = DOM.singleModalDomain.textContent;
  const target = DOM.singleTargetInput.value.trim();
  const accountId = DOM.singleModalAccountId.value;

  if (!isDelete && !target) {
    alert('Masukkan URL tujuan redirect terlebih dahulu.');
    return;
  }

  try {
    const res = await fetch('/api/redirect/single', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        zone_id: zoneId,
        source_hostname: source,
        destination_url: target,
        account_id: accountId,
        delete: isDelete
      })
    });
    const data = await res.json();

    if (data.success) {
      closeModal('singleModal');
      if (isDelete) {
        delete targetsMap[zoneId];
        showToast(`Aturan redirect untuk '${source}' berhasil dihapus.`);
      } else {
        targetsMap[zoneId] = data.target;
        showToast(`301 Redirect berhasil dipasang ke ${data.target}`);
      }
      renderCurrentPage();
    } else {
      alert('Gagal: ' + (data.error || 'Unknown error'));
    }
  } catch (err) {
    alert('Error: ' + err.message);
  }
}

// --- DELETE & CLEAN ACTIONS ---

async function deleteSelectedRedirects() {
  if (selectedZoneIds.size === 0) {
    alert('Silakan centang satu atau beberapa domain pada tabel terlebih dahulu.');
    return;
  }

  const selectedZones = allZones.filter(z => selectedZoneIds.has(z.id));
  const ok = confirm(`Hapus semua aturan redirect untuk ${selectedZones.length} domain yang dicentang?`);
  if (!ok) return;

  DOM.deleteSelectedBtn.disabled = true;
  try {
    const res = await fetch('/api/redirect/delete-bulk', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ zones: selectedZones })
    });
    const data = await res.json();

    selectedZones.forEach(z => delete targetsMap[z.id]);
    selectedZoneIds.clear();
    showToast(`Selesai! Total ${data.deleted_rules || 0} aturan redirect berhasil dibersihkan.`);
    renderCurrentPage();
  } catch (err) {
    showToast('Gagal menghapus redirect: ' + err.message, true);
  } finally {
    DOM.deleteSelectedBtn.disabled = false;
  }
}

async function deleteDomainRedirects(zone) {
  const ok = confirm(`Hapus semua aturan redirect untuk domain '${zone.name}'?`);
  if (!ok) return;

  try {
    const res = await fetch('/api/redirect/single', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        zone_id: zone.id,
        source_hostname: zone.name,
        account_id: zone.account_id,
        delete: true
      })
    });
    const data = await res.json();
    if (data.success) {
      delete targetsMap[zone.id];
      showToast(`Aturan redirect untuk '${zone.name}' berhasil dibersihkan.`);
      renderCurrentPage();
    } else {
      alert('Gagal: ' + data.error);
    }
  } catch (err) {
    alert('Error: ' + err.message);
  }
}

async function cleanStaleCache() {
  const ok = confirm('Apakah Anda ingin membersihkan sisa data dari akun Cloudflare yang sudah tidak terhubung?\n\nDomain yatim dari akun yang sudah diputuskan akan dibersihkan dari penyimpanan lokal.');
  if (!ok) return;

  try {
    const res = await fetch('/api/domains/clean-cache', { method: 'POST' });
    const data = await res.json();
    showToast(`Pembersihan Berhasil: ${data.pruned_count} domain sisa akun lama telah dihapus.`);
    loadDomains();
    loadStatus();
  } catch (err) {
    showToast('Gagal membersihkan cache: ' + err.message, true);
  }
}

async function refreshFromCloudflare() {
  const selectedAcc = DOM.accountFilter.value;
  let confirmMsg = 'Muat ulang daftar domain langsung dari server Cloudflare?\n\nData lokal akan diperbarui dengan data resmi terbaru.';
  let reqPayload = { account_id: 'all' };

  if (selectedAcc && selectedAcc !== 'all') {
    confirmMsg = `Muat ulang domain dari Cloudflare untuk akun '${selectedAcc}' saja?\n\n(Pilih 'Semua Akun' pada dropdown filter jika ingin memuat seluruh akun)`;
    reqPayload = { account_id: selectedAcc };
  }

  const ok = confirm(confirmMsg);
  if (!ok) return;

  DOM.refreshCfBtn.disabled = true;
  showToast('Menghubungi Cloudflare API...');

  try {
    const res = await fetch('/api/domains/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(reqPayload)
    });
    const data = await res.json();
    if (data.success) {
      showToast(`Berhasil memuat domain dari Cloudflare! Total ${data.count} domain.`);
      await loadDomains();
      await loadStatus();
    } else {
      alert('Gagal refresh dari Cloudflare: ' + data.error);
    }
  } catch (err) {
    alert('Error refresh: ' + err.message);
  } finally {
    DOM.refreshCfBtn.disabled = false;
  }
}

// --- ACCOUNTS MANAGER ---

function openAccountsModal() {
  renderAccountsTable();
  DOM.accountsModal.style.display = 'flex';
}

function renderAccountsTable() {
  DOM.accountsTableBody.innerHTML = '';
  accountsList.forEach(acc => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td style="font-weight: 600;">
        ${acc.is_active ? '★ ' : ''}${acc.label}
        ${acc.is_active ? '<span class="pill pill-success" style="margin-left: 6px;">Aktif</span>' : ''}
      </td>
      <td>${acc.is_connected ? '<span style="color: var(--positive);">● Siaga</span>' : '<span style="color: var(--negative);">○ Terputus</span>'}</td>
      <td class="tabular-nums">${(acc.domain_count || 0).toLocaleString()} Domain</td>
      <td style="text-align: right; display: flex; gap: 4px; justify-content: flex-end;">
        <button class="btn btn-secondary btn-icon" style="padding: 4px 8px; font-size: 11px;" title="Tarik ulang domain untuk akun ini saja" onclick="syncSingleAccount('${acc.label}')">🔄 Sync</button>
        ${!acc.is_active ? `<button class="btn btn-secondary btn-icon" style="padding: 4px 8px; font-size: 11px;" onclick="switchAccount('${acc.label}')">Gunakan</button>` : ''}
        <button class="btn btn-danger btn-icon" style="padding: 4px 8px; font-size: 11px;" onclick="deleteAccount('${acc.label}')">Putuskan</button>
      </td>
    `;
    DOM.accountsTableBody.appendChild(tr);
  });
}

function toggleAuthFields() {
  const method = DOM.newAccountAuthMethod.value;
  if (method === 'key') {
    document.getElementById('tokenFieldWrap').style.display = 'none';
    document.getElementById('keyFieldWrap').style.display = 'grid';
  } else {
    document.getElementById('tokenFieldWrap').style.display = 'block';
    document.getElementById('keyFieldWrap').style.display = 'none';
  }
}

async function addNewAccount() {
  const label = DOM.newAccountLabel.value.trim();
  const method = DOM.newAccountAuthMethod.value;
  const token = DOM.newAccountToken.value.trim();
  const globalKey = DOM.newAccountGlobalKey.value.trim();
  const email = DOM.newAccountEmail.value.trim();

  if (!label) {
    alert('Masukkan label nama akun.');
    return;
  }
  if (method === 'token' && !token) {
    alert('Masukkan API Token Cloudflare.');
    return;
  }
  if (method === 'key' && (!globalKey || !email)) {
    alert('Masukkan Global API Key dan Email.');
    return;
  }

  const originalText = DOM.saveNewAccountBtn.innerHTML;
  DOM.saveNewAccountBtn.disabled = true;
  DOM.saveNewAccountBtn.innerHTML = '⏳ Menghubungkan & Memuat Domain...';
  showToast(`Menghubungkan akun '${label}' dan menarik domain dari Cloudflare...`);

  try {
    const res = await fetch('/api/accounts/add', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        label,
        auth_method: method,
        token,
        global_api_key: globalKey,
        email
      })
    });
    const data = await res.json();
    if (data.success) {
      DOM.newAccountLabel.value = '';
      DOM.newAccountToken.value = '';
      DOM.newAccountGlobalKey.value = '';
      DOM.newAccountEmail.value = '';
      showToast(`✅ Akun '${label}' terhubung! ${data.zones_count || 0} domain berhasil dimuat.`);
      await loadStatus();
      await loadDomains();
      renderAccountsTable();
    } else {
      alert('Gagal menambahkan akun: ' + (data.error || 'Terjadi kesalahan'));
    }
  } catch (err) {
    alert('Error: ' + err.message);
  } finally {
    DOM.saveNewAccountBtn.disabled = false;
    DOM.saveNewAccountBtn.innerHTML = originalText;
  }
}

async function syncSingleAccount(label) {
  showToast(`Menarik daftar domain terbaru untuk akun '${label}'...`);
  try {
    const res = await fetch('/api/accounts/sync', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ label })
    });
    const data = await res.json();
    if (data.success) {
      showToast(`✅ Akun '${label}' berhasil disinkronkan (${data.zones_count} domain)!`);
      await loadStatus();
      await loadDomains();
      renderAccountsTable();
    } else {
      alert('Gagal sinkronisasi: ' + (data.error || 'Terjadi kesalahan'));
    }
  } catch (err) {
    alert('Error sync: ' + err.message);
  }
}

async function switchAccount(label) {
  try {
    const res = await fetch('/api/accounts/switch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ label })
    });
    const data = await res.json();
    if (data.success) {
      showToast(`Beralih ke akun '${label}'.`);
      await loadStatus();
      renderAccountsTable();
    }
  } catch (err) {
    alert('Error switch: ' + err.message);
  }
}

async function deleteAccount(label) {
  const ok = confirm(`Apakah Anda yakin ingin memutuskan akun '${label}'?\n\nKredensial akan dibersihkan dari RAM dan config.json.`);
  if (!ok) return;

  try {
    const res = await fetch('/api/accounts/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ label })
    });
    const data = await res.json();
    if (data.success) {
      showToast(`Akun '${label}' telah diputuskan.`);
      await loadStatus();
      renderAccountsTable();
      loadDomains();
    }
  } catch (err) {
    alert('Error: ' + err.message);
  }
}

// --- UTILITIES & MODAL HELPERS ---

function closeModal(modalId) {
  const m = document.getElementById(modalId);
  if (m) m.style.display = 'none';
}

function showToast(message, isError = false) {
  const toast = document.createElement('div');
  toast.className = `toast ${isError ? 'toast-error' : 'toast-success'}`;
  toast.innerHTML = `<span>${isError ? '✕' : '✓'}</span><span>${message}</span>`;
  DOM.toastContainer.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    toast.style.transition = 'all 0.2s ease';
    setTimeout(() => toast.remove(), 200);
  }, 4000);
}

