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

// Security Sanitizer (XSS Protection)
function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

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
  searchTargetInput: document.getElementById('searchTargetInput'),
  clearTargetSearchBtn: document.getElementById('clearTargetSearchBtn'),
  targetSearchBanner: document.getElementById('targetSearchBanner'),
  targetSearchQueryText: document.getElementById('targetSearchQueryText'),
  targetSearchCount: document.getElementById('targetSearchCount'),
  resetTargetFilterBtn: document.getElementById('resetTargetFilterBtn'),
  openTargetExplorerBtn: document.getElementById('openTargetExplorerBtn'),
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

  targetExplorerModal: document.getElementById('targetExplorerModal'),
  targetExplorerSearchInput: document.getElementById('targetExplorerSearchInput'),
  targetExplorerTableBody: document.getElementById('targetExplorerTableBody'),
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
  DOM.searchTargetInput.addEventListener('input', () => {
    currentPage = 1;
    filterAndRender();
  });
  DOM.clearTargetSearchBtn.addEventListener('click', () => {
    DOM.searchTargetInput.value = '';
    currentPage = 1;
    filterAndRender();
  });
  DOM.resetTargetFilterBtn.addEventListener('click', () => {
    DOM.searchTargetInput.value = '';
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
  DOM.openTargetExplorerBtn.addEventListener('click', openTargetExplorerModal);
  DOM.targetExplorerSearchInput.addEventListener('input', renderTargetExplorerTable);
  DOM.checkLiveBtn.addEventListener('click', () => startLiveRedirectCheck());
  DOM.cancelCheckBtn.addEventListener('click', () => cancelLiveRedirectCheck(false));
  DOM.openBulkBtn.addEventListener('click', openBulkModal);
  DOM.executeBulkBtn.addEventListener('click', executeBulkRedirect);
  DOM.deleteSelectedBtn.addEventListener('click', deleteSelectedRedirects);
  DOM.cleanCacheBtn.addEventListener('click', cleanStaleCache);
  DOM.refreshCfBtn.addEventListener('click', refreshFromCloudflare);

  // Single Modal Actions
  DOM.saveSingleRedirectBtn.addEventListener('click', () => saveSingleRedirect(false));
  DOM.deleteSingleRedirectBtn.addEventListener('click', () => saveSingleRedirect(true));
  DOM.singleTargetInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      saveSingleRedirect(false);
    }
  });

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

    if (accountsList.length > 0) {
      DOM.activeAccountText.textContent = `${accountsList.length} Akun Siaga (Global)`;
      DOM.activeAccountBadge.classList.add('connected');
    } else {
      DOM.activeAccountText.textContent = 'Belum Ada Akun';
      DOM.activeAccountBadge.classList.remove('connected');
    }

    DOM.kpiAccountsCount.textContent = accountsList.length;

    // Refresh Account Filter Dropdown
    const currentVal = DOM.accountFilter.value;
    DOM.accountFilter.innerHTML = '<option value="all">Semua Akun</option>';
    accountsList.forEach(acc => {
      const opt = document.createElement('option');
      opt.value = acc.label;
      opt.textContent = `${acc.label} (${(acc.domain_count || 0).toLocaleString()} Domain)`;
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

// --- TARGET MATCHING & EXTRACTION HELPERS ---

function extractCleanHost(urlOrDomain) {
  if (!urlOrDomain) return '';
  let str = String(urlOrDomain).trim().toLowerCase();
  if (str.startsWith('https://')) str = str.slice(8);
  else if (str.startsWith('http://')) str = str.slice(7);
  if (str.startsWith('www.')) str = str.slice(4);
  return str.split('/')[0].split('?')[0].split(':')[0].trim();
}

function matchesTargetDestination(destUrl, targetQuery) {
  if (!destUrl || !targetQuery) return false;
  const destStr = String(destUrl).trim().toLowerCase();
  const queryStr = String(targetQuery).trim().toLowerCase();

  // 1. Exact string match
  if (destStr === queryStr) return true;

  const cleanQueryHost = extractCleanHost(queryStr);
  const isDomainQuery = cleanQueryHost.includes('.');

  // Check if query has a specific path (e.g. "nagawin.com/m/referral" or "/m/referral")
  let queryPath = '';
  const rawNoProto = queryStr.replace(/^https?:\/\//i, '');
  if (rawNoProto.includes('/')) {
    const parts = rawNoProto.split('/');
    if (parts.length > 1 && parts.slice(1).join('/').trim()) {
      queryPath = '/' + parts.slice(1).join('/').trim().replace(/\/+$/, '');
    }
  }

  const destHost = extractCleanHost(destStr);

  if (isDomainQuery) {
    // Strict host matching: exact hostname OR valid subdomain
    // Contoh: "nagawin.com" HANYA cocok dengan "nagawin.com" & "sub.nagawin.com",
    // TIDAK AKAN cocok dengan "agen9nagawin.com" atau "nagawin.com.co"!
    const hostMatches = (destHost === cleanQueryHost) || destHost.endsWith('.' + cleanQueryHost);
    if (!hostMatches) return false;

    if (queryPath) {
      return destStr.includes(queryPath);
    }
    return true;
  } else {
    // Non-domain query (misal kata kunci "veldtrip", "referral", "/promo")
    return destStr.includes(queryStr) || (cleanQueryHost && destHost.includes(cleanQueryHost));
  }
}

// --- FILTER & PAGINATION ENGINE ---

function filterAndRender() {
  const query = DOM.searchInput.value.trim().toLowerCase();
  const targetQuery = (DOM.searchTargetInput ? DOM.searchTargetInput.value.trim().toLowerCase() : '');
  const selectedAccount = DOM.accountFilter.value.toLowerCase();
  const selectedStatus = DOM.statusFilter.value.toLowerCase();
  const selectedRedirect = DOM.redirectFilter.value;

  let cleanQuery = '';
  let apexQuery = '';
  if (query) {
    cleanQuery = query.replace(/^https?:\/\//i, '').replace(/^\/\//, '').split('/')[0].split('?')[0].split('#')[0].split(':')[0].trim();
    apexQuery = cleanQuery.startsWith('www.') ? cleanQuery.slice(4) : cleanQuery;
  }

  filteredZones = allZones.filter(z => {
    // 1. Source domain match (auto-resolves www, subdomains, full URLs, and partial queries)
    if (query) {
      const zName = z.name.toLowerCase();
      const matchRaw = zName.includes(query);
      const matchClean = cleanQuery && zName.includes(cleanQuery);
      const matchApex = apexQuery && (zName === apexQuery || zName.includes(apexQuery));
      const matchSubdomain = cleanQuery && cleanQuery.endsWith('.' + zName);
      if (!matchRaw && !matchClean && !matchApex && !matchSubdomain) {
        return false;
      }
    }

    // 2. Destination / Target URL match (Reverse redirect search)
    if (targetQuery) {
      const candidates = [];

      // A. Cloudflare rule target
      const cfTarget = targetsMap[z.id];
      if (cfTarget && typeof cfTarget === 'string' && cfTarget.trim()) {
        candidates.push(cfTarget.trim());
      }

      // B. Live HTTP redirect target (HANYA jika domain benar-benar memiliki redirect!)
      const chk = redirectChecksMap[z.name.toLowerCase()];
      if (chk) {
        const isLiveRedirect = Boolean(
          chk.has_redirect ||
          (chk.hops && chk.hops > 0) ||
          (chk.target_url && chk.target_url.trim()) ||
          [301, 302, 303, 307, 308].includes(chk.status_code)
        );

        if (isLiveRedirect) {
          if (chk.target_url && typeof chk.target_url === 'string' && chk.target_url.trim()) {
            candidates.push(chk.target_url.trim());
          }
          if (chk.final_url && typeof chk.final_url === 'string' && chk.final_url.trim()) {
            candidates.push(chk.final_url.trim());
          }
          if (Array.isArray(chk.chain)) {
            chk.chain.forEach(c => {
              if (c && typeof c === 'string' && c.trim()) {
                candidates.push(c.trim());
              }
            });
          }
        }
      }

      // Domain tanpa aturan Cloudflare dan tanpa redirect (misal: 200 OK Tanpa Redirect)
      // TIDAK memiliki target tujuan apa pun!
      if (candidates.length === 0) {
        return false;
      }

      const isMatch = candidates.some(cand => matchesTargetDestination(cand, targetQuery));
      if (!isMatch) return false;
    }

    // 3. Account match
    if (selectedAccount !== 'all' && (z.account_label || '').toLowerCase() !== selectedAccount) {
      return false;
    }
    // 4. Status CF match
    if (selectedStatus !== 'all' && (z.status || '').toLowerCase() !== selectedStatus) {
      return false;
    }
    // 5. Redirect Status match
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

  // Update Target Search Banner
  if (DOM.targetSearchBanner) {
    if (targetQuery) {
      DOM.targetSearchBanner.style.display = 'flex';
      DOM.targetSearchQueryText.textContent = targetQuery;
      DOM.targetSearchCount.textContent = filteredZones.length.toLocaleString();
      if (DOM.clearTargetSearchBtn) DOM.clearTargetSearchBtn.style.display = 'block';
    } else {
      DOM.targetSearchBanner.style.display = 'none';
      if (DOM.clearTargetSearchBtn) DOM.clearTargetSearchBtn.style.display = 'none';
    }
  }

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

      const nawalaBadge = chkData.bypassed_nawala ? ' <span class="badge-tag-nawala" title="Bypass Nawala/Internet Positif via DoH">DoH Bypass</span>' : '';
      if (isMult) {
        const pill = document.createElement('span');
        pill.className = 'pill pill-warning clickable-target-badge';
        pill.innerHTML = `[${escapeHtml(code)} · ${escapeHtml(hops)} hops] ${escapeHtml(target)}${nawalaBadge}`;
        pill.title = `Terdeteksi ${hops}x Pengalihan. Rantai: ${chkData.chain ? chkData.chain.join(' → ') : target}${chkData.bypassed_nawala ? ' (Bypass Nawala/ISP)' : ''}\n\nKlik untuk memfilter semua domain yang mengarah ke target ini`;
        pill.addEventListener('click', (e) => {
          e.stopPropagation();
          filterByTargetDestination(target);
        });
        tdTarget.appendChild(pill);
      } else if (hops === 1) {
        const pill = document.createElement('span');
        pill.className = 'pill pill-success clickable-target-badge';
        pill.innerHTML = `[${escapeHtml(code || 301)}] ${escapeHtml(target)}${nawalaBadge}`;
        pill.title = `Normal 1x Redirect: ${target}${chkData.bypassed_nawala ? ' (Bypass Nawala/ISP)' : ''}\n\nKlik untuk memfilter semua domain yang mengarah ke target ini`;
        pill.addEventListener('click', (e) => {
          e.stopPropagation();
          filterByTargetDestination(target);
        });
        tdTarget.appendChild(pill);
      } else if (chkData.error) {
        const pill = document.createElement('span');
        pill.className = 'pill pill-danger';
        pill.textContent = `Error: ${chkData.error}`;
        tdTarget.appendChild(pill);
      } else {
        const pill = document.createElement('span');
        pill.className = 'pill pill-neutral';
        pill.innerHTML = `${escapeHtml(code || 200)} OK (Tanpa Redirect)${nawalaBadge}`;
        tdTarget.appendChild(pill);
      }
    } else {
      const curTarget = targetsMap[z.id];
      if (curTarget) {
        const pill = document.createElement('span');
        pill.className = 'pill pill-neutral clickable-target-badge';
        pill.style.color = 'var(--accent-blue)';
        pill.textContent = `[CF Rule] ${curTarget}`;
        pill.title = 'Target dari aturan Cloudflare\n\nKlik untuk memfilter semua domain yang mengarah ke target ini';
        pill.addEventListener('click', (e) => {
          e.stopPropagation();
          filterByTargetDestination(curTarget);
        });
        tdTarget.appendChild(pill);
      } else {
        tdTarget.innerHTML = '<span style="color: var(--text-subtle);">-</span>';
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
    redirectBtn.className = 'btn btn-secondary btn-icon';
    redirectBtn.style.fontSize = '12px';
    redirectBtn.style.padding = '4px 10px';
    redirectBtn.textContent = 'Redirect';
    redirectBtn.title = 'Ubah aturan redirect domain ini';
    redirectBtn.addEventListener('click', () => openSingleModal(z));
    actionWrap.appendChild(redirectBtn);

    const checkBtn = document.createElement('button');
    checkBtn.className = 'btn btn-secondary btn-icon';
    checkBtn.style.padding = '4px 8px';
    checkBtn.title = 'Uji live redirect domain ini sekarang';
    checkBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="13" height="13"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>';
    checkBtn.addEventListener('click', () => checkSingleDomain(z));
    actionWrap.appendChild(checkBtn);

    const delBtn = document.createElement('button');
    delBtn.className = 'btn btn-danger btn-icon';
    delBtn.style.padding = '4px 8px';
    delBtn.title = 'Hapus semua aturan redirect domain ini';
    delBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="13" height="13"><path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/></svg>';
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
  DOM.quickTraceOutput.innerHTML = '<span style="color: var(--text-muted);">Menghubungi server &amp; DNS DoH...</span>';

  try {
    const res = await fetch('/api/redirect/trace-single', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain: raw })
    });
    const data = await res.json();
    redirectChecksMap[raw.toLowerCase()] = data;

    const nwBadge = data.bypassed_nawala ? ' (Bypass Nawala via DoH)' : '';
    if (data.is_multiple || data.hops > 1) {
      DOM.quickTraceOutput.innerHTML = `<span class="pill pill-warning">[${escapeHtml(data.status_code || 301)} · ${escapeHtml(data.hops)} hops] ${escapeHtml(data.target_url)}${data.bypassed_nawala ? ' (DoH)' : ''}</span>`;
      showToast(`Domain '${raw}' terdeteksi ${data.hops}x Redirects!${nwBadge}`, true);
    } else if (data.hops === 1) {
      DOM.quickTraceOutput.innerHTML = `<span class="pill pill-success">[${escapeHtml(data.status_code || 301)}] ${escapeHtml(data.target_url)}${data.bypassed_nawala ? ' (DoH)' : ''}</span>`;
      showToast(`Domain '${raw}' normal 1x redirect ke ${data.target_url}${nwBadge}`);
    } else if (data.error) {
      DOM.quickTraceOutput.innerHTML = `<span class="pill pill-danger">Error: ${escapeHtml(data.error)}</span>`;
      showToast(`Gagal memeriksa '${raw}': ${data.error}`, true);
    } else {
      DOM.quickTraceOutput.innerHTML = `<span class="pill pill-neutral">200 OK (Tanpa Redirect)${data.bypassed_nawala ? ' (DoH)' : ''}</span>`;
      showToast(`Domain '${raw}' aktif tanpa redirect.${nwBadge}`);
    }

    updateKpis();
    filterAndRender();
  } catch (err) {
    DOM.quickTraceOutput.innerHTML = `<span class="pill pill-danger">Error: ${escapeHtml(err.message)}</span>`;
    showToast('Gagal memeriksa domain: ' + err.message, true);
  } finally {
    DOM.quickTraceBtn.disabled = false;
  }
}

async function checkSingleDomain(zone, isSilent = false) {
  if (!isSilent) {
    showToast(`Memeriksa live redirect '${zone.name}'...`);
  }
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

    if (!isSilent) {
      if (data.is_multiple || data.hops > 1) {
        showToast(`⚠️ '${zone.name}' terdeteksi ${data.hops}x Redirects!`, true);
      } else if (data.hops === 1) {
        showToast(`✅ '${zone.name}' normal 1x redirect (${data.status_code}) ke ${data.target_url}`);
      } else if (data.error) {
        showToast(`✕ '${zone.name}': ${data.error}`, true);
      } else {
        showToast(`○ '${zone.name}': 200 OK (Tanpa Redirect)`);
      }
    }
  } catch (err) {
    if (!isSilent) {
      showToast(`Gagal memeriksa '${zone.name}': ` + err.message, true);
    }
  }
}

// --- CONCURRENT BATCH LIVE REDIRECT CHECKER ---

async function startLiveRedirectCheck(customDomains = null, isAuto = false) {
  if (activeScanTaskId) {
    if (isAuto) {
      cancelLiveRedirectCheck(true);
    } else {
      showToast('Pengecekan live redirect sedang berlangsung.', true);
      return;
    }
  }

  // Use customDomains if provided, else selected domains if any, else use all filtered
  let targetDomains = [];
  if (Array.isArray(customDomains) && customDomains.length > 0) {
    targetDomains = customDomains;
  } else if (selectedZoneIds.size > 0) {
    targetDomains = allZones.filter(z => selectedZoneIds.has(z.id)).map(z => z.name);
  } else {
    targetDomains = filteredZones.map(z => z.name);
  }

  if (targetDomains.length === 0) {
    if (!isAuto) showToast('Tidak ada domain yang dapat diperiksa.', true);
    return;
  }

  if (!isAuto && targetDomains.length > 50) {
    const ok = confirm(`Mulai pengecekan live redirect untuk ${targetDomains.length} domain?\n\nPengecekan berjalan otomatis di background secara multi-threaded (cepat dan tidak membuat lag).`);
    if (!ok) return;
  }

  DOM.checkLiveBtn.disabled = true;
  DOM.progressCard.style.display = 'flex';
  DOM.progressBarFill.style.width = '0%';
  DOM.progressTitle.textContent = isAuto
    ? `Mengecek otomatis live redirect ${targetDomains.length} domain yang baru dialihkan...`
    : `Memulai pengecekan ${targetDomains.length} domain...`;

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
      scanPollInterval = null;
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
      if (current % 5 === 0 || current === total) {
        updateKpis();
        renderCurrentPage();
      }
    }

    if (task.status === 'completed' || task.status === 'error') {
      clearInterval(scanPollInterval);
      scanPollInterval = null;
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

function cancelLiveRedirectCheck(isSilent = false) {
  if (activeScanTaskId) {
    fetch('/api/redirect/check-live/cancel', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ task_id: activeScanTaskId })
    }).catch(() => {});
  }
  if (scanPollInterval) {
    clearInterval(scanPollInterval);
    scanPollInterval = null;
  }
  activeScanTaskId = null;
  DOM.progressCard.style.display = 'none';
  DOM.checkLiveBtn.disabled = false;
  if (!isSilent) {
    showToast('Pengecekan live redirect dihentikan.');
  }
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

// --- DOMAIN RESOLUTION HELPERS (Apex & Subdomain Auto-Resolution) ---

function extractDomainComponents(raw) {
  if (!raw) return { raw: '', clean: '', apex: '' };
  let clean = raw.trim()
    .replace(/^https?:\/\//i, '')
    .replace(/^\/\//, '')
    .split('/')[0]
    .split('?')[0]
    .split('#')[0]
    .split(':')[0]
    .toLowerCase();

  let apex = clean;
  if (apex.startsWith('www.')) {
    apex = apex.slice(4);
  }
  return { raw, clean, apex };
}

function findMatchingZoneInState(rawDomain) {
  const { clean, apex } = extractDomainComponents(rawDomain);
  if (!clean) return null;

  // 1. Direct exact match with clean (e.g. sub.domain.com or domain.com)
  let zone = allZones.find(z => z.name.toLowerCase() === clean);
  if (zone) return { zone, matchType: 'exact', rootName: zone.name.toLowerCase() };

  // 2. Match without 'www.' (e.g. www.domain.com -> domain.com)
  if (apex && apex !== clean) {
    zone = allZones.find(z => z.name.toLowerCase() === apex);
    if (zone) return { zone, matchType: 'www', rootName: zone.name.toLowerCase() };
  }

  // 3. Subdomain matching: match parent/apex zone (e.g. sub.foundryprojectharrogate.co.uk -> foundryprojectharrogate.co.uk)
  let bestMatch = null;
  let longestLen = 0;
  for (const z of allZones) {
    const zName = z.name.toLowerCase();
    if (clean === zName || clean.endsWith('.' + zName)) {
      if (zName.length > longestLen) {
        longestLen = zName.length;
        bestMatch = z;
      }
    }
  }

  if (bestMatch) {
    return { zone: bestMatch, matchType: 'subdomain', rootName: bestMatch.name.toLowerCase() };
  }

  return null;
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
    const { clean } = extractDomainComponents(raw);
    if (!clean) return;

    const matchResult = findMatchingZoneInState(clean);

    if (matchResult && matchResult.zone) {
      const zone = matchResult.zone;
      if (!zone.is_connected) {
        unconnectedDomains.push(`${clean} (${zone.account_label})`);
      } else {
        // If input is www.<root> or <root>, use apex zone name so Cloudflare rule covers apex + www.
        // If input is a dedicated subdomain (e.g. blog.domain.com), target that specific hostname.
        const sourceHost = (clean === 'www.' + zone.name.toLowerCase() || clean === zone.name.toLowerCase())
          ? zone.name.toLowerCase()
          : clean;

        items.push({
          zone_id: zone.id,
          source: sourceHost,
          target: targetUrl,
          account_id: zone.account_id,
          account_label: zone.account_label
        });
      }
    } else {
      unconnectedDomains.push(`${clean} (Zona tidak ditemukan)`);
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
      showToast(`Bulk Redirect: ${data.success} berhasil diterapkan.`);

      // Optimistically update targetsMap and redirectChecksMap for applied domains
      const appliedDomains = [];
      items.forEach(item => {
        if (item.zone_id && item.source) {
          const finalTarget = item.target;
          targetsMap[item.zone_id] = finalTarget;

          redirectChecksMap[item.source.toLowerCase()] = {
            domain: item.source,
            status_code: 301,
            target_url: finalTarget,
            hops: 1,
            has_redirect: true,
            is_multiple: false,
            chain: [finalTarget],
            bypassed_nawala: false
          };

          const matchedZone = allZones.find(z => z.id === item.zone_id);
          if (matchedZone && matchedZone.name.toLowerCase() !== item.source.toLowerCase()) {
            redirectChecksMap[matchedZone.name.toLowerCase()] = {
              domain: matchedZone.name,
              status_code: 301,
              target_url: finalTarget,
              hops: 1,
              has_redirect: true,
              is_multiple: false,
              chain: [finalTarget],
              bypassed_nawala: false
            };
            appliedDomains.push(matchedZone.name);
          }
          appliedDomains.push(item.source);
        }
      });

      updateKpis();
      filterAndRender();

      // Otomatis verifikasi live redirect tanpa perlu klik tombol "Cek Live Redirect"
      const uniqueApplied = Array.from(new Set(appliedDomains));
      if (uniqueApplied.length > 0) {
        showToast(`Mengecek otomatis live redirect untuk ${uniqueApplied.length} domain...`);
        setTimeout(() => {
          startLiveRedirectCheck(uniqueApplied, true);
        }, 1000);
      }
    } else {
      alert('Gagal mengeksekusi: ' + (data.error || 'Unknown error'));
    }
  } catch (err) {
    alert('Error saat mengirim request: ' + err.message);
  } finally {
    DOM.executeBulkBtn.disabled = false;
    DOM.executeBulkBtn.textContent = 'Terapkan Redirect Massal';
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
  DOM.singleModalAccountInfo.textContent = `Akun Pemilik: ${zone.account_label} (Terhubung)`;
  DOM.singleModal.style.display = 'flex';
}

async function saveSingleRedirect(isDelete = false) {
  // Pastikan isDelete strictly boolean (cegah PointerEvent / MouseEvent terkirim sebagai truthy)
  const deleteMode = (isDelete === true);
  const zoneId = DOM.singleModalZoneId.value;
  const source = DOM.singleModalDomain.textContent;
  const target = DOM.singleTargetInput.value.trim();
  const accountId = DOM.singleModalAccountId.value;

  if (!deleteMode && !target) {
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
        delete: deleteMode
      })
    });
    const data = await res.json();

    if (data.success) {
      closeModal('singleModal');
      const currentZone = allZones.find(z => z.id === zoneId) || { id: zoneId, name: source };
      if (deleteMode) {
        delete targetsMap[zoneId];
        redirectChecksMap[source.toLowerCase()] = {
          domain: source,
          status_code: 200,
          target_url: '',
          hops: 0,
          has_redirect: false,
          is_multiple: false,
          chain: [],
          bypassed_nawala: false
        };
        showToast(`Aturan redirect untuk '${source}' berhasil dihapus.`);
        updateKpis();
        filterAndRender();
        setTimeout(() => checkSingleDomain(currentZone, true), 800);
      } else {
        targetsMap[zoneId] = data.target;
        redirectChecksMap[source.toLowerCase()] = {
          domain: source,
          status_code: 301,
          target_url: data.target,
          hops: 1,
          has_redirect: true,
          is_multiple: false,
          chain: [data.target],
          bypassed_nawala: false
        };
        showToast(`301 Redirect berhasil dipasang ke ${data.target}`);
        updateKpis();
        filterAndRender();
        setTimeout(() => checkSingleDomain(currentZone, false), 1000);
      }
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

    const deletedDomains = [];
    selectedZones.forEach(z => {
      delete targetsMap[z.id];
      redirectChecksMap[z.name.toLowerCase()] = {
        domain: z.name,
        status_code: 200,
        target_url: '',
        hops: 0,
        has_redirect: false,
        is_multiple: false,
        chain: [],
        bypassed_nawala: false
      };
      deletedDomains.push(z.name);
    });
    selectedZoneIds.clear();
    showToast(`Selesai! Total ${data.deleted_rules || 0} aturan redirect berhasil dibersihkan.`);
    updateKpis();
    filterAndRender();

    if (deletedDomains.length > 0) {
      setTimeout(() => {
        startLiveRedirectCheck(deletedDomains, true);
      }, 1000);
    }
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
      redirectChecksMap[zone.name.toLowerCase()] = {
        domain: zone.name,
        status_code: 200,
        target_url: '',
        hops: 0,
        has_redirect: false,
        is_multiple: false,
        chain: [],
        bypassed_nawala: false
      };
      showToast(`Aturan redirect untuk '${zone.name}' berhasil dibersihkan.`);
      updateKpis();
      filterAndRender();
      setTimeout(() => checkSingleDomain(zone, true), 800);
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

    const tdLabel = document.createElement('td');
    tdLabel.style.fontWeight = '600';
    tdLabel.textContent = acc.label;

    const tdStatus = document.createElement('td');
    tdStatus.innerHTML = '<span class="pill pill-success" style="font-size: 11px;">Terhubung</span>';

    const tdCount = document.createElement('td');
    tdCount.className = 'tabular-nums';
    tdCount.textContent = `${(acc.domain_count || 0).toLocaleString()} domain`;

    const tdActions = document.createElement('td');
    tdActions.style.textAlign = 'right';
    tdActions.style.display = 'flex';
    tdActions.style.gap = '6px';
    tdActions.style.justifyContent = 'flex-end';

    const syncBtn = document.createElement('button');
    syncBtn.className = 'btn btn-secondary btn-icon';
    syncBtn.style.padding = '3px 8px';
    syncBtn.style.fontSize = '11.5px';
    syncBtn.title = 'Tarik ulang domain untuk akun ini';
    syncBtn.textContent = 'Sync';
    syncBtn.addEventListener('click', () => syncSingleAccount(acc.label));

    const delBtn = document.createElement('button');
    delBtn.className = 'btn btn-danger btn-icon';
    delBtn.style.padding = '3px 8px';
    delBtn.style.fontSize = '11.5px';
    delBtn.title = 'Putuskan akun ini';
    delBtn.textContent = 'Putuskan';
    delBtn.addEventListener('click', () => deleteAccount(acc.label));

    tdActions.appendChild(syncBtn);
    tdActions.appendChild(delBtn);

    tr.appendChild(tdLabel);
    tr.appendChild(tdStatus);
    tr.appendChild(tdCount);
    tr.appendChild(tdActions);

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
      showToast(`Akun '${label}' terhubung! ${data.zones_count || 0} domain berhasil dimuat.`);
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
      showToast(`Akun '${label}' berhasil disinkronkan (${data.zones_count} domain).`);
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
  toast.innerHTML = `<span style="font-weight: 600;">${isError ? 'Error' : 'Info'}:</span> <span>${escapeHtml(message)}</span>`;
  DOM.toastContainer.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    toast.style.transition = 'opacity 0.2s ease, transform 0.2s ease';
    setTimeout(() => toast.remove(), 200);
  }, 4000);
}

// --- TARGET DESTINATIONS DIRECTORY & REVERSE LOOKUP ---

function filterByTargetDestination(rawUrl) {
  if (!rawUrl) return;
  const host = extractCleanHost(rawUrl);
  if (!host) return;
  if (DOM.searchTargetInput) {
    DOM.searchTargetInput.value = host;
  }
  currentPage = 1;
  filterAndRender();
  showToast(`Memfilter domain yang mengarah ke '${host}'`);
}

function openTargetExplorerModal() {
  if (DOM.targetExplorerSearchInput) DOM.targetExplorerSearchInput.value = '';
  renderTargetExplorerTable();
  DOM.targetExplorerModal.style.display = 'flex';
}

function renderTargetExplorerTable() {
  const query = (DOM.targetExplorerSearchInput ? DOM.targetExplorerSearchInput.value : '').trim().toLowerCase();
  const targetMapCount = {};

  allZones.forEach(z => {
    const chk = redirectChecksMap[z.name.toLowerCase()];
    const isLive = chk && Boolean(
      chk.has_redirect ||
      (chk.hops && chk.hops > 0) ||
      (chk.target_url && chk.target_url.trim()) ||
      [301, 302, 303, 307, 308].includes(chk.status_code)
    );

    const rawTarget = isLive
      ? (chk.final_url || chk.target_url)
      : (targetsMap[z.id] || '');

    if (rawTarget && rawTarget.trim()) {
      const host = extractCleanHost(rawTarget);
      if (host) {
        if (!targetMapCount[host]) {
          targetMapCount[host] = { host: host, sampleUrl: rawTarget.trim(), count: 0 };
        }
        targetMapCount[host].count++;
      }
    }
  });

  let sortedTargets = Object.values(targetMapCount).sort((a, b) => b.count - a.count);
  if (query) {
    sortedTargets = sortedTargets.filter(item => matchesTargetDestination(item.sampleUrl, query) || item.host.includes(query));
  }

  DOM.targetExplorerTableBody.innerHTML = '';
  if (sortedTargets.length === 0) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td colspan="4" style="text-align: center; color: var(--text-muted); padding: 24px;">Tidak ada domain target tujuan yang ditemukan.</td>`;
    DOM.targetExplorerTableBody.appendChild(tr);
    return;
  }

  sortedTargets.forEach((item, idx) => {
    const tr = document.createElement('tr');

    const tdIdx = document.createElement('td');
    tdIdx.style.color = 'var(--text-muted)';
    tdIdx.textContent = idx + 1;

    const tdTarget = document.createElement('td');
    const spanHost = document.createElement('span');
    spanHost.style.fontWeight = '600';
    spanHost.style.color = '#ffffff';
    spanHost.style.fontSize = '13px';
    spanHost.style.fontFamily = 'var(--font-mono)';
    spanHost.textContent = item.host;

    const spanSample = document.createElement('span');
    spanSample.style.display = 'block';
    spanSample.style.fontSize = '11.5px';
    spanSample.style.color = 'var(--text-subtle)';
    spanSample.style.marginTop = '2px';
    spanSample.style.fontFamily = 'var(--font-mono)';
    spanSample.textContent = item.sampleUrl;

    tdTarget.appendChild(spanHost);
    tdTarget.appendChild(spanSample);

    const tdCount = document.createElement('td');
    tdCount.style.textAlign = 'center';
    const pillCount = document.createElement('span');
    pillCount.className = 'pill pill-success';
    pillCount.style.fontSize = '11.5px';
    pillCount.style.fontWeight = '500';
    pillCount.textContent = `${item.count.toLocaleString()} domain`;
    tdCount.appendChild(pillCount);

    const tdAction = document.createElement('td');
    tdAction.style.textAlign = 'right';
    const filterBtn = document.createElement('button');
    filterBtn.className = 'btn btn-secondary btn-icon';
    filterBtn.style.padding = '4px 10px';
    filterBtn.style.fontSize = '11.5px';
    filterBtn.textContent = 'Filter';
    filterBtn.addEventListener('click', () => selectTargetFromExplorer(item.host));
    tdAction.appendChild(filterBtn);

    tr.appendChild(tdIdx);
    tr.appendChild(tdTarget);
    tr.appendChild(tdCount);
    tr.appendChild(tdAction);

    DOM.targetExplorerTableBody.appendChild(tr);
  });
}

function selectTargetFromExplorer(host) {
  closeModal('targetExplorerModal');
  if (DOM.searchTargetInput) {
    DOM.searchTargetInput.value = host;
  }
  currentPage = 1;
  filterAndRender();
  showToast(`Menampilkan domain yang mengarah ke '${host}'`);
}

window.selectTargetFromExplorer = selectTargetFromExplorer;
window.filterByTargetDestination = filterByTargetDestination;
window.openTargetExplorerModal = openTargetExplorerModal;

