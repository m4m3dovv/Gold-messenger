const TOKEN_KEY = 'mh_admin_token';
let token = sessionStorage.getItem(TOKEN_KEY);
let page = 0;
const PAGE_SIZE = 20;
let currentSearch = '';

const screens = {
  login: document.getElementById('screen-login'),
  dashboard: document.getElementById('screen-dashboard'),
};
function showScreen(name) {
  for (const k in screens) screens[k].classList.toggle('hidden', k !== name);
}

async function api(path, opts = {}) {
  const res = await fetch(path, {
    ...opts,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(opts.headers || {}),
    },
  });
  if (res.status === 401) {
    logout();
    throw new Error('unauthorized');
  }
  return res.json();
}

function logout() {
  token = null;
  sessionStorage.removeItem(TOKEN_KEY);
  showScreen('login');
}

document.getElementById('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = document.getElementById('login-username').value.trim();
  const password = document.getElementById('login-password').value;
  const errEl = document.getElementById('login-error');
  errEl.classList.add('hidden');

  const res = await fetch('/api/admin/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  const body = await res.json();
  if (res.status !== 200) {
    errEl.textContent = 'Ad və ya parol yanlışdır.';
    errEl.classList.remove('hidden');
    return;
  }
  token = body.token;
  sessionStorage.setItem(TOKEN_KEY, token);
  enterDashboard();
});

document.getElementById('logout-btn').addEventListener('click', logout);

async function enterDashboard() {
  showScreen('dashboard');
  await loadStats();
  await loadUsers();
}

async function loadStats() {
  const s = await api('/api/admin/stats');
  document.getElementById('stat-users').textContent = s.totalUsers ?? '—';
  document.getElementById('stat-messages').textContent = s.totalMessages ?? '—';
  document.getElementById('stat-groups').textContent = s.totalGroups ?? '—';
  document.getElementById('stat-active').textContent = s.activeLast24h ?? '—';
}

async function loadUsers() {
  const params = new URLSearchParams({
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
    search: currentSearch,
  });
  const { users } = await api('/api/admin/users?' + params.toString());
  const tbody = document.getElementById('user-table-body');
  tbody.innerHTML = '';
  for (const u of users) {
    const tr = document.createElement('tr');
    const lastSeen = u.lastSeenAt ? new Date(u.lastSeenAt).toLocaleString('az-AZ') : '—';
    tr.innerHTML = `
      <td>#${String(u.id).padStart(6, '0')}</td>
      <td>${escapeHtml(u.username)}</td>
      <td>${u.keyVersion}</td>
      <td>${lastSeen}</td>
      <td><span class="badge ${u.isBanned ? 'badge--banned' : 'badge--ok'}">${u.isBanned ? 'Bloklanıb' : 'Aktiv'}</span></td>
      <td></td>
    `;
    const actionCell = tr.lastElementChild;
    const btn = document.createElement('button');
    btn.className = 'btn btn--sm ' + (u.isBanned ? 'btn--ghost' : 'btn--danger');
    btn.textContent = u.isBanned ? 'Blokdan çıxar' : 'Blokla';
    btn.addEventListener('click', () => toggleBan(u.id, !u.isBanned));
    actionCell.appendChild(btn);
    tbody.appendChild(tr);
  }
  document.getElementById('page-label').textContent = String(page + 1);
}

async function toggleBan(userId, banned) {
  await api(`/api/admin/users/${userId}/ban`, {
    method: 'POST',
    body: JSON.stringify({ banned }),
  });
  await loadUsers();
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

document.getElementById('search-btn').addEventListener('click', () => {
  currentSearch = document.getElementById('search-input').value.trim();
  page = 0;
  loadUsers();
});
document.getElementById('prev-page').addEventListener('click', () => {
  if (page > 0) { page--; loadUsers(); }
});
document.getElementById('next-page').addEventListener('click', () => {
  page++; loadUsers();
});

if (token) {
  enterDashboard().catch(() => showScreen('login'));
} else {
  showScreen('login');
}
