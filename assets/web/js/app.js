// ====== iptables-web 应用主控 ======

const AppState = {
  page: 'dashboard',
  theme: typeof localStorage !== 'undefined' ? (localStorage.getItem('iptables-web-theme') || 'light') : 'light',
  themes: [
    { id: 'light', icon: '☀️', label: '默认白色' },
    { id: 'dark', icon: '🌙', label: '深色' },
    { id: 'blue', icon: '🔷', label: '蓝色' },
    { id: 'green', icon: '🟢', label: '绿色' },
    { id: 'gray', icon: '⚙', label: '灰色' }
  ],
  chains: [],
  systemInfo: null,
  username: typeof sessionStorage !== 'undefined' ? (sessionStorage.getItem('auth_username') || '') : '',
  role: typeof sessionStorage !== 'undefined' ? (sessionStorage.getItem('auth_role') || '') : '',

  async init() {
    this.theme = localStorage.getItem('iptables-web-theme') || 'light';
    this.applyTheme();
    this.username = sessionStorage.getItem('auth_username') || '';
    this.role = sessionStorage.getItem('auth_role') || '';

    // Check auth by trying to access a protected endpoint
    var needLogin = false;
    try {
      await api.listRules();
    } catch (e) {
      if (e.status === 401) {
        needLogin = true;
      }
    }

    if (needLogin) {
      window.location.href = '/login.html';
      return;
    }

	this.page = pageFromHash(window.location.hash);
    this.updateUserDisplay();
	try { this.systemInfo = await api.getSystemInfo(); } catch (e) { /* status is optional */ }
    this.navigate(this.page);
  },

  navigate(page) {
	page = normalizePage(page);
    this.page = page;
	if (window.location.hash !== '#' + page) {
	  history.replaceState(null, '', '#' + page);
	}
    document.querySelectorAll('.sidebar-nav a').forEach(a => {
      a.classList.toggle('active', a.dataset.page === page);
    });
    document.querySelectorAll('.page-section').forEach(s => {
      s.classList.toggle('active', s.dataset.page === page);
    });
	const sidebar = document.querySelector('.sidebar');
	if (sidebar && window.innerWidth <= 768) {
	  sidebar.classList.remove('open');
	  this.updateMobileMenu(false);
	}
    if (page === 'rules' && typeof RulesList !== 'undefined') RulesList.refresh();
    if (page === 'chains' && typeof ChainsView !== 'undefined') ChainsView.refresh();
    if (page === 'docker' && typeof DockerPorts !== 'undefined') DockerPorts.refresh();
    if (page === 'assistant' && typeof RuleAssistant !== 'undefined') RuleAssistant.render();
    if (page === 'system' && typeof SystemView !== 'undefined') SystemView.refresh();
  },

	toggleSidebar() {
	  const sidebar = document.querySelector('.sidebar');
	  if (!sidebar) return;
	  const open = sidebar.classList.toggle('open');
	  this.updateMobileMenu(open);
	},

	updateMobileMenu(open) {
	  const button = document.getElementById('mobile-menu-toggle');
	  if (!button) return;
	  button.textContent = open ? '✕' : '☰';
	  button.setAttribute('aria-label', open ? '关闭导航菜单' : '打开导航菜单');
	},

  setTheme(theme) {
    if (!this.themes.some(t => t.id === theme)) {
      theme = 'light';
    }
    this.theme = theme;
    localStorage.setItem('iptables-web-theme', this.theme);
    this.applyTheme();
  },

  toggleTheme() {
    const idx = this.themes.findIndex(t => t.id === this.theme);
    const next = this.themes[(idx + 1) % this.themes.length];
    this.setTheme(next.id);
  },

  applyTheme() {
    document.documentElement.setAttribute('data-theme', this.theme);
    const icon = document.getElementById('theme-icon');
    const label = document.getElementById('theme-label');
    const select = document.getElementById('theme-select');
    const current = this.themes.find(t => t.id === this.theme) || this.themes[0];
    if (icon) icon.textContent = current.icon;
    if (label) label.textContent = current.label;
    if (select) select.value = current.id;
  },

  updateUserDisplay() {
    const el = document.getElementById('user-info');
    if (el && this.username) {
      el.textContent = this.username;
    }
  },

  canManageRules() {
    return this.role === 'admin' || !getAuthToken();
  },

  async logout() {
    try { await api.logout(); } catch (e) { /* ignore */ }
    sessionStorage.clear();
    window.location.href = '/login.html';
  },

  async refreshSystemInfo() {
    try {
      this.systemInfo = await api.getSystemInfo();
    } catch (e) {
      // silent
    }
  }
};

const APP_PAGES = ['dashboard', 'rules', 'chains', 'docker', 'assistant', 'system'];

function normalizePage(page) {
  return APP_PAGES.includes(page) ? page : 'dashboard';
}

function pageFromHash(hash) {
  return normalizePage(String(hash || '').replace(/^#\/?/, ''));
}

if (typeof document !== 'undefined') {
  document.addEventListener('DOMContentLoaded', () => {
    AppState.init();
    window.App = AppState;
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      const modal = document.getElementById('rule-modal');
      if (modal && !modal.classList.contains('hidden')) {
        modal.classList.add('hidden');
      }
    }
  });
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { normalizePage, pageFromHash };
}
