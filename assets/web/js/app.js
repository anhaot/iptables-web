// ====== iptables-web controller application state ======

const GLOBAL_PAGES = ['fleet', 'assistant', 'hosts', 'users'];
const HOST_PAGES = ['dashboard', 'rules', 'chains', 'docker', 'system'];
const APP_PAGES = GLOBAL_PAGES.concat(HOST_PAGES);
const AGENT_OFFLINE_AFTER_MS = 45000;

const AppState = {
  page: 'fleet',
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
  authDisabled: typeof sessionStorage !== 'undefined' ? sessionStorage.getItem('auth_disabled') === '1' : false,
  hostIDs: [],
  hosts: [],
  hostStatuses: {},
  hostMonitor: null,
  // This is an opened host detail, not a global host switcher. It is kept in
  // session storage only so refreshing a detail page does not lose context.
  selectedHostID: typeof sessionStorage !== 'undefined' ? (sessionStorage.getItem('selected_host_id') || '') : '',
  localMode: typeof sessionStorage !== 'undefined' ? sessionStorage.getItem('local_firewall_mode') === '1' : false,
  hostContextVersion: 0,

  hostScopeKey() {
    if (this.activeLocal()) return 'local';
    return this.selectedHostID ? `host:${this.selectedHostID}` : 'none';
  },

  captureHostContext() {
    return {
      version: this.hostContextVersion,
      key: this.hostScopeKey(),
      hostID: this.activeLocal() ? '' : this.selectedHostID
    };
  },

  isHostContextCurrent(context) {
    return !!context && context.version === this.hostContextVersion && context.key === this.hostScopeKey();
  },

  invalidateRuleSummary(context) {
    if (typeof FleetOverview === 'undefined') return;
    const key = context && context.key ? context.key : this.hostScopeKey();
    const id = key === 'local' ? 'local' : key.startsWith('host:') ? key.slice(5) : '';
    if (id) FleetOverview.invalidateRuleDetails(id);
  },

  async init() {
    this.theme = localStorage.getItem('iptables-web-theme') || 'light';
    this.applyTheme();
    this.username = sessionStorage.getItem('auth_username') || '';
    this.role = sessionStorage.getItem('auth_role') || '';

    let needLogin = false;
    try {
      const session = await api.sessionCheck();
      if (session) {
        this.username = session.username || '';
        this.role = session.role || '';
        this.hostIDs = Array.isArray(session.host_ids) ? session.host_ids.slice() : [];
        this.authDisabled = session.auth_disabled === true;
        sessionStorage.setItem('auth_username', this.username);
        sessionStorage.setItem('auth_role', this.role);
        if (this.authDisabled) sessionStorage.setItem('auth_disabled', '1');
        else sessionStorage.removeItem('auth_disabled');
      }
      if (session && session.requires_password_change) {
        window.location.href = '/change-password.html';
        return;
      }
    } catch (e) {
      if (e.status === 401) needLogin = true;
    }
    if (needLogin) {
      window.location.href = '/login.html';
      return;
    }

    await this.loadHosts();
    const requested = pageFromHash(window.location.hash);
    if (!this.canAccessLocal()) this.localMode = false;
    this.page = HOST_PAGES.includes(requested) && !this.activeHost() && !this.activeLocal() ? 'fleet' : requested;
    this.updateUserDisplay();
    this.renderHostContext();
    this.navigate(this.page);
    this.startHostMonitor();
  },

  navigate(page) {
    page = normalizePage(page);
    if ((page === 'hosts' || page === 'users') && !this.canManageFleet()) page = 'fleet';
    if (HOST_PAGES.includes(page) && !this.activeHost() && !this.activeLocal()) page = 'fleet';
    this.page = page;
    if (window.location.hash !== '#' + page) history.replaceState(null, '', '#' + page);

    document.querySelectorAll('.sidebar-nav a').forEach(a => {
      const active = a.dataset.page === 'local'
        ? this.activeLocal() && HOST_PAGES.includes(page)
        : a.dataset.page === page;
      a.classList.toggle('active', active);
      if (active) a.setAttribute('aria-current', 'page');
      else a.removeAttribute('aria-current');
    });
    document.querySelectorAll('.page-section').forEach(section => {
      section.classList.toggle('active', section.dataset.page === page);
    });
    this.renderHostContext();

    if (page === 'fleet' && typeof FleetOverview !== 'undefined') FleetOverview.refresh();
    if (page === 'rules' && typeof RulesList !== 'undefined') RulesList.refresh();
    if (page === 'chains' && typeof ChainsView !== 'undefined') ChainsView.refresh();
    if (page === 'docker' && typeof DockerPorts !== 'undefined') DockerPorts.refresh();
    if (page === 'assistant' && typeof RuleAssistant !== 'undefined') RuleAssistant.render();
    if (page === 'hosts' && typeof HostManagement !== 'undefined') HostManagement.refresh();
    if ((page === 'users' || page === 'system') && typeof SystemView !== 'undefined') SystemView.refresh();
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
    if (!this.themes.some(item => item.id === theme)) theme = 'light';
    this.theme = theme;
    localStorage.setItem('iptables-web-theme', this.theme);
    this.applyTheme();
  },

  toggleTheme() {
    const idx = this.themes.findIndex(item => item.id === this.theme);
    this.setTheme(this.themes[(idx + 1) % this.themes.length].id);
  },

  applyTheme() {
    document.documentElement.setAttribute('data-theme', this.theme);
    const current = this.themes.find(item => item.id === this.theme) || this.themes[0];
    const icon = document.getElementById('theme-icon');
    const label = document.getElementById('theme-label');
    const select = document.getElementById('theme-select');
    if (icon) icon.textContent = current.icon;
    if (label) label.textContent = current.label;
    if (select) select.value = current.id;
  },

  updateUserDisplay() {
    const element = document.getElementById('user-info');
    if (element && this.username) element.textContent = this.username;
    const localNav = document.getElementById('local-firewall-nav');
    if (localNav) localNav.hidden = !this.canAccessLocal();
    document.querySelectorAll('[data-admin-only]').forEach(element => {
      element.hidden = !this.canManageFleet();
    });
    document.querySelectorAll('[data-auth-required]').forEach(element => {
      element.hidden = this.authDisabled;
    });
    this.renderFleetIndicator();
  },

  async loadHosts() {
    try {
      this.hosts = await api.listHosts();
    } catch (_) {
      if (!Array.isArray(this.hosts)) this.hosts = [];
    }
    if (this.selectedHostID && !this.hosts.some(host => host.id === this.selectedHostID && host.enabled)) {
      this.selectedHostID = '';
      this.hostContextVersion++;
      sessionStorage.removeItem('selected_host_id');
    }
    this.renderFleetIndicator();
    this.renderHostContext();
  },

  activeHost() {
    if (!this.selectedHostID) return null;
    return this.hosts.find(host => host.id === this.selectedHostID && host.enabled) || null;
  },

  activeLocal() {
    return this.localMode && this.canAccessLocal();
  },

  openLocal(page) {
    if (!this.canAccessLocal()) {
      Toasts.error('管理员尚未给你分配本机防火墙');
      return;
    }
    this.selectedHostID = '';
    this.localMode = true;
    this.hostContextVersion++;
    this.systemInfo = null;
    sessionStorage.removeItem('selected_host_id');
    sessionStorage.setItem('local_firewall_mode', '1');
    this.navigate(HOST_PAGES.includes(page) ? page : 'dashboard');
  },

  openHost(id, page) {
    const host = this.hosts.find(item => item.id === String(id || '') && item.enabled);
    if (!host) {
      Toasts.error('这台主机不可用或未授权');
      return;
    }
    this.selectedHostID = host.id;
    this.localMode = false;
    this.hostContextVersion++;
    sessionStorage.setItem('selected_host_id', host.id);
    sessionStorage.removeItem('local_firewall_mode');
    this.systemInfo = null;
    this.navigate(HOST_PAGES.includes(page) ? page : 'dashboard');
  },

  closeHost(destination) {
    this.selectedHostID = '';
    this.localMode = false;
    this.hostContextVersion++;
    this.systemInfo = null;
    sessionStorage.removeItem('selected_host_id');
    sessionStorage.removeItem('local_firewall_mode');
    this.navigate(GLOBAL_PAGES.includes(destination) ? destination : 'fleet');
  },

  currentHostName() {
    const host = this.activeHost();
    return host ? host.name : this.activeLocal() ? '本机防火墙' : '未打开主机';
  },

  currentHostTarget() {
    const host = this.activeHost();
    return host ? `${host.name} · ${host.base_url}` : this.activeLocal() ? '本机防火墙 · 本地直连' : '未打开主机';
  },

  setHostStatus(id, status) {
    if (!id) return;
    this.hostStatuses[id] = status || {};
    this.renderFleetIndicator();
    this.renderHostContext();
  },

  renderHostContext() {
    const root = document.getElementById('host-context-bar');
    if (!root) return;
    const host = this.activeHost();
    const local = this.activeLocal();
    const hostPage = HOST_PAGES.includes(this.page) && (!!host || local);
    root.hidden = !hostPage;
    if (!hostPage) return;
    if (local) {
      root.className = 'host-context-bar host-detail-header is-local local-tabs-only';
      root.innerHTML = `<nav class="host-detail-tabs" aria-label="本机防火墙导航">${hostDetailTabs(this.page)}</nav>`;
      return;
    }
    const status = this.hostStatuses[host.id] || {};
    const view = hostConnectivityPresentation(host, status);
    const statusText = view.text;
    root.className = `host-context-bar host-detail-header is-remote${view.isProblem ? ' has-error' : ''}`;
    root.innerHTML = `<div class="host-context-main"><button class="btn btn-sm btn-secondary" type="button" onclick="AppState.closeHost('fleet')">← 返回主机列表</button><div class="host-context-identity"><span class="host-context-kicker">主机配置</span><strong>${escapeHtml(host.name)}</strong><span class="host-context-address">${escapeHtml(host.base_url)}</span><span class="host-context-status">${escapeHtml(statusText)}</span></div></div><nav class="host-detail-tabs" aria-label="主机配置导航">${hostDetailTabs(this.page)}</nav>`;
  },

  canManageFleet() {
    return this.role === 'admin' || !getAuthToken();
  },

  canAccessLocal() {
    return this.canManageFleet() || this.hostIDs.includes('local');
  },

  canManageRules() {
    const host = this.activeHost();
    if (this.activeLocal()) return this.canAccessLocal();
    if (!host) return false;
    return true;
  },

  async logout() {
    if (this.authDisabled) {
      sessionStorage.clear();
      window.location.href = '/';
      return;
    }
    try { await api.logout(); } catch (_) { /* ignore */ }
    sessionStorage.clear();
    window.location.href = '/login.html';
  },

  async refreshSystemInfo() {
    if (!this.activeHost() && !this.activeLocal()) return;
    const context = this.captureHostContext();
    try {
      const info = await api.getSystemInfo(context.hostID);
      if (!this.isHostContextCurrent(context)) return;
      this.systemInfo = info;
      this.renderHostContext();
    } catch (_) { /* optional */ }
  },

  startHostMonitor() {
    if (this.hostMonitor || typeof window === 'undefined') return;
    this.hostMonitor = window.setInterval(async () => {
      try {
        const hosts = await api.listHosts();
        this.hosts = hosts;
        this.renderFleetIndicator();
        this.renderHostContext();
        if (this.page === 'fleet' && typeof FleetOverview !== 'undefined') {
          FleetOverview.refreshHeartbeatViews();
          void FleetOverview.probeHosts(FleetOverview.refreshSerial);
        }
        if (this.page === 'hosts' && typeof HostManagement !== 'undefined') {
          HostManagement.hosts = hosts;
          hosts.forEach(host => HostManagement.renderStatus(host.id));
          void HostManagement.probeAll(true, false);
        }
      } catch (_) { /* keep the last known state */ }
    }, 15000);
  },

  renderFleetIndicator() {
    const element = document.getElementById('fleet-health-count');
    if (!element) return;
    const offline = this.hosts.filter(host => host.enabled && agentHeartbeatState(host).state === 'offline').length;
    element.hidden = offline === 0;
    element.textContent = String(offline);
    element.title = `${offline} 台 Agent 离线`;
  }
};

function agentHeartbeatState(host, now) {
  const timestamp = host && host.agent_last_seen_at ? new Date(host.agent_last_seen_at).getTime() : NaN;
  if (!Number.isFinite(timestamp)) return { state: 'unknown', age: null };
  const age = Math.max(0, (typeof now === 'number' ? now : Date.now()) - timestamp);
  return { state: age > AGENT_OFFLINE_AFTER_MS ? 'offline' : 'reporting', age };
}

function formatAgentHeartbeat(timestamp, now) {
  const value = new Date(timestamp).getTime();
  if (!Number.isFinite(value)) return '尚未收到 Agent 心跳';
  const age = Math.max(0, (typeof now === 'number' ? now : Date.now()) - value);
  if (age < 10000) return 'Agent 刚刚上报';
  if (age < 60000) return `Agent ${Math.floor(age / 1000)} 秒前上报`;
  if (age < 3600000) return `Agent ${Math.floor(age / 60000)} 分钟前上报`;
  if (age < 86400000) return `Agent ${Math.floor(age / 3600000)} 小时前上报`;
  return `Agent ${Math.floor(age / 86400000)} 天前上报`;
}

function hostConnectivityPresentation(host, status, now) {
  status = status || {};
  if (!host.enabled) return { text: '已停用', className: 'badge-drop', kind: 'disabled', isProblem: false, canOpen: false };
  const heartbeat = agentHeartbeatState(host, now);
  const detail = formatAgentHeartbeat(host.agent_last_seen_at, now);
  if (heartbeat.state === 'offline') return { text: 'Agent 离线', className: 'badge-drop', kind: 'offline', isProblem: true, canOpen: false, detail };
  if (status.queued) return { text: '排队检测…', className: 'badge-return', kind: 'loading', isProblem: false, canOpen: true, detail };
  if (status.loading) return { text: '回连检测中…', className: 'badge-return', kind: 'loading', isProblem: false, canOpen: true, detail };
  if (status.online) return { text: `在线 · ${Number(status.latency || 0)}ms`, className: 'badge-accept', kind: 'online', isProblem: false, canOpen: true, detail };
  if (status.error && heartbeat.state === 'reporting') return { text: '回连异常', className: 'badge-drop', kind: 'reverse-error', isProblem: true, canOpen: false, detail };
  if (status.error) return { text: '连接异常', className: 'badge-drop', kind: 'reverse-error', isProblem: true, canOpen: false, detail };
  if (heartbeat.state === 'reporting') return { text: 'Agent 在线', className: 'badge-accept', kind: 'reporting', isProblem: false, canOpen: true, detail };
  return { text: '等待 Agent 心跳', className: 'badge-return', kind: 'unknown', isProblem: false, canOpen: true, detail };
}

function hostDetailTabs(activePage) {
  const tabs = [
    ['dashboard', '概览'], ['rules', '规则'], ['chains', '实时链'],
    ['docker', 'Docker'], ['system', '备份与审计']
  ];
  return tabs.map(([page, label]) => `<a href="#${page}" class="${activePage === page ? 'active' : ''}" ${activePage === page ? 'aria-current="page"' : ''} onclick="AppState.navigate('${page}');return false">${label}</a>`).join('');
}

function normalizePage(page) {
  return APP_PAGES.includes(page) ? page : 'fleet';
}

function pageFromHash(hash) {
  return normalizePage(String(hash || '').replace(/^#\/?/, ''));
}

if (typeof document !== 'undefined') {
  document.addEventListener('DOMContentLoaded', () => {
    AppState.init();
    window.App = AppState;
  });
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape') {
      const modal = document.getElementById('rule-modal');
      if (modal && !modal.classList.contains('hidden') && typeof RuleForm !== 'undefined') RuleForm.close();
    }
  });
  window.addEventListener('hashchange', () => AppState.navigate(pageFromHash(window.location.hash)));
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { normalizePage, pageFromHash, hostDetailTabs, agentHeartbeatState, formatAgentHeartbeat, hostConnectivityPresentation };
}
