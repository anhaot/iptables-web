// ====== Unified managed-host overview ======

const FleetOverview = {
  loading: false,
  statuses: {},
  expanded: new Set(),
  ruleDetails: {},
  ruleDetailSerials: {},
  refreshSerial: 0,
  probing: false,
 searchQuery: '',

  async refresh() {
    const serial = ++this.refreshSerial;
    Object.keys(this.ruleDetailSerials).forEach(id => { this.ruleDetailSerials[id]++; });
    this.ruleDetails = {};
    this.loading = true;
    this.render();
    await AppState.loadHosts();
    if (serial !== this.refreshSerial) return;
    this.loading = false;
    this.render();
    this.loadExpandedRuleDetails();
    void this.probeHosts(serial);
  },

  loadExpandedRuleDetails() {
    this.expanded.forEach(id => {
      const local = id === 'local';
      const host = local ? null : AppState.hosts.find(item => item.id === id);
      const canOpen = local || (host && hostConnectivityPresentation(host, this.statuses[id] || AppState.hostStatuses[id] || {}).canOpen);
      if (canOpen) void this.loadRuleDetails(id, local);
    });
  },

  invalidateRuleDetails(id) {
    if (!id) return;
    this.ruleDetailSerials[id] = (this.ruleDetailSerials[id] || 0) + 1;
    delete this.ruleDetails[id];
  },

  async probeHosts(serial) {
    if (this.probing) return;
    this.probing = true;
    const now = Date.now();
    const hosts = AppState.hosts.filter(host => {
      const status = this.statuses[host.id] || AppState.hostStatuses[host.id] || {};
      return host.enabled && agentHeartbeatState(host).state !== 'offline' && (!status.checkedAt || now - status.checkedAt > effectiveHostMonitoring(host).probe_interval_seconds * 1000);
    });
    let cursor = 0;
    try {
      const workers = Array.from({ length: Math.min(5, hosts.length) }, async () => {
        while (cursor < hosts.length && serial === this.refreshSerial) {
          const host = hosts[cursor++];
          this.statuses[host.id] = { ...(this.statuses[host.id] || AppState.hostStatuses[host.id] || {}), loading: true };
          this.renderHostStatus(host.id);
          try {
            const result = await api.probeHost(host.id);
            this.statuses[host.id] = { online: true, latency: Number(result.latency_ms || 0), checkedAt: Date.parse(result.checked_at) || Date.now() };
          } catch (error) {
            this.statuses[host.id] = { online: false, error: error.message, checkedAt: Date.now() };
          }
          AppState.setHostStatus(host.id, this.statuses[host.id]);
          this.renderHostStatus(host.id);
        }
      });
      await Promise.all(workers);
      if (serial === this.refreshSerial) this.renderSummary();
    } finally {
      this.probing = false;
    }
  },

  refreshHeartbeatViews() {
    this.renderSummary();
    AppState.hosts.forEach(host => this.renderHostStatus(host.id));
  },

  summaryCounts() {
    const hosts = AppState.hosts;
    let reporting = 0;
    let offline = 0;
    let reverseError = 0;
    hosts.forEach(host => {
      const heartbeat = agentHeartbeatState(host);
      const view = hostConnectivityPresentation(host, this.statuses[host.id] || AppState.hostStatuses[host.id] || {});
      if (host.enabled && (heartbeat.state === 'reporting' || view.kind === 'online')) reporting++;
      if (view.kind === 'offline') offline++;
      if (view.kind === 'reverse-error') reverseError++;
    });
    const includesLocal = AppState.canAccessLocal();
    return {
      total: hosts.length + (includesLocal ? 1 : 0),
      reporting: reporting + (includesLocal ? 1 : 0),
      offline,
      reverseError
    };
  },

  renderSummary() {
    const root = document.getElementById('fleet-summary');
    if (root) root.innerHTML = this.summaryCards(this.summaryCounts());
  },

  summaryCards(counts) {
    return `<div class="stat-card"><div class="stat-label">已纳管主机</div><div class="stat-value">${counts.total}</div></div><div class="stat-card"><div class="stat-label">当前在线</div><div class="stat-value fleet-online">${counts.reporting}</div></div><div class="stat-card"><div class="stat-label">Agent 离线</div><div class="stat-value fleet-abnormal">${counts.offline}</div></div><div class="stat-card"><div class="stat-label">回连异常</div><div class="stat-value fleet-warning">${counts.reverseError}</div></div>`;
  },

  renderHostStatus(id) {
    const host = AppState.hosts.find(item => item.id === id);
    if (!host) return;
    const view = hostConnectivityPresentation(host, this.statuses[id] || AppState.hostStatuses[id] || {});
    const badge = document.getElementById('fleet-status-' + id);
    const report = document.getElementById('fleet-report-' + id);
    const detailState = document.getElementById('fleet-detail-state-' + id);
    const detailHeartbeat = document.getElementById('fleet-detail-heartbeat-' + id);
    if (badge) badge.innerHTML = `<span class="badge ${view.className}">${escapeHtml(view.text)}</span>`;
    if (report) report.textContent = view.detail || '尚未收到 Agent 心跳';
    if (detailState) detailState.textContent = view.text;
    if (detailHeartbeat) detailHeartbeat.textContent = view.detail || '尚未收到 Agent 心跳';
    document.querySelectorAll(`[data-fleet-open="${id}"]`).forEach(button => { button.disabled = !view.canOpen; });
  },

  statusBadge(host) {
    const view = hostConnectivityPresentation(host, this.statuses[host.id] || AppState.hostStatuses[host.id] || {});
    return `<span class="badge ${view.className}">${escapeHtml(view.text)}</span>`;
  },

  render() {
    const root = document.getElementById('fleet-content');
    if (!root) return;
    root.innerHTML = `<div id="fleet-summary" class="card-grid fleet-summary">${this.summaryCards(this.summaryCounts())}</div>
      <div class="card fleet-hosts-card">
        <div class="card-header fleet-hosts-header"><div class="fleet-hosts-title"><h3>纳管主机</h3><small>每台主机默认收起；展开后可预览规则并进入完整配置。</small></div><div class="toolbar fleet-host-actions"><input class="search-input" type="search" aria-label="搜索纳管主机" placeholder="搜索名称、IP、分组或 Agent ID" value="${escapeHtml(this.searchQuery)}" oninput="FleetOverview.setSearch(this.value)"><span id="fleet-search-count"></span><div class="btn-group"><button class="btn btn-sm btn-secondary" onclick="FleetOverview.refresh()">刷新状态</button>${AppState.canManageFleet() ? '<button class="btn btn-sm btn-primary" onclick="AppState.navigate(\'hosts\')">纳管 Agent</button>' : ''}</div></div></div>
 <div id="fleet-host-results">${this.loading ? '<div class="loading-spinner"><div class="spinner"></div> 加载主机...</div>' : this.renderHosts(AppState.hosts)}</div>
      </div>`;
    this.updateSearchCount();
  },

  setSearch(value) {
    this.searchQuery = String(value || '');
    const list = document.getElementById('fleet-host-results');
    if (list) list.innerHTML = this.renderHosts(AppState.hosts);
    this.updateSearchCount();
  },

  updateSearchCount() {
    const count = document.getElementById('fleet-search-count');
    if (count) count.textContent = `显示 ${this.visibleHostCount || 0} / ${this.summaryCounts().total} 台`;
  },

  renderHosts(hosts) {
    const rows = [];
    const local = { name: '本机防火墙', group: '管理中心', base_url: typeof location !== 'undefined' ? location.origin : '', agent_id: 'local' };
    if (AppState.canAccessLocal() && fleetHostMatches(local, this.searchQuery)) rows.push(this.renderLocalRow());
    hosts.filter(host => fleetHostMatches(host, this.searchQuery)).forEach(host => rows.push(this.renderRemoteRow(host)));
    this.visibleHostCount = rows.length;
    if (!rows.length && this.searchQuery.trim()) return '<div class="empty-state"><h3>没有匹配的主机</h3><p>试试名称、IP 或分组，或清空搜索条件。</p><button class="btn btn-secondary" onclick="FleetOverview.searchQuery=\'\';FleetOverview.render()">清空搜索</button></div>';
    if (!rows.length) return '<div class="empty-state"><h3>当前没有可管理的主机</h3><p>请联系管理员为你的账号分配主机或主机组。</p></div>';
    return `<div class="fleet-host-list">${rows.join('')}</div>`;
  },

  renderLocalRow() {
    const id = 'local';
    const open = this.expanded.has(id);
    return `<article class="fleet-host-row is-local ${open ? 'is-expanded' : ''}">
      <button class="fleet-host-summary" type="button" aria-expanded="${open}" onclick="FleetOverview.toggleHost('local',true)">
        <span class="fleet-host-chevron" aria-hidden="true">›</span>
        <span class="fleet-host-primary"><strong>本机防火墙</strong><small>管理中心</small></span>
        <span class="fleet-host-endpoint"><strong>控制端自身</strong><small>本地直连</small></span>
        <span class="fleet-host-report"><strong>无需 Agent</strong><small>中心内置节点</small></span>
        <span class="fleet-host-state"><span class="badge badge-accept">在线</span></span>
      </button>
      ${open ? this.renderExpandedDetail(id, true, null, true) : ''}
    </article>`;
  },

  renderRemoteRow(host) {
    const open = this.expanded.has(host.id);
    const view = hostConnectivityPresentation(host, this.statuses[host.id] || AppState.hostStatuses[host.id] || {});
    return `<article class="fleet-host-row ${view.isProblem ? 'has-problem' : ''} ${open ? 'is-expanded' : ''}">
      <button class="fleet-host-summary" type="button" aria-expanded="${open}" onclick="FleetOverview.toggleHost('${host.id}',false)">
        <span class="fleet-host-chevron" aria-hidden="true">›</span>
        <span class="fleet-host-primary"><strong>${escapeHtml(host.name)}</strong><small>${escapeHtml(host.group || '未分组')}</small></span>
        <span class="fleet-host-endpoint"><strong>${escapeHtml(formatManagedHostEndpoint(host.base_url))}</strong><small>${escapeHtml(host.base_url)}</small></span>
        <span class="fleet-host-report"><strong id="fleet-report-${host.id}">${escapeHtml(view.detail || '尚未收到 Agent 心跳')}</strong><small>${host.has_api_key ? '凭据已加密' : '缺少 Agent Key'}</small></span>
        <span id="fleet-status-${host.id}" class="fleet-host-state">${this.statusBadge(host)}</span>
      </button>
      ${open ? this.renderExpandedDetail(host.id, false, host, view.canOpen) : ''}
    </article>`;
  },

  renderExpandedDetail(id, local, host, canOpen) {
    const detail = this.ruleDetails[id];
    const hostName = local ? '本机防火墙' : host.name;
    const description = local
      ? '中心端内置节点，不经过 Agent 回连。'
      : '查看主机身份、接入方式与规则状态；完整配置仍在主机详情页完成。';
    return `<div class="fleet-host-detail">
      <div class="fleet-host-detail-header">
        <div class="fleet-host-detail-title"><span>主机详情</span><h4>${escapeHtml(hostName)}</h4><p>${description}</p></div>
        <div class="toolbar fleet-host-actions">
          <button class="btn btn-sm btn-secondary" type="button" ${canOpen ? '' : 'disabled'} ${local ? '' : `data-fleet-open="${id}"`} onclick="${local ? "AppState.openLocal('dashboard')" : `AppState.openHost('${id}','dashboard')`}">进入主机概览</button>
          <button class="btn btn-sm btn-primary" type="button" ${canOpen ? '' : 'disabled'} ${local ? '' : `data-fleet-open="${id}"`} onclick="${local ? "AppState.openLocal('rules')" : `AppState.openHost('${id}','rules')`}">管理防火墙规则</button>
        </div>
      </div>
      ${this.renderHostFacts(local, host)}
      <div class="fleet-rule-panel">
        <div class="fleet-rule-heading"><strong>规则摘要</strong><small>${canOpen ? '最多预览 3 条托管规则' : '主机恢复在线后自动开放规则入口'}</small></div>
        <div id="fleet-rules-${id}" class="fleet-rule-preview" aria-live="polite">${this.renderRulePreview(detail, canOpen)}</div>
      </div>
    </div>`;
  },

  renderHostFacts(local, host) {
    if (local) {
      return `<dl class="fleet-host-facts">
        ${fleetHostFact('节点类型', '中心本机', '保留主机 ID · local')}
        ${fleetHostFact('通信路径', '本地直连', '不经过远程 Agent')}
        ${fleetHostFact('运行状态', '在线', '随中心服务运行')}
        ${fleetHostFact('访问控制', '逐台授权', '无需 Agent Key')}
      </dl>`;
    }
    const view = hostConnectivityPresentation(host, this.statuses[host.id] || AppState.hostStatuses[host.id] || {});
    const protocol = managedHostProtocol(host.base_url);
    const agentID = host.agent_id || '';
    const caNote = protocol === 'HTTPS'
      ? (host.has_custom_ca ? '使用自定义 CA 严格校验' : '使用系统 CA 校验')
      : '仅建议用于可信内网';
    return `<dl class="fleet-host-facts">
      ${fleetHostFact('Agent 身份', agentID ? shortFleetIdentifier(agentID) : '尚未提供', agentID ? '签名身份已验证' : '等待 Agent 身份', agentID)}
      ${fleetHostFact('接入方式', protocol, caNote)}
      ${fleetHostFact('连接状态', view.text, view.detail || '尚未收到 Agent 心跳', '', `fleet-detail-state-${host.id}`, `fleet-detail-heartbeat-${host.id}`)}
      ${fleetHostFact('认证保护', host.has_api_key ? 'Agent Key 已加密' : '缺少 Agent Key', host.has_custom_ca ? '已配置自定义 CA' : '未配置自定义 CA')}
      ${fleetHostFact('纳管时间', formatFleetTimestamp(host.created_at), host.enabled ? '主机已启用' : '主机已停用')}
    </dl>`;
  },

  renderRulePreview(detail, canOpen) {
    if (!canOpen) return '<div class="fleet-rule-message is-offline"><strong>暂时无法读取规则</strong><span>Agent 当前离线或回连异常，主机资料仍可查看；恢复连接后即可进入配置。</span></div>';
    if (!detail || detail.loading) return '<div class="fleet-rule-message"><span class="spinner"></span> 正在读取规则摘要...</div>';
    if (detail.error) return `<div class="fleet-rule-message has-error">规则读取失败：${escapeHtml(detail.error)}</div>`;
    const rules = Array.isArray(detail.rules) ? detail.rules : [];
    if (!rules.length) return '<div class="fleet-rule-message">当前没有托管规则。</div>';
    return `<div class="fleet-rule-summary"><strong>${rules.length} 条托管规则</strong><div class="fleet-rule-items">${rules.slice(0, 3).map(rule => `<span><b>${escapeHtml(rule.action || '—')}</b> ${escapeHtml(rule.chain || '—')} · ${escapeHtml(rule.desc || rule.dport || '未命名规则')}</span>`).join('')}</div>${rules.length > 3 ? `<small>另有 ${rules.length - 3} 条，进入规则页查看全部。</small>` : ''}</div>`;
  },

  toggleHost(id, local) {
    if (this.expanded.has(id)) {
      this.expanded.delete(id);
      this.render();
      return;
    }
    this.expanded.add(id);
    this.render();
    const host = local ? null : AppState.hosts.find(item => item.id === id);
    const canOpen = local || (host && hostConnectivityPresentation(host, this.statuses[id] || AppState.hostStatuses[id] || {}).canOpen);
    if (canOpen && !this.ruleDetails[id]) void this.loadRuleDetails(id, local);
  },

  async loadRuleDetails(id, local) {
    const serial = (this.ruleDetailSerials[id] || 0) + 1;
    this.ruleDetailSerials[id] = serial;
    this.ruleDetails[id] = { loading: true };
    this.renderRuleDetail(id, true);
    try {
      const rules = local ? await api.listLocalRules() : await api.listHostRules(id);
      if (this.ruleDetailSerials[id] !== serial) return;
      this.ruleDetails[id] = { loading: false, rules: Array.isArray(rules) ? rules : [] };
    } catch (error) {
      if (this.ruleDetailSerials[id] !== serial) return;
      this.ruleDetails[id] = { loading: false, error: error.message || '未知错误', rules: [] };
    }
    this.renderRuleDetail(id, true);
  },

  renderRuleDetail(id, canOpen) {
    const root = document.getElementById('fleet-rules-' + id);
    if (root) root.innerHTML = this.renderRulePreview(this.ruleDetails[id], canOpen);
  }
};

function formatManagedHostEndpoint(baseURL) {
  try {
    const parsed = new URL(baseURL);
    return parsed.hostname + (parsed.port ? ':' + parsed.port : '');
  } catch (_) {
    return baseURL || '地址未知';
  }
}

function managedHostProtocol(baseURL) {
  try {
    return new URL(baseURL).protocol.replace(':', '').toUpperCase() || '未知协议';
  } catch (_) {
    return '未知协议';
  }
}

function shortFleetIdentifier(value) {
  value = String(value || '');
  return value.length > 24 ? `${value.slice(0, 12)}…${value.slice(-8)}` : value;
}

function formatFleetTimestamp(value) {
  const date = new Date(value || '');
  if (Number.isNaN(date.getTime())) return '时间未知';
  return date.toLocaleString('zh-CN', {
    hour12: false,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit'
  });
}

function fleetHostFact(label, value, note, title, valueID, noteID) {
  const titleAttr = title ? ` title="${escapeHtml(title)}"` : '';
  const valueIDAttr = valueID ? ` id="${valueID}"` : '';
  const noteIDAttr = noteID ? ` id="${noteID}"` : '';
  return `<div class="fleet-host-fact"><dt>${escapeHtml(label)}</dt><dd class="fleet-host-fact-value"${valueIDAttr}${titleAttr}>${escapeHtml(value)}</dd><dd class="fleet-host-fact-note"${noteIDAttr}>${escapeHtml(note)}</dd></div>`;
}

function fleetHostMatches(host, query) {
 const text = [host.name, host.group, host.base_url, host.agent_id].map(value => String(value || '').toLowerCase()).join(' ');
 return String(query || '').trim().toLowerCase().split(/\s+/).filter(Boolean).every(term => text.includes(term));
}

if (typeof module !== 'undefined' && module.exports) module.exports = { fleetHostMatches };
