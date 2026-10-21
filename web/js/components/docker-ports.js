// ====== Docker 端口映射管理 ======

const DockerPorts = {
  mappings: [],
	rules: [],
  loading: false,
  error: null,
  family: 'ipv4',
  diagnostics: null,
	searchQuery: '',
	policyFilter: 'all',
	expandedPolicies: new Set(),
  expandedContainers: new Set(),
	refreshSerial: 0,
 selectedRules: new Set(),
 selectionContext: null,
 bulkForm: null,
 mutating: false,

  setFamily(family) {
    this.family = family === 'ipv6' ? 'ipv6' : 'ipv4';
    this.render();
  },

  get policies() {
	return buildDockerPolicies(this.mappings, this.rules, this.family);
  },

  get filteredPolicies() {
	const query = this.searchQuery.trim().toLowerCase();
	return this.policies.filter(policy => {
	  if (this.policyFilter !== 'all' && policy.status.id !== this.policyFilter) return false;
	  if (!query) return true;
	  const mapping = policy.mapping || {};
	  const values = [
		mapping.container_name, mapping.host_ip, mapping.host_port, mapping.container_port,
		policy.hostIP, policy.port, policy.protocol, policy.status.label,
		...policy.rules.flatMap(rule => [rule.source, rule.desc, rule.action, rule.chain]),
	  ];
	  return values.some(value => String(value || '').toLowerCase().includes(query));
	});
  },

  async refresh() {
 this.resetSelectionContext();
    const serial = ++this.refreshSerial;
    const context = AppState.captureHostContext();
    this.loading = true;
    this.error = null;
    this.render();
    const results = await Promise.allSettled([api.getDockerMappings(context.hostID), api.getDockerDiagnostics(context.hostID), api.listRules('', 'packet', context.hostID)]);
    if (serial !== this.refreshSerial || !AppState.isHostContextCurrent(context)) return;
    if (results[0].status === 'fulfilled') this.mappings = results[0].value;
    else { this.mappings = []; this.error = results[0].reason.message; }
    this.diagnostics = results[1].status === 'fulfilled' ? results[1].value : null;
	this.rules = results[2].status === 'fulfilled' ? results[2].value : [];
	if (results[2].status !== 'fulfilled' && !this.error) this.error = results[2].reason.message;
    this.selectedRules = new Set([...this.selectedRules].filter(id => this.rules.some(rule => rule.id === id)));
    const groupKeys = new Set(this.groups().map(group => group.key));
    this.expandedContainers = new Set([...this.expandedContainers].filter(key => groupKeys.has(key)));
    this.expandFilteredContainers();
 this.loading = false;
    this.render();
  },

	togglePolicy(key) {
	  if (this.expandedPolicies.has(key)) this.expandedPolicies.delete(key);
	  else this.expandedPolicies.add(key);
	  this.render();
	},

  toggleContainer(key) {
    if (this.expandedContainers.has(key)) this.expandedContainers.delete(key);
    else this.expandedContainers.add(key);
    this.render();
  },

  expandFilteredContainers() {
    if (!this.searchQuery.trim() && this.policyFilter === 'all') return;
    groupDockerPolicies(this.filteredPolicies).forEach(group => this.expandedContainers.add(group.key));
  },

	setPolicyFilter(value) {
	  this.policyFilter = value || 'all';
	  this.expandFilteredContainers();
	  this.render();
	},

	openRule(id) {
	  if (!AppState.canManageRules()) return Toasts.error('需要管理员权限');
	  const rule = this.rules.find(item => item.id === id);
	  if (!rule) return Toasts.error('规则不存在，请刷新后重试');
	  RuleForm.open(rule, () => this.refresh());
	},

	async toggleRule(id) {
	  if (!AppState.canManageRules()) return Toasts.error('需要管理员权限');
	  const context = AppState.captureHostContext();
	  try {
		const updated = await api.toggleRule(id, context.hostID);
		AppState.invalidateRuleSummary(context);
		if (!AppState.isHostContextCurrent(context)) return;
		Toasts.success(updated.enabled ? '规则已启用' : '规则已禁用');
		await this.refresh();
	  } catch (e) {
		Toasts.error('切换失败：' + e.message);
	  }
	},

	async deleteRule(id) {
	  if (!AppState.canManageRules()) return Toasts.error('需要管理员权限');
	  const context = AppState.captureHostContext();
	  const rule = this.rules.find(item => item.id === id);
	  if (!rule) return Toasts.error('规则不存在，请刷新后重试');
	  const accepted = await Dialogs.confirm({
		title: '删除 Docker 来源规则',
		message: '删除后该端口的访问策略可能发生变化，请确认规则作用范围。',
		target: `${AppState.currentHostTarget()} · ${rule.desc || rule.source || rule.id}`,
		confirmText: '删除规则',
		danger: true
	  });
	  if (!accepted) return;
	  if (!AppState.isHostContextCurrent(context)) return Toasts.warning('主机已切换，请重新执行删除操作');
	  try {
		await api.deleteRule(id, context.hostID);
		AppState.invalidateRuleSummary(context);
		if (!AppState.isHostContextCurrent(context)) return;
		Toasts.success('规则已删除');
		await this.refresh();
	  } catch (e) {
		Toasts.error('删除失败：' + e.message);
	  }
	},

	showInRules(policy) {
	  const chain = policy.rules.length ? policy.rules[0].chain : 'DOCKER_USER';
	  RulesList.filterChain = chain || 'DOCKER_USER';
	  RulesList.searchQuery = String(policy.port || '');
	  AppState.navigate('rules');
	  setTimeout(() => RulesList.refresh(), 100);
	},

  createRuleFromMapping(mapping) {
    if (!AppState.canManageRules()) {
      Toasts.error('需要管理员权限');
      return;
    }
    if (dockerMappingFamily(mapping) === 'ipv6') {
      Toasts.error('IPv6 映射当前只读；请使用规则助手生成并审核 ip6tables 规则');
      return;
    }
    if (!dockerRulePathUsable(this.diagnostics)) {
      Toasts.error(this.diagnostics.path.message || 'DOCKER_USER 当前不在有效转发路径中');
      return;
    }
    const rule = {
	  backend: 'packet',
	  chain: 'DOCKER_USER',
      action: 'DROP',
      protocol: mapping.protocol || 'tcp',
      source: '',
      dest: '',
	  dport: '',
	  original_dport: String(mapping.host_port),
      sport: '',
      in_iface: '',
      out_iface: '',
      state: '',
      desc: '阻止访问 ' + dockerMappingDescription(mapping),
      enabled: true,
      position: 1,
    };
    RuleForm.open(rule, (saved) => {
	  this.refresh();
	}, 'packet');
  },

  setSearch(value) {
    this.searchQuery = String(value || '');
    this.expandFilteredContainers();
    const root = document.getElementById('docker-policy-results');
    if (root) { root.innerHTML = this.renderPolicyGroups(); this.bindPolicyEvents(root); this.updateSelectionViews(); }
  },

  resetSelectionContext() {
    const context = AppState.captureHostContext();
    if (!this.selectionContext || !AppState.isHostContextCurrent(this.selectionContext)) {
      this.selectedRules = new Set(); this.bulkForm = null;
      this.mappings = []; this.rules = []; this.diagnostics = null;
      this.expandedPolicies = new Set(); this.error = null;
      this.expandedContainers = new Set();
      this.selectionContext = context;
    }
  },

  groups() { return groupDockerPolicies(this.policies); },

  renderPolicyGroups() {
    const canManage = AppState.canManageRules();
    const canAdd = canManage && this.family === 'ipv4' && dockerRulePathUsable(this.diagnostics);
    const groups = groupDockerPolicies(this.filteredPolicies);
    if (!groups.length) return '<div class="empty-state"><h3>没有匹配的访问策略</h3><p>请调整容器、端口或来源搜索条件。</p></div>';
    const allGroups = new Map(this.groups().map(group => [group.key,group]));
    return groups.map((visible, index) => {
      const group = allGroups.get(visible.key) || visible;
      const groupRules = uniqueDockerRules(group.policies);
      const expanded = this.expandedContainers.has(group.key);
      const bodyID = `docker-container-body-${index}`;
      return `<section class="docker-container-group" aria-label="${escapeHtml(group.name)}"><div class="docker-container-header"><button type="button" class="docker-container-toggle" data-container-toggle="${escapeHtml(group.key)}" aria-expanded="${expanded}" ${expanded ? `aria-controls="${bodyID}"` : ''} aria-label="${expanded ? '收起' : '展开'}${group.residual ? '策略' : '容器'} ${escapeHtml(group.name)}"><span class="docker-container-chevron" aria-hidden="true">${expanded ? '▾' : '▸'}</span><span class="docker-container-summary"><strong>${escapeHtml(group.name)}</strong><small>${group.policies.length} 个发布端口 · ${groupRules.length} 条托管规则${visible.policies.length !== group.policies.length ? ` · 当前显示 ${visible.policies.length} 个端口` : ''}</small></span></button><div class="btn-group">${canAdd && group.mappings.length ? `<button class="btn btn-sm btn-primary" data-container-add="${escapeHtml(group.key)}" ${this.mutating ? 'disabled' : ''}>批量添加来源</button>` : ''}${canManage && this.family === 'ipv4' && groupRules.length ? `<button class="btn btn-sm btn-danger" data-container-clear="${escapeHtml(group.key)}" ${this.mutating ? 'disabled' : ''}>${group.residual ? '清空此残留策略' : '清空此容器规则'}</button>` : ''}</div></div>${expanded ? `<div id="${bodyID}" class="docker-policy-list">${visible.policies.map(policy => renderDockerPolicy(policy, canManage, canAdd, this.expandedPolicies.has(policy.key), this.selectedRules)).join('')}</div>` : ''}</section>`;
    }).join('');
  },

  toggleRuleSelection(id, checked) {
    if (checked) this.selectedRules.add(id); else this.selectedRules.delete(id);
    this.updateSelectionViews();
  },

  togglePolicySelection(key, checked) {
    const policy = this.policies.find(item => item.key === key);
    if (!policy) return;
    policy.rules.forEach(rule => { if (checked) this.selectedRules.add(rule.id); else this.selectedRules.delete(rule.id); });
 this.updateSelectionViews();
  },

  updateSelectionViews() {
    const root = document.getElementById('docker-content');
    if (!root) return;
 const byKey = new Map(this.policies.map(policy => [policy.key, policy]));
    root.querySelectorAll('[data-rule-select]').forEach(input => { input.checked = this.selectedRules.has(input.dataset.ruleSelect); });
    root.querySelectorAll('[data-policy-select]').forEach(input => {
      const policy = byKey.get(input.dataset.policySelect);
      const selected = policy ? policy.rules.filter(rule => this.selectedRules.has(rule.id)).length : 0;
      input.checked = !!policy && policy.rules.length > 0 && selected === policy.rules.length;
      input.indeterminate = selected > 0 && selected < policy.rules.length;
    });
    root.querySelectorAll('[data-delete-selected]').forEach(button => { button.disabled = !this.selectedRules.size || this.mutating; button.textContent = `删除所选（${this.selectedRules.size}）`; });
  },

  async deleteMany(rules, title, target) {
    if (!AppState.canManageRules() || this.mutating) return;
    const unique = Array.from(new Map(rules.map(rule => [rule.id, { ...rule }])).values());
    if (!unique.length) return Toasts.info('请先选择规则');
    if (unique.length > 1000) return Toasts.warning('每批最多删除 1000 条，请分批选择');
    const context = AppState.captureHostContext();
    const fallbackCount = unique.filter(rule => ['DROP','REJECT'].includes(rule.action) && !rule.source).length;
    const accepted = await Dialogs.confirm({
      title, target: `${AppState.currentHostTarget()} · ${target} · ${unique.length} 条规则`,
      message: `将删除已确认的 ${unique.length} 条托管规则（包含禁用规则）。${fallbackCount ? `其中 ${fallbackCount} 条是兜底拒绝规则，删除后对应端口可能恢复为对所有来源开放。` : '现有兜底拒绝规则会保留；没有允许来源时端口可能完全阻断。'} Docker 自身及其他工具的规则保留。`,
      detail: unique.map(rule => `${rule.chain} #${rule.position} ${rule.action} · ${rule.source || '任意来源'} · 原始端口 ${rule.original_dport || rule.dport || '任意'}`).join('\n'),
      confirmText: `确认删除 ${unique.length} 条`, danger: true
    });
    if (!accepted) return;
    if (!AppState.isHostContextCurrent(context)) return Toasts.warning('主机已切换，请重新选择规则');
    this.mutating = true; this.updateSelectionViews();
    try {
      const result = await api.batchDeleteRules(unique, context.hostID);
      AppState.invalidateRuleSummary(context);
      if (!AppState.isHostContextCurrent(context)) return;
      unique.forEach(rule => this.selectedRules.delete(rule.id));
      Toasts.success(`已删除 ${result.removed} 条规则`);
      await this.refresh();
    } catch (error) {
      if (AppState.isHostContextCurrent(context)) Toasts.error([404, 405].includes(error.status) ? '目标 Agent 不支持批量操作，请先升级 Agent' : '删除失败：' + error.message);
    } finally { this.mutating = false; if (AppState.isHostContextCurrent(context)) { this.render(); } }
  },

  deleteSelected() { return this.deleteMany(this.rules.filter(rule => this.selectedRules.has(rule.id)), '删除所选 Docker 规则', '已勾选规则'); },

  clearContainer(key) {
    const group = this.groups().find(item => item.key === key);
    if (group) return this.deleteMany(uniqueDockerRules(group.policies), group.residual ? '清空残留策略' : '清空容器托管规则', `${group.name} · ${group.policies.map(policy => `${policy.port}/${policy.protocol}`).join('、')}`);
  },

  clearPolicy(key) {
    const policy = this.policies.find(item => item.key === key);
    if (policy) return this.deleteMany(policy.rules, '清空此发布端口规则', `${formatHostEndpoint(policy.hostIP, policy.port)}/${policy.protocol}`);
  },

  openBulkSources(mappings) {
    if (!AppState.canManageRules() || this.mutating || this.loading || !dockerRulePathUsable(this.diagnostics)) return;
    const unique = Array.from(new Map(mappings.filter(mapping => dockerMappingFamily(mapping) === 'ipv4').map(mapping => [dockerPolicyKey(mapping.protocol, normalizeDockerPolicyHost(mapping.host_ip, 'ipv4'), mapping.host_port), { ...mapping }])).values());
    if (!unique.length) return;
    this.bulkForm = { context: AppState.captureHostContext(), mappings: unique, selected: new Set(unique.map((_,index) => index)), sources: '' };
    this.render();
    document.getElementById('docker-bulk-sources')?.focus();
  },

  closeBulkSources() { if (!this.mutating) { this.bulkForm = null; this.render(); } },

  updateBulkSources(value) { if (this.bulkForm) { this.bulkForm.sources = value; this.updateBulkPreview(); } },

  toggleBulkPort(index, checked) {
    if (!this.bulkForm) return;
    if (checked) this.bulkForm.selected.add(index); else this.bulkForm.selected.delete(index);
    this.updateBulkPreview();
  },

  updateBulkPreview() {
    const form = this.bulkForm;
    if (!form) return;
    const sources = parseDockerSources(form.sources);
    const combinations = sources.length * form.selected.size;
    const preview = document.getElementById('docker-bulk-preview');
    if (preview) preview.textContent = `${sources.length} 个来源 × ${form.selected.size} 个发布端口 = ${combinations} 个组合（每批最多 200 个）`;
    const submit = document.getElementById('docker-bulk-submit');
    if (submit) submit.disabled = this.mutating || !combinations || combinations > 200 || sources.length > 100 || form.selected.size > 50;
  },

  renderBulkSources() {
    const form = this.bulkForm;
    if (!form || !AppState.isHostContextCurrent(form.context)) return '';
    return `<div class="docker-bulk-modal"><div class="modal-overlay" onclick="DockerPorts.closeBulkSources()"></div><section class="modal" role="dialog" aria-modal="true" aria-labelledby="docker-bulk-title"><div class="modal-header"><h2 id="docker-bulk-title">批量添加允许来源</h2><button type="button" class="modal-close" aria-label="关闭批量添加" onclick="DockerPorts.closeBulkSources()">✕</button></div><form onsubmit="DockerPorts.submitBulkSources();return false"><label class="form-label" for="docker-bulk-sources">来源 IPv4 / CIDR</label><textarea id="docker-bulk-sources" class="form-textarea mono" rows="6" maxlength="8192" required placeholder="每行一个，例如：&#10;192.168.1.10&#10;10.20.0.0/16" oninput="DockerPorts.updateBulkSources(this.value)">${escapeHtml(form.sources)}</textarea><p class="monitoring-note">支持换行或逗号分隔，重复来源自动合并；保留已有来源，为每个端口复用或补齐兜底 DROP。</p><fieldset class="docker-bulk-ports"><legend>应用到发布端口</legend>${form.mappings.map((mapping,index) => `<label class="form-check"><input type="checkbox" data-bulk-port="${index}" ${form.selected.has(index) ? 'checked' : ''}>${escapeHtml(mapping.container_name || '容器')} · ${escapeHtml(formatHostEndpoint(mapping.host_ip, mapping.host_port))}/${escapeHtml(mapping.protocol || 'tcp')}</label>`).join('')}</fieldset><p id="docker-bulk-preview" aria-live="polite"></p><div class="btn-group"><button class="btn btn-secondary" type="button" onclick="DockerPorts.closeBulkSources()">取消</button><button id="docker-bulk-submit" class="btn btn-primary" type="submit" disabled>预览并添加</button></div></form></section></div>`;
  },

  async submitBulkSources() {
    const form = this.bulkForm;
    if (!form || this.mutating) return;
    if (!AppState.isHostContextCurrent(form.context)) return this.closeBulkSources();
    const sources = parseDockerSources(form.sources);
    const mappings = form.mappings.filter((_,index) => form.selected.has(index));
    if (!sources.length || sources.length > 100 || !mappings.length || mappings.length > 50 || sources.length * mappings.length > 200) return Toasts.warning('请选择端口和来源，每批最多 200 个组合');
    const accepted = await Dialogs.confirm({title: '确认批量添加 Docker 来源', target: AppState.currentHostTarget(), message: `允许 ${sources.length} 个来源访问 ${mappings.length} 个发布端口；已有来源保留，其他来源由兜底 DROP 阻止。`, detail: `来源：\n${sources.join('\n')}\n\n发布端口：\n${mappings.map(mapping => `${mapping.container_name} · ${formatHostEndpoint(mapping.host_ip,mapping.host_port)}/${mapping.protocol}`).join('\n')}`, confirmText: '确认添加'});
    if (!accepted) return;
    if (!AppState.isHostContextCurrent(form.context)) return Toasts.warning('主机已切换，请重新配置');
    this.mutating = true; this.updateBulkPreview();
    try {
      const result = await api.createDockerWhitelistBatch(dockerBatchPayload(sources, mappings), form.context.hostID);
      AppState.invalidateRuleSummary(form.context);
      if (!AppState.isHostContextCurrent(form.context)) return;
      this.bulkForm = null;
      Toasts.success(`新增 ${result.added_sources} 条来源规则、${result.added_fallbacks} 条兜底规则，跳过 ${result.skipped_sources} 个已有来源`);
      await this.refresh();
    } catch (error) {
      if (AppState.isHostContextCurrent(form.context)) Toasts.error([404, 405].includes(error.status) ? '目标 Agent 不支持批量操作，请先升级 Agent' : '添加失败：' + error.message);
    } finally { this.mutating = false; if (AppState.isHostContextCurrent(form.context)) this.render(); }
  },

  bindPolicyEvents(root) {
    root.querySelectorAll('[data-container-toggle]').forEach(button => button.addEventListener('click', () => this.toggleContainer(button.dataset.containerToggle)));
    root.querySelectorAll('[data-policy-toggle]').forEach(button => button.addEventListener('click', () => this.togglePolicy(button.dataset.policyToggle)));
    root.querySelectorAll('[data-policy-rules]').forEach(button => button.addEventListener('click', () => { const policy = this.policies.find(item => item.key === button.dataset.policyRules); if (policy) this.showInRules(policy); }));
    root.querySelectorAll('[data-rule-edit]').forEach(button => button.addEventListener('click', () => this.openRule(button.dataset.ruleEdit)));
    root.querySelectorAll('[data-rule-toggle]').forEach(button => button.addEventListener('click', () => this.toggleRule(button.dataset.ruleToggle)));
    root.querySelectorAll('[data-rule-delete]').forEach(button => button.addEventListener('click', () => this.deleteRule(button.dataset.ruleDelete)));
    root.querySelectorAll('[data-rule-select]').forEach(input => input.addEventListener('change', () => this.toggleRuleSelection(input.dataset.ruleSelect,input.checked)));
    root.querySelectorAll('[data-policy-select]').forEach(input => input.addEventListener('change', () => this.togglePolicySelection(input.dataset.policySelect,input.checked)));
    root.querySelectorAll('[data-policy-clear]').forEach(button => button.addEventListener('click', () => this.clearPolicy(button.dataset.policyClear)));
    root.querySelectorAll('[data-container-clear]').forEach(button => button.addEventListener('click', () => this.clearContainer(button.dataset.containerClear)));
    root.querySelectorAll('[data-container-add]').forEach(button => button.addEventListener('click', () => { const group = this.groups().find(item => item.key === button.dataset.containerAdd); if (group) this.openBulkSources(group.mappings); }));
    root.querySelectorAll('[data-bulk-port]').forEach(input => input.addEventListener('change', () => this.toggleBulkPort(Number(input.dataset.bulkPort),input.checked)));
    root.querySelectorAll('[data-mapping-idx]').forEach(button => button.addEventListener('click', () => {
      const mapping = this.mappings[Number(button.dataset.mappingIdx)];
      if (mapping) { if (button.dataset.action === 'whitelist') this.openBulkSources([mapping]); else this.createRuleFromMapping(mapping); }
    }));
  },

  render() {
    const root = document.getElementById('docker-content');
    if (!root) return;
    const canManage = AppState.canManageRules();
    const ipv4Count = this.mappings.filter(mapping => dockerMappingFamily(mapping) === 'ipv4').length;
    const ipv6Count = this.mappings.length - ipv4Count;
	const visible = this.filteredPolicies;
    const pathUsable = dockerRulePathUsable(this.diagnostics);
    const path = (this.diagnostics || {}).path || {};

    root.innerHTML = `
      <div class="info-banner">
        <span class="banner-icon">💡</span>
        <span>
		  <strong>Docker 发布端口由 iptables 管理，不使用 firewalld/INPUT。</strong>
		  对 <code>-p 18080:80</code>，程序会在 <strong>DOCKER_USER</strong> 中按连接的原始宿主机端口 <strong>18080</strong> 匹配，避免误伤其他同为容器端口 80 的服务。
          白名单访问必须同时创建 <strong>ACCEPT</strong> 和兜底 <strong>DROP</strong>。
        </span>
      </div>

      ${this.diagnostics && !pathUsable ? `<div class="alert alert-error"><strong>Docker 规则链路不可用：</strong>${escapeHtml(path.message || 'DOCKER_USER 不在当前 Docker 转发路径中')}。为避免产生不会生效的规则，Docker 端口操作已禁用。</div>` : ''}

      <div class="toolbar" style="margin-bottom:1rem">
        <button class="btn btn-secondary" onclick="DockerPorts.refresh()">↻ 扫描 Docker 端口</button>
 ${canManage && this.family === 'ipv4' ? `<button class="btn btn-danger" data-delete-selected onclick="DockerPorts.deleteSelected()" disabled>删除所选（${this.selectedRules.size}）</button>` : ''}
		<input class="search-input" type="text" placeholder="搜索容器、端口或来源 IP..." value="${escapeHtml(this.searchQuery)}" oninput="DockerPorts.setSearch(this.value)">
		<select class="form-select docker-policy-filter" onchange="DockerPorts.setPolicyFilter(this.value)" aria-label="访问策略状态">
		  ${[['all','全部状态'],['protected','白名单保护'],['unprotected','未配置保护'],['blocked','完全阻止'],['risk','存在异常'],['unmanaged','未管理'],['residual','残留策略']].map(([value,label]) => `<option value="${value}" ${this.policyFilter === value ? 'selected' : ''}>${label}</option>`).join('')}
		</select>
      </div>
      <div class="chain-pills" style="margin-bottom:1rem" role="tablist" aria-label="Docker 端口地址族">
        <button class="chain-pill ${this.family === 'ipv4' ? 'active' : ''}" onclick="DockerPorts.setFamily('ipv4')">IPv4 <span class="badge badge-return">${ipv4Count}</span></button>
        <button class="chain-pill ${this.family === 'ipv6' ? 'active' : ''}" onclick="DockerPorts.setFamily('ipv6')">IPv6 <span class="badge badge-return">${ipv6Count}</span></button>
      </div>
      ${this.family === 'ipv6' ? '<div class="alert alert-info">IPv6 发布端口单独展示。当前规则管理后端只操作 IPv4 packet 规则；IPv6 映射为只读，可在规则助手中生成并审核 ip6tables / nftables 命令。</div>' : ''}
      ${!canManage ? '<div class="alert alert-info">当前账号为只读权限，可以查看 Docker 端口映射；创建阻止或白名单规则需要管理员权限。</div>' : ''}

      ${this.error ? `<div class="alert alert-warning">
        ⚠ 无法检测 Docker 端口映射：${escapeHtml(this.error)}。
        <br><small>请检查目标主机的 Docker 服务及 /var/run/docker.sock 访问权限。</small>
      </div>` : ''}

      ${this.loading ? '<div class="loading-spinner"><div class="spinner"></div> 正在扫描 Docker 端口映射...</div>' : ''}

	  ${!this.loading && visible.length === 0 && !this.error ? `
        <div class="empty-state">
          <div class="empty-icon">🐳</div>
		  <h3>${this.searchQuery || this.policyFilter !== 'all' ? '没有匹配的访问策略' : `未检测到 ${this.family.toUpperCase()} Docker 端口映射或残留策略`}</h3>
		  <p>${this.searchQuery || this.policyFilter !== 'all' ? '请调整搜索词或状态筛选。' : '如果已运行带有端口映射的 Docker 容器，请检查目标主机的 Docker 服务和 socket 访问权限。'}</p>
        </div>
      ` : ''}

      <div id="docker-policy-results">${!this.loading && visible.length > 0 ? this.renderPolicyGroups() : ''}</div>
 ${this.renderBulkSources()}
    `;

    this.bindPolicyEvents(root);
    this.updateSelectionViews();
    this.updateBulkPreview();
  }
};

function dockerBatchPayload(sources, mappings) {
 return { sources, mappings: mappings.map(mapping => ({ protocol: mapping.protocol || 'tcp', host_ip: mapping.host_ip || '', host_port: Number(mapping.host_port), container_name: mapping.container_name || '', container_port: Number(mapping.container_port) })) };
}

function parseDockerSources(value) {
 return Array.from(new Set(String(value || '').split(/[\s,;，；]+/).map(item => item.trim()).filter(Boolean)));
}

function groupDockerPolicies(policies) {
 const groups = new Map();
 (policies || []).forEach(policy => {
  const mapping = policy.mapping;
  const key = mapping ? 'container:' + (mapping.container_id || mapping.container_name || policy.key) : 'residual:' + policy.key;
  if (!groups.has(key)) groups.set(key, { key, name: mapping ? mapping.container_name || 'Docker 容器' : '残留访问策略', residual: !mapping, policies: [], mappings: [] });
  const group = groups.get(key); group.policies.push(policy); if (mapping) group.mappings.push(mapping);
 });
 return [...groups.values()];
}

function uniqueDockerRules(policies) { return [...new Map(policies.flatMap(policy => policy.rules).map(rule => [rule.id, rule])).values()]; }

function buildDockerPolicies(mappings, rules, family) {
	const policies = [];
	const byKey = new Map();
	(mappings || []).forEach((mapping, mappingIndex) => {
	  if (dockerMappingFamily(mapping) !== family) return;
	  const protocol = String(mapping.protocol || 'tcp').toLowerCase();
	  const hostIP = normalizeDockerPolicyHost(mapping.host_ip, family);
	  const port = String(mapping.host_port || '');
	  const key = dockerPolicyKey(protocol, hostIP, port);
	  const policy = { key, mapping, mappingIndex, protocol, hostIP, port, family, rules: [], residual: false };
	  policies.push(policy);
	  byKey.set(key, policy);
	});

	if (family === 'ipv4') {
	  (rules || []).filter(isDockerPolicyRule).forEach(rule => {
		const protocol = String(rule.protocol || 'tcp').toLowerCase();
		const hostIP = normalizeDockerPolicyHost(rule.original_dest, 'ipv4');
		const port = String(rule.original_dport || '');
		const key = dockerPolicyKey(protocol, hostIP, port);
		let policy = byKey.get(key);
		if (!policy) {
		  policy = { key, mapping: null, mappingIndex: -1, protocol, hostIP, port, family: 'ipv4', rules: [], residual: true };
		  byKey.set(key, policy);
		  policies.push(policy);
		}
		policy.rules.push(rule);
	  });
	}

	return policies.map(finalizeDockerPolicy).sort((a, b) => {
	  if (a.residual !== b.residual) return a.residual ? 1 : -1;
	  const aPort = parseInt(a.port, 10) || 0;
	  const bPort = parseInt(b.port, 10) || 0;
	  return aPort - bPort || a.protocol.localeCompare(b.protocol);
	});
}

function isDockerPolicyRule(rule) {
	const chain = String((rule || {}).chain || '').toUpperCase();
	return (chain === 'DOCKER_USER' || chain === 'FORWARD') && String((rule || {}).original_dport || '').trim() !== '';
}

function normalizeDockerPolicyHost(hostIP, family) {
	const host = String(hostIP || '').replace(/^\[|\]$/g, '').trim();
	if (!host || host === '0.0.0.0' || host === '::') return family === 'ipv6' ? '::' : '0.0.0.0';
	return host;
}

function dockerPolicyKey(protocol, hostIP, port) {
	return [String(protocol || 'tcp').toLowerCase(), String(hostIP || '0.0.0.0'), String(port || '')].join('|');
}

function finalizeDockerPolicy(policy) {
	policy.rules.sort((a, b) => String(a.chain || '').localeCompare(String(b.chain || '')) || (Number(a.position) || 0) - (Number(b.position) || 0));
	policy.enabledRules = policy.rules.filter(rule => rule.enabled);
	policy.allowRules = policy.enabledRules.filter(rule => String(rule.action || '').toUpperCase() === 'ACCEPT');
	policy.allowedSources = Array.from(new Set(policy.allowRules.map(rule => String(rule.source || '').trim() || '任意来源')));
	policy.fallbackRules = policy.enabledRules.filter(rule => ['DROP','REJECT'].includes(String(rule.action || '').toUpperCase()) && !rule.source);
	policy.disabledCount = policy.rules.length - policy.enabledRules.length;
	policy.chains = Array.from(new Set(policy.rules.map(rule => String(rule.chain || '').toUpperCase()).filter(Boolean)));
	policy.positions = policy.rules.map(rule => Number(rule.position) || 0).filter(Boolean).sort((a,b) => a-b);
	policy.positionLabel = policy.chains.length > 1
	  ? policy.chains.map(chain => `${chain} ${formatPolicyPositions(policy.rules.filter(rule => String(rule.chain || '').toUpperCase() === chain).map(rule => Number(rule.position) || 0).filter(Boolean))}`).join('；')
	  : formatPolicyPositions(policy.positions);
	policy.orderRisk = findDockerPolicyOrderRisk(policy);
	policy.protectionStatus = classifyDockerPolicy(policy);
	policy.status = policy.residual
	  ? { id: 'residual', label: '残留策略', tone: 'warning', detail: `Docker 映射已消失，仍有 ${policy.rules.length} 条托管规则` }
	  : policy.protectionStatus;
	return policy;
}

function findDockerPolicyOrderRisk(policy) {
	for (const fallback of policy.fallbackRules) {
	  const chain = String(fallback.chain || '').toUpperCase();
	  const blockedAllow = policy.allowRules.find(rule => String(rule.chain || '').toUpperCase() === chain && (Number(rule.position) || 0) > (Number(fallback.position) || 0));
	  if (blockedAllow) return `兜底 ${fallback.action} 位于允许 ${blockedAllow.source || '任意来源'} 的规则之前`;
	}
	return '';
}

function classifyDockerPolicy(policy) {
	if (policy.family === 'ipv6') return { id: 'unmanaged', label: 'IPv6 只读', tone: 'muted', detail: '当前界面不管理 IPv6 Docker 规则' };
	if (!policy.rules.length) return { id: 'unmanaged', label: '未管理', tone: 'muted', detail: '未配置本程序访问策略' };
	if (policy.chains.length > 1) return { id: 'risk', label: '跨链策略', tone: 'warning', detail: `规则分布在 ${policy.chains.join('、')}，请在执行顺序中分别检查` };
	if (policy.orderRisk) return { id: 'risk', label: '顺序异常', tone: 'danger', detail: policy.orderRisk };
	if (!policy.enabledRules.length) return { id: 'risk', label: '策略已禁用', tone: 'warning', detail: `${policy.rules.length} 条规则当前全部禁用` };
	const broadAllow = policy.allowRules.some(rule => !String(rule.source || '').trim());
	if (broadAllow) return { id: 'unprotected', label: '允许任意来源', tone: 'warning', detail: '存在未限制来源的 ACCEPT 规则' };
	if (policy.allowRules.length && policy.fallbackRules.length) {
	  return { id: 'protected', label: '白名单保护', tone: 'success', detail: `允许 ${policy.allowedSources.length} 个来源，其他来源已阻止` };
	}
	if (!policy.allowRules.length && policy.fallbackRules.length) {
	  return { id: 'blocked', label: '完全阻止', tone: 'danger', detail: '没有启用的允许来源，其他来源已阻止' };
	}
	if (policy.allowRules.length) {
	  const disabledFallback = policy.rules.some(rule => !rule.enabled && ['DROP','REJECT'].includes(String(rule.action || '').toUpperCase()) && !rule.source);
	  return {
		id: disabledFallback ? 'risk' : 'unprotected',
		label: disabledFallback ? '兜底已禁用' : '未配置保护',
		tone: 'warning',
		detail: disabledFallback ? '允许规则已启用，但兜底 DROP/REJECT 被禁用' : `允许 ${policy.allowedSources.length} 个来源，但没有启用的兜底 DROP/REJECT`,
	  };
	}
	return { id: 'risk', label: '自定义策略', tone: 'warning', detail: '存在规则，但无法识别为完整白名单或阻止策略' };
}

function formatPolicyPositions(positions) {
	const unique = Array.from(new Set(positions));
	if (!unique.length) return '—';
	const contiguous = unique.every((value, index) => index === 0 || value === unique[index - 1] + 1);
	if (contiguous && unique.length > 1) return `#${unique[0]}–#${unique[unique.length - 1]}`;
	return unique.map(value => `#${value}`).join('、');
}

function renderDockerPolicy(policy, canManage, canMutateMapping, expanded, selected) {
	const mapping = policy.mapping || {};
	const endpoint = policy.mapping
	  ? `${formatHostEndpoint(mapping.host_ip, mapping.host_port)} → ${mapping.container_name || 'Docker 容器'}:${mapping.container_port}/${policy.protocol}`
	  : `${formatHostEndpoint(policy.hostIP, policy.port)}/${policy.protocol}`;
	const status = policy.status;
	const disabledText = policy.disabledCount ? ` · ${policy.disabledCount} 条禁用` : '';
	const positionText = policy.positionLabel !== '—' ? ` · 位置 ${policy.positionLabel}` : '';
	return `
	  <section class="docker-policy-card docker-policy-${escapeHtml(status.tone)}">
		<div class="docker-policy-summary">
		  <button class="docker-policy-expand" data-policy-toggle="${escapeHtml(policy.key)}" aria-expanded="${expanded}" title="${expanded ? '收起访问策略' : '展开访问策略'}">${expanded ? '▾' : '▸'}</button>
		  <div class="docker-policy-service">
			<div class="docker-policy-endpoint">${escapeHtml(endpoint)}</div>
			<div class="docker-policy-detail">${escapeHtml(status.detail + disabledText + positionText)}</div>
		  </div>
		  <button class="btn btn-sm btn-secondary" data-policy-toggle="${escapeHtml(policy.key)}">${expanded ? '收起' : '查看来源'}</button>
		</div>
		${expanded ? renderDockerPolicyDetails(policy, canManage, canMutateMapping, selected) : ''}
	  </section>`;
}

function renderDockerPolicyDetails(policy, canManage, canMutateMapping, selected) {
	const warning = policy.orderRisk
	  ? `<div class="alert alert-error"><strong>顺序风险：</strong>${escapeHtml(policy.orderRisk)}</div>`
	  : policy.residual
		? '<div class="alert alert-warning">Docker 已找不到对应端口映射；这些规则仍可能留在 DOCKER_USER/FORWARD 中。</div>'
		: '';
	const rows = policy.rules.length
	  ? policy.rules.map(rule => renderDockerPolicyRule(rule, canManage, selected)).join('')
	  : '<div class="docker-policy-empty">当前端口没有本程序托管的访问规则。</div>';
	return `<div class="docker-policy-details">
	  ${warning}
	  <div class="docker-policy-rules-header"><span>${canManage && policy.rules.length ? `<label class="form-check"><input type="checkbox" data-policy-select="${escapeHtml(policy.key)}" aria-label="全选此端口规则">全选此端口规则</label>` : '允许来源与兜底规则'}</span><span>${policy.rules.length} 条规则</span></div>
	  <div class="docker-policy-rules">${rows}</div>
	  <div class="docker-policy-actions">
		${canManage && canMutateMapping && policy.mapping ? `<button class="btn btn-sm btn-primary" data-mapping-idx="${policy.mappingIndex}" data-action="whitelist">+ 添加允许来源</button><button class="btn btn-sm btn-secondary" data-mapping-idx="${policy.mappingIndex}" data-action="drop">添加阻止规则</button>` : ''}
		${canManage && policy.rules.length ? `<button class="btn btn-sm btn-danger" data-policy-clear="${escapeHtml(policy.key)}">清空此端口规则</button>` : ''}
 ${policy.rules.length ? `<button class="btn btn-sm btn-secondary" data-policy-rules="${escapeHtml(policy.key)}">在执行顺序中查看</button>` : ''}
	  </div>
	</div>`;
}

function renderDockerPolicyRule(rule, canManage, selected) {
	const action = String(rule.action || '').toUpperCase();
	let source = rule.source || '任意来源';
	if (['DROP','REJECT'].includes(action) && !rule.source) source = '其他所有来源';
	const state = rule.enabled ? '<span class="docker-rule-state enabled">已启用</span>' : '<span class="docker-rule-state disabled">已禁用</span>';
	return `<div class="docker-policy-rule ${rule.enabled ? '' : 'disabled'}">
	  <div class="docker-policy-rule-source">${canManage ? `<label class="docker-rule-selection"><input type="checkbox" data-rule-select="${escapeHtml(rule.id)}" aria-label="选择 ${escapeHtml(rule.action)} ${escapeHtml(source)}" ${selected && selected.has(rule.id) ? 'checked' : ''}><strong>${escapeHtml(source)}</strong></label>` : `<strong>${escapeHtml(source)}</strong>`}<span>${escapeHtml(rule.desc || '—')}</span></div>
	  <div class="docker-policy-rule-meta"><span>${escapeHtml(rule.chain)} #${escapeHtml(rule.position)}</span>${actionBadge(action)}${state}</div>
	  ${canManage ? `<div class="btn-group docker-policy-rule-actions"><button class="btn btn-xs btn-secondary" data-rule-toggle="${escapeHtml(rule.id)}">${rule.enabled ? '禁用' : '启用'}</button><button class="btn btn-xs btn-secondary" data-rule-edit="${escapeHtml(rule.id)}">编辑</button><button class="btn btn-xs btn-danger" data-rule-delete="${escapeHtml(rule.id)}">删除</button></div>` : ''}
	</div>`;
}

function sameRulePort(rule, proto, port) {
	return String(rule.chain || '').toUpperCase() === 'DOCKER_USER' &&
    String(rule.protocol || 'tcp').toLowerCase() === String(proto || 'tcp').toLowerCase() &&
	String(rule.original_dport || '') === String(port || '');
}

function formatHostEndpoint(hostIP, port) {
  const host = hostIP || '0.0.0.0';
  return (host.includes(':') ? '[' + host + ']' : host) + ':' + port;
}

function dockerMappingFamily(mapping) {
  const declared = String((mapping || {}).family || '').toLowerCase();
  if (declared === 'ipv6' || declared === 'ipv4') return declared;
  const hostIP = String((mapping || {}).host_ip || '').replace(/^\[|\]$/g, '');
  return hostIP.includes(':') ? 'ipv6' : 'ipv4';
}

function dockerRulePathUsable(diagnostics) {
  return !diagnostics || !diagnostics.path || diagnostics.path.usable !== false;
}

function dockerMappingDescription(mapping) {
  const hostIP = String(mapping.host_ip || '').replace(/^\[|\]$/g, '');
  const host = !hostIP || hostIP === '0.0.0.0' || hostIP === '::'
    ? '宿主机:' + mapping.host_port
    : formatHostEndpoint(hostIP, mapping.host_port);
  return host + ' → ' + (mapping.container_name || 'Docker 容器') + ':' + mapping.container_port;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
	DockerPorts, dockerBatchPayload, parseDockerSources, groupDockerPolicies, uniqueDockerRules, sameRulePort, formatHostEndpoint, dockerMappingFamily, dockerRulePathUsable, dockerMappingDescription,
	buildDockerPolicies, dockerPolicyKey, normalizeDockerPolicyHost, classifyDockerPolicy, formatPolicyPositions,
  };
}
