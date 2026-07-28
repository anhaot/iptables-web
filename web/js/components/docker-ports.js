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
    this.loading = true;
    this.error = null;
    this.render();
    const results = await Promise.allSettled([api.getDockerMappings(), api.getDockerDiagnostics(), api.listRules('', 'packet')]);
    if (results[0].status === 'fulfilled') this.mappings = results[0].value;
    else this.error = results[0].reason.message;
    this.diagnostics = results[1].status === 'fulfilled' ? results[1].value : null;
	this.rules = results[2].status === 'fulfilled' ? results[2].value : [];
	if (results[2].status !== 'fulfilled' && !this.error) this.error = results[2].reason.message;
    this.loading = false;
    this.render();
  },

	togglePolicy(key) {
	  if (this.expandedPolicies.has(key)) this.expandedPolicies.delete(key);
	  else this.expandedPolicies.add(key);
	  this.render();
	},

	setPolicyFilter(value) {
	  this.policyFilter = value || 'all';
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
	  try {
		const updated = await api.toggleRule(id);
		Toasts.success(updated.enabled ? '规则已启用' : '规则已禁用');
		await this.refresh();
	  } catch (e) {
		Toasts.error('切换失败：' + e.message);
	  }
	},

	async deleteRule(id) {
	  if (!AppState.canManageRules()) return Toasts.error('需要管理员权限');
	  const rule = this.rules.find(item => item.id === id);
	  if (!rule) return Toasts.error('规则不存在，请刷新后重试');
	  if (!confirm('确定删除这条来源规则吗？\n\n' + (rule.desc || rule.source || rule.id))) return;
	  try {
		await api.deleteRule(id);
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

  async createWhitelistFromMapping(mapping) {
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
    const detectedSource = String((this.diagnostics || {}).client_ip || '');
    const promptText = detectedSource
      ? '管理页面连接到 33801 时，服务器看到的 TCP 对端地址是 ' + detectedSource + '。它不一定是物理网卡地址，也不能证明访问 Docker 端口时来源相同；若 18080 走同一路径可直接使用。'
      : '允许访问的来源 IPv4/CIDR，例如 1.2.3.4 或 10.0.0.0/8';
    const source = prompt(promptText, detectedSource);
    if (!source || !source.trim()) return;

    try {
      const result = await api.createDockerWhitelist({
        source: source.trim(), protocol: mapping.protocol || 'tcp',
        host_ip: mapping.host_ip || '', host_port: mapping.host_port,
        container_name: mapping.container_name || '', container_port: mapping.container_port
      });
      Toasts[result.created === false ? 'info' : 'success'](result.created === false
        ? '这个来源已经在该端口的允许列表中'
        : '白名单已整体应用：允许规则在前，兜底 DROP 在后');
	  await this.refresh();
    } catch (e) {
      Toasts.error('创建白名单失败：' + e.message);
    }
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

      ${this.diagnostics && this.diagnostics.client_ip ? `<div class="alert alert-info">管理页面连接到 33801 时，服务器看到的 TCP 对端地址是 <strong>${escapeHtml(this.diagnostics.client_ip)}</strong>。它不是“物理机真实 IP”判定，也不能保证访问 Docker 端口时来源相同；VMware NAT、代理或 VPN 都可能改变它。</div>` : ''}
      ${this.diagnostics && !pathUsable ? `<div class="alert alert-error"><strong>Docker 规则链路不可用：</strong>${escapeHtml(path.message || 'DOCKER_USER 不在当前 Docker 转发路径中')}。为避免产生不会生效的规则，Docker 端口操作已禁用。</div>` : ''}

      <div class="toolbar" style="margin-bottom:1rem">
        <button class="btn btn-secondary" onclick="DockerPorts.refresh()">↻ 扫描 Docker 端口</button>
		<input class="search-input" type="text" placeholder="搜索容器、端口或来源 IP..." value="${escapeHtml(this.searchQuery)}" oninput="DockerPorts.searchQuery=this.value;DockerPorts.render()">
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
        <br><small>请尝试挂载 Docker socket：<code>-v /var/run/docker.sock:/var/run/docker.sock:ro</code></small>
      </div>` : ''}

      ${this.loading ? '<div class="loading-spinner"><div class="spinner"></div> 正在扫描 Docker 端口映射...</div>' : ''}

	  ${!this.loading && visible.length === 0 && !this.error ? `
        <div class="empty-state">
          <div class="empty-icon">🐳</div>
		  <h3>${this.searchQuery || this.policyFilter !== 'all' ? '没有匹配的访问策略' : `未检测到 ${this.family.toUpperCase()} Docker 端口映射或残留策略`}</h3>
		  <p>${this.searchQuery || this.policyFilter !== 'all' ? '请调整搜索词或状态筛选。' : '如果已运行带有端口映射的 Docker 容器，请挂载 Docker socket 以启用自动检测。'}</p>
        </div>
      ` : ''}

      ${!this.loading && visible.length > 0 ? `
		<div class="docker-policy-list">
		  ${visible.map(policy => renderDockerPolicy(policy, canManage, this.family === 'ipv4' && pathUsable, this.expandedPolicies.has(policy.key))).join('')}
        </div>
      ` : ''}
    `;

    // Safe event binding - avoids XSS from JSON.stringify in onclick
	root.querySelectorAll('button[data-policy-toggle]').forEach(btn => {
	  btn.addEventListener('click', function() {
		DockerPorts.togglePolicy(this.getAttribute('data-policy-toggle'));
	  });
	});
	root.querySelectorAll('button[data-policy-rules]').forEach(btn => {
	  btn.addEventListener('click', function() {
		const policy = DockerPorts.policies.find(item => item.key === this.getAttribute('data-policy-rules'));
		if (policy) DockerPorts.showInRules(policy);
	  });
	});
	root.querySelectorAll('button[data-rule-edit]').forEach(btn => {
	  btn.addEventListener('click', function() { DockerPorts.openRule(this.getAttribute('data-rule-edit')); });
	});
	root.querySelectorAll('button[data-rule-toggle]').forEach(btn => {
	  btn.addEventListener('click', function() { DockerPorts.toggleRule(this.getAttribute('data-rule-toggle')); });
	});
	root.querySelectorAll('button[data-rule-delete]').forEach(btn => {
	  btn.addEventListener('click', function() { DockerPorts.deleteRule(this.getAttribute('data-rule-delete')); });
	});
	root.querySelectorAll('button[data-mapping-idx]').forEach(btn => {
      btn.addEventListener('click', function() {
        const idx = parseInt(this.getAttribute('data-mapping-idx'));
        const action = this.getAttribute('data-action');
        if (DockerPorts.mappings[idx]) {
          if (action === 'whitelist') {
            DockerPorts.createWhitelistFromMapping(DockerPorts.mappings[idx]);
          } else {
            DockerPorts.createRuleFromMapping(DockerPorts.mappings[idx]);
          }
        }
      });
    });
  }
};

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

function renderDockerPolicy(policy, canManage, canMutateMapping, expanded) {
	const mapping = policy.mapping || {};
	const name = mapping.container_name || '残留访问策略';
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
			<div class="docker-policy-title-row"><strong>${escapeHtml(name)}</strong><span class="docker-policy-status ${escapeHtml(status.tone)}">${escapeHtml(status.label)}</span></div>
			<div class="docker-policy-endpoint">${escapeHtml(endpoint)}</div>
			<div class="docker-policy-detail">${escapeHtml(status.detail + disabledText + positionText)}</div>
		  </div>
		  <button class="btn btn-sm btn-secondary" data-policy-toggle="${escapeHtml(policy.key)}">${expanded ? '收起' : '查看来源'}</button>
		</div>
		${expanded ? renderDockerPolicyDetails(policy, canManage, canMutateMapping) : ''}
	  </section>`;
}

function renderDockerPolicyDetails(policy, canManage, canMutateMapping) {
	const warning = policy.orderRisk
	  ? `<div class="alert alert-error"><strong>顺序风险：</strong>${escapeHtml(policy.orderRisk)}</div>`
	  : policy.residual
		? '<div class="alert alert-warning">Docker 已找不到对应端口映射；这些规则仍可能留在 DOCKER_USER/FORWARD 中。</div>'
		: '';
	const rows = policy.rules.length
	  ? policy.rules.map(rule => renderDockerPolicyRule(rule, canManage)).join('')
	  : '<div class="docker-policy-empty">当前端口没有本程序托管的访问规则。</div>';
	return `<div class="docker-policy-details">
	  ${warning}
	  <div class="docker-policy-rules-header"><span>允许来源与兜底规则</span><span>${policy.rules.length} 条规则</span></div>
	  <div class="docker-policy-rules">${rows}</div>
	  <div class="docker-policy-actions">
		${canManage && canMutateMapping && policy.mapping ? `<button class="btn btn-sm btn-primary" data-mapping-idx="${policy.mappingIndex}" data-action="whitelist">+ 添加允许来源</button><button class="btn btn-sm btn-secondary" data-mapping-idx="${policy.mappingIndex}" data-action="drop">添加阻止规则</button>` : ''}
		${policy.rules.length ? `<button class="btn btn-sm btn-secondary" data-policy-rules="${escapeHtml(policy.key)}">在执行顺序中查看</button>` : ''}
	  </div>
	</div>`;
}

function renderDockerPolicyRule(rule, canManage) {
	const action = String(rule.action || '').toUpperCase();
	let source = rule.source || '任意来源';
	if (['DROP','REJECT'].includes(action) && !rule.source) source = '其他所有来源';
	const state = rule.enabled ? '<span class="docker-rule-state enabled">已启用</span>' : '<span class="docker-rule-state disabled">已禁用</span>';
	return `<div class="docker-policy-rule ${rule.enabled ? '' : 'disabled'}">
	  <div class="docker-policy-rule-source"><strong>${escapeHtml(source)}</strong><span>${escapeHtml(rule.desc || '—')}</span></div>
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
	sameRulePort, formatHostEndpoint, dockerMappingFamily, dockerRulePathUsable, dockerMappingDescription,
	buildDockerPolicies, dockerPolicyKey, normalizeDockerPolicyHost, classifyDockerPolicy, formatPolicyPositions,
  };
}
