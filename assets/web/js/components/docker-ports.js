// ====== Docker 端口映射管理 ======

const DockerPorts = {
  mappings: [],
  loading: false,
  error: null,
  family: 'ipv4',
  diagnostics: null,

  setFamily(family) {
    this.family = family === 'ipv6' ? 'ipv6' : 'ipv4';
    this.render();
  },

  get filteredMappings() {
    return this.mappings.map((mapping, index) => ({ mapping, index })).filter(item => dockerMappingFamily(item.mapping) === this.family);
  },

  async refresh() {
    this.loading = true;
    this.error = null;
    this.render();
    const results = await Promise.allSettled([api.getDockerMappings(), api.getDockerDiagnostics()]);
    if (results[0].status === 'fulfilled') this.mappings = results[0].value;
    else this.error = results[0].reason.message;
    this.diagnostics = results[1].status === 'fulfilled' ? results[1].value : null;
    this.loading = false;
    this.render();
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
      AppState.navigate('rules');
      setTimeout(() => RulesList.refresh(), 200);
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
      AppState.navigate('rules');
      setTimeout(() => RulesList.refresh(), 200);
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
    const visible = this.filteredMappings;
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
        <span style="font-size:0.8rem;color:var(--text-muted)">
          仅通过 Docker socket / CLI 确认发布映射
        </span>
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
          <h3>未检测到 ${this.family.toUpperCase()} Docker 端口映射</h3>
          <p>如果已运行带有端口映射的 Docker 容器，请挂载 Docker socket 以启用自动检测。</p>
          <code style="display:inline-block;margin-top:0.5rem">-v /var/run/docker.sock:/var/run/docker.sock:ro</code>
        </div>
      ` : ''}

      ${!this.loading && visible.length > 0 ? `
        <div class="mapping-list">
          ${visible.map(item => { const m = item.mapping; const idx = item.index; return `
            <div class="mapping-item">
              <div class="mapping-info">
                <span class="mapping-name">${escapeHtml(m.container_name)}</span>
                <span class="mapping-port">${escapeHtml(formatHostEndpoint(m.host_ip, m.host_port))} → :${m.container_port}/${escapeHtml(m.protocol)}</span>
                <span class="mapping-tag">DOCKER 链</span>
              </div>
              ${canManage && this.family === 'ipv4' && pathUsable ? `<div class="btn-group">
                <button class="btn btn-sm btn-primary" data-mapping-idx="${idx}" data-action="drop">
                  阻止
                </button>
                <button class="btn btn-sm btn-secondary" data-mapping-idx="${idx}" data-action="whitelist">
                  只允许 IP
                </button>
              </div>` : '<span style="font-size:0.8rem;color:var(--text-muted)">只读</span>'}
            </div>
          `; }).join('')}
        </div>
      ` : ''}
    `;

    // Safe event binding - avoids XSS from JSON.stringify in onclick
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
  module.exports = { sameRulePort, formatHostEndpoint, dockerMappingFamily, dockerRulePathUsable, dockerMappingDescription };
}
