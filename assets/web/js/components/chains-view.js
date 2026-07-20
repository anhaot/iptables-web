// ====== 实时 iptables / nftables 链浏览器 ======

const ChainsView = {
  chains: [],
  loading: false,
  error: null,
  expanded: {},

  async refresh() {
    this.loading = true;
    this.error = null;
    this.render();
    try {
      this.chains = await api.getChains('packet');
    } catch (e) {
      this.error = e.message;
      this.chains = [];
    } finally {
      this.loading = false;
      this.render();
    }
  },

  toggleExpand(name) {
    this.expanded[name] = !this.expanded[name];
    this.render();
  },

  render() {
    const root = document.getElementById('chains-content');
    if (!root) return;
    root.innerHTML = `
      <div class="alert alert-info"><strong>实时链只读取 packet 后端。</strong>Docker 发布端口通常经过 FORWARD / DOCKER-USER；宿主机服务通常经过 INPUT。程序不会读取或修改 firewalld Zone。</div>
      <div class="toolbar" style="margin-bottom:1rem">
        <button class="btn btn-secondary" onclick="ChainsView.refresh()">↻ 刷新</button>
        <span style="font-size:0.85rem;color:var(--text-muted)">实时读取当前 iptables / nftables 链和规则</span>
      </div>
      ${this.error ? '<div class="alert alert-error">' + escapeHtml(this.error) + '</div>' : ''}
      ${this.loading ? '<div class="loading-spinner"><div class="spinner"></div> 加载实时配置中...</div>' : ''}
      ${!this.loading ? this.renderChains() : ''}
    `;
  },

  renderChains() {
    if (!this.chains.length) {
      return '<div class="empty-state"><div class="empty-icon">📋</div><h3>未找到链</h3><p>无法获取当前 packet 防火墙的实时规则。</p></div>';
    }
    return this.chains.map(chain => `
      <div class="chain-card">
        <div class="chain-card-header" onclick="ChainsView.toggleExpand('${escapeHtml(chain.name)}')" title="${escapeHtml(FirewallHelp.chainTitle(chain.name))}">
          <span><strong>${escapeHtml(chain.name)}</strong><span class="help-dot" title="${escapeHtml(FirewallHelp.chainTitle(chain.name))}">?</span>
            <span style="color:var(--text-muted);margin-left:.5rem;font-size:.8rem">策略: ${escapeHtml(chain.policy || '—')} · ${chain.rules ? chain.rules.length : 0} 条规则</span>
          </span>
          <span style="color:var(--text-muted)">${this.expanded[chain.name] ? '▴' : '▾'}</span>
        </div>
        ${this.expanded[chain.name] ? renderPacketChainBody(chain) : ''}
      </div>`).join('');
  }
};

function renderPacketChainBody(chain) {
  if (!chain.rules || !chain.rules.length) {
    return '<div style="padding:1rem;color:var(--text-muted);font-size:.85rem">此链中暂无规则</div>';
  }
  return `<div class="chain-card-body"><table class="chain-rules-table">
    <thead><tr><th>#</th><th>目标</th><th>协议</th><th>入站接口</th><th>出站接口</th><th>来源</th><th>目标地址</th><th>选项</th></tr></thead>
    <tbody>${chain.rules.map(rule => `<tr>
      <td class="mono">${rule.num}</td><td>${actionBadge(rule.target)}</td><td class="mono">${escapeHtml(rule.prot || '全部')}</td>
      <td class="mono">${escapeHtml(readableAny(rule.in, '任意接口'))}</td><td class="mono">${escapeHtml(readableAny(rule.out, '任意接口'))}</td>
      <td class="mono">${escapeHtml(readableAny(rule.source, '任意来源'))}</td><td class="mono">${escapeHtml(readableAny(rule.dest, '任意目标'))}</td>
      <td class="mono">${escapeHtml(rule.options || '—')}</td>
    </tr>`).join('')}</tbody>
  </table></div>`;
}

function readableAny(value, fallback) {
  const normalized = String(value || '').trim();
  return !normalized || normalized === '*' || normalized === 'anywhere' || normalized === '0.0.0.0/0' || normalized === '::/0' ? fallback : normalized;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { readableAny };
}
