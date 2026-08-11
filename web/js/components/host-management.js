// ====== Lightweight Agent registration and connectivity ======

const HostManagement = {
  hosts: [], pending: [], selectedPending: {}, pendingCAPEM: {}, statuses: {}, loading: false, editing: null,
  error: '', probeConcurrency: 5,
  activeProbes: 0, probeWaiters: [], probingAll: false,

  async refresh() {
    this.loading = true;
    this.error = '';
    this.render();
    try {
      const canManage = AppState.canManageFleet();
      const [hosts, pending] = await Promise.all([
        api.listHosts(),
        canManage ? api.listAgentEnrollments() : Promise.resolve([])
      ]);
      this.hosts = hosts;
      this.pending = pending;
      const pendingIDs = new Set(pending.map(item => item.id));
      Object.keys(this.selectedPending).forEach(id => {
        if (!pendingIDs.has(id)) delete this.selectedPending[id];
      });
      Object.keys(this.pendingCAPEM).forEach(id => {
        if (!pendingIDs.has(id)) delete this.pendingCAPEM[id];
      });
      AppState.hosts = this.hosts;
      AppState.renderHostContext();
    } catch (e) {
      this.error = e.message;
    }
    this.loading = false;
    this.render();
    void this.probeAll(true, false);
  },

  edit(id) {
    this.editing = this.hosts.find(host => host.id === id) || null;
    this.render();
  },

  cancelEdit() { this.editing = null; this.render(); },

  async save(form) {
    if (!AppState.canManageFleet()) return Toasts.error('需要管理员权限');
    const data = new FormData(form);
    const usesHTTPS = this.editing?.base_url?.startsWith('https://');
    const payload = {
      name: String(data.get('name') || '').trim(),
      group: String(data.get('group') || '').trim(),
      ca_pem: usesHTTPS ? String(data.get('ca_pem') || '').trim() : '',
      clear_ca: usesHTTPS && data.get('clear_ca') === 'on',
      enabled: data.get('enabled') === 'on'
    };
    try {
      if (!this.editing) throw new Error('只能编辑已完成纳管的 Agent');
      await api.updateHost(this.editing.id, payload);
      Toasts.success('Agent 主机已更新');
      this.editing = null;
      await this.refresh();
    } catch (e) { Toasts.error('保存主机失败：' + e.message); }
  },

  pendingIDs(id) {
    if (id) return /^[a-f0-9]{24}$/.test(id) ? [id] : [];
    return this.pending.filter(item => this.selectedPending[item.id]).map(item => item.id);
  },

  togglePending(id, checked) {
    if (!/^[a-f0-9]{24}$/.test(id)) return;
    if (checked) this.selectedPending[id] = true;
    else delete this.selectedPending[id];
    this.updatePendingToolbar();
  },

  toggleAllPending(checked) {
    this.pending.forEach(item => {
      if (checked) this.selectedPending[item.id] = true;
      else delete this.selectedPending[item.id];
    });
    document.querySelectorAll('[data-enrollment-checkbox]').forEach(box => { box.checked = checked; });
    this.updatePendingToolbar();
  },

  updatePendingToolbar() {
    const count = this.pendingIDs().length;
    const label = document.getElementById('pending-selection-count');
    if (label) label.textContent = `已选择 ${count} 台`;
    document.querySelectorAll('[data-pending-batch-action]').forEach(button => { button.disabled = count === 0; });
    const selectAll = document.getElementById('pending-select-all');
    if (selectAll) {
      selectAll.checked = this.pending.length > 0 && count === this.pending.length;
      selectAll.indeterminate = count > 0 && count < this.pending.length;
    }
  },

  setPendingCA(id, value) {
    if (/^[a-f0-9]{24}$/.test(id)) this.pendingCAPEM[id] = String(value || '');
  },

  async approvePending(id) {
    if (!AppState.canManageFleet()) return Toasts.error('需要管理员权限');
    const ids = this.pendingIDs(id);
    if (!ids.length) return Toasts.info('请先选择待确认 Agent');
    const accepted = await Dialogs.confirm({
      title: ids.length > 1 ? '批量确认纳管' : '确认纳管 Agent',
      message: `管理端将回连并验证 ${ids.length} 台 Agent，验证成功后才会加入纳管清单。`,
      target: ids.length === 1 ? this.pending.find(item => item.id === ids[0])?.name || ids[0] : `共 ${ids.length} 台`,
      confirmText: ids.length > 1 ? '批量确认' : '确认纳管'
    });
    if (!accepted) return;
    try {
      const caPEMByID = {};
      ids.forEach(itemID => {
        const value = String(this.pendingCAPEM[itemID] || '').trim();
        if (value) caPEMByID[itemID] = value;
      });
      const results = await api.approveAgentEnrollments(ids, caPEMByID);
      const failed = results.filter(item => !item.success);
      const succeeded = results.length - failed.length;
      if (succeeded) Toasts.success(`已纳管 ${succeeded} 台 Agent`);
      if (failed.length) {
        await Dialogs.alert({
          title: '部分 Agent 未能纳管',
          message: `${failed.length} 台回连验证或保存失败，其申请仍保留，可排查后重试。`,
          detail: failed.map(item => `${item.id}: ${item.error || '未知错误'}`).join('\n')
        });
      }
      ids.forEach(itemID => { delete this.selectedPending[itemID]; delete this.pendingCAPEM[itemID]; });
      await this.refresh();
    } catch (e) { Toasts.error('确认纳管失败：' + e.message); }
  },

  async rejectPending(id) {
    if (!AppState.canManageFleet()) return Toasts.error('需要管理员权限');
    const ids = this.pendingIDs(id);
    if (!ids.length) return Toasts.info('请先选择待确认 Agent');
    const accepted = await Dialogs.confirm({
      title: ids.length > 1 ? '批量拒绝申请' : '拒绝 Agent 申请',
      message: '拒绝后，该 Agent 的申请将在当前管理端隐藏 24 小时；不会卸载 Agent，也不会修改其防火墙规则。',
      target: ids.length === 1 ? this.pending.find(item => item.id === ids[0])?.name || ids[0] : `共 ${ids.length} 台`,
      confirmText: '拒绝申请',
      danger: true
    });
    if (!accepted) return;
    try {
      await api.rejectAgentEnrollments(ids);
      ids.forEach(itemID => { delete this.selectedPending[itemID]; });
      Toasts.success(`已拒绝 ${ids.length} 台 Agent 申请`);
      await this.refresh();
    } catch (e) { Toasts.error('拒绝申请失败：' + e.message); }
  },

  installCommand() {
    const origin = window.location.origin.replace(/\/$/, '');
    return `sudo MANAGER_URL=${origin} bash install-agent.sh`;
  },

  async copyInstallCommand() {
    try {
      await navigator.clipboard.writeText(this.installCommand());
      Toasts.success('安装命令已复制');
    } catch (_) { Toasts.error('浏览器未允许复制，请手动选择命令'); }
  },

  async remove(id) {
    if (!AppState.canManageFleet()) return Toasts.error('需要管理员权限');
    const host = this.hosts.find(item => item.id === id);
    const accepted = await Dialogs.confirm({
      title: '移除纳管主机',
      message: '只会从中心移除这台主机并撤销用户分配，不会卸载目标机 Agent，也不会删除目标机上的防火墙规则。',
      target: host ? `${host.name} · ${host.base_url}` : id,
      confirmText: '删除登记',
      danger: true
    });
    if (!accepted) return;
    try {
      await api.deleteHost(id);
      if (AppState.selectedHostID === id) AppState.closeHost('hosts');
      Toasts.success('主机已从中心移除');
      await this.refresh();
    } catch (e) { Toasts.error('删除失败：' + e.message); }
  },

  async probeAll(quiet, force) {
    if (this.probingAll) {
      if (!quiet) Toasts.info('主机检测正在进行中');
      return;
    }
    this.probingAll = true;
    const now = Date.now();
    const hosts = this.hosts.filter(host => host.enabled && hostStatusPresentation(host, this.statuses[host.id] || {}).kind !== 'offline' && (force || !this.statuses[host.id]?.checkedAt || now - this.statuses[host.id].checkedAt > 60000));
    let cursor = 0;
    try {
      const workers = Array.from({ length: Math.min(this.probeConcurrency, hosts.length) }, async () => {
        while (cursor < hosts.length) {
          const host = hosts[cursor++];
          await this.probe(host.id, quiet);
        }
      });
      await Promise.all(workers);
      if (!quiet && hosts.length) Toasts.info(`已完成 ${hosts.length} 台主机检测`);
    } finally {
      this.probingAll = false;
    }
  },

  async acquireProbeSlot() {
    if (this.activeProbes < this.probeConcurrency) {
      this.activeProbes++;
      return;
    }
    await new Promise(resolve => this.probeWaiters.push(resolve));
  },

  releaseProbeSlot() {
    const next = this.probeWaiters.shift();
    if (next) next();
    else this.activeProbes = Math.max(0, this.activeProbes - 1);
  },

  async probe(id, quiet) {
    if (this.statuses[id]?.loading || this.statuses[id]?.queued) return;
    const queuedStatus = { ...(this.statuses[id] || {}), queued: true, loading: false };
    this.statuses[id] = queuedStatus;
    AppState.setHostStatus(id, queuedStatus);
    this.renderStatus(id);
    await this.acquireProbeSlot();
    const loadingStatus = { ...(this.statuses[id] || {}), loading: true };
    delete loadingStatus.queued;
    this.statuses[id] = loadingStatus;
    AppState.setHostStatus(id, loadingStatus);
    this.renderStatus(id);
    try {
      const result = await api.probeHost(id);
      this.statuses[id] = { online: true, latency: Number(result.latency_ms || 0), checkedAt: Date.now() };
      if (!quiet) Toasts.success('远程主机连接正常');
    } catch (e) {
      this.statuses[id] = { online: false, error: e.message, checkedAt: Date.now() };
      if (!quiet) Toasts.error('连接失败，请查看诊断详情');
    } finally {
      this.releaseProbeSlot();
      AppState.setHostStatus(id, this.statuses[id]);
      this.renderStatus(id);
    }
  },

  renderStatus(id) {
    const host = this.hosts.find(item => item.id === id);
    const cell = document.getElementById('host-status-cell-' + id);
    if (!host || !cell) return;
    cell.innerHTML = this.renderStatusCell(host);
  },

  renderStatusCell(host) {
    const status = this.statuses[host.id] || {};
    const view = hostStatusPresentation(host, status);
    const detailButton = status.error ? `<button class="btn btn-xs btn-secondary" type="button" onclick="HostManagement.showProbeError('${host.id}')">诊断详情</button>` : '';
    const checked = status.checkedAt ? `<small class="host-checked-at">${escapeHtml(formatHostCheckedAt(status.checkedAt))}</small>` : '<small class="host-checked-at">尚无回连检测记录</small>';
    const heartbeat = `<small class="host-agent-seen">${escapeHtml(view.detail || '尚未收到 Agent 心跳')}</small>`;
    return `<div class="host-status-wrap"><span class="badge ${view.className}">${escapeHtml(view.text)}</span>${detailButton}${heartbeat}${checked}</div>`;
  },

  showProbeError(id) {
    const host = this.hosts.find(item => item.id === id);
    const status = this.statuses[id] || {};
    if (!status.error) return;
    Dialogs.alert({
      title: '远程连接诊断',
      message: '连接检测未通过。可复制以下技术详情用于排查网络、证书或访问密钥。',
      target: host ? `${host.name} · ${host.base_url}` : id,
      detail: String(status.error)
    });
  },

  render() {
    const root = document.getElementById('hosts-content');
    if (!root) return;
    const canManage = AppState.canManageFleet();
    const editing = this.editing;
    const installCommand = escapeHtml(this.installCommand());
    root.innerHTML = `
      <div class="agent-onboarding"><div><span class="agent-step">目标主机</span><strong>运行安装脚本</strong><small>部署轻量二进制与 systemd 服务</small></div><span class="agent-arrow">→</span><div><span class="agent-step">Agent 主动发起</span><strong>签名纳管申请</strong><small>不需要在管理端手工填写地址或密钥</small></div><span class="agent-arrow">→</span><div><span class="agent-step">当前中心</span><strong>单台或批量确认</strong><small>回连验证成功后加入纳管清单</small></div></div>
      ${canManage ? `<div class="agent-install-card"><div><strong>目标机安装命令</strong><small>直接运行 <code>sudo bash install-agent.sh</code> 即可进入交互安装；右侧命令用于直接安装。Agent 注册应直连中心内网 IP；若当前页面经过域名或反向代理，请先替换 MANAGER_URL。默认监听 33802，只应允许当前管理端访问。</small></div><code>${installCommand}</code><button class="btn btn-sm btn-secondary" type="button" onclick="HostManagement.copyInstallCommand()">复制命令</button></div>` : ''}
      ${this.error ? `<div class="alert alert-error"><strong>主机清单加载失败。</strong><details class="inline-error-detail"><summary>查看详情</summary><pre>${escapeHtml(this.error)}</pre></details></div>` : ''}
      ${canManage ? `${this.renderPending()}
      ${editing ? `<div class="host-setup-grid single-column">
        <div class="card host-form-card">
          <div class="card-header"><div><h3>编辑已纳管主机</h3><small>地址由 Agent 的签名申请维护；这里调整名称、分组和访问状态</small></div></div>
          <form onsubmit="HostManagement.save(this);return false">
            <div class="host-form-grid">
              <div class="form-group"><label class="form-label">显示名称</label><input class="form-input" name="name" autocomplete="off" maxlength="64" required value="${escapeHtml(editing ? editing.name : '')}" placeholder="生产节点 01"></div>
              <div class="form-group"><label class="form-label">分组</label><input class="form-input" name="group" autocomplete="off" maxlength="64" value="${escapeHtml(editing ? (editing.group || '') : '')}" placeholder="production"></div>
              <div class="form-group host-form-span"><label class="form-label">Agent 回连地址</label><div class="read-only-field mono">${escapeHtml(editing.base_url)}</div><small>如需变更，请修改目标机的 <code>AGENT_PUBLIC_URL</code> 并重启 Agent，然后在待确认列表批准地址变更。</small></div>
            </div>
            <div id="host-tls-fields" class="host-tls-fields" ${editing.base_url.startsWith('https://') ? '' : 'hidden'}>
              <label class="form-label">HTTPS 自签名证书 CA（可选）</label>
              <textarea class="form-textarea mono" name="ca_pem" rows="5" placeholder="-----BEGIN CERTIFICATE-----"></textarea>
              ${editing && editing.has_custom_ca ? '<label class="form-check"><input type="checkbox" name="clear_ca"> 删除当前自定义 CA</label><small>留空会保留现有 CA；粘贴新证书会替换。</small>' : ''}
            </div>
            <div class="host-form-actions"><label class="form-check"><input type="checkbox" name="enabled" ${editing.enabled ? 'checked' : ''}> 启用此主机</label><div class="btn-group"><button class="btn btn-primary" type="submit">保存修改</button><button class="btn btn-secondary" type="button" onclick="HostManagement.cancelEdit()">取消</button></div></div>
          </form>
        </div>
      </div>` : ''}` : '<div class="alert alert-info">这里只显示管理员分配给你的主机。Agent 申请确认、主机编辑与删除需要中心管理员权限。</div>'}
      <div class="card host-list-card"><div class="card-header"><div><h3>纳管主机清单</h3><small>心跳表示 Agent 是否存活；回连检测表示中心能否访问 Agent 管理接口</small></div><div class="btn-group"><button class="btn btn-sm btn-secondary" onclick="HostManagement.refresh()">刷新清单</button><button class="btn btn-sm btn-primary" onclick="HostManagement.probeAll(false,true)">检测全部</button></div></div>
        ${this.loading ? '<div class="loading-spinner"><div class="spinner"></div> 加载中...</div>' : this.renderTable(canManage)}
      </div>`;
    this.updatePendingToolbar();
  },

  renderPending() {
    if (!this.pending.length) return '<div class="card pending-agent-card"><div class="card-header"><div><h3>待确认 Agent</h3><small>Agent 安装后会自动出现在这里</small></div></div><div class="empty-state compact"><div class="empty-icon">✓</div><h3>暂无待确认申请</h3><p>无需在管理端手工添加；在目标机执行上方命令即可。</p></div></div>';
    const selectedCount = this.pendingIDs().length;
    return `<div class="card pending-agent-card"><div class="card-header"><div><h3>待确认 Agent <span class="badge badge-return">${this.pending.length}</span></h3><small>确认时会由管理端回连 Agent 并验证自动交换的凭据</small></div><div class="pending-agent-actions"><span id="pending-selection-count">已选择 ${selectedCount} 台</span><button class="btn btn-sm btn-primary" data-pending-batch-action onclick="HostManagement.approvePending()" ${selectedCount ? '' : 'disabled'}>批量确认</button><button class="btn btn-sm btn-danger" data-pending-batch-action onclick="HostManagement.rejectPending()" ${selectedCount ? '' : 'disabled'}>批量拒绝</button></div></div><div class="table-container"><table><thead><tr><th class="selection-cell"><input id="pending-select-all" type="checkbox" aria-label="全选待确认 Agent" onchange="HostManagement.toggleAllPending(this.checked)" ${selectedCount === this.pending.length ? 'checked' : ''}></th><th>Agent</th><th>回连地址</th><th>来源 / 最近申请</th><th>操作</th></tr></thead><tbody>${this.pending.map(item => {
      const id = /^[a-f0-9]{24}$/.test(item.id) ? item.id : '';
      if (!id) return '';
      const httpsCA = item.base_url.startsWith('https://') ? `<details class="pending-ca"><summary>私有 CA（可选）</summary><textarea class="form-textarea mono" maxlength="262144" rows="3" placeholder="公开 CA 可留空；私有 CA 粘贴 PEM" oninput="HostManagement.setPendingCA('${id}',this.value)">${escapeHtml(this.pendingCAPEM[id] || '')}</textarea><small>中心按来源 IP 回连，证书必须包含 ${escapeHtml(item.source_ip)} 的 IP SAN。</small></details>` : '';
      return `<tr><td class="selection-cell"><input type="checkbox" data-enrollment-checkbox value="${id}" aria-label="选择 ${escapeHtml(item.name)}" onchange="HostManagement.togglePending('${id}',this.checked)" ${this.selectedPending[id] ? 'checked' : ''}></td><td><strong>${escapeHtml(item.name)}</strong><br><small>${escapeHtml(item.group || '未分组')} · ID ${id}</small></td><td><span class="mono">${escapeHtml(item.base_url)}</span>${item.existing_host_id ? '<br><span class="badge badge-return">地址变更申请</span>' : ''}${httpsCA}</td><td><span class="mono">${escapeHtml(item.source_ip)}</span><br><small>${escapeHtml(formatEnrollmentTime(item.last_seen_at))}</small></td><td><div class="btn-group"><button class="btn btn-xs btn-primary" onclick="HostManagement.approvePending('${id}')">确认</button><button class="btn btn-xs btn-danger" onclick="HostManagement.rejectPending('${id}')">拒绝</button></div></td></tr>`;
    }).join('')}</tbody></table></div></div>`;
  },

  renderTable(canManage) {
    if (!this.hosts.length) return '<div class="empty-state"><div class="empty-icon">🖥</div><h3>尚未纳管 Agent 主机</h3><p>在目标机运行安装脚本，然后在上方确认它的申请。</p></div>';
    return `<div class="table-container"><table><thead><tr><th>主机</th><th>Agent 地址</th><th>在线状态 / 心跳</th><th>认证</th><th>操作</th></tr></thead><tbody>${this.hosts.map(host => {
      const scheme = host.base_url.startsWith('https://') ? 'HTTPS' : 'HTTP';
      const status = this.statuses[host.id] || {};
      const view = hostStatusPresentation(host, status);
      return `<tr><td><strong>${escapeHtml(host.name)}</strong><br><small>${escapeHtml(host.group || '未分组')}</small></td><td><span class="badge badge-return">${scheme}</span> <span class="mono">${escapeHtml(host.base_url)}</span></td><td id="host-status-cell-${host.id}">${this.renderStatusCell(host)}</td><td>${host.has_api_key ? 'Agent Key 已加密' : '缺少 Agent Key'}${host.has_custom_ca ? ' · 自定义 CA' : ''}</td><td><div class="btn-group"><button class="btn btn-xs btn-secondary" onclick="HostManagement.probe('${host.id}',false)" ${status.loading || view.kind === 'offline' ? 'disabled' : ''}>检测</button><button class="btn btn-xs btn-primary" onclick="AppState.openHost('${host.id}','dashboard')" ${view.canOpen ? '' : 'disabled'}>查看配置</button>${canManage ? `<button class="btn btn-xs btn-secondary" onclick="HostManagement.edit('${host.id}')">编辑</button><button class="btn btn-xs btn-danger" onclick="HostManagement.remove('${host.id}')">移除</button>` : ''}</div></td></tr>`;
    }).join('')}</tbody></table></div>`;
  }
};

function hostStatusPresentation(host, status) {
  if (typeof hostConnectivityPresentation === 'function') return hostConnectivityPresentation(host, status);
  status = status || {};
  const seen = new Date(host.agent_last_seen_at || '').getTime();
  const reporting = Number.isFinite(seen) && Date.now() - seen <= 45000;
  const detail = Number.isFinite(seen) ? formatFallbackAgentSeen(seen) : '尚未收到 Agent 心跳';
  if (!host.enabled) return { text: '已停用', className: 'badge-drop', kind: 'disabled', canOpen: false, detail };
  if (Number.isFinite(seen) && !reporting) return { text: 'Agent 离线', className: 'badge-drop', kind: 'offline', canOpen: false, detail };
  if (status.queued || status.loading) return { text: '回连检测中…', className: 'badge-return', canOpen: true, detail };
  if (status.online) return { text: `在线 · ${Number(status.latency || 0)}ms`, className: 'badge-accept', canOpen: true, detail };
  if (status.error) return { text: reporting ? '回连异常' : '连接异常', className: 'badge-drop', canOpen: false, detail };
  if (reporting) return { text: 'Agent 在线', className: 'badge-accept', canOpen: true, detail };
  return { text: '等待 Agent 心跳', className: 'badge-return', canOpen: true, detail };
}

function formatFallbackAgentSeen(timestamp) {
  const seconds = Math.max(0, Math.floor((Date.now() - timestamp) / 1000));
  if (seconds < 10) return 'Agent 刚刚上报';
  if (seconds < 60) return `Agent ${seconds} 秒前上报`;
  if (seconds < 3600) return `Agent ${Math.floor(seconds / 60)} 分钟前上报`;
  return `Agent ${Math.floor(seconds / 3600)} 小时前上报`;
}

function formatHostCheckedAt(timestamp) {
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) return '检测时间未知';
  return `最近检测 ${date.toLocaleTimeString('zh-CN', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}`;
}

function formatEnrollmentTime(timestamp) {
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) return '申请时间未知';
  return `最近申请 ${date.toLocaleString('zh-CN', { hour12: false })}`;
}

if (typeof module !== 'undefined' && module.exports) module.exports = { HostManagement, hostStatusPresentation, formatHostCheckedAt, formatEnrollmentTime };
