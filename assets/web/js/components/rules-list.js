// ====== packet 规则列表管理 ======

const RulesList = {
  rules: [], loading: false, error: null, filterChain: '', searchQuery: '',
  pendingOrder: null, draggedId: '', interpretationVisible: false, refreshSerial: 0,

  async refresh() {
    const serial = ++this.refreshSerial;
    const context = AppState.captureHostContext();
    this.loading = true; this.error = null; this.pendingOrder = null; this.interpretationVisible = false; this.render();
    try {
      const info = await api.getSystemInfo(context.hostID);
      if (serial !== this.refreshSerial || !AppState.isHostContextCurrent(context)) return;
      const rules = await api.listRules(this.filterChain || '', 'packet', context.hostID);
      if (serial !== this.refreshSerial || !AppState.isHostContextCurrent(context)) return;
      AppState.systemInfo = info;
      this.rules = rules;
    } catch (e) {
      if (serial === this.refreshSerial && AppState.isHostContextCurrent(context)) this.error = e.message;
    } finally {
      if (serial === this.refreshSerial && AppState.isHostContextCurrent(context)) {
        this.loading = false;
        this.render();
      }
    }
  },

  async toggle(id) {
    if (!AppState.canManageRules()) return Toasts.error('需要管理员权限');
    const context = AppState.captureHostContext();
    try {
      const updated = await api.toggleRule(id, context.hostID);
      AppState.invalidateRuleSummary(context);
      if (!AppState.isHostContextCurrent(context)) return;
      const index = this.rules.findIndex(rule => rule.id === id);
      if (index >= 0) this.rules[index] = updated;
      this.render();
      Toasts.success(updated.enabled ? '规则已启用' : '规则已禁用');
    } catch (e) { Toasts.error('切换失败：' + e.message); }
  },

  async deleteRule(id) {
    if (!AppState.canManageRules()) return Toasts.error('需要管理员权限');
    const context = AppState.captureHostContext();
    const rule = this.rules.find(item => item.id === id);
    const accepted = await Dialogs.confirm({
      title: '删除防火墙规则',
      message: '规则会立即从运行中的防火墙和托管清单中删除，此操作不可撤销。',
      target: `${AppState.currentHostTarget()} · ${rule ? (rule.desc || `${rule.chain} ${rule.action}`) : id}`,
      confirmText: '删除规则',
      danger: true
    });
    if (!accepted) return;
    if (!AppState.isHostContextCurrent(context)) return Toasts.warning('主机已切换，请重新执行删除操作');
    try { await api.deleteRule(id, context.hostID); AppState.invalidateRuleSummary(context); if (!AppState.isHostContextCurrent(context)) return; this.rules = this.rules.filter(rule => rule.id !== id); this.render(); Toasts.success('规则已删除'); }
    catch (e) { Toasts.error('删除失败：' + e.message); }
  },

  openCreate() {
    if (!AppState.canManageRules()) return Toasts.error('需要管理员权限');
    RuleForm.open(null, () => this.refresh());
  },

  openEdit(id) {
    if (!AppState.canManageRules()) return Toasts.error('需要管理员权限');
    const rule = this.rules.find(item => item.id === id);
    if (rule) RuleForm.open(rule, () => this.refresh());
  },

  setChain(chain) { this.filterChain = chain; this.pendingOrder = null; this.interpretationVisible = false; this.refresh(); },
  toggleInterpretation() { this.interpretationVisible = !this.interpretationVisible; this.render(); },
  resetOrder() { this.pendingOrder = null; this.interpretationVisible = false; this.render(); },

  getOrderedChainRules() {
    const rules = this.rules.filter(rule => !this.filterChain || rule.chain === this.filterChain).sort((a,b) => (a.position || 0) - (b.position || 0));
    if (!this.filterChain || !this.pendingOrder) return rules;
    const byID = new Map(rules.map(rule => [rule.id, rule]));
    return this.pendingOrder.map(id => byID.get(id)).filter(Boolean).concat(rules.filter(rule => !this.pendingOrder.includes(rule.id)));
  },

  get hasPendingOrder() {
    if (!this.filterChain || !this.pendingOrder) return false;
    const current = this.rules.filter(rule => rule.chain === this.filterChain).sort((a,b) => (a.position || 0) - (b.position || 0)).map(rule => rule.id);
    return this.pendingOrder.join('|') !== current.join('|');
  },

  get filtered() {
    let rules = this.filterChain ? this.getOrderedChainRules() : this.rules;
    const query = this.searchQuery.trim().toLowerCase();
    if (!query) return rules;
    return rules.filter(rule => [rule.desc, rule.source, rule.dest, rule.dport, rule.original_dest, rule.original_dport, rule.chain].some(value => String(value || '').toLowerCase().includes(query)));
  },

  reorderDraft(from, to) { this.pendingOrder = reorderItems(this.getOrderedChainRules(), from, to).map(rule => rule.id); this.render(); },
  dragStart(id, event) { if (!AppState.canManageRules() || !this.filterChain || this.searchQuery) return; this.draggedId = id; if (event.dataTransfer) { event.dataTransfer.effectAllowed='move'; event.dataTransfer.setData('text/plain',id); } },
  dragOver(event) { if (this.draggedId && !this.searchQuery) event.preventDefault(); },
  dragDrop(targetId, event) { if (event) event.preventDefault(); const rules = this.getOrderedChainRules(); const from = rules.findIndex(rule => rule.id === this.draggedId); const to = rules.findIndex(rule => rule.id === targetId); this.draggedId=''; if (from >= 0 && to >= 0 && from !== to) this.reorderDraft(from,to); },
  dragEnd() { this.draggedId=''; },

  async saveOrder() {
    if (!AppState.canManageRules()) return Toasts.error('需要管理员权限');
    if (!this.filterChain || !this.pendingOrder) return;
    const context = AppState.captureHostContext();
    const risk = findOrderingRisk(this.getOrderedChainRules());
    if (risk) return Toasts.error(risk);
    try { await api.reorderRules(this.filterChain, this.pendingOrder, context.hostID); AppState.invalidateRuleSummary(context); if (!AppState.isHostContextCurrent(context)) return; Toasts.success('规则顺序已更新'); await this.refresh(); }
    catch (e) { Toasts.error('保存顺序失败：' + e.message); }
  },

  render() {
    const root = document.getElementById('rules-content'); if (!root) return;
    const chains = ['', 'FORWARD', 'INPUT', 'DOCKER_USER', 'OUTPUT', 'DOCKER'];
    const labels = {'':'全部链',FORWARD:'FORWARD',INPUT:'INPUT',DOCKER_USER:'DOCKER_USER',OUTPUT:'OUTPUT',DOCKER:'DOCKER'};
    const canManage = AppState.canManageRules();
    const chainRules = this.filterChain ? this.getOrderedChainRules() : [];
    const risk = this.filterChain ? findOrderingRisk(chainRules) : '';
    const canReorder = canManage && !!this.filterChain && !this.searchQuery && chainRules.length > 1;
    root.innerHTML = `
      <div class="toolbar" style="margin-bottom:1rem"><div class="chain-pills">${chains.map(chain => `<button class="chain-pill ${this.filterChain === chain ? 'active' : ''}" onclick="RulesList.setChain('${chain}')" title="${escapeHtml(chain ? FirewallHelp.chainTitle(chain) : '查看全部托管规则；选择具体链后才能排序。')}">${labels[chain]}${chain ? '<span class="help-dot">?</span>' : ''}</button>`).join('')}</div>
        <input class="search-input" type="text" placeholder="搜索规则..." value="${escapeHtml(this.searchQuery)}" oninput="RulesList.searchQuery=this.value;RulesList.render()">
        ${canManage ? '<button class="btn btn-primary" onclick="RulesList.openCreate()">+ 添加规则</button>' : ''}</div>
      ${this.error ? `<div class="alert alert-error">${escapeHtml(this.error)} <button class="btn btn-sm btn-ghost" onclick="RulesList.refresh()">重试</button></div>` : ''}
      ${!canManage ? '<div class="alert alert-info">当前账号为只读权限。</div>' : ''}
      ${this.filterChain ? `<div class="toolbar" style="margin-bottom:1rem"><span style="font-size:.85rem;color:var(--text-muted)">当前链：<strong>${escapeHtml(this.filterChain)}</strong>。规则按从上到下匹配。</span><button class="btn btn-secondary" onclick="RulesList.toggleInterpretation()">${this.interpretationVisible ? '收起解读' : '解读顺序'}</button>${canManage ? `<button class="btn btn-primary" onclick="RulesList.saveOrder()" ${!this.hasPendingOrder || risk ? 'disabled' : ''}>保存顺序</button><button class="btn btn-secondary" onclick="RulesList.resetOrder()" ${!this.hasPendingOrder ? 'disabled' : ''}>撤销调整</button>` : ''}</div>` : '<div class="sorting-hint">选择具体链后，可以拖动规则调整顺序。</div>'}
      ${this.filterChain && this.searchQuery ? '<div class="alert alert-warning">清空搜索条件后才能调整顺序。</div>' : ''}
      ${this.filterChain && chainRules.length <= 1 ? '<div class="sorting-hint">至少有两条规则时才能调整顺序。</div>' : ''}
      ${this.hasPendingOrder && !risk ? '<div class="alert alert-info">顺序草稿尚未生效，请点击“保存顺序”。</div>' : ''}
      ${risk ? `<div class="alert alert-error">${escapeHtml(risk)}</div>` : ''}
      ${this.filterChain && this.interpretationVisible ? renderOrderInterpretation(chainRules,risk) : ''}
      ${this.loading ? '<div class="loading-spinner"><div class="spinner"></div> 加载规则中...</div>' : ''}
      ${!this.loading ? renderRulesTable(this.filtered, canManage, canReorder, !!this.filterChain) : ''}`;
  }
};

function renderRulesTable(rules, canManage, canReorder, hasChain) {
  if (!rules.length) return `<div class="empty-state"><div class="empty-icon">🔒</div><h3>暂无规则</h3><p>添加第一条 packet 防火墙规则开始管理。</p>${canManage ? '<button class="btn btn-primary" onclick="RulesList.openCreate()">创建第一条规则</button>' : ''}</div>`;
  return `<div class="table-container"><table class="rules-table"><thead><tr><th>顺序</th><th>描述</th><th>链</th><th>来源</th><th>目标</th><th>协议/端口</th><th>动作</th><th>状态</th><th>操作</th></tr></thead><tbody>${rules.map((rule,index) => `<tr draggable="${canReorder}" ondragstart="RulesList.dragStart('${escapeHtml(rule.id)}',event)" ondragover="RulesList.dragOver(event)" ondrop="RulesList.dragDrop('${escapeHtml(rule.id)}',event)" ondragend="RulesList.dragEnd()" style="opacity:${rule.enabled ? '1' : '.5'}">
    <td class="mono rule-order-cell"><span class="drag-handle ${canReorder ? '' : 'disabled'}">⋮⋮</span>${hasChain ? index+1 : (rule.position || index+1)}</td><td><strong>${escapeHtml(displayRuleDescription(rule))}</strong><div class="rule-id">${escapeHtml((rule.id || '').substring(0,8))}</div></td>
    <td><span class="badge badge-return" title="${escapeHtml(FirewallHelp.chainTitle(rule.chain))}">${escapeHtml(rule.chain)}</span></td><td class="mono">${escapeHtml(rule.source || '任意来源')}</td><td class="mono">${escapeHtml(rule.dest || '任意目标')}</td>
    <td class="mono">${escapeHtml(rule.protocol || 'all')}${rule.dport ? ' dpt:' + escapeHtml(rule.dport) : ''}${rule.original_dest ? ' original-dst:' + escapeHtml(rule.original_dest) : ''}${rule.original_dport ? ' original-dpt:' + escapeHtml(rule.original_dport) : ''}${rule.sport ? ' spt:' + escapeHtml(rule.sport) : ''}</td><td>${actionBadge(rule.action)}</td>
    <td><label class="toggle"><input type="checkbox" aria-label="${rule.enabled ? '禁用' : '启用'}规则：${escapeHtml(displayRuleDescription(rule))}" ${rule.enabled ? 'checked' : ''} ${canManage ? '' : 'disabled'} onchange="RulesList.toggle('${escapeHtml(rule.id)}')"><span class="slider"></span></label></td>
    <td>${canManage ? `<div class="btn-group rule-action-buttons"><button class="btn btn-xs btn-secondary" aria-label="编辑规则：${escapeHtml(displayRuleDescription(rule))}" title="编辑规则" onclick="RulesList.openEdit('${escapeHtml(rule.id)}')">✎</button><button class="btn btn-xs btn-danger" aria-label="删除规则：${escapeHtml(displayRuleDescription(rule))}" title="删除规则" onclick="RulesList.deleteRule('${escapeHtml(rule.id)}')">✕</button></div>` : '只读'}</td></tr>`).join('')}</tbody></table></div>`;
}

function actionBadge(action) {
  const classes={ACCEPT:'badge-accept',DROP:'badge-drop',REJECT:'badge-reject',LOG:'badge-log',RETURN:'badge-return'};
  const labels={ACCEPT:'允许',DROP:'丢弃',REJECT:'拒绝',LOG:'日志',RETURN:'返回'};
  return `<span class="badge ${classes[action] || ''}">${escapeHtml(labels[action] || action)}</span>`;
}

function findOrderingRisk(rules) {
  for (let i=0;i<rules.length;i++) { const blocker=rules[i]; if (!blocker.enabled || !['DROP','REJECT'].includes(String(blocker.action||'').toUpperCase()) || blocker.source || blocker.dest) continue;
    for (let j=i+1;j<rules.length;j++) { const later=rules[j]; if (later.enabled && String(later.action||'').toUpperCase()==='ACCEPT' && later.source && dropBlocksAccept(blocker,later)) return `不能把兜底 ${blocker.action} 放到允许规则前面，否则 ${later.source} 的流量会被先拦截`; }
  } return '';
}

function dropBlocksAccept(drop,accept) {
  const same=(a,b) => !String(a||'') || String(a||'')===String(b||'');
  const proto=String(drop.protocol||'all').toLowerCase();
  return (proto==='all' || proto==='' || proto===String(accept.protocol||'all').toLowerCase()) && same(drop.dport,accept.dport) && same(drop.original_dest,accept.original_dest) && same(drop.original_dport,accept.original_dport) && same(drop.sport,accept.sport) && same(drop.in_iface,accept.in_iface) && same(drop.out_iface,accept.out_iface);
}

function reorderItems(items,from,to) { const result=items.slice(); if (from<0 || to<0 || from>=result.length || to>=result.length || from===to) return result; const moved=result.splice(from,1)[0]; result.splice(to,0,moved); return result; }

function renderOrderInterpretation(rules,risk) { return `<div class="alert ${risk ? 'alert-warning' : 'alert-info'}"><strong>规则顺序解读</strong><ol style="margin:.5rem 0 0 1.25rem">${rules.map((rule,index) => `<li>${escapeHtml(describeRule(rule,index+1))}</li>`).join('')}</ol>${risk ? `<div><strong>风险：</strong>${escapeHtml(risk)}</div>` : ''}</div>`; }
function describeRule(rule,index) { const action={ACCEPT:'允许',DROP:'丢弃',REJECT:'拒绝',LOG:'记录日志',RETURN:'返回上级链'}[String(rule.action||'').toUpperCase()] || rule.action; const port=rule.original_dport ? `Docker 原始宿主机端口 ${rule.original_dport}` : (rule.dport ? `目标端口 ${rule.dport}` : '任意目标端口'); return `第 ${index} 条：${action} ${rule.source || '任意来源'} 到 ${rule.dest || '任意目标'} 的 ${(rule.protocol || 'all').toUpperCase()} 流量，${port}${rule.enabled ? '' : '（当前禁用）'}`; }

function displayRuleDescription(rule) {
  const desc = String((rule || {}).desc || '');
  const originalPort = String((rule || {}).original_dport || '');
  if (!desc || !originalPort) return desc || '—';
  const oldDockerDirection = desc.match(/^(.*?)([^\s]+):(\d+)\s*→\s*:(\d+)$/);
  if (!oldDockerDirection || oldDockerDirection[4] !== originalPort) return desc;
  return `${oldDockerDirection[1]}宿主机:${oldDockerDirection[4]} → ${oldDockerDirection[2]}:${oldDockerDirection[3]}`;
}

if (typeof module !== 'undefined' && module.exports) module.exports={reorderItems,findOrderingRisk,dropBlocksAccept,displayRuleDescription};
