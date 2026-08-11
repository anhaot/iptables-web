// ====== packet 规则创建/编辑弹窗 ======

const RuleForm = {
  rule: null,
  originalRule: null,
  callback: null,
  saving: false,
  preview: null,
  previewCandidate: null,
  previousFocus: null,
  scopeContext: null,

  open(rule, callback) {
    this.previousFocus = document.activeElement;
    this.scopeContext = AppState.captureHostContext();
    this.originalRule = rule ? { ...rule } : null;
    this.rule = normalizeDockerPortCandidate(rule ? { ...rule, backend: 'packet' } : {
      backend: 'packet', chain: 'FORWARD', action: 'DROP', protocol: 'tcp',
      source: '', dest: '', dport: '', original_dest: '', original_dport: '', sport: '', in_iface: '',
      out_iface: '', state: '', desc: '', enabled: true, position: 1,
    });
    this.callback = callback || (() => {});
    this.saving = false;
    this.preview = null;
    this.previewCandidate = null;
    this.render();
  },

  close() {
    const modal = document.getElementById('rule-modal');
    if (modal) modal.classList.add('hidden');
    this.callback = null;
    const previousFocus = this.previousFocus;
    this.previousFocus = null;
    this.scopeContext = null;
    if (previousFocus && typeof previousFocus.focus === 'function' && document.contains(previousFocus)) {
      setTimeout(() => previousFocus.focus(), 0);
    }
  },

  handleKeydown(event) {
    if (event.key === 'Escape') {
      event.preventDefault();
      this.close();
      return;
    }
    if (event.key !== 'Tab') return;
    const content = document.getElementById('rule-modal-content');
    if (!content) return;
    const focusable = Array.from(content.querySelectorAll('button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'));
    if (!focusable.length) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  },

  updateField(field, value) { this.rule[field] = value; },

  updateOriginalPort(value) {
    this.rule.original_dport = value;
    const dportInput = document.getElementById('rule-dport');
    if (!dportInput) return;
    const hasOriginalPort = String(value || '').trim() !== '';
    if (hasOriginalPort) {
      this.rule.dport = '';
      dportInput.value = '';
    }
    dportInput.disabled = hasOriginalPort;
  },

  async save() {
    const candidate = normalizeDockerPortCandidate({ ...this.rule, backend: 'packet' });
    this.previewCandidate = candidate;
    this.preview = buildRuleChangePreview(this.originalRule, candidate);
    this.render();
  },

  backToEdit() {
    this.preview = null;
    this.previewCandidate = null;
    this.render();
  },

  async confirmSave() {
    const candidate = this.previewCandidate;
    if (!candidate) return;
    const context = this.scopeContext;
    if (!AppState.isHostContextCurrent(context)) {
      Toasts.warning('主机已切换，请在当前主机重新打开规则编辑器');
      this.close();
      return;
    }
    if (isBroadDropRule(candidate)) {
      const accepted = await Dialogs.confirm({
        title: '确认高风险阻断规则',
        message: '这条规则没有限定来源、目标、端口或网卡，会丢弃整条链上的大量流量，可能中断管理连接或业务。',
        target: `${AppState.currentHostTarget()} · ${candidate.chain} ${candidate.action}`,
        confirmText: '仍然保存',
        danger: true
      });
      if (!accepted) return;
    }
    this.saving = true;
    this.render();
    try {
      const saved = candidate.id ? await api.updateRule(candidate.id, candidate, context.hostID) : await api.createRule(candidate, context.hostID);
      AppState.invalidateRuleSummary(context);
      if (!AppState.isHostContextCurrent(context)) {
        this.close();
        return;
      }
      Toasts.success(candidate.id ? '规则已更新' : '规则已创建');
      const callback = this.callback;
      this.close();
      if (callback) callback(saved);
    } catch (e) {
      Toasts.error('保存失败：' + e.message);
      this.saving = false;
      this.preview = null;
      this.previewCandidate = null;
      this.render();
    }
  },

  render() {
    const modal = document.getElementById('rule-modal');
    const content = document.getElementById('rule-modal-content');
    if (!modal || !content || !this.rule) return;
    const wasHidden = modal.classList.contains('hidden');
    modal.classList.remove('hidden');
    const r = this.rule;
    const isEdit = !!r.id;
    content.innerHTML = `
      <div class="modal-header"><h2 id="rule-modal-title">${isEdit ? '✏️ 编辑规则' : '➕ 创建新规则'}</h2><button class="modal-close" type="button" aria-label="关闭规则编辑器" onclick="RuleForm.close()">✕</button></div>
      <div class="alert alert-info">规则由 packet 后端管理。Docker 发布端口请选择 FORWARD / DOCKER_USER，并优先填写“原始目标端口”。</div>
      <div class="form-group"><label class="form-label">描述说明</label><input class="form-input" type="text" aria-label="描述说明" value="${escapeHtml(r.desc || '')}" placeholder="例如：仅允许内网访问 Docker nginx" oninput="RuleForm.updateField('desc',this.value)"></div>
      <div class="form-row">
        <div class="form-group"><label class="form-label">链 (Chain)</label><select class="form-select" aria-label="链" onchange="RuleForm.updateField('chain',this.value)">
          ${['FORWARD','INPUT','DOCKER_USER','OUTPUT','DOCKER'].map(value => `<option value="${value}" ${r.chain === value ? 'selected' : ''}>${value}</option>`).join('')}
        </select><div class="form-hint">Docker 转发流量通常选 DOCKER_USER；宿主机入站服务选 INPUT</div></div>
        <div class="form-group"><label class="form-label">动作 (Action)</label><select class="form-select" aria-label="动作" onchange="RuleForm.updateField('action',this.value)">
          ${[['ACCEPT','允许'],['DROP','丢弃'],['REJECT','拒绝'],['LOG','记录日志'],['RETURN','返回']].map(([value,label]) => `<option value="${value}" ${r.action === value ? 'selected' : ''}>${value} — ${label}</option>`).join('')}
        </select><div class="form-hint">白名单必须让 ACCEPT 位于兜底 DROP / REJECT 前面</div></div>
      </div>
	      <div class="form-row">
	        <div class="form-group"><label class="form-label">Docker 映射前的宿主机 IP</label><input class="form-input" type="text" aria-label="Docker 映射前的宿主机 IP" value="${escapeHtml(r.original_dest || '')}" placeholder="例如 10.0.0.5；0.0.0.0 映射留空" oninput="RuleForm.updateField('original_dest',this.value)"><div class="form-hint">用于区分不同宿主机 IP 上相同的发布端口；仅用于 FORWARD / DOCKER_USER。</div></div>
	        <div class="form-group"><label class="form-label">Docker 映射前的宿主机端口</label><input class="form-input" type="text" aria-label="Docker 映射前的宿主机端口" value="${escapeHtml(r.original_dport || '')}" placeholder="例如 18080；仅用于 FORWARD / DOCKER_USER" oninput="RuleForm.updateOriginalPort(this.value)"><div class="form-hint">填写后会禁用并清空普通 dport。Docker DNAT 后普通 dport 已是容器端口。</div></div>
	      </div>
      <div class="form-row">
        <div class="form-group"><label class="form-label">协议</label><select class="form-select" aria-label="协议" onchange="RuleForm.updateField('protocol',this.value)">${['tcp','udp','icmp','all'].map(value => `<option value="${value}" ${r.protocol === value ? 'selected' : ''}>${value.toUpperCase()}</option>`).join('')}</select></div>
        <div class="form-group"><label class="form-label">连接状态 (conntrack)</label><select class="form-select" aria-label="连接状态" onchange="RuleForm.updateField('state',this.value)">${['','NEW','ESTABLISHED','RELATED','NEW,ESTABLISHED','ESTABLISHED,RELATED','INVALID'].map(value => `<option value="${value}" ${r.state === value ? 'selected' : ''}>${value || '任意'}</option>`).join('')}</select></div>
      </div>
      <div class="form-row">
        ${textField('来源 IP/CIDR','source',r.source,'例如：192.168.1.0/24，留空表示任意')}
        ${textField('目标 IP/CIDR','dest',r.dest,'例如：10.0.0.1，留空表示任意')}
      </div>
      <div class="form-row">
        <div class="form-group"><label class="form-label">目标端口 (dport)</label><input id="rule-dport" class="form-input" type="text" aria-label="目标端口" value="${escapeHtml(r.dport || '')}" placeholder="普通 INPUT 规则填写；使用原始目标端口时留空" oninput="RuleForm.updateField('dport',this.value)" ${r.original_dport ? 'disabled' : ''}><div class="form-hint">Docker 原始宿主机端口已填写时，本字段必须为空。</div></div>
        ${textField('来源端口 (sport)','sport',r.sport,'例如：1024:65535，留空表示任意')}
      </div>
      <div class="form-row">
        ${textField('入站网卡','in_iface',r.in_iface,'例如：ens33, docker0')}
        ${textField('出站网卡','out_iface',r.out_iface,'例如：ens33, docker0')}
      </div>
      <div class="form-group"><label class="form-label">规则位置</label><input class="form-input" type="number" aria-label="规则位置" min="1" value="${escapeHtml(String(r.position || 1))}" oninput="RuleForm.updateField('position',parseInt(this.value,10)||1)"><div class="form-hint">超出范围会自动放到链末尾；保存后可在具体链中拖动调整。</div></div>
      <div class="form-group"><label class="form-label"><input type="checkbox" ${r.enabled ? 'checked' : ''} onchange="RuleForm.updateField('enabled',this.checked)" style="margin-right:.5rem">立即启用此规则</label></div>
      ${isEdit ? `<div style="font-size:.75rem;color:var(--text-muted)">ID: <span class="mono">${escapeHtml(r.id)}</span></div>` : ''}
      ${this.preview ? renderRuleChangePreview(this.preview) : ''}
      <div class="modal-footer">
        ${this.preview
          ? `<button class="btn btn-secondary" onclick="RuleForm.backToEdit()" ${this.saving ? 'disabled' : ''}>返回修改</button><button class="btn btn-primary" onclick="RuleForm.confirmSave()" ${this.saving ? 'disabled' : ''}>${this.saving ? '保存中...' : '确认并保存'}</button>`
          : `<button class="btn btn-secondary" onclick="RuleForm.close()">取消</button><button class="btn btn-primary" onclick="RuleForm.save()">预览变更</button>`}
      </div>`;
    if (wasHidden) {
      setTimeout(() => {
        const firstField = content.querySelector('input:not([disabled]), select:not([disabled]), textarea:not([disabled])') || content.querySelector('button:not([disabled])');
        if (firstField) firstField.focus();
        else content.focus();
      }, 0);
    } else if (!content.contains(document.activeElement)) {
      content.focus();
    }
  }
};

const RULE_PREVIEW_FIELDS = [
  ['chain','链'], ['action','动作'], ['protocol','协议'], ['source','来源'], ['dest','目标'],
  ['dport','目标端口'], ['original_dest','Docker 原始目标 IP'], ['original_dport','Docker 原始目标端口'],
  ['sport','来源端口'], ['in_iface','入站网卡'], ['out_iface','出站网卡'], ['state','连接状态'],
  ['position','位置'], ['enabled','启用状态'], ['desc','描述'],
];

function buildRuleChangePreview(before, after) {
  const rows = [];
  for (const [field, label] of RULE_PREVIEW_FIELDS) {
    const oldValue = before ? previewValue(field, before[field]) : '—';
    const newValue = previewValue(field, after[field]);
    if ((!before && newValue !== '—') || (before && oldValue !== newValue)) {
      rows.push({ field, label, before: oldValue, after: newValue });
    }
  }
  return { mode: before ? 'update' : 'create', rows };
}

function previewValue(field, value) {
  if (field === 'enabled') return value ? '已启用' : '已禁用';
  if (value === undefined || value === null || value === '') return '—';
  return String(value);
}

function renderRuleChangePreview(preview) {
  const rows = preview.rows.length
    ? preview.rows.map(row => `<tr><td>${escapeHtml(row.label)}</td><td class="mono">${escapeHtml(row.before)}</td><td class="mono">${escapeHtml(row.after)}</td></tr>`).join('')
    : '<tr><td colspan="3">没有检测到字段变化。</td></tr>';
  return `<div class="rule-change-preview">
    <div class="alert alert-warning"><strong>变更预览：</strong>请核对规则作用范围和执行位置，确认后才会写入防火墙。</div>
    <div class="table-container"><table><thead><tr><th>字段</th><th>变更前</th><th>变更后</th></tr></thead><tbody>${rows}</tbody></table></div>
  </div>`;
}

function textField(label, field, value, placeholder) {
  return `<div class="form-group"><label class="form-label">${escapeHtml(label)}</label><input class="form-input" type="text" aria-label="${escapeHtml(label)}" value="${escapeHtml(value || '')}" placeholder="${escapeHtml(placeholder)}" oninput="RuleForm.updateField('${field}',this.value)"></div>`;
}

function isBroadDropRule(rule) {
  const action = String(rule.action || '').toUpperCase();
  return ['DROP','REJECT'].includes(action) && !rule.source && !rule.dest && !rule.dport && !rule.original_dest && !rule.original_dport && !rule.sport && !rule.in_iface && !rule.out_iface && !rule.state;
}

function normalizeDockerPortCandidate(rule) {
  const normalized = { ...(rule || {}) };
  if (String(normalized.original_dport || '').trim()) normalized.dport = '';
  return normalized;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { isBroadDropRule, normalizeDockerPortCandidate, buildRuleChangePreview };
}
