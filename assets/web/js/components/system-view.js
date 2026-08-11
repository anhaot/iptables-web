// ====== 系统管理：用户管理、备份、恢复 ======

const SystemView = {
  loading: false,
  restoreData: '',
  restoreFileName: '',
  restoreFileSize: 0,
  restoreFileError: '',
  restoreConfirm: false,
  users: [],
  editingUser: null,
  showUserModal: false,
  showPasswordModal: false,
  auditEvents: [],
  rollback: { available: false },
  rollbackConfirm: false,
  hosts: [],
  securityPolicy: null,
  accessKeys: [],
  newAccessKey: null,
  refreshSerial: 0,

  async refresh() {
    var serial = ++this.refreshSerial;
    var context = AppState.captureHostContext();
    this.loading = true;
    this.render();
    var role = sessionStorage.getItem('auth_role') || '';
    var requests = [];
    var mode = AppState.page;
    if (mode === 'users' && (role === 'admin' || !getAuthToken())) requests = [api.listUsers(), api.listHosts(), api.getSecurityPolicy(), api.listAccessKeys()];
    if (mode === 'system') requests = [
      (!AppState.activeLocal() || AppState.canManageFleet()) ? api.listAuditEvents(20, context.hostID) : Promise.resolve([]),
      api.getRollbackStatus(context.hostID)
    ];
    var results = await Promise.allSettled(requests);
    if (serial !== this.refreshSerial || AppState.page !== mode || (mode === 'system' && !AppState.isHostContextCurrent(context))) return;
    if (mode === 'users') {
      if (results[0] && results[0].status === 'fulfilled') this.users = results[0].value;
      if (results[1] && results[1].status === 'fulfilled') this.hosts = results[1].value;
      if (results[2] && results[2].status === 'fulfilled') this.securityPolicy = results[2].value;
      if (results[3] && results[3].status === 'fulfilled') this.accessKeys = results[3].value;
    }
    if (mode === 'system') {
      if (results[0] && results[0].status === 'fulfilled') this.auditEvents = results[0].value;
      if (results[1] && results[1].status === 'fulfilled') this.rollback = results[1].value;
    }
    this.loading = false;
    this.render();
  },

  // ==================== Backup / Restore ====================

  async doBackup() {
    if (!AppState.canManageRules()) {
      Toasts.error('没有当前主机的管理权限');
      return;
    }
    const context = AppState.captureHostContext();
    try {
	  const backup = await api.backupRules('all', context.hostID);
      if (!AppState.isHostContextCurrent(context)) return;
      const url = URL.createObjectURL(backup.blob);
      const a = document.createElement('a');
      a.href = url;
	  a.download = backup.filename || ('iptables-web-complete-' + new Date().toISOString().slice(0,10) + '.json');
      a.click();
      URL.revokeObjectURL(url);
      Toasts.success('备份已下载');
    } catch (e) {
      Toasts.error('备份失败：' + e.message);
    }
  },

  async doRestore() {
    if (!AppState.canManageRules()) {
      Toasts.error('没有当前主机的管理权限');
      return;
    }
    if (!this.restoreData.trim()) {
	  Toasts.warning('请先选择完整备份 JSON 文件');
      return;
    }
    if (!this.restoreConfirm) {
      this.restoreConfirm = true;
      this.render();
      return;
    }
    const context = AppState.captureHostContext();
    try {
	  await api.restoreRulesFile(this.restoreData, undefined, context.hostID);
      AppState.invalidateRuleSummary(context);
      if (!AppState.isHostContextCurrent(context)) return;
      this.restoreData = '';
	  this.restoreFileName = '';
	  this.restoreFileSize = 0;
	  this.restoreFileError = '';
      this.restoreConfirm = false;
      Toasts.success('规则集已成功恢复');
      this.render();
    } catch (e) {
      Toasts.error('恢复失败：' + e.message);
      this.restoreConfirm = false;
      this.render();
    }
  },

  async selectRestoreFile(input) {
	this.restoreConfirm = false;
	this.restoreFileError = '';
	var file = input && input.files ? input.files[0] : null;
	if (!file) return;
	if (file.size > 16 * 1024 * 1024) {
	  this.restoreData = '';
	  this.restoreFileName = '';
	  this.restoreFileSize = 0;
	  this.restoreFileError = '备份文件超过 16 MB 上限';
	  this.render();
	  return;
	}
	try {
	  var text = await file.text();
	  var documentData = JSON.parse(text);
	  if (!documentData || !documentData.manifest || documentData.manifest.format !== 'iptables-web-combined-backup') {
		throw new Error('不是 iptables-web 下载的完整备份 JSON');
	  }
	  if (documentData.manifest.version !== 1) {
		throw new Error('不支持的备份版本：' + documentData.manifest.version);
	  }
	  if (!documentData.files || typeof documentData.files['packet.rules'] !== 'string' || !documentData.files['packet.rules'].trim()) {
		throw new Error('备份中缺少 packet.rules，可能是导出时防火墙备份失败');
	  }
	  var managedName = documentData.manifest.managed_rules_file || 'managed-rules.json';
	  if (typeof documentData.files[managedName] !== 'string') {
		throw new Error('备份中缺少 ' + managedName);
	  }
	  this.restoreData = text;
	  this.restoreFileName = file.name;
	  this.restoreFileSize = file.size;
	} catch (e) {
	  this.restoreData = '';
	  this.restoreFileName = '';
	  this.restoreFileSize = 0;
	  this.restoreFileError = e.message || '无法读取备份文件';
	}
	this.render();
  },

  clearRestoreFile() {
	this.restoreData = '';
	this.restoreFileName = '';
	this.restoreFileSize = 0;
	this.restoreFileError = '';
	this.restoreConfirm = false;
	this.render();
  },

  async clearManagedRules() {
    if (!AppState.canManageRules()) {
      Toasts.error('没有当前主机的管理权限');
      return;
    }
    const context = AppState.captureHostContext();
    const accepted = await Dialogs.confirm({
      title: '清空界面托管规则',
      message: '会立即从运行中的防火墙删除全部界面托管规则并清空 rules.json；不会 flush 链，也不会删除外部规则。',
      target: AppState.currentHostTarget(),
      confirmText: '清空托管规则',
      danger: true
    });
    if (!accepted) return;
    if (!AppState.isHostContextCurrent(context)) return Toasts.warning('主机已切换，请重新执行清空操作');
    try {
      const result = await api.clearManagedRules(context.hostID);
      AppState.invalidateRuleSummary(context);
      if (!AppState.isHostContextCurrent(context)) return;
      const removed = Number((result || {}).removed || 0);
      Toasts.success('已清空 ' + removed + ' 条界面托管规则，现在可以卸载服务');
      await AppState.refreshSystemInfo();
      this.render();
    } catch (e) {
      Toasts.error('清空失败：' + e.message);
    }
  },

  async downloadAudit() {
    var context = AppState.captureHostContext();
    try {
      var audit = await api.downloadAudit(context.hostID);
      if (!AppState.isHostContextCurrent(context)) return;
      var url = URL.createObjectURL(audit.blob);
      var link = document.createElement('a');
      link.href = url;
      link.download = audit.filename || ('iptables-web-audit-' + new Date().toISOString().slice(0, 10) + '.json');
      link.click();
      URL.revokeObjectURL(url);
      Toasts.success('审计日志已导出');
    } catch (e) {
      Toasts.error(e.message || '审计日志导出失败');
    }
  },

  async rollbackLastChange() {
    if (!this.rollback || !this.rollback.available) {
      Toasts.warning('当前没有可用的回滚窗口');
      return;
    }
    if (!this.rollbackConfirm) {
      this.rollbackConfirm = true;
      this.render();
      return;
    }
    var context = AppState.captureHostContext();
    try {
      var result = await api.rollbackLastChange(this.rollback.id, context.hostID);
      AppState.invalidateRuleSummary(context);
      if (!AppState.isHostContextCurrent(context)) return;
      this.rollbackConfirm = false;
      Toasts.success('已回滚 ' + Number(result.restored_rules || 0) + ' 条托管规则');
      await AppState.refreshSystemInfo();
      await this.refresh();
    } catch (e) {
      this.rollbackConfirm = false;
      Toasts.error('回滚失败：' + e.message);
      await this.refresh();
    }
  },

  // ==================== User Management ====================

  openCreateUser() {
    this.editingUser = null;
    this.showUserModal = true;
    this.render();
  },

  openEditUser(id) {
    this.editingUser = this.users.find(function(u) { return u.id === id; }) || null;
    this.showUserModal = true;
    this.render();
  },

  closeUserModal() {
    this.showUserModal = false;
    this.showPasswordModal = false;
    this.editingUser = null;
    this.render();
  },

  openPasswordChange() {
    this.showPasswordModal = true;
    this.render();
  },

  updateHostAssignmentVisibility(role) {
    var element = document.getElementById('su-host-assignments');
    if (element) element.hidden = role === 'admin';
  },

  updateLockoutVisibility(mode) {
    var field = document.getElementById('sp-lockout-minutes');
    if (field) field.disabled = mode !== 'timed';
  },

  async saveUser(formEl) {
    var username = formEl.querySelector('#su-username').value.trim();
    var password = formEl.querySelector('#su-password').value;
    var role = formEl.querySelector('#su-role').value;
    var hostIDs = Array.from(formEl.querySelectorAll('input[name="host_ids"]:checked')).map(function(input) { return input.value; });
    var hostGroups = Array.from(formEl.querySelectorAll('input[name="host_groups"]:checked')).map(function(input) { return input.value; });
    var data = { username: username, role: role, host_ids: role === 'user' ? hostIDs : [], host_groups: role === 'user' ? hostGroups : [] };
    if (password) data.password = password;

    try {
      if (this.editingUser) {
        await api.updateUser(this.editingUser.id, data);
        Toasts.success('用户已更新');
      } else {
        await api.createUser(data);
        Toasts.success('用户已创建');
      }
      this.closeUserModal();
      this.users = await api.listUsers();
      this.render();
    } catch (e) {
      Toasts.error(e.message);
    }
  },

  async saveSecurityPolicy(formEl) {
    var numberValue = function(id) { return Number(formEl.querySelector(id).value); };
    var defaultPassword = formEl.querySelector('#sp-default-password').value;
    var defaultPasswordConfirm = formEl.querySelector('#sp-default-password-confirm').value;
    if (defaultPassword !== defaultPasswordConfirm) {
      Toasts.error('两次输入的账户重置默认密码不一致');
      return;
    }
    var policy = {
      password: {
        min_length: numberValue('#sp-min-length'),
        min_uppercase: numberValue('#sp-min-uppercase'),
        min_lowercase: numberValue('#sp-min-lowercase'),
        min_digits: numberValue('#sp-min-digits'),
        min_special: numberValue('#sp-min-special'),
        history_count: numberValue('#sp-history-count'),
        min_changed_characters: numberValue('#sp-min-changed')
      },
      captcha: {
        case_sensitive: formEl.querySelector('#sp-captcha-case').checked
      },
      login: {
        max_failures: numberValue('#sp-max-failures'),
        lockout_mode: formEl.querySelector('#sp-lockout-mode').value,
        lockout_minutes: numberValue('#sp-lockout-minutes'),
        password_max_age_days: numberValue('#sp-password-max-age'),
        default_reset_password: defaultPassword
      }
    };
    try {
      this.securityPolicy = await api.updateSecurityPolicy(policy);
      Toasts.success('登录与密码安全策略已保存并立即生效');
      this.render();
    } catch (e) {
      Toasts.error(e.message);
    }
  },

  async resetAccount(id) {
    var user = this.users.find(function(item) { return item.id === id; });
    if (!user || user.role !== 'user') return;
    var configured = !!(this.securityPolicy && this.securityPolicy.login && this.securityPolicy.login.default_reset_password_configured);
    if (!configured) {
      Toasts.warning('请先在登录安全策略中设置账户重置默认密码');
      return;
    }
    const accepted = await Dialogs.confirm({
      title: '重置普通用户账户',
      message: '将解除账户锁定、撤销现有会话，并改为管理员配置的默认密码。用户下次登录后必须立即修改密码。',
      target: user.username,
      confirmText: '重置账户',
      danger: true
    });
    if (!accepted) return;
    try {
      await api.resetAccount(id);
      Toasts.success('账户已重置，可使用默认密码登录');
      this.users = await api.listUsers();
      this.render();
    } catch (e) {
      Toasts.error(e.message);
    }
  },

  async unlockAccount(id) {
    var user = this.users.find(function(item) { return item.id === id; });
    if (!user || !user.login_disabled) return;
    try {
      await api.unlockAccount(id);
      Toasts.success('账户已解锁，原密码保持不变');
      this.users = await api.listUsers();
      this.render();
    } catch (e) {
      Toasts.error(e.message);
    }
  },

  async createAccessKey(formEl) {
    var name = String(new FormData(formEl).get('name') || '').trim();
    if (!name) return Toasts.warning('请输入访问密钥名称');
    try {
      var result = await api.createAccessKey(name);
      this.newAccessKey = { name: result.access_key.name, key: result.key };
      this.accessKeys = await api.listAccessKeys();
      this.render();
    } catch (e) {
      Toasts.error(e.message);
    }
  },

  async copyNewAccessKey() {
    if (!this.newAccessKey) return;
    try {
      await navigator.clipboard.writeText(this.newAccessKey.key);
      Toasts.success('访问密钥已复制');
    } catch (_) {
      Toasts.error('浏览器未允许复制，请手动选择密钥');
    }
  },

  dismissNewAccessKey() {
    this.newAccessKey = null;
    this.render();
  },

  async revokeAccessKey(id) {
    var item = this.accessKeys.find(function(key) { return key.id === id; });
    if (!item) return;
    const accepted = await Dialogs.confirm({
      title: '撤销中心访问密钥',
      message: '使用该密钥的 API 集成会立即失效，不影响 Agent 自动交换的管理凭据。',
      target: item.name,
      confirmText: '撤销密钥',
      danger: true
    });
    if (!accepted) return;
    try {
      await api.deleteAccessKey(id);
      this.accessKeys = await api.listAccessKeys();
      Toasts.success('访问密钥已撤销');
      this.render();
    } catch (e) {
      Toasts.error(e.message);
    }
  },

  renderAccessKeysCard() {
    var oneTime = this.newAccessKey ? '<div class="alert alert-warning"><strong>仅显示一次，请立即复制</strong><p>' + escapeHtml(this.newAccessKey.name) + '</p><code class="mono access-key-once">' + escapeHtml(this.newAccessKey.key) + '</code><div class="btn-group"><button class="btn btn-sm btn-primary" onclick="SystemView.copyNewAccessKey()">复制密钥</button><button class="btn btn-sm btn-secondary" onclick="SystemView.dismissNewAccessKey()">我已保存</button></div></div>' : '';
    var rows = this.accessKeys.length ? '<div class="table-container"><table><thead><tr><th>名称</th><th>创建时间</th><th>操作</th></tr></thead><tbody>' + this.accessKeys.map(function(item) {
      return '<tr><td><strong>' + escapeHtml(item.name) + '</strong><br><small>ID ' + escapeHtml(item.id) + '</small></td><td>' + formatDate(item.created_at) + '</td><td><button class="btn btn-xs btn-danger" onclick="SystemView.revokeAccessKey(\'' + item.id + '\')">撤销</button></td></tr>';
    }).join('') + '</tbody></table></div>' : '<div class="empty-state compact"><p>尚未创建中心 API 访问密钥。</p></div>';
    return '<div class="card" style="margin-bottom:1.25rem"><div class="card-header"><div><h3>🔐 中心 API 访问密钥</h3><small>仅供脚本或外部 API 集成；Agent 管理密钥由系统自动交换，不在这里配置。</small></div></div>' + oneTime + '<form class="access-key-create" onsubmit="SystemView.createAccessKey(this);return false"><div class="form-group"><label class="form-label">密钥名称</label><input class="form-input" name="name" maxlength="64" required placeholder="例如：自动化发布"></div><button class="btn btn-sm btn-primary" type="submit">创建密钥</button></form>' + rows + '</div>';
  },

  async deleteUser(id) {
    var user = this.users.find(function(u) { return u.id === id; });
    if (!user) return;
    const accepted = await Dialogs.confirm({
      title: '删除控制端用户',
      message: '用户将无法继续登录当前控制端，此操作不可撤销。',
      target: user.username + ' · 控制端 ' + window.location.host,
      confirmText: '删除用户',
      danger: true
    });
    if (!accepted) return;
    try {
      await api.deleteUser(id);
      Toasts.success('用户已删除');
      this.users = await api.listUsers();
      this.render();
    } catch (e) {
      Toasts.error(e.message);
    }
  },

  async changePassword(formEl) {
    var oldPwd = formEl.querySelector('#su-old-password').value;
    var newPwd = formEl.querySelector('#su-new-password').value;
    var confirmPwd = formEl.querySelector('#su-confirm-password').value;
    if (newPwd !== confirmPwd) {
      Toasts.error('两次输入的新密码不一致');
      return;
    }
    try {
      await api.changePassword(oldPwd, newPwd);
      sessionStorage.clear();
      window.location.href = '/login.html?password_changed=1';
    } catch (e) {
      Toasts.error(e.message);
    }
  },

  // ==================== Render ====================

  render() {
    var usersMode = AppState.page === 'users';
    var root = document.getElementById(usersMode ? 'users-content' : 'system-content');
    if (!root) return;

    var role = sessionStorage.getItem('auth_role') || '';
    var self = this;
    var html = '';

    // ---- Controller user management ----
    if (usersMode) {
      if (role === 'admin' || !getAuthToken()) {
        html += this.renderSecurityPolicyCard();
      }
      html += '<div class="card" style="margin-bottom:1.25rem">' +
      '<div class="card-header"><h3>👥 用户管理</h3>' +
        '<div class="btn-group">' +
          (!AppState.authDisabled ? '<button class="btn btn-sm btn-secondary" onclick="SystemView.openPasswordChange()">🔑 修改密码</button>' : '') +
          (role === 'admin' ? '<button class="btn btn-sm btn-primary" onclick="SystemView.openCreateUser()">+ 添加用户</button>' : '') +
        '</div>' +
      '</div>';

    if (role !== 'admin' && getAuthToken()) {
      html += '<div class="alert alert-info" style="margin:1rem">普通用户不能查看或修改其他账号。你仍可修改自己的登录密码；主机权限由中心管理员分配。</div>';
    } else if (this.users.length === 0) {
      html += '<div style="text-align:center;padding:2rem;color:var(--text-muted)">暂无用户数据</div>';
    } else {
      html += '<div class="table-container"><table>' +
        '<thead><tr><th>用户名</th><th>角色与状态</th><th>可管理范围</th><th>密码状态</th><th>创建时间</th><th>更新时间</th>' +
          (role === 'admin' ? '<th style="width:210px">操作</th>' : '') +
        '</tr></thead><tbody>';

      for (var i = 0; i < this.users.length; i++) {
        var u = this.users[i];
        var isCurrentUser = Boolean(AppState.username && u.username === AppState.username);
        html += '<tr>' +
          '<td><span style="font-weight:600">' + escapeHtml(u.username) + '</span></td>' +
          '<td><span class="badge ' + (u.role === 'admin' ? 'badge-log' : 'badge-return') + '">' +
            (u.role === 'admin' ? '管理员' : '普通用户') + '</span>' +
            (u.login_disabled ? ' <span class="badge badge-drop">账户已锁定</span>' : '') + '</td>' +
          '<td>' + this.renderUserHosts(u) + '</td>' +
          '<td>' + this.renderPasswordStatus(u) + '</td>' +
          '<td>' + formatDate(u.created_at) + '</td>' +
          '<td>' + formatDate(u.updated_at) + '</td>';
        if (role === 'admin') {
          html += '<td><div class="btn-group">' +
            '<button class="btn btn-xs btn-secondary" onclick="SystemView.openEditUser(\'' + u.id + '\')">编辑</button>' +
            (u.login_disabled ? '<button class="btn btn-xs btn-secondary" onclick="SystemView.unlockAccount(\'' + u.id + '\')">解锁</button>' : '') +
            (u.role === 'user' ? '<button class="btn btn-xs btn-secondary" onclick="SystemView.resetAccount(\'' + u.id + '\')">重置账户</button>' : '') +
            (isCurrentUser ? '<span class="badge badge-return">当前账号</span>' : '<button class="btn btn-xs btn-danger" onclick="SystemView.deleteUser(\'' + u.id + '\')">删除</button>') +
          '</div></td>';
        }
        html += '</tr>';
      }
      html += '</tbody></table></div>';
    }
    html += '</div>';
    if (AppState.canManageFleet()) html += this.renderAccessKeysCard();
    }

    // ---- Opened host backup / restore ----
    if (!usersMode && AppState.canManageRules()) {
      html += '<div class="system-storage-grid">' +
        '<div class="card">' +
          '<div class="card-header"><h3>📥 备份全部规则</h3>' +
            '<button class="btn btn-sm btn-primary" onclick="SystemView.doBackup()">下载全部备份</button></div>' +
	          '<p style="font-size:0.85rem;color:var(--text-secondary);line-height:1.6">导出 IPv4、可用时的 IPv6、iptables-web 托管记录和清单。下载的完整 JSON 文件可直接用于右侧恢复。</p>' +
        '</div>' +
        '<div class="card">' +
          '<div class="card-header"><h3>📤 恢复规则</h3></div>' +
	      '<input id="restore-backup-file" type="file" accept=".json,application/json" style="display:none" onchange="SystemView.selectRestoreFile(this)">' +
	      '<div class="restore-file-picker">' +
	        '<button class="btn btn-secondary" onclick="document.getElementById(\'restore-backup-file\').click()">选择备份 JSON</button>' +
	        (this.restoreFileName ? '<div class="restore-file-info"><strong>' + escapeHtml(this.restoreFileName) + '</strong><span>' + (this.restoreFileSize / 1024).toFixed(1) + ' KB</span><button class="btn btn-xs btn-secondary" onclick="SystemView.clearRestoreFile()">重新选择</button></div>' : '<span class="restore-file-empty">尚未选择文件</span>') +
	      '</div>' +
	      (this.restoreFileError ? '<div class="alert alert-danger" style="margin-bottom:0.75rem">' + escapeHtml(this.restoreFileError) + '</div>' : '') +
          (this.restoreConfirm ? '<div class="alert alert-warning" style="margin-bottom:0.75rem"><strong>⚠ 警告：</strong>恢复前会先做语法校验；校验通过后仍会修改完整防火墙规则集。确认继续？</div>' : '') +
          '<button class="btn ' + (this.restoreConfirm ? 'btn-danger' : 'btn-secondary') + '" onclick="SystemView.doRestore()" ' + (!this.restoreData.trim() ? 'disabled' : '') + '>' +
            (this.restoreConfirm ? '⚠ 确认恢复' : '恢复规则') + '</button>' +
        '</div>' +
        '<div class="card">' +
          '<div class="card-header"><h3>🧹 清空界面托管规则</h3></div>' +
          '<p style="font-size:0.85rem;color:var(--text-secondary);line-height:1.6">精确删除通过本界面写入的运行态规则并清空托管记录。不会 flush 整条链，也不会删除 Docker、firewalld 或其他工具创建的外部规则。建议卸载前先执行。</p>' +
          '<button class="btn btn-danger" onclick="SystemView.clearManagedRules()">清空界面配置的规则</button>' +
        '</div>' +
        '<div class="card">' +
          '<div class="card-header"><h3>↩ 最近变更回滚</h3></div>' +
          renderRollbackStatus(this.rollback, this.rollbackConfirm) +
          '<button class="btn ' + (this.rollbackConfirm ? 'btn-danger' : 'btn-secondary') + '" onclick="SystemView.rollbackLastChange()" ' + (!(this.rollback && this.rollback.available) ? 'disabled' : '') + '>' +
            (this.rollbackConfirm ? '确认回滚最近变更' : '回滚最近变更') + '</button>' +
        '</div>' +
      '</div>';

      if (!AppState.activeLocal() || AppState.canManageFleet()) {
        html += '<div class="card" style="margin-top:1.25rem">' +
          '<div class="card-header"><h3>🧾 变更审计</h3><button class="btn btn-sm btn-secondary" onclick="SystemView.downloadAudit()">导出完整审计</button></div>' +
          renderAuditEvents(this.auditEvents) +
        '</div>';
      } else {
        html += '<div class="alert alert-info" style="margin-top:1.25rem">中心本机审计包含用户、主机和密钥管理记录，仅管理员可查看；远程 Agent 的防火墙审计仍对该主机授权用户开放。</div>';
      }
    } else if (!usersMode) {
      html += '<div class="alert alert-info">请先从纳管概览打开一台有权管理的主机。</div>';
    }

    // User edit/create modal
    if (usersMode && this.showUserModal) {
      var isEdit = !!this.editingUser;
      var passwordPolicy = (this.securityPolicy && this.securityPolicy.password) || { min_length: 1 };
      var passwordHelp = this.passwordPolicySummary(passwordPolicy);
      html += modalOverlay(
        '<div class="card-header"><h3>' + (isEdit ? '编辑用户 · ' + escapeHtml(this.editingUser.username) : '添加用户') + '</h3></div>' +
        '<form onsubmit="SystemView.saveUser(this);return false">' +
          '<div class="form-group">' +
            '<label class="form-label">用户名</label>' +
            '<input class="form-input" id="su-username" autocomplete="username" required minlength="3" maxlength="32"' +
              ' value="' + (isEdit ? escapeHtml(this.editingUser.username) : '') + '" placeholder="3-32 个字符">' +
          '</div>' +
          '<div class="form-group">' +
            '<label class="form-label">密码' + (isEdit ? ' (留空不修改)' : '') + '</label>' +
            '<input class="form-input" id="su-password" type="password" autocomplete="new-password" ' + (isEdit ? '' : 'required') + ' minlength="' + Number(passwordPolicy.min_length || 1) + '" maxlength="128" placeholder="' + escapeHtml(passwordHelp) + '">' +
            '<small class="permission-help">' + escapeHtml(passwordHelp) + '。管理员重置后，用户首次登录仍必须再次修改。</small>' +
          '</div>' +
          '<div class="form-group">' +
            '<label class="form-label">角色</label>' +
            '<select class="form-select" id="su-role" onchange="SystemView.updateHostAssignmentVisibility(this.value)">' +
              '<option value="user"' + (isEdit && this.editingUser.role === 'user' ? ' selected' : '') + '>普通用户</option>' +
              '<option value="admin"' + (isEdit && this.editingUser.role === 'admin' ? ' selected' : '') + '>管理员</option>' +
            '</select>' +
          '</div>' +
          '<div class="form-group" id="su-host-assignments" ' + (isEdit && this.editingUser.role === 'admin' ? 'hidden' : '') + '>' +
            '<label class="form-label">可管理范围</label>' +
            '<p class="permission-help">可以按主机组授权，也可以补充选择单台主机；两种授权会合并，用户拥有范围内主机的完整管理权限。</p>' +
            this.renderHostGroupAssignmentOptions(isEdit ? (this.editingUser.host_groups || []) : []) +
            this.renderHostAssignmentOptions(isEdit ? (this.editingUser.host_ids || []) : []) +
          '</div>' +
          '<div class="modal-footer">' +
            '<button type="button" class="btn btn-secondary" onclick="SystemView.closeUserModal()">取消</button>' +
            '<button type="submit" class="btn btn-primary">' + (isEdit ? '保存' : '创建') + '</button>' +
          '</div>' +
        '</form>',
        function() { self.closeUserModal(); }
      );
    }

    // Password change modal
    if (usersMode && this.showPasswordModal) {
      var ownPasswordPolicy = (this.securityPolicy && this.securityPolicy.password) || { min_length: 8 };
      var ownPasswordHelp = this.passwordPolicySummary(ownPasswordPolicy);
      html += modalOverlay(
        '<div class="card-header"><h3>🔑 修改密码</h3></div>' +
        '<form onsubmit="SystemView.changePassword(this);return false">' +
		  '<input type="text" name="username" autocomplete="username" value="' + escapeHtml(AppState.username || '') + '" hidden>' +
          '<div class="form-group">' +
            '<label class="form-label">原密码</label>' +
            '<input class="form-input" id="su-old-password" type="password" autocomplete="current-password" required placeholder="输入当前密码">' +
          '</div>' +
          '<div class="form-group">' +
            '<label class="form-label">新密码</label>' +
            '<input class="form-input" id="su-new-password" type="password" autocomplete="new-password" required minlength="' + Number(ownPasswordPolicy.min_length || 1) + '" maxlength="128" placeholder="' + escapeHtml(ownPasswordHelp) + '">' +
          '</div>' +
          '<div class="form-group">' +
            '<label class="form-label">确认新密码</label>' +
            '<input class="form-input" id="su-confirm-password" type="password" autocomplete="new-password" required minlength="' + Number(ownPasswordPolicy.min_length || 1) + '" maxlength="128" placeholder="再次输入新密码">' +
            '<small class="permission-help">' + escapeHtml(ownPasswordHelp) + '</small>' +
          '</div>' +
          '<div class="modal-footer">' +
            '<button type="button" class="btn btn-secondary" onclick="SystemView.closeUserModal()">取消</button>' +
            '<button type="submit" class="btn btn-primary">修改密码</button>' +
          '</div>' +
        '</form>',
        function() { self.closeUserModal(); }
      );
    }

    root.innerHTML = html;
  },

  renderUserHosts(user) {
    if (user.role === 'admin') return '<span class="badge badge-accept">全部主机</span>';
    var ids = Array.isArray(user.host_ids) ? user.host_ids : [];
    var groups = Array.isArray(user.host_groups) ? user.host_groups : [];
    if (!ids.length && !groups.length) return '<span class="text-muted">未分配</span>';
    var groupChips = groups.map(function(group) {
      return '<span class="permission-host-chip is-group">组 · ' + escapeHtml(group) + '</span>';
    }).join('');
    var names = ids.map(function(id) {
      if (id === 'local') return '本机防火墙';
      var host = SystemView.hosts.find(function(item) { return item.id === id; });
      return host ? host.name : '已移除主机';
    });
    var visible = names.slice(0, 3).map(function(name) { return '<span class="permission-host-chip">' + escapeHtml(name) + '</span>'; }).join('');
    return '<div class="permission-host-list">' + groupChips + visible + (names.length > 3 ? '<span class="permission-more">+' + (names.length - 3) + '</span>' : '') + '</div>';
  },

  renderPasswordStatus(user) {
    if (user.must_change_password) return '<span class="badge badge-drop">登录后修改</span>';
    var days = Number(this.securityPolicy && this.securityPolicy.login ? this.securityPolicy.login.password_max_age_days : 0);
    if (!days) return '<span class="text-muted">长期有效</span>';
    var changedAt = new Date(user.password_changed_at || user.updated_at).getTime();
    if (!Number.isFinite(changedAt)) return '<span class="text-muted">日期未知</span>';
    var expiresAt = changedAt + days * 86400000;
    if (Date.now() >= expiresAt) return '<span class="badge badge-drop">密码已到期</span>';
    var remaining = Math.max(1, Math.ceil((expiresAt - Date.now()) / 86400000));
    return '<span class="text-muted">' + remaining + ' 天后到期</span>';
  },

  renderHostGroupAssignmentOptions(selectedGroups) {
    var selected = new Set((Array.isArray(selectedGroups) ? selectedGroups : []).map(function(group) { return String(group).toLowerCase(); }));
    var counts = {};
    this.hosts.forEach(function(host) {
      var group = (host.group || '').trim();
      if (!group) return;
      var key = group.toLowerCase();
      if (!counts[key]) counts[key] = { name: group, count: 0 };
      counts[key].count++;
    });
    var groups = Object.keys(counts).sort().map(function(key) { return counts[key]; });
    if (!groups.length) return '<div class="permission-section"><strong>按主机组授权</strong><div class="permission-empty">当前主机尚未设置分组，可在 Agent 纳管中编辑主机分组。</div></div>';
    return '<div class="permission-section"><strong>按主机组授权</strong><small>组权限会自动覆盖以后加入该组的主机。</small><div class="permission-host-grid">' + groups.map(function(group) {
      return '<label class="permission-host-option is-group"><input type="checkbox" name="host_groups" value="' + escapeHtml(group.name) + '" ' + (selected.has(group.name.toLowerCase()) ? 'checked' : '') + '><span><strong>' + escapeHtml(group.name) + '</strong><small>' + group.count + ' 台主机 · 动态继承</small></span></label>';
    }).join('') + '</div></div>';
  },

  renderHostAssignmentOptions(selectedIDs) {
    var selected = new Set(Array.isArray(selectedIDs) ? selectedIDs : []);
    var localOption = '<label class="permission-host-option is-local"><input type="checkbox" name="host_ids" value="local" ' + (selected.has('local') ? 'checked' : '') + '><span><strong>本机防火墙</strong><small>管理中心 · 分配后拥有完整主机管理权限</small></span></label>';
    return '<div class="permission-section"><strong>按单台主机授权</strong><small>本机防火墙也按一台主机独立授权；适合跨组补充例外主机。</small><div class="permission-host-grid">' + localOption + this.hosts.map(function(host) {
      return '<label class="permission-host-option"><input type="checkbox" name="host_ids" value="' + escapeHtml(host.id) + '" ' + (selected.has(host.id) ? 'checked' : '') + '><span><strong>' + escapeHtml(host.name) + '</strong><small>' + escapeHtml(host.group || '未分组') + ' · ' + escapeHtml(host.base_url) + '</small></span></label>';
    }).join('') + '</div></div>';
  },

  passwordPolicySummary(policy) {
    var parts = ['至少 ' + Number(policy.min_length || 1) + ' 位'];
    if (Number(policy.min_uppercase || 0)) parts.push('大写≥' + Number(policy.min_uppercase));
    if (Number(policy.min_lowercase || 0)) parts.push('小写≥' + Number(policy.min_lowercase));
    if (Number(policy.min_digits || 0)) parts.push('数字≥' + Number(policy.min_digits));
    if (Number(policy.min_special || 0)) parts.push('特殊字符≥' + Number(policy.min_special));
    if (Number(policy.history_count || 0)) parts.push('不可复用最近 ' + Number(policy.history_count) + ' 个密码');
    if (Number(policy.min_changed_characters || 0)) parts.push('至少改变 ' + Number(policy.min_changed_characters) + ' 个字符');
    return parts.join('，');
  },

  renderSecurityPolicyCard() {
    if (!this.securityPolicy) return '<div class="card security-policy-card"><div class="loading-spinner"><div class="spinner"></div> 加载安全策略...</div></div>';
    var password = this.securityPolicy.password || {};
    var captcha = this.securityPolicy.captcha || {};
    var login = this.securityPolicy.login || { max_failures: 5, lockout_mode: 'timed', lockout_minutes: 15, password_max_age_days: 0, default_reset_password_configured: false };
    var numberField = function(id, label, value, min, max) {
      return '<label class="security-policy-field"><span>' + label + '</span><input class="form-input" id="' + id + '" type="number" required min="' + min + '" max="' + max + '" value="' + Number(value || 0) + '"></label>';
    };
    return '<div class="card security-policy-card">' +
      '<div class="card-header"><div><h3>登录安全策略</h3><small>策略保存后立即用于新验证码以及后续创建、重置和修改密码。</small></div></div>' +
      '<form onsubmit="SystemView.saveSecurityPolicy(this);return false">' +
        '<div class="security-policy-section"><div><strong>密码要求</strong><small>已有密码不会因为策略提高而立刻失效。字符差异只在用户提供当前密码时比较；管理员重置后会强制用户再次改密。</small></div><div class="security-policy-grid">' +
          numberField('sp-min-length', '最小长度', password.min_length, 1, 128) +
          numberField('sp-min-uppercase', '大写字母至少', password.min_uppercase, 0, 16) +
          numberField('sp-min-lowercase', '小写字母至少', password.min_lowercase, 0, 16) +
          numberField('sp-min-digits', '数字至少', password.min_digits, 0, 16) +
          numberField('sp-min-special', '特殊字符至少', password.min_special, 0, 16) +
          numberField('sp-history-count', '禁止复用最近密码', password.history_count, 0, 10) +
          numberField('sp-min-changed', '至少改变字符数', password.min_changed_characters, 0, 128) +
        '</div></div>' +
        '<div class="security-policy-section captcha-policy-row"><div><strong>验证码</strong><small>验证码始终混合大小写字母和数字；可决定校验时是否区分大小写。</small></div>' +
          '<label class="form-check"><input id="sp-captcha-case" type="checkbox" ' + (captcha.case_sensitive ? 'checked' : '') + '> 区分大小写</label></div>' +
        '<div class="security-policy-section"><div><strong>登录失败处理</strong><small>达到失败次数后，可以等待自动解锁，也可以锁定账户直到管理员执行账户重置。</small></div><div class="security-policy-grid">' +
          numberField('sp-max-failures', '允许连续失败次数', login.max_failures, 1, 20) +
          '<label class="security-policy-field"><span>达到上限后</span><select class="form-select" id="sp-lockout-mode" onchange="SystemView.updateLockoutVisibility(this.value)"><option value="timed" ' + (login.lockout_mode === 'timed' ? 'selected' : '') + '>等待后自动解锁</option><option value="administrator" ' + (login.lockout_mode === 'administrator' ? 'selected' : '') + '>锁定至管理员重置</option></select></label>' +
          '<label class="security-policy-field"><span>自动解锁等待分钟</span><input class="form-input" id="sp-lockout-minutes" type="number" required min="1" max="1440" value="' + Number(login.lockout_minutes || 15) + '" ' + (login.lockout_mode === 'timed' ? '' : 'disabled') + '></label>' +
          numberField('sp-password-max-age', '密码有效期（天，0 不限制）', login.password_max_age_days, 0, 3650) +
        '</div></div>' +
        '<div class="security-policy-section"><div><strong>账户重置默认密码</strong><small>只写保存，服务端仅持久化哈希。重置普通用户时会解除锁定、撤销会话，并强制登录后改密。</small></div><div><input type="text" name="username" autocomplete="username" value="administrator-default-reset" hidden><div class="default-password-status"><span class="badge ' + (login.default_reset_password_configured ? 'badge-accept' : 'badge-return') + '">' + (login.default_reset_password_configured ? '已配置' : '未配置') + '</span><small>留空表示保持当前设置不变。</small></div><div class="security-policy-grid two-fields">' +
          '<label class="security-policy-field"><span>新的默认密码</span><input class="form-input" id="sp-default-password" type="password" autocomplete="new-password" maxlength="128" placeholder="' + (login.default_reset_password_configured ? '留空保持不变' : '设置后才可重置账户') + '"></label>' +
          '<label class="security-policy-field"><span>确认默认密码</span><input class="form-input" id="sp-default-password-confirm" type="password" autocomplete="new-password" maxlength="128" placeholder="再次输入"></label>' +
        '</div></div></div>' +
        '<div class="security-policy-actions"><span>' + escapeHtml(this.passwordPolicySummary(password)) + '</span><button class="btn btn-primary" type="submit">保存安全策略</button></div>' +
      '</form></div>';
  }
};

function renderRollbackStatus(rollback, confirming) {
  if (!rollback || !rollback.available) {
    return '<p style="font-size:0.85rem;color:var(--text-muted);line-height:1.6">当前没有可回滚的规则变更。每次成功修改规则后会开启 10 分钟窗口。</p>';
  }
  var expires = formatDate(rollback.expires_at);
  var html = '<p style="font-size:0.85rem;color:var(--text-secondary);line-height:1.6">可回滚操作：<strong>' +
    escapeHtml(auditActionLabel(rollback.action)) + '</strong><br>操作者：' + escapeHtml(rollback.actor || '—') +
    ' · 目标规则数：' + Number(rollback.rule_count || 0) + '<br>有效期至：' + escapeHtml(expires) + '</p>';
  if (confirming) {
    html += '<div class="alert alert-warning"><strong>请再次确认：</strong>将恢复变更前的全部托管规则；当前状态会成为新的反向回滚点。</div>';
  }
  return html;
}

function renderAuditEvents(events) {
  if (!events || events.length === 0) {
    return '<div style="padding:1.5rem;text-align:center;color:var(--text-muted)">暂无管理员变更记录</div>';
  }
  var rows = events.map(function(event) {
    var changed = Number((event.rule_changes || []).length) + Number((event.user_changes || []).length) +
      Number((event.host_changes || []).length) + Number((event.access_key_changes || []).length) +
      Number(event.security_policy_after ? 1 : 0);
    return '<tr class="audit-event-summary"><td>' + escapeHtml(formatDate(event.created_at)) + '</td>' +
      '<td><strong>' + escapeHtml(event.actor || 'anonymous') + '</strong><br><small>' + escapeHtml(event.role || '—') + ' · ' + escapeHtml(event.remote_ip || '—') + '</small></td>' +
      '<td>' + escapeHtml(auditActionLabel(event.action)) + '</td>' +
      '<td>' + changed + '</td>' +
      '<td><span class="badge ' + (event.status < 400 ? 'badge-accept' : 'badge-drop') + '">' + Number(event.status || 0) + '</span></td></tr>' +
      '<tr class="audit-event-detail-row"><td colspan="5">' + renderAuditDetails(event) + '</td></tr>';
  }).join('');
  return '<div class="table-container"><table><thead><tr><th>时间</th><th>操作者</th><th>操作</th><th>变化数</th><th>结果</th></tr></thead><tbody>' + rows + '</tbody></table></div>';
}

function renderAuditDetails(event) {
  var sections = [];
  var request = [String(event.method || ''), String(event.path || '')].filter(Boolean).join(' ');
  sections.push('<div class="audit-request"><strong>请求</strong><code>' + escapeHtml(request || '—') + '</code>' +
    '<small>Request ID：' + escapeHtml(event.request_id || '—') + '</small></div>');
  appendAuditChangeSection(sections, '规则变化', event.rule_changes, function(change) {
    return auditChangePair('规则 ' + (change.id || '—'), change.before, change.after);
  });
  appendAuditChangeSection(sections, '用户变化', event.user_changes, function(change) {
    return auditChangePair('用户 ' + (change.id || '—'), change.before, change.after);
  });
  appendAuditChangeSection(sections, '主机变化', event.host_changes, function(change) {
    return auditChangePair('主机 ' + (change.id || '—'), change.before, change.after);
  });
  appendAuditChangeSection(sections, '访问密钥变化', event.access_key_changes, function(change) {
    return auditChangePair('访问密钥 ' + (change.id || '—'), change.before, change.after);
  });
  if (event.security_policy_before || event.security_policy_after) {
    sections.push('<section><strong>安全策略变化</strong>' + auditBeforeAfter(event.security_policy_before, event.security_policy_after) + '</section>');
  }
  if (sections.length === 1) {
    sections.push('<p class="audit-no-diff">该请求没有产生可见的数据快照变化；失败原因或远端响应请结合状态码与服务日志查看。</p>');
  }
  return '<details class="audit-event-details"><summary>查看详情</summary><div class="audit-event-body">' + sections.join('') + '</div></details>';
}

function appendAuditChangeSection(sections, title, changes, renderer) {
  if (!Array.isArray(changes) || !changes.length) return;
  sections.push('<section><strong>' + escapeHtml(title) + '</strong>' + changes.map(renderer).join('') + '</section>');
}

function auditChangePair(title, before, after) {
  return '<div class="audit-change-pair"><span>' + escapeHtml(title) + '</span>' + auditBeforeAfter(before, after) + '</div>';
}

function auditBeforeAfter(before, after) {
  return '<div class="audit-before-after"><div><small>变更前</small><pre>' + escapeHtml(auditJSONString(before)) + '</pre></div>' +
    '<div><small>变更后</small><pre>' + escapeHtml(auditJSONString(after)) + '</pre></div></div>';
}

function auditJSONString(value) {
  if (value === undefined || value === null) return '—';
  try { return JSON.stringify(value, null, 2); } catch (_) { return String(value); }
}

function auditActionLabel(action) {
  var labels = {
    create_rule: '创建规则', update_rule: '更新规则', delete_rule: '删除规则',
    toggle_rule: '启停规则', reorder_rules: '调整规则顺序',
    create_docker_whitelist: '创建 Docker 白名单', restore_firewall: '恢复防火墙',
    clear_managed_rules: '清空托管规则', rollback_change: '回滚最近变更',
    change_password: '修改密码', manage_user: '管理用户', update_security_policy: '更新安全策略',
    manage_remote_host: '管理远程主机', manage_access_key: '管理中心访问密钥',
    approve_agent_enrollment: '确认 Agent 纳管', reject_agent_enrollment: '拒绝 Agent 纳管',
  };
  return labels[action] || action || '未知操作';
}

function modalOverlay(body, onClose) {
  return '<div style="position:fixed;inset:0;z-index:200;display:flex;align-items:center;justify-content:center;padding:1rem">' +
    '<div style="position:absolute;inset:0;background:var(--bg-modal-overlay);backdrop-filter:blur(4px)" onclick="' + onClose.toString().replace(/"/g, '&quot;') + '"></div>' +
    '<div class="modal">' + body + '</div>' +
  '</div>';
}

function formatDate(iso) {
  if (!iso) return '—';
  var d = new Date(iso);
  return d.getFullYear() + '-' +
    String(d.getMonth() + 1).padStart(2, '0') + '-' +
    String(d.getDate()).padStart(2, '0') + ' ' +
    String(d.getHours()).padStart(2, '0') + ':' +
    String(d.getMinutes()).padStart(2, '0');
}
