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

  async refresh() {
    this.loading = true;
    this.render();
    var role = sessionStorage.getItem('auth_role') || '';
    var requests = [api.listUsers()];
    if (role === 'admin' || !getAuthToken()) {
      requests.push(api.listAuditEvents(20), api.getRollbackStatus());
    }
    var results = await Promise.allSettled(requests);
    if (results[0].status === 'fulfilled') this.users = results[0].value;
    if (results[1] && results[1].status === 'fulfilled') this.auditEvents = results[1].value;
    if (results[2] && results[2].status === 'fulfilled') this.rollback = results[2].value;
    this.loading = false;
    this.render();
  },

  // ==================== Backup / Restore ====================

  async doBackup() {
    if (!AppState.canManageRules()) {
      Toasts.error('需要管理员权限');
      return;
    }
    try {
	  const backup = await api.backupRules('all');
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
      Toasts.error('需要管理员权限');
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
    try {
	  await api.restoreRulesFile(this.restoreData);
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
      Toasts.error('需要管理员权限');
      return;
    }
    if (!confirm('确定清空所有通过本界面配置的规则吗？\n\n这会立即从运行防火墙中删除托管规则并清空 rules.json；不会 flush 链，也不会删除外部规则。')) return;
    try {
      const result = await api.clearManagedRules();
      const removed = Number((result || {}).removed || 0);
      Toasts.success('已清空 ' + removed + ' 条界面托管规则，现在可以卸载服务');
      await AppState.refreshSystemInfo();
      this.render();
    } catch (e) {
      Toasts.error('清空失败：' + e.message);
    }
  },

  async downloadAudit() {
    try {
      var audit = await api.downloadAudit();
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
    try {
      var result = await api.rollbackLastChange(this.rollback.id);
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

  async saveUser(formEl) {
    var username = formEl.querySelector('#su-username').value.trim();
    var password = formEl.querySelector('#su-password').value;
    var role = formEl.querySelector('#su-role').value;
    var data = { username: username, role: role };
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

  async deleteUser(id) {
    var user = this.users.find(function(u) { return u.id === id; });
    if (!user) return;
    if (!confirm('确定要删除用户 "' + user.username + '" 吗？此操作不可撤销。')) return;
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
      Toasts.success('密码已修改');
      this.showPasswordModal = false;
      this.render();
    } catch (e) {
      Toasts.error(e.message);
    }
  },

  // ==================== Render ====================

  render() {
    var root = document.getElementById('system-content');
    if (!root) return;

    var role = sessionStorage.getItem('auth_role') || '';
    var self = this;
    var html = '';

    // ---- User management (top) ----
    html += '<div class="card" style="margin-bottom:1.25rem">' +
      '<div class="card-header"><h3>👥 用户管理</h3>' +
        '<div class="btn-group">' +
          '<button class="btn btn-sm btn-secondary" onclick="SystemView.openPasswordChange()">🔑 修改密码</button>' +
          (role === 'admin' ? '<button class="btn btn-sm btn-primary" onclick="SystemView.openCreateUser()">+ 添加用户</button>' : '') +
        '</div>' +
      '</div>';

    if (this.users.length === 0) {
      html += '<div style="text-align:center;padding:2rem;color:var(--text-muted)">暂无用户数据</div>';
    } else {
      html += '<div class="table-container"><table>' +
        '<thead><tr><th>用户名</th><th>角色</th><th>创建时间</th><th>更新时间</th>' +
          (role === 'admin' ? '<th style="width:120px">操作</th>' : '') +
        '</tr></thead><tbody>';

      for (var i = 0; i < this.users.length; i++) {
        var u = this.users[i];
        html += '<tr>' +
          '<td><span style="font-weight:600">' + escapeHtml(u.username) + '</span></td>' +
          '<td><span class="badge ' + (u.role === 'admin' ? 'badge-log' : 'badge-return') + '">' +
            (u.role === 'admin' ? '管理员' : '普通用户') + '</span></td>' +
          '<td>' + formatDate(u.created_at) + '</td>' +
          '<td>' + formatDate(u.updated_at) + '</td>';
        if (role === 'admin') {
          html += '<td><div class="btn-group">' +
            '<button class="btn btn-xs btn-secondary" onclick="SystemView.openEditUser(\'' + u.id + '\')">编辑</button>' +
            '<button class="btn btn-xs btn-danger" onclick="SystemView.deleteUser(\'' + u.id + '\')">删除</button>' +
          '</div></td>';
        }
        html += '</tr>';
      }
      html += '</tbody></table></div>';
    }
    html += '</div>';

    // ---- Backup / Restore (below) ----
    if (role === 'admin' || !getAuthToken()) {
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

      html += '<div class="card" style="margin-top:1.25rem">' +
        '<div class="card-header"><h3>🧾 管理员变更审计</h3><button class="btn btn-sm btn-secondary" onclick="SystemView.downloadAudit()">导出完整审计</button></div>' +
        renderAuditEvents(this.auditEvents) +
      '</div>';
    } else {
      html += '<div class="alert alert-info">当前账号为只读权限，备份和恢复完整防火墙规则集需要管理员权限。</div>';
    }

    // User edit/create modal
    if (this.showUserModal) {
      var isEdit = !!this.editingUser;
      html += modalOverlay(
        '<div class="card-header"><h3>' + (isEdit ? '编辑用户 · ' + escapeHtml(this.editingUser.username) : '添加用户') + '</h3></div>' +
        '<form onsubmit="SystemView.saveUser(this);return false">' +
          '<div class="form-group">' +
            '<label class="form-label">用户名</label>' +
            '<input class="form-input" id="su-username" required minlength="3" maxlength="32"' +
              ' value="' + (isEdit ? escapeHtml(this.editingUser.username) : '') + '" placeholder="3-32 个字符">' +
          '</div>' +
          '<div class="form-group">' +
            '<label class="form-label">密码' + (isEdit ? ' (留空不修改)' : '') + '</label>' +
            '<input class="form-input" id="su-password" type="password" autocomplete="new-password" ' + (isEdit ? '' : 'required') + ' minlength="6" placeholder="至少 6 个字符">' +
          '</div>' +
          '<div class="form-group">' +
            '<label class="form-label">角色</label>' +
            '<select class="form-select" id="su-role">' +
              '<option value="user"' + (isEdit && this.editingUser.role === 'user' ? ' selected' : '') + '>普通用户</option>' +
              '<option value="admin"' + (isEdit && this.editingUser.role === 'admin' ? ' selected' : '') + '>管理员</option>' +
            '</select>' +
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
    if (this.showPasswordModal) {
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
            '<input class="form-input" id="su-new-password" type="password" autocomplete="new-password" required minlength="6" placeholder="至少 6 个字符">' +
          '</div>' +
          '<div class="form-group">' +
            '<label class="form-label">确认新密码</label>' +
            '<input class="form-input" id="su-confirm-password" type="password" autocomplete="new-password" required minlength="6" placeholder="再次输入新密码">' +
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
    var changed = Number((event.rule_changes || []).length) + Number((event.user_changes || []).length);
    return '<tr><td>' + escapeHtml(formatDate(event.created_at)) + '</td>' +
      '<td><strong>' + escapeHtml(event.actor || 'anonymous') + '</strong><br><small>' + escapeHtml(event.remote_ip || '—') + '</small></td>' +
      '<td>' + escapeHtml(auditActionLabel(event.action)) + '</td>' +
      '<td>' + changed + '</td>' +
      '<td><span class="badge ' + (event.status < 400 ? 'badge-accept' : 'badge-drop') + '">' + Number(event.status || 0) + '</span></td></tr>';
  }).join('');
  return '<div class="table-container"><table><thead><tr><th>时间</th><th>操作者</th><th>操作</th><th>变化数</th><th>结果</th></tr></thead><tbody>' + rows + '</tbody></table></div>';
}

function auditActionLabel(action) {
  var labels = {
    create_rule: '创建规则', update_rule: '更新规则', delete_rule: '删除规则',
    toggle_rule: '启停规则', reorder_rules: '调整规则顺序',
    create_docker_whitelist: '创建 Docker 白名单', restore_firewall: '恢复防火墙',
    clear_managed_rules: '清空托管规则', rollback_change: '回滚最近变更',
    change_password: '修改密码', manage_user: '管理用户',
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
