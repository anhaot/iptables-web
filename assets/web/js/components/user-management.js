// ====== 用户管理组件 ======

const UserManagement = {
  users: [],
  editingUser: null,
  showCreateModal: false,
  showPasswordModal: false,

  async refresh() {
    try {
      this.users = await api.listUsers();
    } catch (e) {
      Toasts.error('加载用户列表失败: ' + e.message);
      this.users = [];
    }
    this.render();
  },

  openCreate() {
    this.editingUser = null;
    this.showCreateModal = true;
    this.render();
  },

  openEdit(id) {
    this.editingUser = this.users.find(u => u.id === id) || null;
    this.showCreateModal = true;
    this.render();
  },

  closeModal() {
    this.showCreateModal = false;
    this.showPasswordModal = false;
    this.editingUser = null;
    this.render();
  },

  openPasswordChange() {
    this.showPasswordModal = true;
    this.render();
  },

  async saveUser(formEl) {
    const username = formEl.querySelector('#um-username').value.trim();
    const password = formEl.querySelector('#um-password').value;
    const role = formEl.querySelector('#um-role').value;

    const data = { username, role };
    if (password) data.password = password;

    try {
      if (this.editingUser) {
        await api.updateUser(this.editingUser.id, data);
        Toasts.success('用户已更新');
      } else {
        await api.createUser(data);
        Toasts.success('用户已创建');
      }
      this.closeModal();
      await this.refresh();
    } catch (e) {
      Toasts.error(e.message);
    }
  },

  async deleteUser(id) {
    const user = this.users.find(u => u.id === id);
    if (!user) return;
    if (!confirm('确定要删除用户 "' + user.username + '" 吗？此操作不可撤销。')) return;
    try {
      await api.deleteUser(id);
      Toasts.success('用户已删除');
      await this.refresh();
    } catch (e) {
      Toasts.error(e.message);
    }
  },

  async changePassword(formEl) {
    const oldPwd = formEl.querySelector('#um-old-password').value;
    const newPwd = formEl.querySelector('#um-new-password').value;
    const confirmPwd = formEl.querySelector('#um-confirm-password').value;
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

  render() {
    const root = document.getElementById('users-content');
    if (!root) return;

    const role = sessionStorage.getItem('auth_role') || '';

    let html = '';

    // Toolbar
    html += `<div style="display:flex;gap:0.75rem;margin-bottom:1rem;flex-wrap:wrap">
      ${role === 'admin' ? `
        <button class="btn btn-primary" onclick="UserManagement.openCreate()">+ 添加用户</button>
      ` : ''}
      <button class="btn btn-secondary" onclick="UserManagement.openPasswordChange()">🔑 修改密码</button>
    </div>`;

    // Users table
    if (this.users.length === 0) {
      html += '<div class="empty-state"><div class="empty-icon">👥</div><h3>暂无用户数据</h3></div>';
    } else {
      html += `<div class="table-container"><table>
        <thead><tr><th>用户名</th><th>角色</th><th>创建时间</th><th>更新时间</th>
          ${role === 'admin' ? '<th>操作</th>' : ''}
        </tr></thead>
        <tbody>${this.users.map(u => `
          <tr>
            <td><span style="font-weight:500">${escapeHtml(u.username)}</span></td>
            <td><span class="badge ${u.role === 'admin' ? 'badge-log' : 'badge-return'}">${u.role === 'admin' ? '管理员' : '普通用户'}</span></td>
            <td>${formatDate(u.created_at)}</td>
            <td>${formatDate(u.updated_at)}</td>
            ${role === 'admin' ? `
              <td>
                <div style="display:flex;gap:0.5rem">
                  <button class="btn btn-xs btn-secondary" onclick="UserManagement.openEdit('${u.id}')">编辑</button>
                  <button class="btn btn-xs btn-danger" onclick="UserManagement.deleteUser('${u.id}')">删除</button>
                </div>
              </td>` : ''}
          </tr>
        `).join('')}</tbody>
      </table></div>`;
    }

    // Create/Edit modal
    if (this.showCreateModal) {
      const isEdit = !!this.editingUser;
      html += `
        <div style="position:fixed;inset:0;z-index:100;display:flex;align-items:center;justify-content:center">
          <div style="position:absolute;inset:0;background:rgba(0,0,0,0.5)" onclick="UserManagement.closeModal()"></div>
          <div class="card" style="position:relative;width:420px;max-width:90vw;z-index:101;max-height:80vh;overflow-y:auto">
            <div class="card-header"><h3>${isEdit ? '编辑用户: ' + escapeHtml(this.editingUser.username) : '添加用户'}</h3></div>
            <form onsubmit="UserManagement.saveUser(this);return false">
              <div class="form-group">
                <label class="form-label">用户名</label>
                <input class="form-input" id="um-username" required minlength="3" maxlength="32"
                       value="${isEdit ? escapeHtml(this.editingUser.username) : ''}"
                       placeholder="3-32 个字符">
              </div>
              <div class="form-group">
                <label class="form-label">密码${isEdit ? ' (留空则不修改)' : ''}</label>
                <input class="form-input" id="um-password" type="password" autocomplete="new-password"
                       ${isEdit ? '' : 'required'} minlength="6"
                       placeholder="至少 6 个字符">
              </div>
              <div class="form-group">
                <label class="form-label">角色</label>
                <select class="form-select" id="um-role">
                  <option value="user" ${isEdit && this.editingUser.role === 'user' ? 'selected' : ''}>普通用户</option>
                  <option value="admin" ${isEdit && this.editingUser.role === 'admin' ? 'selected' : ''}>管理员</option>
                </select>
              </div>
              <div style="display:flex;gap:0.5rem;margin-top:1rem">
                <button type="submit" class="btn btn-primary" style="flex:1">${isEdit ? '保存' : '创建'}</button>
                <button type="button" class="btn btn-secondary" onclick="UserManagement.closeModal()">取消</button>
              </div>
            </form>
          </div>
        </div>`;
    }

    // Change password modal
    if (this.showPasswordModal) {
      html += `
        <div style="position:fixed;inset:0;z-index:100;display:flex;align-items:center;justify-content:center">
          <div style="position:absolute;inset:0;background:rgba(0,0,0,0.5)" onclick="UserManagement.closeModal()"></div>
          <div class="card" style="position:relative;width:400px;max-width:90vw;z-index:101">
          <div class="card-header"><h3>🔑 修改密码</h3></div>
          <form onsubmit="UserManagement.changePassword(this);return false">
			<input type="text" name="username" autocomplete="username" value="${escapeHtml(AppState.username || '')}" hidden>
            <div class="form-group">
                <label class="form-label">原密码</label>
                <input class="form-input" id="um-old-password" type="password" autocomplete="current-password" required placeholder="输入当前密码">
              </div>
              <div class="form-group">
                <label class="form-label">新密码</label>
                <input class="form-input" id="um-new-password" type="password" autocomplete="new-password" required minlength="6" placeholder="至少 6 个字符">
              </div>
              <div class="form-group">
                <label class="form-label">确认新密码</label>
                <input class="form-input" id="um-confirm-password" type="password" autocomplete="new-password" required minlength="6" placeholder="再次输入新密码">
              </div>
              <div style="display:flex;gap:0.5rem;margin-top:1rem">
                <button type="submit" class="btn btn-primary" style="flex:1">修改密码</button>
                <button type="button" class="btn btn-secondary" onclick="UserManagement.closeModal()">取消</button>
              </div>
            </form>
          </div>
        </div>`;
    }

    root.innerHTML = html;
  }
};

function formatDate(iso) {
  if (!iso) return '—';
  var d = new Date(iso);
  return d.getFullYear() + '-' +
    String(d.getMonth() + 1).padStart(2, '0') + '-' +
    String(d.getDate()).padStart(2, '0') + ' ' +
    String(d.getHours()).padStart(2, '0') + ':' +
    String(d.getMinutes()).padStart(2, '0');
}
