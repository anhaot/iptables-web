// ====== Toast 通知系统 ======

const Toasts = {
  container: null,

  init() {
    this.container = document.getElementById('toast-container');
    if (!this.container) {
      this.container = document.createElement('div');
      this.container.id = 'toast-container';
      this.container.className = 'toast-container';
      document.body.appendChild(this.container);
    }
  },

  show(message, type, duration) {
    type = type || 'info';
    duration = duration || 4000;
    if (!this.container) this.init();
    const toast = document.createElement('div');
    toast.className = 'toast ' + type;
    const icons = { success: '✓', error: '✕', warning: '⚠', info: 'ℹ' };
    toast.innerHTML = '<span>' + (icons[type] || 'ℹ') + '</span><span>' + escapeHtml(message) + '</span>';
    this.container.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(20px)';
      toast.style.transition = 'all 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, duration);
  },

  success(msg) { this.show(msg, 'success'); },
  error(msg) { this.show(msg, 'error', 6000); },
  warning(msg) { this.show(msg, 'warning'); },
  info(msg) { this.show(msg, 'info'); },
};

// ====== 统一对话框 ======

const Dialogs = {
  active: null,

  confirm(options) {
    return this.open({ ...options, mode: 'confirm' });
  },

  prompt(options) {
    return this.open({ ...options, mode: 'prompt' });
  },

  alert(options) {
    return this.open({ ...options, mode: 'alert' });
  },

  open(options) {
    options = options || {};
    if (this.active) this.close(this.active.mode === 'prompt' ? null : false);
    const previousFocus = document.activeElement;
    let root = document.getElementById('dialog-root');
    if (!root) {
      root = document.createElement('div');
      root.id = 'dialog-root';
      document.body.appendChild(root);
    }

    return new Promise(resolve => {
      const mode = options.mode || 'confirm';
      const title = options.title || (mode === 'alert' ? '提示' : '请确认');
      const confirmText = options.confirmText || (mode === 'alert' ? '关闭' : '确认');
      const cancelText = options.cancelText || '取消';
      const target = options.target ? `<div class="dialog-target"><span>作用目标</span><strong>${escapeHtml(options.target)}</strong></div>` : '';
      const detail = options.detail ? `<details class="dialog-detail"><summary>查看技术详情</summary><pre>${escapeHtml(options.detail)}</pre><button class="btn btn-xs btn-secondary" type="button" data-dialog-copy>复制详情</button></details>` : '';
      const input = mode === 'prompt' ? `<label class="form-label" for="dialog-input">${escapeHtml(options.label || '输入内容')}</label><input id="dialog-input" class="form-input" type="text" value="${escapeHtml(options.defaultValue || '')}" placeholder="${escapeHtml(options.placeholder || '')}" autocomplete="off">` : '';
      root.innerHTML = `<div class="dialog-shell" role="presentation">
        <div class="dialog-overlay" data-dialog-cancel></div>
        <div class="dialog-panel" role="dialog" aria-modal="true" aria-labelledby="dialog-title" aria-describedby="dialog-message">
          <div class="dialog-header"><h2 id="dialog-title">${escapeHtml(title)}</h2><button class="modal-close" type="button" data-dialog-cancel aria-label="关闭">✕</button></div>
          <div id="dialog-message" class="dialog-message">${escapeHtml(options.message || '')}</div>
          ${target}${input}${detail}
          <div class="dialog-footer">
            ${mode === 'alert' ? '' : `<button class="btn btn-secondary" type="button" data-dialog-cancel>${escapeHtml(cancelText)}</button>`}
            <button class="btn ${options.danger ? 'btn-danger' : 'btn-primary'}" type="button" data-dialog-confirm>${escapeHtml(confirmText)}</button>
          </div>
        </div>
      </div>`;

      const keyHandler = event => {
        if (event.key === 'Escape') {
          event.preventDefault();
          event.stopPropagation();
          this.close(mode === 'prompt' ? null : false);
        }
        if (event.key === 'Enter' && mode === 'prompt' && event.target.id === 'dialog-input') {
          event.preventDefault();
          this.submitPrompt();
        }
      };
      root.addEventListener('keydown', keyHandler);
      root.querySelectorAll('[data-dialog-cancel]').forEach(button => button.addEventListener('click', () => this.close(mode === 'prompt' ? null : false)));
      root.querySelector('[data-dialog-confirm]').addEventListener('click', () => mode === 'prompt' ? this.submitPrompt() : this.close(true));
      const copyButton = root.querySelector('[data-dialog-copy]');
      if (copyButton) copyButton.addEventListener('click', () => this.copyDetail(options.detail, copyButton));
      this.active = { resolve, root, keyHandler, previousFocus, mode };
      const initialFocus = mode === 'prompt' ? root.querySelector('#dialog-input') : root.querySelector('[data-dialog-confirm]');
      if (initialFocus) {
        initialFocus.focus();
        if (mode === 'prompt') initialFocus.select();
      }
    });
  },

  submitPrompt() {
    if (!this.active || this.active.mode !== 'prompt') return;
    const input = this.active.root.querySelector('#dialog-input');
    this.close(input ? input.value : '');
  },

  async copyDetail(detail, button) {
    try {
      await navigator.clipboard.writeText(String(detail || ''));
      button.textContent = '已复制';
    } catch (_) {
      Toasts.error('复制失败，请手动选择详情文本');
    }
  },

  close(value) {
    if (!this.active) return;
    const active = this.active;
    this.active = null;
    active.root.removeEventListener('keydown', active.keyHandler);
    active.root.replaceChildren();
    active.resolve(value);
    if (active.previousFocus && typeof active.previousFocus.focus === 'function') active.previousFocus.focus();
  }
};

function escapeHtml(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = String(str);
  return div.innerHTML;
}
