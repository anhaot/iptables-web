// ====== 规则助手：命令生成 + 命令解读 ======

const RuleAssistant = {
  mode: 'generate', // 'generate' | 'interpret'
  scenario: '',
  backend: 'all',
  chain: 'INPUT',
  zone: 'public',
  family: 'ipv4',
  permanent: true,
  port: '',
  protocol: 'tcp',
  source: '',
  iface: '',
  interpretCmd: '',
  commands: [],
  explanation: '',
  warnings: [],

  setBackend(backend) {
    this.backend = backend;
    if (backend === 'firewalld') this.chain = 'INPUT';
    this.render();
  },

  setMode(m) {
    this.mode = m;
    this.warnings = [];
    this.render();
  },

  async generate() {
    try {
      const resp = await apiRequest('POST', '/assistant/generate', {
        scenario: this.scenario,
        backend: this.backend,
        chain: this.chain,
        zone: this.zone,
        family: this.family,
        permanent: this.permanent,
        port: this.port,
        protocol: this.protocol,
        source: this.source,
        interface: this.iface
      });
      this.commands = resp.commands || [];
      this.warnings = resp.warnings || [];
    } catch (e) {
      this.warnings = [e.message];
      this.commands = [];
    }
    this.render();
  },

  async interpret() {
    if (!this.interpretCmd.trim()) return;
    try {
      const resp = await apiRequest('POST', '/assistant/interpret', {
        command: this.interpretCmd
      });
      this.explanation = resp.explanation || '';
      this.warnings = resp.warnings || [];
    } catch (e) {
      this.warnings = [e.message];
      this.explanation = '';
    }
    this.render();
  },

  copyCommand(cmd) {
    const fallback = () => {
      const ta = document.createElement('textarea');
      ta.value = cmd;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.top = '-1000px';
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      try {
        document.execCommand('copy');
        Toasts.success('命令已复制');
      } catch (e) {
        Toasts.error('复制失败，请手动选择命令文本');
      } finally {
        document.body.removeChild(ta);
      }
    };

    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(cmd)
        .then(() => Toasts.success('命令已复制到剪贴板'))
        .catch(fallback);
      return;
    }
    fallback();
  },

  copyCommandAt(index) {
    const item = this.commands[index];
    if (!item || !item.command) {
      Toasts.error('没有可复制的命令');
      return;
    }
    this.copyCommand(item.command);
  },

  render() {
    const root = document.getElementById('assistant-content');
    if (!root) return;

    const scenarios = [
      { id: 'block_port', title: '阻止端口', desc: '添加 DROP 规则阻止外部访问指定端口', icon: '🚫' },
      { id: 'allow_ip', title: '仅允许指定 IP', desc: '先 ACCEPT 指定来源，再 DROP 所有其他', icon: '🔐' },
      { id: 'allow_ip_port', title: 'IP + 端口白名单', desc: '仅允许指定 IP 访问指定端口', icon: '🎯' },
      { id: 'restrict_port', title: '限制端口仅内网', desc: '只允许内网 IP 访问该端口', icon: '🏠' },
      { id: 'limit_rate', title: '限制连接速率', desc: '防止单 IP 暴力攻击（SSH/Web）', icon: '⏱' },
    ];

    root.innerHTML = `
      <div style="display:flex;gap:1rem;margin-bottom:1.5rem">
        <button class="btn ${this.mode === 'generate' ? 'btn-primary' : 'btn-secondary'}"
                onclick="RuleAssistant.setMode('generate')">
          📝 生成命令
        </button>
        <button class="btn ${this.mode === 'interpret' ? 'btn-primary' : 'btn-secondary'}"
                onclick="RuleAssistant.setMode('interpret')">
          🔍 命令解读
        </button>
      </div>

      ${this.mode === 'generate' ? this.renderGenerate(scenarios) : this.renderInterpret()}
    `;
  },

  renderGenerate(scenarios) {
    return `
      <div class="assistant-grid">
        <!-- 左侧：场景选择 + 表单 -->
        <div class="card">
          <div class="card-header"><h3>📝 选择场景</h3></div>
          <div style="display:flex;flex-direction:column;gap:0.5rem;margin-bottom:1rem">
            ${scenarios.map(s => `
              <div class="mapping-item" style="cursor:pointer;background:${this.scenario === s.id ? 'var(--accent-light)' : 'var(--bg-secondary)'};border-color:${this.scenario === s.id ? 'var(--accent)' : 'var(--border)'}"
                   onclick="RuleAssistant.scenario='${s.id}';RuleAssistant.render()">
                <div class="mapping-info">
                  <span style="font-size:1.2rem">${s.icon}</span>
                  <div>
                    <span class="mapping-name">${escapeHtml(s.title)}</span>
                    <div style="font-size:0.75rem;color:var(--text-muted)">${escapeHtml(s.desc)}</div>
                  </div>
                </div>
              </div>
            `).join('')}
          </div>

          ${this.scenario ? `
            <div class="card-header" style="margin-top:0.5rem"><h3>⚙ 参数设置</h3></div>
            <div class="form-group">
              <label class="form-label">生成目标</label>
              <select class="form-select" onchange="RuleAssistant.setBackend(this.value)">
                ${[
                  ['all','全部后端'],
                  ['iptables','iptables'],
                  ['nftables','nftables'],
                  ['firewalld','firewalld 命令']
                ].map(b => '<option value="'+b[0]+'" '+(this.backend===b[0]?'selected':'')+'>'+b[1]+'</option>').join('')}
              </select>
              <div class="form-hint">firewalld 仅在助手中生成文本，不会恢复 Zone 规则管理页面</div>
            </div>

            <div class="form-group">
              <label class="form-label">链</label>
              <select class="form-select" onchange="RuleAssistant.chain=this.value;RuleAssistant.render()">
                ${['INPUT','FORWARD','DOCKER_USER'].map(c =>
                  '<option value="'+c+'" '+(this.chain===c?'selected':'')+'>'+c+' — '+chainCN(c)+'</option>'
                ).join('')}
              </select>
	              <div class="form-hint">宿主机服务选 INPUT；Docker 发布端口优先选 DOCKER_USER（端口按 DNAT 前的宿主机端口解释）</div>
            </div>

            ${this.backend === 'firewalld' || this.backend === 'all' ? `
              <div class="form-row">
                <div class="form-group">
                  <label class="form-label">firewalld Zone</label>
                  <input class="form-input" type="text" value="${escapeHtml(this.zone)}" placeholder="public" oninput="RuleAssistant.zone=this.value">
                </div>
                <div class="form-group">
                  <label class="form-label">firewalld 持久化</label>
                  <label style="display:flex;align-items:center;gap:.5rem;padding:.65rem 0">
                    <input type="checkbox" ${this.permanent ? 'checked' : ''} onchange="RuleAssistant.permanent=this.checked">
                    生成 --permanent 并附带 reload
                  </label>
                </div>
              </div>` : ''}

            <div class="form-group">
              <label class="form-label">地址族</label>
              <select class="form-select" onchange="RuleAssistant.family=this.value">
                ${[['ipv4','IPv4（iptables）'],['ipv6','IPv6（ip6tables）'],['','按地址自动判断']].map(f => '<option value="'+f[0]+'" '+(this.family===f[0]?'selected':'')+'>'+f[1]+'</option>').join('')}
              </select>
            </div>

            ${this.scenario !== 'allow_ip' ? `
              <div class="form-group">
                <label class="form-label">端口</label>
                <input class="form-input" type="text" value="${escapeHtml(this.port)}"
                       placeholder="例如 8080 或 8000:9000"
                       oninput="RuleAssistant.port=this.value">
              </div>
            ` : ''}

            ${['allow_ip','allow_ip_port','restrict_port'].includes(this.scenario) ? `
              <div class="form-group">
                <label class="form-label">来源 IP/CIDR</label>
                <input class="form-input" type="text" value="${escapeHtml(this.source)}"
                       placeholder="例如 192.168.1.0/24"
                       oninput="RuleAssistant.source=this.value">
                <div class="form-hint">${this.scenario==='restrict_port'?'指定内网IP段（非内网将被阻止）':'允许访问的IP地址或网段'}</div>
              </div>
            ` : ''}

            ${this.scenario !== 'block_port' ? '' : `
              <div class="form-group">
                <label class="form-label">限制来源（可选）</label>
                <input class="form-input" type="text" value="${escapeHtml(this.source)}"
                       placeholder="留空=阻止所有来源"
                       oninput="RuleAssistant.source=this.value">
              </div>
            `}

            <div class="form-group">
              <label class="form-label">协议</label>
              <select class="form-select" onchange="RuleAssistant.protocol=this.value">
                ${['tcp','udp','all'].map(p =>
                  '<option value="'+p+'" '+(this.protocol===p?'selected':'')+'>'+p.toUpperCase()+'</option>'
                ).join('')}
              </select>
            </div>

            <button class="btn btn-primary" style="width:100%;margin-top:0.5rem"
                    onclick="RuleAssistant.generate()">
              🔧 生成命令
            </button>
          ` : '<div class="empty-state" style="padding:2rem"><p>请先选择一个应用场景</p></div>'}
        </div>

        <!-- 右侧：生成结果 -->
        <div class="card">
          <div class="card-header"><h3>📋 生成的命令</h3></div>
          ${this.warnings.length > 0 ? this.warnings.map(w => `
            <div class="alert alert-warning">${escapeHtml(w)}</div>
          `).join('') : ''}

          ${this.commands.length === 0 ? `
            <div class="empty-state" style="padding:2rem">
              <div class="empty-icon">💡</div>
              <p>选择场景并填写参数后，<br>点击「生成命令」查看结果</p>
            </div>
          ` : ''}

          ${this.commands.map((c, i) => `
            <div style="margin-bottom:1rem;${i>0?'margin-top:1.5rem;padding-top:1rem;border-top:1px solid var(--border)':''}">
              <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:0.5rem">
                <span class="badge badge-return">${escapeHtml(c.label)}</span>
                <button class="btn btn-xs btn-primary" onclick="RuleAssistant.copyCommandAt(${i})">
                  📋 复制
                </button>
              </div>
              <pre style="font-size:0.8rem;padding:0.75rem;white-space:pre-wrap;word-break:break-all">${escapeHtml(c.command)}</pre>
              ${c.note ? '<div style="font-size:0.75rem;color:var(--text-muted);margin-top:0.25rem">💡 '+escapeHtml(c.note)+'</div>' : ''}
            </div>
          `).join('')}
        </div>
      </div>
    `;
  },

  renderInterpret() {
    return `
      <div class="assistant-grid">
        <div class="card">
          <div class="card-header"><h3>🔍 粘贴命令</h3></div>
          <div class="form-group">
            <textarea class="form-input" rows="6" style="font-family:var(--font-mono);font-size:0.8rem"
                      placeholder="粘贴 iptables 或 nft 命令...
例如: iptables -I INPUT -p tcp --dport 8880 -j DROP
      nft add rule ip filter INPUT tcp dport 8880 drop
      firewall-cmd --zone=public --add-port=33801/tcp"
                      oninput="RuleAssistant.interpretCmd=this.value">${escapeHtml(this.interpretCmd)}</textarea>
          </div>
          <button class="btn btn-primary" style="width:100%"
                  onclick="RuleAssistant.interpret()"
                  ${!this.interpretCmd.trim() ? 'disabled' : ''}>
            🔍 开始解读
          </button>

          <div style="margin-top:1.5rem">
            <div class="card-header"><h3>💡 常用命令示例</h3></div>
            <div style="display:flex;flex-direction:column;gap:0.4rem">
              ${[
                ['阻止端口','iptables -I INPUT -p tcp --dport 8080 -j DROP'],
                ['允许IP','iptables -I INPUT -s 192.168.1.0/24 -j ACCEPT'],
                ['端口+IP','iptables -I INPUT -p tcp -s 10.0.0.5 --dport 3306 -j ACCEPT'],
                ['限制速率','iptables -I INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP'],
                ['IPv6阻止','ip6tables -I INPUT -p tcp --dport 8880 -j DROP'],
                ['nft阻止','nft add rule ip filter INPUT tcp dport 8880 drop'],
                ['nft限制IP','nft add rule ip filter INPUT ip saddr 10.0.0.0/8 tcp dport 5432 accept'],
                ['firewalld阻止端口',"firewall-cmd --zone=public --add-rich-rule='rule family=\"ipv4\" port port=\"8880\" protocol=\"tcp\" drop'"],
                ['firewalld放行IP端口',"firewall-cmd --permanent --zone=public --add-rich-rule='rule family=\"ipv4\" source address=\"10.0.0.0/8\" port port=\"3306\" protocol=\"tcp\" accept'"],
              ].map(e => `
                <div class="mapping-item" style="cursor:pointer;padding:0.5rem 0.75rem"
                     onclick="RuleAssistant.interpretCmd=${jsQuote(e[1])};RuleAssistant.render()">
                  <span style="font-size:0.75rem;font-weight:500;color:var(--accent)">${escapeHtml(e[0])}</span>
                  <code style="font-size:0.7rem;color:var(--text-secondary);word-break:break-all">${escapeHtml(e[1])}</code>
                </div>
              `).join('')}
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-header"><h3>📖 解读结果</h3></div>
          ${this.warnings.length > 0 ? this.warnings.map(w => `
            <div class="alert alert-warning">${escapeHtml(w)}</div>
          `).join('') : ''}

          ${this.explanation ? `
            <div style="line-height:1.7;font-size:0.875rem;color:var(--text-primary)">
              ${markdownToHtml(this.explanation)}
            </div>
          ` : `
            <div class="empty-state" style="padding:2rem">
              <div class="empty-icon">📖</div>
              <p>粘贴命令后点击「开始解读」<br>查看各参数含义和风险评估</p>
            </div>
          `}
        </div>
      </div>
    `;
  }
};

function chainCN(c) {
  const m = { 'INPUT': '入站', 'FORWARD': '转发', 'DOCKER_USER': 'Docker用户' };
  return m[c] || c;
}

function markdownToHtml(md) {
  // Escape HTML first to prevent XSS
  return escapeHtml(md)
    .replace(/### (.+)/g, '<h3 style="font-size:1rem;margin:0.75rem 0 0.5rem">$1</h3>')
    .replace(/^- (.+)/gm, '<li style="margin-left:1rem">$1</li>')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/`([^`]+)`/g, '<code style="background:var(--bg-secondary);padding:0.1rem 0.35rem;border-radius:4px">$1</code>')
    .replace(/\n&gt; (.+)/g, '<blockquote style="border-left:3px solid var(--accent);padding:0.25rem 0.75rem;margin:0.5rem 0;background:var(--accent-light);border-radius:0 4px 4px 0">$1</blockquote>')
    .replace(/\n\n/g, '<br>');
}

function jsQuote(value) {
  return JSON.stringify(String(value));
}
