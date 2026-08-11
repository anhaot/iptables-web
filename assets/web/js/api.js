const API_BASE = '/api/v1';

class ApiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

function getAuthToken() {
  return sessionStorage.getItem('auth_token') || '';
}

function getSelectedHostID() {
  return sessionStorage.getItem('selected_host_id') || '';
}

function scopedAPIPath(path, explicitHostID) {
  const hostID = explicitHostID === undefined ? getSelectedHostID() : String(explicitHostID || '');
  if (!hostID) return path;
  const scopedPrefixes = ['/rules', '/system/', '/docker/', '/health'];
  if (!scopedPrefixes.some(prefix => path === prefix || path.startsWith(prefix))) return path;
  return `/hosts/${encodeURIComponent(hostID)}/api${path}`;
}

async function apiRequest(method, path, body, rawJSON, unscoped, hostID) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  const token = getAuthToken();
  if (token) {
    opts.headers['Authorization'] = 'Bearer ' + token;
  }
  if (body !== undefined && body !== null) {
    opts.body = rawJSON ? body : JSON.stringify(body);
  }
  try {
    const requestPath = unscoped ? path : scopedAPIPath(path, hostID);
    const resp = await fetch(`${API_BASE}${requestPath}`, opts);
    // Redirect to login if unauthorized
    if (resp.status === 401) {
      sessionStorage.clear();
      if (window.location.pathname !== '/login.html') {
        window.location.href = '/login.html';
      }
      throw new ApiError(401, 'unauthorized', '请先登录');
    }
    if (resp.status === 204) {
      return null;
    }
    const json = await resp.json();
    if (!resp.ok) {
      const code = json.error?.code || 'unknown';
      if (resp.status === 403 && code === 'password_change_required' && window.location.pathname !== '/change-password.html') {
        window.location.href = '/change-password.html';
      }
      throw new ApiError(resp.status, code, json.error?.message || resp.statusText);
    }
    return json.data;
  } catch (err) {
    if (err instanceof ApiError) throw err;
    throw new ApiError(0, 'network_error', err.message || 'Network request failed');
  }
}

const api = {
  // Auth
  login: (username, password) => apiRequest('POST', '/auth/login', { username, password }),
  logout: () => apiRequest('POST', '/auth/logout'),
  sessionCheck: () => apiRequest('GET', '/auth/session'),
  getAuthPolicy: () => apiRequest('GET', '/auth/policy'),

  // Users
  listUsers: () => apiRequest('GET', '/users'),
  getUser: (id) => apiRequest('GET', `/users/${id}`),
  createUser: (user) => apiRequest('POST', '/users', user),
  updateUser: (id, user) => apiRequest('PUT', `/users/${id}`, user),
  resetAccount: (id) => apiRequest('POST', `/users/${id}/reset-account`),
  unlockAccount: (id) => apiRequest('POST', `/users/${id}/unlock`),
  deleteUser: (id) => apiRequest('DELETE', `/users/${id}`),
  changePassword: (oldPwd, newPwd) => apiRequest('POST', '/auth/password', { old_password: oldPwd, new_password: newPwd }),
  getSecurityPolicy: () => apiRequest('GET', '/security-policy'),
  updateSecurityPolicy: (policy) => apiRequest('PUT', '/security-policy', policy),

  // Managed Agents (always handled by the controller)
  listHosts: () => apiRequest('GET', '/hosts'),
  getHost: (id) => apiRequest('GET', `/hosts/${id}`),
  updateHost: (id, host) => apiRequest('PUT', `/hosts/${id}`, host),
  deleteHost: (id) => apiRequest('DELETE', `/hosts/${id}`),
  probeHost: (id) => apiRequest('GET', `/hosts/${id}/probe`),
  batchCreateRule: (hostIDs, rule) => apiRequest('POST', '/hosts/batch/rules', { host_ids: hostIDs, rule }),
  listAgentEnrollments: () => apiRequest('GET', '/agent-enrollments'),
  approveAgentEnrollments: (ids, caPEMByID) => apiRequest('POST', '/agent-enrollments/approve', { ids, ca_pem_by_id: caPEMByID || {} }),
  rejectAgentEnrollments: (ids) => apiRequest('POST', '/agent-enrollments/reject', { ids }),

  // Compatibility credentials for controller API integrations. Agent
  // enrollment exchanges its own credential automatically.
  listAccessKeys: () => apiRequest('GET', '/access-keys'),
  createAccessKey: (name) => apiRequest('POST', '/access-keys', { name }),
  deleteAccessKey: (id) => apiRequest('DELETE', `/access-keys/${id}`),

  // Rules
  listRules: (chain, backend, hostID) => {
    const params = new URLSearchParams();
    if (chain) params.set('chain', chain);
    if (backend) params.set('backend', backend);
    const query = params.toString();
    return apiRequest('GET', `/rules${query ? `?${query}` : ''}`, undefined, false, false, hostID);
  },
  listLocalRules: () => apiRequest('GET', '/rules', undefined, false, true),
  listHostRules: (id) => apiRequest('GET', `/hosts/${encodeURIComponent(id)}/api/rules`, undefined, false, true),
  getRule: (id, hostID) => apiRequest('GET', `/rules/${id}`, undefined, false, false, hostID),
  createRule: (rule, hostID) => apiRequest('POST', '/rules', rule, false, false, hostID),
  updateRule: (id, rule, hostID) => apiRequest('PUT', `/rules/${id}`, rule, false, false, hostID),
  deleteRule: (id, hostID) => apiRequest('DELETE', `/rules/${id}`, undefined, false, false, hostID),
  toggleRule: (id, hostID) => apiRequest('POST', `/rules/${id}/toggle`, undefined, false, false, hostID),
  reorderRules: (chain, ids, hostID) => apiRequest('PUT', '/rules/reorder', { backend: 'packet', chain, rule_ids: ids }, false, false, hostID),

  // System
  getChains: (backend, hostID) => apiRequest('GET', `/system/chains?backend=${encodeURIComponent(backend || 'packet')}`, undefined, false, false, hostID),
  getChainRules: (chain, backend, hostID) => apiRequest('GET', `/system/chains/${encodeURIComponent(chain)}/rules?backend=${encodeURIComponent(backend || 'packet')}`, undefined, false, false, hostID),
  getSystemInfo: (hostID) => apiRequest('GET', '/system/status', undefined, false, false, hostID),
  backupRules: (backend, hostID) => {
    const headers = {};
    const token = getAuthToken();
    if (token) headers['Authorization'] = 'Bearer ' + token;
    const path = scopedAPIPath(`/system/backup?backend=${encodeURIComponent(backend || 'packet')}`, hostID);
    return fetch(`${API_BASE}${path}`, { headers }).then(r => {
      if (r.status === 401) {
        sessionStorage.clear();
        window.location.href = '/login.html';
        throw new Error('请先登录');
      }
      if (r.status === 403) throw new Error('没有当前主机的管理权限');
      if (!r.ok) throw new Error('Backup failed');
      const disposition = r.headers.get('Content-Disposition') || '';
      const filenameMatch = disposition.match(/filename="?([^";]+)"?/i);
      return r.blob().then(blob => ({ blob, filename: filenameMatch ? filenameMatch[1] : '' }));
    });
  },
  restoreRules: (data, backend, hostID) => apiRequest('POST', `/system/restore?backend=${encodeURIComponent(backend || 'packet')}`, { data }, false, false, hostID),
  restoreRulesFile: (jsonText, backend, hostID) => apiRequest('POST', `/system/restore?backend=${encodeURIComponent(backend || 'packet')}`, jsonText, true, false, hostID),
  clearManagedRules: (hostID) => apiRequest('DELETE', '/system/managed-rules', undefined, false, false, hostID),
  listAuditEvents: (limit, hostID) => apiRequest('GET', `/system/audit?limit=${encodeURIComponent(limit || 50)}`, undefined, false, false, hostID),
  getRollbackStatus: (hostID) => apiRequest('GET', '/system/rollback', undefined, false, false, hostID),
  rollbackLastChange: (id, hostID) => apiRequest('POST', '/system/rollback', { id }, false, false, hostID),
  downloadAudit: (hostID) => {
    const headers = {};
    const token = getAuthToken();
    if (token) headers['Authorization'] = 'Bearer ' + token;
    return fetch(`${API_BASE}${scopedAPIPath('/system/audit?download=1', hostID)}`, { headers }).then(r => {
      if (r.status === 401) {
        sessionStorage.clear();
        window.location.href = '/login.html';
        throw new Error('请先登录');
      }
      if (r.status === 403) throw new Error('没有当前主机的管理权限');
      if (!r.ok) throw new Error('审计日志导出失败');
      const disposition = r.headers.get('Content-Disposition') || '';
      const filenameMatch = disposition.match(/filename="?([^";]+)"?/i);
      return r.blob().then(blob => ({ blob, filename: filenameMatch ? filenameMatch[1] : '' }));
    });
  },

  // Docker
  getDockerMappings: (hostID) => apiRequest('GET', '/docker/mappings', undefined, false, false, hostID),
  getDockerDiagnostics: (hostID) => apiRequest('GET', '/docker/diagnostics', undefined, false, false, hostID),
  createDockerWhitelist: (request, hostID) => apiRequest('POST', '/docker/whitelist', request, false, false, hostID),

  // Assistant
  listScenarios: () => apiRequest('GET', '/assistant/scenarios'),
  generateCommand: (req) => apiRequest('POST', '/assistant/generate', req),
  interpretCommand: (cmd) => apiRequest('POST', '/assistant/interpret', { command: cmd }),

  // Health
  health: () => apiRequest('GET', '/health'),
};

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { scopedAPIPath };
}
