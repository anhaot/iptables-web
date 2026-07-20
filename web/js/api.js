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

async function apiRequest(method, path, body, rawJSON) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  const token = getAuthToken();
  if (token) {
    opts.headers['Authorization'] = 'Bearer ' + token;
  }
  if (body !== undefined && body !== null) {
    opts.body = rawJSON ? body : JSON.stringify(body);
  }
  try {
    const resp = await fetch(`${API_BASE}${path}`, opts);
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
      throw new ApiError(resp.status, json.error?.code || 'unknown', json.error?.message || resp.statusText);
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

  // Users
  listUsers: () => apiRequest('GET', '/users'),
  getUser: (id) => apiRequest('GET', `/users/${id}`),
  createUser: (user) => apiRequest('POST', '/users', user),
  updateUser: (id, user) => apiRequest('PUT', `/users/${id}`, user),
  deleteUser: (id) => apiRequest('DELETE', `/users/${id}`),
  changePassword: (oldPwd, newPwd) => apiRequest('POST', '/auth/password', { old_password: oldPwd, new_password: newPwd }),

  // Rules
  listRules: (chain, backend) => {
    const params = new URLSearchParams();
    if (chain) params.set('chain', chain);
    if (backend) params.set('backend', backend);
    const query = params.toString();
    return apiRequest('GET', `/rules${query ? `?${query}` : ''}`);
  },
  getRule: (id) => apiRequest('GET', `/rules/${id}`),
  createRule: (rule) => apiRequest('POST', '/rules', rule),
  updateRule: (id, rule) => apiRequest('PUT', `/rules/${id}`, rule),
  deleteRule: (id) => apiRequest('DELETE', `/rules/${id}`),
  toggleRule: (id) => apiRequest('POST', `/rules/${id}/toggle`),
  reorderRules: (chain, ids) => apiRequest('PUT', '/rules/reorder', { backend: 'packet', chain, rule_ids: ids }),

  // System
  getChains: (backend) => apiRequest('GET', `/system/chains?backend=${encodeURIComponent(backend || 'packet')}`),
  getChainRules: (chain, backend) => apiRequest('GET', `/system/chains/${encodeURIComponent(chain)}/rules?backend=${encodeURIComponent(backend || 'packet')}`),
  getSystemInfo: () => apiRequest('GET', '/system/status'),
  backupRules: (backend) => {
    const headers = {};
    const token = getAuthToken();
    if (token) headers['Authorization'] = 'Bearer ' + token;
    return fetch(`${API_BASE}/system/backup?backend=${encodeURIComponent(backend || 'packet')}`, { headers }).then(r => {
      if (r.status === 401) {
        sessionStorage.clear();
        window.location.href = '/login.html';
        throw new Error('请先登录');
      }
      if (r.status === 403) throw new Error('需要管理员权限');
      if (!r.ok) throw new Error('Backup failed');
      const disposition = r.headers.get('Content-Disposition') || '';
      const filenameMatch = disposition.match(/filename="?([^";]+)"?/i);
      return r.blob().then(blob => ({ blob, filename: filenameMatch ? filenameMatch[1] : '' }));
    });
  },
  restoreRules: (data, backend) => apiRequest('POST', `/system/restore?backend=${encodeURIComponent(backend || 'packet')}`, { data }),
  restoreRulesFile: (jsonText, backend) => apiRequest('POST', `/system/restore?backend=${encodeURIComponent(backend || 'packet')}`, jsonText, true),
  clearManagedRules: () => apiRequest('DELETE', '/system/managed-rules'),

  // Docker
  getDockerMappings: () => apiRequest('GET', '/docker/mappings'),
  getDockerDiagnostics: () => apiRequest('GET', '/docker/diagnostics'),
  createDockerWhitelist: (request) => apiRequest('POST', '/docker/whitelist', request),

  // Assistant
  listScenarios: () => apiRequest('GET', '/assistant/scenarios'),
  generateCommand: (req) => apiRequest('POST', '/assistant/generate', req),
  interpretCommand: (cmd) => apiRequest('POST', '/assistant/interpret', { command: cmd }),

  // Health
  health: () => apiRequest('GET', '/health'),
};
