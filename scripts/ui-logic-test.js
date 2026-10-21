'use strict';

const assert = require('assert');
const fs = require('fs');
const { pageFromHash, hostDetailTabs, agentHeartbeatState, hostConnectivityPresentation } = require('../web/js/app.js');
const { reorderItems, findOrderingRisk, displayRuleDescription } = require('../web/js/components/rules-list.js');

assert.strictEqual(pageFromHash('#rules'), 'rules', 'refresh must preserve rules page');
assert.strictEqual(pageFromHash('#docker'), 'docker', 'refresh must preserve Docker page');
assert.strictEqual(pageFromHash('#hosts'), 'hosts', 'refresh must preserve multi-host page');
assert.strictEqual(pageFromHash('#fleet'), 'fleet');
assert.strictEqual(pageFromHash('#assistant'), 'assistant');
assert.strictEqual(pageFromHash(''), 'fleet');
assert.match(hostDetailTabs('rules'), /class="active"[^>]*>规则</);
assert.doesNotMatch(hostDetailTabs('rules'), /规则助手/, 'assistant must be a global sidebar tool');
const heartbeatNow = Date.parse('2026-08-05T12:00:00Z');
assert.strictEqual(agentHeartbeatState({ agent_last_seen_at: '2026-08-05T11:59:30Z' }, heartbeatNow).state, 'reporting');
assert.strictEqual(agentHeartbeatState({ agent_last_seen_at: '2026-08-05T11:59:00Z' }, heartbeatNow).state, 'offline');
assert.strictEqual(hostConnectivityPresentation({ enabled: true, agent_last_seen_at: '2026-08-05T11:59:00Z' }, { online: true }, heartbeatNow).text, 'Agent 离线');
assert.strictEqual(hostConnectivityPresentation({ enabled: true, agent_last_seen_at: '2026-08-05T11:59:30Z' }, { error: 'blocked' }, heartbeatNow).text, '回连异常');

const rules = [{ id: 'one' }, { id: 'two' }, { id: 'three' }];
assert.deepStrictEqual(reorderItems(rules, 0, 2).map(rule => rule.id), ['two', 'three', 'one']);
assert.deepStrictEqual(reorderItems(rules, 2, 1).map(rule => rule.id), ['one', 'three', 'two']);
assert.deepStrictEqual(rules.map(rule => rule.id), ['one', 'two', 'three'], 'input array must not be mutated');

const unsafe = [
  { enabled: true, action: 'DROP', protocol: 'tcp', dport: '443' },
  { enabled: true, action: 'ACCEPT', protocol: 'tcp', dport: '443', source: '10.0.0.0/8' }
];
assert.match(findOrderingRisk(unsafe), /不能把兜底 DROP/);
assert.strictEqual(findOrderingRisk(unsafe.slice().reverse()), '');
assert.strictEqual(
  displayRuleDescription({ desc: '允许 192.168.21.188 访问 nginx:80 → :18080', original_dport: '18080' }),
  '允许 192.168.21.188 访问 宿主机:18080 → nginx:80'
);

global.escapeHtml = value => String(value == null ? '' : value)
  .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');
global.actionBadge = action => `<b>${action}</b>`;
global.FirewallHelp = {
  chainTitle: name => `chain:${name}`
};
const { readableAny } = require('../web/js/components/chains-view.js');
assert.strictEqual(readableAny('*', '任意接口'), '任意接口');
const {
  dockerMappingFamily, formatHostEndpoint, dockerMappingDescription, dockerRulePathUsable,
  buildDockerPolicies, formatPolicyPositions,
} = require('../web/js/components/docker-ports.js');
assert.strictEqual(dockerMappingFamily({ family: 'ipv4', host_ip: '::' }), 'ipv4');
assert.strictEqual(dockerMappingFamily({ host_ip: '0.0.0.0' }), 'ipv4');
assert.strictEqual(dockerMappingFamily({ host_ip: '::' }), 'ipv6');
assert.strictEqual(dockerMappingFamily({ host_ip: '[::1]' }), 'ipv6');
assert.strictEqual(formatHostEndpoint('::', 8080), '[::]:8080');
assert.strictEqual(dockerMappingDescription({ host_ip: '0.0.0.0', host_port: 18080, container_name: 'nginx', container_port: 80 }), '宿主机:18080 → nginx:80');
assert.strictEqual(dockerRulePathUsable({ path: { usable: false } }), false);
const dockerPolicies = buildDockerPolicies([
  { family: 'ipv4', protocol: 'tcp', host_ip: '0.0.0.0', host_port: 38080, container_name: 'nginx', container_port: 8080 },
  { family: 'ipv4', protocol: 'tcp', host_ip: '0.0.0.0', host_port: 38880, container_name: 'kuboard', container_port: 80 },
], [
  { id: 'allow-a', chain: 'DOCKER_USER', protocol: 'tcp', original_dport: '38080', source: '10.118.24.59', action: 'ACCEPT', position: 1, enabled: true },
  { id: 'allow-b', chain: 'DOCKER_USER', protocol: 'tcp', original_dport: '38080', source: '20.3.10.121', action: 'ACCEPT', position: 2, enabled: true },
  { id: 'drop', chain: 'DOCKER_USER', protocol: 'tcp', original_dport: '38080', source: '', action: 'DROP', position: 8, enabled: true },
  { id: 'orphan', chain: 'DOCKER_USER', protocol: 'tcp', original_dest: '10.0.0.5', original_dport: '39999', source: '', action: 'DROP', position: 9, enabled: true },
], 'ipv4');
assert.strictEqual(dockerPolicies.length, 3, 'mappings plus an orphaned policy should be grouped');
assert.strictEqual(dockerPolicies[0].mapping.container_name, 'nginx');
assert.strictEqual(dockerPolicies[0].status.id, 'protected');
assert.deepStrictEqual(dockerPolicies[0].allowedSources, ['10.118.24.59', '20.3.10.121']);
assert.strictEqual(dockerPolicies[1].status.id, 'unmanaged');
assert.strictEqual(dockerPolicies[2].status.id, 'residual');
assert.strictEqual(formatPolicyPositions([1, 2, 3]), '#1–#3');
assert.strictEqual(formatPolicyPositions([1, 3, 8]), '#1、#3、#8');
const riskyPolicy = buildDockerPolicies([
  { family: 'ipv4', protocol: 'tcp', host_ip: '0.0.0.0', host_port: 30081, container_name: 'kuboard', container_port: 30081 },
], [
  { id: 'early-drop', chain: 'DOCKER_USER', protocol: 'tcp', original_dport: '30081', source: '', action: 'DROP', position: 1, enabled: true },
  { id: 'late-allow', chain: 'DOCKER_USER', protocol: 'tcp', original_dport: '30081', source: '10.0.0.8', action: 'ACCEPT', position: 2, enabled: true },
], 'ipv4')[0];
assert.strictEqual(riskyPolicy.status.id, 'risk');
assert.match(riskyPolicy.orderRisk, /位于允许/);
const { normalizeDockerPortCandidate, buildRuleChangePreview } = require('../web/js/components/rule-form.js');
assert.deepStrictEqual(
  normalizeDockerPortCandidate({ dport: '18080', original_dport: '18080' }),
  { dport: '', original_dport: '18080' }
);
const preview = buildRuleChangePreview(
  { chain: 'INPUT', action: 'ACCEPT', protocol: 'tcp', dport: '80', enabled: true },
  { chain: 'INPUT', action: 'DROP', protocol: 'tcp', dport: '80', enabled: true }
);
assert.strictEqual(preview.mode, 'update');
assert.deepStrictEqual(preview.rows.map(row => row.field), ['action']);
const ruleFormUI = fs.readFileSync(require.resolve('../web/js/components/rule-form.js'), 'utf8');
assert.doesNotMatch(ruleFormUI, /zone\s*:/, 'packet rule form must not submit legacy firewalld zone');
assert.match(ruleFormUI, /预览变更/);

const rulesUI = fs.readFileSync(require.resolve('../web/js/components/rules-list.js'), 'utf8');
assert.doesNotMatch(rulesUI, /moveRule\(|>↑<|>↓</, 'sorting must use drag only');
assert.doesNotMatch(rulesUI, /这里仅管理 packet 规则/, 'removed packet-only banner must stay removed');
const assistantUI = fs.readFileSync(require.resolve('../web/js/components/rule-assistant.js'), 'utf8');
assert.match(assistantUI, /firewalld 命令/);
assert.match(assistantUI, /firewalld阻止端口/);
const systemUI = fs.readFileSync(require.resolve('../web/js/components/system-view.js'), 'utf8');
assert.match(systemUI, /下载全部备份/);
assert.match(systemUI, /选择备份 JSON/);
assert.match(systemUI, /restoreRulesFile/);
assert.doesNotMatch(systemUI, /粘贴组合 JSON/);
assert.match(systemUI, /清空界面配置的规则/);
assert.match(systemUI, /导出完整审计/);
assert.match(systemUI, /查看详情/);
assert.match(systemUI, /auditBeforeAfter/);
assert.match(systemUI, /Request ID/);
assert.match(systemUI, /回滚最近变更/);
assert.match(systemUI, /host_ids/);
assert.match(systemUI, /host_groups/);
assert.match(systemUI, /可管理范围/);
assert.match(systemUI, /按主机组授权/);
assert.match(systemUI, /动态继承/);
assert.match(systemUI, /登录安全策略/);
assert.match(systemUI, /min_changed_characters/);
assert.match(systemUI, /case_sensitive/);
assert.match(systemUI, /sp-min-length[^\n]+1, 128/);
assert.match(systemUI, /max_failures/);
assert.match(systemUI, /password_max_age_days/);
assert.match(systemUI, /unlockAccount/);
assert.match(systemUI, /中心 API 访问密钥/);
assert.match(systemUI, /仅显示一次，请立即复制/);
assert.match(systemUI, /Agent 管理密钥由系统自动交换/);
assert.match(systemUI, /resetAccount/);
assert.match(systemUI, /value="local"/);
assert.match(systemUI, /当前账号/, 'current administrator should not be offered a destructive self-delete action');
const apiUI = fs.readFileSync(require.resolve('../web/js/api.js'), 'utf8');
assert.match(apiUI, /selected_host_id/);
assert.match(apiUI, /\/hosts\/\$\{encodeURIComponent\(hostID\)\}\/api/);
const hostManagementUI = fs.readFileSync(require.resolve('../web/js/components/host-management.js'), 'utf8');
assert.match(hostManagementUI, /待确认 Agent/);
assert.match(hostManagementUI, /批量确认/);
assert.match(hostManagementUI, /approveAgentEnrollments/);
assert.match(hostManagementUI, /Agent 主动发起/);
assert.doesNotMatch(hostManagementUI, /name="api_key"/);
assert.match(hostManagementUI, /自签名证书 CA/);
assert.match(hostManagementUI, /地址由 Agent 的签名申请维护/);
assert.match(hostManagementUI, /install-agent\.sh/);
assert.doesNotMatch(hostManagementUI, /当前控制端实例的访问密钥/);
assert.match(hostManagementUI, /AppState\.openHost/);
assert.match(hostManagementUI, /probeConcurrency: 5/);
assert.match(hostManagementUI, /最近检测/);
assert.match(hostManagementUI, /Agent 心跳/);
assert.match(hostManagementUI, /sudo bash install-agent\.sh/);
assert.doesNotMatch(hostManagementUI, /install-agent\.sh --interactive/);
assert.match(apiUI, /createAccessKey/);
assert.match(apiUI, /deleteAccessKey/);
assert.match(apiUI, /listAgentEnrollments/);
assert.match(apiUI, /approveAgentEnrollments/);
assert.match(apiUI, /rejectAgentEnrollments/);
assert.doesNotMatch(apiUI, /createHost:/);
global.sessionStorage = { getItem: key => key === 'selected_host_id' ? 'mutable-host' : '' };
const { scopedAPIPath } = require('../web/js/api.js');
assert.strictEqual(scopedAPIPath('/rules', 'bound-host'), '/hosts/bound-host/api/rules');
assert.strictEqual(scopedAPIPath('/rules', ''), '/rules', 'an explicit local scope must not inherit the mutable selection');
assert.strictEqual(scopedAPIPath('/rules'), '/hosts/mutable-host/api/rules', 'legacy calls may still use the current selection');
const { hostStatusPresentation } = require('../web/js/components/host-management.js');
assert.strictEqual(hostStatusPresentation({ enabled: false }, { online: true }).text, '已停用');
assert.strictEqual(hostStatusPresentation({ enabled: true }, { online: true, latency: 12 }).text, '在线 · 12ms');
const probeMethod = hostManagementUI.match(/async probe\(id, quiet, force = !quiet\) \{[\s\S]*?\n  \},/);
assert.ok(probeMethod, 'host probe method must exist');
assert.doesNotMatch(probeMethod[0], /this\.render\(\)/, 'probe status updates must not replace a form being edited');
assert.match(probeMethod[0], /this\.renderStatus\(id\)/);
const indexUI = fs.readFileSync(require.resolve('../web/index.html'), 'utf8');
assert.match(indexUI, /onclick="updateDashboard\(\)">↻ 刷新/);
assert.match(indexUI, /info\.firewall_version \|\| info\.firewall_backend/);
assert.match(indexUI, /const context = AppState\.captureHostContext\(\)/);
assert.match(indexUI, /api\.getSystemInfo\(targetHostID\)/);
assert.match(indexUI, /role="dialog" aria-modal="true"/);
assert.match(indexUI, /无法读取当前主机规则/);
assert.match(indexUI, /id="host-context-bar"/);
assert.match(indexUI, /href="#fleet"/);
assert.match(indexUI, /id="local-firewall-nav"/);
assert.match(indexUI, /data-page="assistant"/);
assert.match(indexUI, /data-admin-only/);
assert.match(indexUI, /id="fleet-health-count"/);
const baseCSS = fs.readFileSync(require.resolve('../web/css/base.css'), 'utf8');
assert.match(baseCSS, /\[hidden\]\s*\{\s*display:\s*none\s*!important;/, 'hidden authorization links must not be overridden by flex styles');
const componentsCSS = fs.readFileSync(require.resolve('../web/css/components.css'), 'utf8');
assert.match(componentsCSS, /\.fleet-host-facts\s*\{/);
assert.match(componentsCSS, /\.fleet-rule-panel\s*\{/);
assert.match(componentsCSS, /position:\s*sticky/);
const fleetOverviewUI = fs.readFileSync(require.resolve('../web/js/components/fleet-overview.js'), 'utf8');
assert.match(fleetOverviewUI, /renderLocalRow/);
assert.match(fleetOverviewUI, /toggleHost/);
assert.match(fleetOverviewUI, /listHostRules/);
assert.match(fleetOverviewUI, /已纳管主机/);
assert.match(fleetOverviewUI, /Agent 身份/);
assert.match(fleetOverviewUI, /规则摘要/);
assert.match(fleetOverviewUI, /暂时无法读取规则/);
assert.match(fleetOverviewUI, /invalidateRuleDetails/);
assert.match(fleetOverviewUI, /ruleDetailSerials/);
assert.doesNotMatch(fleetOverviewUI, /local-firewall-card/);
assert.doesNotMatch(fleetOverviewUI, /管理控制端自身的 iptables 规则/);
const appUI = fs.readFileSync(require.resolve('../web/js/app.js'), 'utf8');
assert.match(appUI, /local-tabs-only/);
assert.match(appUI, /canAccessLocal/);
assert.match(appUI, /captureHostContext/);
assert.match(appUI, /isHostContextCurrent/);
assert.doesNotMatch(appUI, /← 返回纳管概览/);
assert.doesNotMatch(indexUI, /id="host-select"/);
assert.match(indexUI, /fleet-overview\.js/);
const notificationsUI = fs.readFileSync(require.resolve('../web/js/components/notifications.js'), 'utf8');
assert.match(notificationsUI, /const Dialogs/);
assert.match(rulesUI, /aria-label="\$\{rule\.enabled \? '禁用' : '启用'\}规则/);
assert.match(ruleFormUI, /handleKeydown/);
for (const file of ['rules-list.js', 'rule-form.js', 'docker-ports.js', 'host-management.js', 'system-view.js', 'user-management.js']) {
  const source = fs.readFileSync(require.resolve('../web/js/components/' + file), 'utf8');
  assert.doesNotMatch(source, /(^|[^.\w])(confirm|prompt)\(/m, file + ' must use the unified dialog');
}
const loginUI = fs.readFileSync(require.resolve('../web/login.html'), 'utf8');
assert.doesNotMatch(loginUI, /iptables 与 nftables 双后端/);
assert.match(loginUI, /iptables-nft 兼容后端/);
assert.match(loginUI, /requires_password_change/);
assert.match(loginUI, /验证码包含大小写字母和数字/);
assert.doesNotMatch(loginUI, /text-transform:\s*uppercase/);
const passwordChangeUI = fs.readFileSync(require.resolve('../web/change-password.html'), 'utf8');
assert.match(passwordChangeUI, /需要修改登录密码/);
assert.match(passwordChangeUI, /\/api\/v1\/auth\/password/);
assert.match(passwordChangeUI, /\/api\/v1\/auth\/policy/);
assert.match(passwordChangeUI, /min_length: 1/);
assert.ok(fs.existsSync(require.resolve('../web/favicon.svg')));

process.stdout.write('UI auth, rule preview, audit, rollback, and Docker logic verified\n');

const { effectiveHostMonitoring } = require('../web/js/app.js');
const { fleetHostMatches } = require('../web/js/components/fleet-overview.js');
assert.deepStrictEqual(effectiveHostMonitoring({probe_interval_seconds:30},{probe_interval_seconds:120,offline_after_seconds:90}), {probe_interval_seconds:30,offline_after_seconds:90});
assert.strictEqual(agentHeartbeatState({agent_last_seen_at:'2026-08-05T11:59:00Z',offline_after_seconds:90},heartbeatNow).state,'reporting');
const searchHost={name:'生产 Web',group:'PROD',base_url:'https://10.20.3.4:33802',agent_id:'aabbcc'};
assert.strictEqual(fleetHostMatches(searchHost,'web 10.20'),true);
assert.strictEqual(fleetHostMatches(searchHost,'prod'),true);
assert.strictEqual(fleetHostMatches(searchHost,'10.99'),false);
const { groupDockerPolicies, parseDockerSources, dockerBatchPayload }=require('../web/js/components/docker-ports.js');
assert.deepStrictEqual(parseDockerSources('10.0.0.1,10.0.0.2\n10.0.0.1；10.1.0.0/16'),['10.0.0.1','10.0.0.2','10.1.0.0/16']);
const grouped=groupDockerPolicies(buildDockerPolicies([
 {container_id:'container-a',container_name:'app',host_ip:'0.0.0.0',host_port:8080,container_port:80,protocol:'tcp'},
 {container_id:'container-a',container_name:'app',host_ip:'0.0.0.0',host_port:8443,container_port:443,protocol:'tcp'},
 {container_id:'container-b',container_name:'other',host_ip:'0.0.0.0',host_port:9000,container_port:80,protocol:'tcp'}
],[], 'ipv4'));
assert.strictEqual(grouped.length,2);
assert.strictEqual(grouped[0].mappings.length,2,'one container should group all its published ports');
const payload=dockerBatchPayload(['10.0.0.1'],[{container_id:'not-a-request-field',family:'ipv4',host_port:8080,container_port:80,host_ip:'0.0.0.0',container_name:'app',protocol:'tcp'}]);
assert.strictEqual('container_id' in payload.mappings[0],false,'Docker discovery metadata must not leak into strict API requests');
assert.strictEqual('family' in payload.mappings[0],false);
process.stdout.write('Monitoring inheritance, fleet search, Docker grouping and batch payloads verified\n');

// Exercise actual HTTP response decoding: legacy Agents return a plain text 404.
async function verifyAPIResponsesAndHostIsolation() {
  const { apiRequest, ApiError } = require('../web/js/api.js');
  const originalFetch = global.fetch;
  const originalAppState = global.AppState;
  const originalWindow = global.window;
  global.window = { location: { pathname: '/index.html', href: '' } };
  try {
    for (const [status, body, code] of [
      [404, '404 page not found\n', 'http_error'],
      [405, 'Method Not Allowed', 'http_error'],
      [502, '<html>Bad Gateway</html>', 'http_error'],
      [400, 'null', 'unknown'],
      [409, '{"success":false,"error":{"code":"agent_upgrade_required","message":"请升级 Agent"}}', 'agent_upgrade_required'],
      [200, '{"success":true}unexpected', 'invalid_response'],
      [200, 'null', 'invalid_response'],
      [200, '{"success":false,"error":{"code":"validation_error","message":"bad input"}}', 'validation_error'],
    ]) {
      let requests = 0;
      global.fetch = async () => { requests++; return { status, ok: status < 400, text: async () => body }; };
      await assert.rejects(apiRequest('POST', '/docker/whitelist/batch', {}, false, false, ''), error => error instanceof ApiError && error.status === status && error.code === code && !/Unexpected/.test(error.message));
      assert.strictEqual(requests, 1, 'writes must never be automatically retried');
    }
    global.fetch = async () => ({ status: 201, ok: true, text: async () => '{"success":true,"data":{"id":"created"}}' });
    assert.deepStrictEqual(await apiRequest('POST', '/rules', {}, false, false, ''), {id:'created'});
    global.fetch = async () => ({ status: 204, ok: true, text: async () => { throw new Error('204 has no body'); } });
    assert.strictEqual(await apiRequest('DELETE', '/rules/test', undefined, false, false, ''), null);
    global.fetch = async () => { throw new TypeError('Failed to fetch'); };
    await assert.rejects(apiRequest('GET', '/hosts'), error => error.status === 0 && error.code === 'network_error');

    const { DockerPorts } = require('../web/js/components/docker-ports.js');
    global.AppState = { captureHostContext: () => ({hostID:'new'}), isHostContextCurrent: ctx => ctx.hostID === 'new' };
    DockerPorts.selectionContext = {hostID:'old'};
    DockerPorts.mappings = [{container_name:'old-host-container'}];
    DockerPorts.rules = [{id:'old-rule'}];
    DockerPorts.diagnostics = {path:{usable:true}};
    DockerPorts.selectedRules.add('old-rule');
    DockerPorts.resetSelectionContext();
    assert.deepStrictEqual(DockerPorts.mappings, []);
    assert.deepStrictEqual(DockerPorts.rules, []);
    assert.strictEqual(DockerPorts.diagnostics, null);
    assert.strictEqual(DockerPorts.selectedRules.size, 0);
    process.stdout.write('Legacy/plain text HTTP errors, no write retries, and Docker host isolation verified\n');
  } finally {
    global.fetch = originalFetch; global.AppState = originalAppState; global.window = originalWindow;
  }
}
verifyAPIResponsesAndHostIsolation().catch(error => { console.error(error); process.exitCode = 1; });
