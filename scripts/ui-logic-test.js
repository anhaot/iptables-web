'use strict';

const assert = require('assert');
const fs = require('fs');
const { pageFromHash } = require('../web/js/app.js');
const { reorderItems, findOrderingRisk, displayRuleDescription } = require('../web/js/components/rules-list.js');

assert.strictEqual(pageFromHash('#rules'), 'rules', 'refresh must preserve rules page');
assert.strictEqual(pageFromHash('#docker'), 'docker', 'refresh must preserve Docker page');
assert.strictEqual(pageFromHash(''), 'dashboard');

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
assert.match(systemUI, /回滚最近变更/);
const loginUI = fs.readFileSync(require.resolve('../web/login.html'), 'utf8');
assert.doesNotMatch(loginUI, /iptables 与 nftables 双后端/);
assert.match(loginUI, /iptables-nft 兼容后端/);
assert.match(loginUI, /requires_password_change/);
const passwordChangeUI = fs.readFileSync(require.resolve('../web/change-password.html'), 'utf8');
assert.match(passwordChangeUI, /首次登录，请修改密码/);
assert.match(passwordChangeUI, /\/api\/v1\/auth\/password/);
assert.ok(fs.existsSync(require.resolve('../web/favicon.svg')));

process.stdout.write('UI auth, rule preview, audit, rollback, and Docker logic verified\n');
