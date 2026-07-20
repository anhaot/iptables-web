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
const { dockerMappingFamily, formatHostEndpoint, dockerMappingDescription, dockerRulePathUsable } = require('../web/js/components/docker-ports.js');
assert.strictEqual(dockerMappingFamily({ family: 'ipv4', host_ip: '::' }), 'ipv4');
assert.strictEqual(dockerMappingFamily({ host_ip: '0.0.0.0' }), 'ipv4');
assert.strictEqual(dockerMappingFamily({ host_ip: '::' }), 'ipv6');
assert.strictEqual(dockerMappingFamily({ host_ip: '[::1]' }), 'ipv6');
assert.strictEqual(formatHostEndpoint('::', 8080), '[::]:8080');
assert.strictEqual(dockerMappingDescription({ host_ip: '0.0.0.0', host_port: 18080, container_name: 'nginx', container_port: 80 }), '宿主机:18080 → nginx:80');
assert.strictEqual(dockerRulePathUsable({ path: { usable: false } }), false);
const { normalizeDockerPortCandidate } = require('../web/js/components/rule-form.js');
assert.deepStrictEqual(
  normalizeDockerPortCandidate({ dport: '18080', original_dport: '18080' }),
  { dport: '', original_dport: '18080' }
);

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

process.stdout.write('UI ordering and Docker address-family logic verified\n');
