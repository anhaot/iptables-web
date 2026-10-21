#!/bin/bash
# Offline release-package verification. Does not start the server or access the firewall.
set -euo pipefail

ARCHIVE="${1:-}"
[ -n "${ARCHIVE}" ] || { echo "Usage: bash scripts/verify-package.sh <archive.tar.gz>" >&2; exit 2; }
[ -f "${ARCHIVE}" ] || { echo "Archive not found: ${ARCHIVE}" >&2; exit 1; }

CHECKSUM_FILE="${ARCHIVE}.sha256"
if [ -f "${CHECKSUM_FILE}" ]; then
	expected="$(awk 'NR==1 {print $1}' "${CHECKSUM_FILE}")"
	actual="$(sha256sum "${ARCHIVE}" | awk '{print $1}')"
	[ "${expected}" = "${actual}" ] || { echo "SHA-256 mismatch" >&2; exit 1; }
else
	echo "Missing checksum file: ${CHECKSUM_FILE}" >&2
	exit 1
fi

contents="$(tar -tzf "${ARCHIVE}")"
for required in \
	'/bin/iptables-web' \
	'/bin/iptables-web-agent' \
	'/install-binary.sh' \
	'/install-agent.sh' \
	'/uninstall-agent.sh' \
	'/uninstall.sh' \
	'/README.md' \
	'/LICENSE' \
	'/docs/deployment.md' \
	'/docs/images/dashboard.png' \
	'/scripts/install-lib.sh' \
	'/deploy/systemd/iptables-web.service' \
	'/deploy/systemd/iptables-web-agent.service' \
	'/VERSION'; do
	printf '%s\n' "${contents}" | grep -q "${required}$" || { echo "Package missing ${required}" >&2; exit 1; }
done

for forbidden in \
	'/docs/interview-guide.md' \
	'/xmjs.md' \
	'/scripts/check-source.py' \
	'/scripts/build-package.sh' \
	'/scripts/verify-package.sh' \
	'/scripts/integration-smoke.sh' \
	'/scripts/ui-logic-test.js' \
	'/scripts/install-path-test.sh' \
	'/scripts/healthcheck.sh' \
	'/Dockerfile' \
	'/Dockerfile.release' \
	'/docker-compose.yml' \
	'/docker-compose.release.yml'; do
	if printf '%s\n' "${contents}" | grep -q "${forbidden}$"; then
		echo "Package contains unsupported or source-only file ${forbidden}" >&2
		exit 1
	fi
done

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT
tar -xzf "${ARCHIVE}" -C "${tmp_dir}"
package_root="$(find "${tmp_dir}" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
binary="${package_root}/bin/iptables-web"
agent_binary="${package_root}/bin/iptables-web-agent"

for script in "${package_root}/install-binary.sh" "${package_root}/install-agent.sh" \
	"${package_root}/uninstall.sh" "${package_root}/uninstall-agent.sh" \
	"${package_root}/scripts/install-lib.sh"; do
	bash -n "${script}"
done

[ -x "${binary}" ] || { echo "Binary is not executable" >&2; exit 1; }
[ -x "${agent_binary}" ] || { echo "Agent binary is not executable" >&2; exit 1; }
build_go_version="$(go version -m "${binary}" | awk 'NR==1 {print $2}')"
build_go_minor="$(printf '%s' "${build_go_version}" | sed -n 's/^go1\.\([0-9][0-9]*\).*/\1/p')"
[ -n "${build_go_minor}" ] && [ "${build_go_minor}" -ge 26 ] || {
	echo "Binary was built with unsupported Go version: ${build_go_version}" >&2
	exit 1
}
LC_ALL=C grep -a -q 'print version and exit' "${binary}" || { echo "Binary lacks safe --version support" >&2; exit 1; }
version_output="$(timeout 5 "${binary}" --version)"
case "${version_output}" in "iptables-web "*) ;; *) echo "Unexpected version: ${version_output}" >&2; exit 1 ;; esac
agent_version_output="$(timeout 5 "${agent_binary}" --version)"
case "${agent_version_output}" in "iptables-web-agent "*) ;; *) echo "Unexpected Agent version: ${agent_version_output}" >&2; exit 1 ;; esac
if LC_ALL=C grep -a -q '这里仅管理 packet 规则' "${binary}"; then echo "Binary still embeds the removed packet-only banner" >&2; exit 1; fi
LC_ALL=C grep -a -q '规则顺序解读' "${binary}" || { echo "Binary lacks the current ordering controls" >&2; exit 1; }
LC_ALL=C grep -a -q 'IPv6 发布端口单独展示' "${binary}" || { echo "Binary lacks Docker IPv4/IPv6 classification" >&2; exit 1; }
LC_ALL=C grep -a -q '生成命令' "${binary}" || { echo "Binary lacks the assistant generate entry" >&2; exit 1; }
LC_ALL=C grep -a -q '命令解读' "${binary}" || { echo "Binary lacks the assistant interpretation entry" >&2; exit 1; }
LC_ALL=C grep -a -q 'firewalld 命令' "${binary}" || { echo "Binary lacks firewalld assistant support" >&2; exit 1; }
LC_ALL=C grep -a -q '清空界面配置的规则' "${binary}" || { echo "Binary lacks managed-rule cleanup control" >&2; exit 1; }
LC_ALL=C grep -a -q '下载全部备份' "${binary}" || { echo "Binary lacks one-click complete backup" >&2; exit 1; }
LC_ALL=C grep -a -q '选择备份 JSON' "${binary}" || { echo "Binary lacks JSON-file restore control" >&2; exit 1; }
LC_ALL=C grep -a -q 'restoreRulesFile' "${binary}" || { echo "Binary lacks direct JSON restore upload" >&2; exit 1; }
if LC_ALL=C grep -a -q '粘贴组合 JSON' "${binary}"; then echo "Binary still embeds the obsolete paste-based restore UI" >&2; exit 1; fi
LC_ALL=C grep -a -q 'Docker 映射前的宿主机端口' "${binary}" || { echo "Binary lacks Docker original-port management" >&2; exit 1; }
if LC_ALL=C grep -a -q '管理页面连接到 33801 时' "${binary}"; then echo "Binary still embeds the removed Docker client-address banner" >&2; exit 1; fi
LC_ALL=C grep -a -q 'Docker 规则链路不可用' "${binary}" || { echo "Binary lacks Docker path validation UI" >&2; exit 1; }
LC_ALL=C grep -a -q 'displayRuleDescription' "${binary}" || { echo "Binary lacks corrected Docker mapping descriptions" >&2; exit 1; }
LC_ALL=C grep -a -q '搜索容器、端口或来源 IP' "${binary}" || { echo "Binary lacks Docker policy search" >&2; exit 1; }
LC_ALL=C grep -a -q '白名单保护' "${binary}" || { echo "Binary lacks Docker policy status summaries" >&2; exit 1; }
LC_ALL=C grep -a -q '残留策略' "${binary}" || { echo "Binary lacks residual Docker policy detection" >&2; exit 1; }
LC_ALL=C grep -a -q '在执行顺序中查看' "${binary}" || { echo "Binary lacks Docker policy order navigation" >&2; exit 1; }
LC_ALL=C grep -a -q '预览变更' "${binary}" || { echo "Binary lacks rule change preview" >&2; exit 1; }
LC_ALL=C grep -a -q '导出完整审计' "${binary}" || { echo "Binary lacks audit export UI" >&2; exit 1; }
LC_ALL=C grep -a -q '回滚最近变更' "${binary}" || { echo "Binary lacks rollback window UI" >&2; exit 1; }
LC_ALL=C grep -a -q '需要修改登录密码' "${binary}" || { echo "Binary lacks mandatory password-change flow" >&2; exit 1; }
LC_ALL=C grep -a -q 'iptables-nft 兼容后端' "${binary}" || { echo "Binary has stale login backend description" >&2; exit 1; }
LC_ALL=C grep -a -q 'favicon.svg' "${binary}" || { echo "Binary lacks embedded favicon" >&2; exit 1; }
LC_ALL=C grep -a -q 'Docker 原始宿主机端口已填写时' "${binary}" || { echo "Binary lacks post-DNAT dport protection" >&2; exit 1; }
LC_ALL=C grep -a -q -- '--ctdir ORIGINAL' "${binary}" || { echo "Binary lacks Docker original-direction protection" >&2; exit 1; }
LC_ALL=C grep -a -q 'native nftables rule writes are disabled' "${binary}" || { echo "Binary does not disable native nftables writes" >&2; exit 1; }
if LC_ALL=C grep -a -q 'firewalld 控制入口已显示' "${binary}"; then echo "Binary still embeds the removed firewalld rule UI" >&2; exit 1; fi
LC_ALL=C grep -a -q '0.0.0.0:33801' "${binary}" || { echo "Binary does not contain the external listen default" >&2; exit 1; }
grep -q 'LISTEN_ADDR="${LISTEN_ADDR:-0.0.0.0:33801}"' "${package_root}/install-binary.sh"
grep -q 'nft|nftables) error' "${package_root}/install-binary.sh" || { echo "Installer does not reject native nftables" >&2; exit 1; }
if grep -q 'firewall-cmd\|OPEN_FIREWALL_PORT\|FIREWALLD_ZONE' "${package_root}/install-binary.sh"; then echo "Installer must not configure firewalld" >&2; exit 1; fi
if grep -q 'firewall-cmd\|remove-firewall-port\|FIREWALL_PORT_' "${package_root}/uninstall.sh"; then echo "Uninstaller must not configure firewalld" >&2; exit 1; fi
grep -q -- '--remove-rules' "${package_root}/uninstall.sh"
grep -q -- '--purge' "${package_root}/uninstall.sh"
grep -q 'KEEP_RULES="false"' "${package_root}/uninstall.sh"
grep -q 'AGENT_LISTEN_ADDR="${AGENT_LISTEN_ADDR:-0.0.0.0:33802}"' "${package_root}/install-agent.sh"
grep -q 'MANAGER_URL="${MANAGER_URL:-}"' "${package_root}/install-agent.sh"
grep -q 'sudo bash install-agent.sh' "${package_root}/install-agent.sh" || { echo "Agent installer does not advertise direct interactive installation" >&2; exit 1; }
grep -q -- '--interactive' "${package_root}/install-agent.sh"
grep -q -- '--non-interactive' "${package_root}/install-agent.sh"
grep -q 'AGENT_IDENTITY_FILE' "${package_root}/install-agent.sh"
grep -q 'EnvironmentFile=' "${package_root}/install-agent.sh"
grep -q 'EnvironmentFile=' "${package_root}/install-binary.sh"
if grep -q '^Environment=API_KEY=' "${package_root}/install-binary.sh"; then echo "Installer writes plaintext API_KEY" >&2; exit 1; fi
grep -q '正在恢复安装前状态' "${package_root}/install-binary.sh" || { echo "Controller installer lacks rollback" >&2; exit 1; }
grep -q '正在恢复安装前状态' "${package_root}/install-agent.sh" || { echo "Agent installer lacks rollback" >&2; exit 1; }
if grep -q '^ExecStop=.*--cleanup' "${package_root}/install-agent.sh"; then echo "Agent service restart must not clear managed rules" >&2; exit 1; fi
grep -q 'agent.key.sha256' "${package_root}/install-agent.sh"
grep -q -- '--remove-rules' "${package_root}/uninstall-agent.sh"
grep -q -- '--keep-rules' "${package_root}/uninstall-agent.sh"
grep -q -- '--purge' "${package_root}/uninstall-agent.sh"
grep -q -- '--cleanup' "${package_root}/uninstall-agent.sh"
if grep -Eq 'iptables[[:space:]].*(-F|--flush)' "${package_root}/uninstall-agent.sh"; then echo "Agent uninstaller must never flush chains" >&2; exit 1; fi
LC_ALL=C grep -a -q 'Agent 离线' "${binary}" || { echo "Binary lacks Agent heartbeat/offline status" >&2; exit 1; }
LC_ALL=C grep -a -q '本机防火墙' "${binary}" || { echo "Binary lacks the central local-firewall entry" >&2; exit 1; }
if LC_ALL=C grep -a -q 'install-agent.sh --interactive' "${binary}"; then echo "Binary still requires the optional interactive flag in the UI" >&2; exit 1; fi
if LC_ALL=C grep -a -q '中心本机 · 本地直连' "${binary}"; then echo "Binary still embeds the removed local-host identity row" >&2; exit 1; fi
LC_ALL=C grep -a -q '登录安全策略' "${binary}" || { echo "Binary lacks configurable login security policy" >&2; exit 1; }
LC_ALL=C grep -a -q '按主机组授权' "${binary}" || { echo "Binary lacks host-group user authorization" >&2; exit 1; }
LC_ALL=C grep -a -q '验证码始终混合大小写字母和数字' "${binary}" || { echo "Binary lacks mixed-character CAPTCHA controls" >&2; exit 1; }
LC_ALL=C grep -a -q '每台主机默认收起' "${binary}" || { echo "Binary lacks collapsed fleet rows" >&2; exit 1; }
LC_ALL=C grep -a -q '密码有效期（天，0 不限制）' "${binary}" || { echo "Binary lacks password expiration policy" >&2; exit 1; }
LC_ALL=C grep -a -q '账户重置默认密码' "${binary}" || { echo "Binary lacks secure account reset policy" >&2; exit 1; }
LC_ALL=C grep -a -q 'reset-account' "${binary}" || { echo "Binary lacks account reset endpoint" >&2; exit 1; }
LC_ALL=C grep -a -q '中心 API 访问密钥' "${binary}" || { echo "Binary lacks controller access-key management UI" >&2; exit 1; }
LC_ALL=C grep -a -q '仅显示一次，请立即复制' "${binary}" || { echo "Binary lacks one-time access-key disclosure warning" >&2; exit 1; }
LC_ALL=C grep -a -q '私有 CA（可选）' "${binary}" || { echo "Binary lacks HTTPS enrollment CA input" >&2; exit 1; }
LC_ALL=C grep -a -q '证书必须包含' "${binary}" || { echo "Binary lacks IP-SAN enrollment guidance" >&2; exit 1; }
LC_ALL=C grep -a -q '/unlock' "${binary}" || { echo "Binary lacks account unlock endpoint" >&2; exit 1; }
grep -q "grep '^HOST_CREDENTIAL_KEY='" "${package_root}/install-binary.sh" || { echo "Controller installer does not preserve HOST_CREDENTIAL_KEY" >&2; exit 1; }
grep -q 'MANAGER_CA_DEST=' "${package_root}/install-agent.sh" || { echo "Agent installer does not manage a persistent manager CA copy" >&2; exit 1; }
if LC_ALL=C grep -a -q '至少 6 个字符' "${binary}"; then echo "Binary still embeds the stale six-character password hint" >&2; exit 1; fi

DRY_RUN=true SKIP_FIREWALL_DEP_INSTALL=true \
	BINARY_PATH_OVERRIDE="${binary}" bash "${package_root}/install-binary.sh"
DRY_RUN=true MANAGER_URL=http://10.0.0.5:33801 \
	AGENT_PUBLIC_URL=http://10.0.0.21:33802 AGENT_NAME=verify-node \
	bash "${package_root}/install-agent.sh" --non-interactive
if DRY_RUN=true SKIP_FIREWALL_DEP_INSTALL=true API_KEY=plaintext-must-be-rejected \
	BINARY_PATH_OVERRIDE="${binary}" bash "${package_root}/install-binary.sh" >/dev/null 2>&1; then
	echo "Installer accepted a plaintext API_KEY" >&2
	exit 1
fi

echo "Package verified: ${version_output}"
echo "Agent verified: ${agent_version_output}"
echo "No server or firewall command was started."
