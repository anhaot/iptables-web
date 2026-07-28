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
	'/install-binary.sh' \
	'/uninstall.sh' \
	'/README.md' \
	'/docs/deployment.md' \
	'/VERSION'; do
	printf '%s\n' "${contents}" | grep -q "${required}$" || { echo "Package missing ${required}" >&2; exit 1; }
done

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT
tar -xzf "${ARCHIVE}" -C "${tmp_dir}"
package_root="$(find "${tmp_dir}" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
binary="${package_root}/bin/iptables-web"

[ -x "${binary}" ] || { echo "Binary is not executable" >&2; exit 1; }
build_go_version="$(go version -m "${binary}" | awk 'NR==1 {print $2}')"
build_go_minor="$(printf '%s' "${build_go_version}" | sed -n 's/^go1\.\([0-9][0-9]*\).*/\1/p')"
[ -n "${build_go_minor}" ] && [ "${build_go_minor}" -ge 26 ] || {
	echo "Binary was built with unsupported Go version: ${build_go_version}" >&2
	exit 1
}
LC_ALL=C grep -a -q 'print version and exit' "${binary}" || { echo "Binary lacks safe --version support" >&2; exit 1; }
version_output="$(timeout 5 "${binary}" --version)"
case "${version_output}" in "iptables-web "*) ;; *) echo "Unexpected version: ${version_output}" >&2; exit 1 ;; esac
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
LC_ALL=C grep -a -q '管理页面连接到 33801 时' "${binary}" || { echo "Binary lacks Docker client-address guidance" >&2; exit 1; }
LC_ALL=C grep -a -q 'Docker 规则链路不可用' "${binary}" || { echo "Binary lacks Docker path validation UI" >&2; exit 1; }
LC_ALL=C grep -a -q 'displayRuleDescription' "${binary}" || { echo "Binary lacks corrected Docker mapping descriptions" >&2; exit 1; }
LC_ALL=C grep -a -q '搜索容器、端口或来源 IP' "${binary}" || { echo "Binary lacks Docker policy search" >&2; exit 1; }
LC_ALL=C grep -a -q '白名单保护' "${binary}" || { echo "Binary lacks Docker policy status summaries" >&2; exit 1; }
LC_ALL=C grep -a -q '残留策略' "${binary}" || { echo "Binary lacks residual Docker policy detection" >&2; exit 1; }
LC_ALL=C grep -a -q '在执行顺序中查看' "${binary}" || { echo "Binary lacks Docker policy order navigation" >&2; exit 1; }
LC_ALL=C grep -a -q '预览变更' "${binary}" || { echo "Binary lacks rule change preview" >&2; exit 1; }
LC_ALL=C grep -a -q '导出完整审计' "${binary}" || { echo "Binary lacks audit export UI" >&2; exit 1; }
LC_ALL=C grep -a -q '回滚最近变更' "${binary}" || { echo "Binary lacks rollback window UI" >&2; exit 1; }
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

echo "Package verified: ${version_output}"
echo "No server or firewall command was started."
