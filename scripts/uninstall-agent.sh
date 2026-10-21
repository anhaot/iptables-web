#!/bin/bash
# Safe uninstaller for the lightweight iptables-web Agent.
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-iptables-web-agent}"
AGENT_BIN="${AGENT_BIN:-/usr/local/bin/iptables-web-agent}"
DATA_DIR="${DATA_DIR:-/var/lib/iptables-web-agent}"
CONFIG_DIR="${CONFIG_DIR:-/etc/iptables-web-agent}"
SERVICE_FILE="${SERVICE_FILE:-/etc/systemd/system/iptables-web-agent.service}"
ENV_FILE="${ENV_FILE:-${CONFIG_DIR}/agent.env}"
KEEP_DATA="false"
KEEP_RULES="false"
ASSUME_YES="false"
FORCE="false"

info() { printf '[INFO] %s\n' "$1"; }
warn() { printf '[WARN] %s\n' "$1" >&2; }
error() { printf '[ERROR] %s\n' "$1" >&2; exit 1; }

validate_remove_dir() {
	local name="$1" path="$2"
	local canonical
	canonical="$(realpath -m -- "${path}")" || error "无法规范化 ${name}"
	[ "${canonical}" = "${path}" ] || error "${name} 必须使用规范绝对路径，不能包含符号链接、.. 或尾部斜杠"
	case "${path}" in
		/|/etc|/usr|/var|/opt|/usr/local|/var/lib|/etc/systemd|/etc/systemd/system|/usr/bin|/usr/sbin|/usr/local/bin|/usr/share|/usr/lib|/usr/local/share|/home|/root|/srv|/mnt|/media|/var/log|/var/cache|/var/lib/docker|/var/lib/systemd|/etc/ssh|/etc/ssl|/etc/security|/etc/pam.d|/tmp|/var/tmp) error "拒绝删除过宽的 ${name}: ${path}" ;;
		/dev|/dev/*|/proc|/proc/*|/sys|/sys/*|/boot|/boot/*|/run|/run/*) error "拒绝删除系统目录 ${name}: ${path}" ;;
		/*) ;;
		*) error "${name} 必须是绝对路径: ${path}" ;;
	esac
}

usage() {
	cat <<'EOF'
Usage: sudo bash uninstall-agent.sh [options]

Options:
  --yes          Do not ask for confirmation.
  --keep-data    Keep Agent identity, key hash, rules, audit and rollback data.
  --remove-rules Remove Agent-managed rules recorded in rules.json (default).
  --keep-rules   Leave running Agent-managed rules in place.
  --purge        Remove managed rules, service, binary, configuration and data.
  --force        Continue file removal if exact managed-rule cleanup fails.
  -h, --help     Show this help.

The default cleanup reads the Agent's rules.json and deletes only those exact
rules with their iptables-web ownership comments. It never flushes a chain and
never removes Docker, firewalld, administrator, or other application rules.
EOF
}

while [ "$#" -gt 0 ]; do
	case "$1" in
		--yes) ASSUME_YES="true" ;;
		--keep-data) KEEP_DATA="true" ;;
		--remove-rules) KEEP_RULES="false" ;;
		--keep-rules) KEEP_RULES="true" ;;
		--purge) KEEP_DATA="false"; KEEP_RULES="false" ;;
		--force) FORCE="true" ;;
		-h|--help) usage; exit 0 ;;
		*) error "未知参数: $1" ;;
	esac
	shift
done

[ "$(id -u)" = "0" ] || error "请使用 root 权限卸载 Agent"
[[ "${SERVICE_NAME}" =~ ^[A-Za-z0-9_.@-]+$ ]] || error "SERVICE_NAME 包含非法字符"
validate_remove_dir DATA_DIR "${DATA_DIR}"
validate_remove_dir CONFIG_DIR "${CONFIG_DIR}"

unit_value() {
	local key="$1"
	[ -f "${SERVICE_FILE}" ] || return 0
	sed -n "s|^Environment=${key}=||p" "${SERVICE_FILE}" | tail -n 1
}

env_value() {
	local key="$1" raw
	[ -f "${ENV_FILE}" ] || return 0
	raw="$(sed -n "s|^${key}=||p" "${ENV_FILE}" | tail -n 1)"
	if [[ "${raw}" == \"*\" ]]; then raw="${raw:1:${#raw}-2}"; fi
	raw="${raw//\\\"/\"}"
	raw="${raw//\\\\/\\}"
	printf '%s\n' "${raw}"
}

RULES_FILE="$(env_value RULES_FILE)"; [ -n "${RULES_FILE}" ] || RULES_FILE="$(unit_value RULES_FILE)"
FIREWALL_BACKEND="$(env_value FIREWALL_BACKEND)"; [ -n "${FIREWALL_BACKEND}" ] || FIREWALL_BACKEND="$(unit_value FIREWALL_BACKEND)"
[ -n "${RULES_FILE}" ] || RULES_FILE="${DATA_DIR}/rules.json"
[ -n "${FIREWALL_BACKEND}" ] || FIREWALL_BACKEND="auto"

if [ "${ASSUME_YES}" != "true" ]; then
	printf '%s\n' "将卸载 ${SERVICE_NAME}："
	printf '  服务: %s\n  二进制: %s\n' "${SERVICE_FILE}" "${AGENT_BIN}"
	[ "${KEEP_RULES}" = "true" ] || printf '  删除 rules.json 中由 Agent 精确记录并带所有权标记的规则\n'
	[ "${KEEP_DATA}" = "true" ] || printf '  删除数据和身份目录: %s, %s\n' "${DATA_DIR}" "${CONFIG_DIR}"
	read -r -p '确认继续？[y/N] ' answer
	case "${answer}" in y|Y|yes|YES) ;; *) info "已取消"; exit 0 ;; esac
fi

info "停止并禁用 ${SERVICE_NAME} 服务"
systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
systemctl disable "${SERVICE_NAME}" 2>/dev/null || true

if [ "${KEEP_RULES}" != "true" ] && [ -f "${RULES_FILE}" ]; then
	if [ ! -x "${AGENT_BIN}" ]; then
		[ "${FORCE}" = "true" ] || error "找不到 Agent 二进制，无法安全清理托管规则；已保留文件。可使用 --keep-rules 或 --force。"
		warn "Agent 二进制不存在，未清理托管规则"
	elif ! RULES_FILE="${RULES_FILE}" FIREWALL_BACKEND="${FIREWALL_BACKEND}" "${AGENT_BIN}" --cleanup; then
		[ "${FORCE}" = "true" ] || error "规则精确清理失败；已保留 Agent 和数据。修复后重试，或明确使用 --force。"
		warn "规则清理失败，但 --force 允许继续"
	else
		info "已精确删除 Agent 自己记录并带所有权标记的规则"
	fi
fi

find "${SERVICE_FILE}" -maxdepth 0 -type f -delete 2>/dev/null || true
find "${AGENT_BIN}" -maxdepth 0 -type f -delete 2>/dev/null || true
systemctl daemon-reload
systemctl reset-failed "${SERVICE_NAME}" 2>/dev/null || true

if [ "${KEEP_DATA}" = "true" ]; then
	info "按要求保留 ${DATA_DIR} 和 ${CONFIG_DIR}"
else
	find "${DATA_DIR}" -mindepth 1 -delete 2>/dev/null || true
	rmdir "${DATA_DIR}" 2>/dev/null || true
	find "${CONFIG_DIR}" -mindepth 1 -delete 2>/dev/null || true
	rmdir "${CONFIG_DIR}" 2>/dev/null || true
fi

info "${SERVICE_NAME} 已卸载完成"
