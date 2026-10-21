#!/bin/bash
# Clean uninstaller for native iptables-web installations.
set -euo pipefail

APP_NAME="${APP_NAME:-iptables-web}"
INSTALL_DIR="${INSTALL_DIR:-/opt/${APP_NAME}}"
DATA_DIR="${DATA_DIR:-/var/lib/${APP_NAME}}"
BIN_PATH="${BIN_PATH:-/usr/local/bin/${APP_NAME}}"
SERVICE_FILE="${SERVICE_FILE:-/etc/systemd/system/${APP_NAME}.service}"
CONFIG_DIR="${CONFIG_DIR:-/etc/${APP_NAME}}"
ENV_FILE="${ENV_FILE:-${CONFIG_DIR}/${APP_NAME}.env}"
METADATA_FILE="${INSTALL_DIR}/install.env"
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
Usage: sudo bash uninstall.sh [options]

Options:
  --yes                    Do not ask for confirmation.
  --keep-data              Keep users.json and rules.json.
  --remove-rules           Remove rules recorded in rules.json (default behavior).
  --keep-rules             Leave running managed rules in place (not recommended).
  --purge                  Full cleanup: remove managed rules, files, and data.
  --force                  Continue file removal when managed-rule cleanup fails.
  -h, --help               Show this help.

Default behavior first removes rules recorded by the interface, then removes
the service, binary, documentation, and data. It never flushes a whole chain.
Use --keep-rules only when those rules must intentionally remain active.
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

[ "$(id -u)" -eq 0 ] || error "请使用 root 权限运行卸载脚本"
[[ "${APP_NAME}" =~ ^[A-Za-z0-9_.@-]+$ ]] || error "APP_NAME 包含非法字符"

# Reject unsafe explicit paths before metadata can replace them. In particular,
# an existing installation must never turn an invalid invocation into a valid
# destructive uninstall by silently overriding DATA_DIR.
validate_remove_dir INSTALL_DIR "${INSTALL_DIR}"
validate_remove_dir CONFIG_DIR "${CONFIG_DIR}"
validate_remove_dir DATA_DIR "${DATA_DIR}"

metadata_value() {
	local key="$1"
	[ -f "${METADATA_FILE}" ] || return 0
	awk -F= -v key="${key}" '$1 == key {sub(/^[^=]*=/, ""); print; exit}' "${METADATA_FILE}"
}

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

meta_bin="$(metadata_value BIN_PATH)"
meta_data="$(metadata_value DATA_DIR)"
meta_service="$(metadata_value SERVICE_FILE)"
meta_env="$(metadata_value ENV_FILE)"
meta_config="$(metadata_value CONFIG_DIR)"
[ -n "${meta_bin}" ] && BIN_PATH="${meta_bin}"
[ -n "${meta_data}" ] && DATA_DIR="${meta_data}"
[ -n "${meta_service}" ] && SERVICE_FILE="${meta_service}"
[ -n "${meta_env}" ] && ENV_FILE="${meta_env}"
[ -n "${meta_config}" ] && CONFIG_DIR="${meta_config}"
validate_remove_dir INSTALL_DIR "${INSTALL_DIR}"
validate_remove_dir CONFIG_DIR "${CONFIG_DIR}"
validate_remove_dir DATA_DIR "${DATA_DIR}"

RULES_FILE="$(env_value RULES_FILE)"; [ -n "${RULES_FILE}" ] || RULES_FILE="$(unit_value RULES_FILE)"
USERS_FILE="$(env_value USERS_FILE)"; [ -n "${USERS_FILE}" ] || USERS_FILE="$(unit_value USERS_FILE)"
FIREWALL_BACKEND="$(env_value FIREWALL_BACKEND)"; [ -n "${FIREWALL_BACKEND}" ] || FIREWALL_BACKEND="$(unit_value FIREWALL_BACKEND)"
[ -n "${RULES_FILE}" ] || RULES_FILE="${DATA_DIR}/rules.json"
[ -n "${USERS_FILE}" ] || USERS_FILE="${DATA_DIR}/users.json"
[ -n "${FIREWALL_BACKEND}" ] || FIREWALL_BACKEND="auto"

if [ "${ASSUME_YES}" != "true" ]; then
	printf '%s\n' "将彻底卸载 ${APP_NAME}："
	printf '  服务: %s\n  二进制: %s\n  安装目录: %s\n' "${SERVICE_FILE}" "${BIN_PATH}" "${INSTALL_DIR}"
	[ "${KEEP_RULES}" = "true" ] || printf '  高风险：删除本程序托管的内核防火墙规则\n'
	[ "${KEEP_DATA}" = "true" ] || printf '  删除数据目录: %s\n' "${DATA_DIR}"
	read -r -p '确认继续？[y/N] ' answer
	case "${answer}" in y|Y|yes|YES) ;; *) info "已取消"; exit 0 ;; esac
fi

info "停止并禁用 ${APP_NAME} 服务"
systemctl stop "${APP_NAME}" 2>/dev/null || true
systemctl disable "${APP_NAME}" 2>/dev/null || true

if [ "${KEEP_RULES}" != "true" ] && [ -f "${RULES_FILE}" ]; then
	if [ -x "${BIN_PATH}" ]; then
		info "删除 rules.json 中由本程序托管的防火墙规则"
		if ! RULES_FILE="${RULES_FILE}" USERS_FILE="${USERS_FILE}" \
			FIREWALL_BACKEND="${FIREWALL_BACKEND}" \
			"${BIN_PATH}" --cleanup; then
			if [ "${FORCE}" != "true" ]; then
				error "规则清理失败。已保留程序和数据；修复防火墙后重试，或明确使用 --force。"
			fi
			warn "规则清理失败，但 --force 允许继续"
		fi
	else
		if [ "${FORCE}" != "true" ]; then
			error "找不到支持 --cleanup 的已安装二进制 ${BIN_PATH}，无法安全删除托管规则。可使用 --keep-rules 或 --force。"
		fi
		warn "未清理托管规则：二进制不存在"
	fi
fi

info "删除 systemd 服务、二进制和安装文档"
rm -f "${SERVICE_FILE}"
rm -rf "/etc/systemd/system/${APP_NAME}.service.d"
systemctl daemon-reload
systemctl reset-failed "${APP_NAME}" 2>/dev/null || true
rm -f "${BIN_PATH}"
rm -rf "${INSTALL_DIR}"
rm -rf "${CONFIG_DIR}"

if [ "${KEEP_DATA}" = "true" ]; then
	info "按要求保留数据目录 ${DATA_DIR}"
else
	info "删除数据目录 ${DATA_DIR}"
	rm -rf "${DATA_DIR}"
fi

info "${APP_NAME} 已卸载完成"
