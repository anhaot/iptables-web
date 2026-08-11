#!/bin/bash
# Install or upgrade the controller from a prebuilt binary with systemd rollback.
set -euo pipefail

APP_NAME="${APP_NAME:-iptables-web}"
INSTALL_DIR="${INSTALL_DIR:-/opt/${APP_NAME}}"
DATA_DIR="${DATA_DIR:-/var/lib/${APP_NAME}}"
CONFIG_DIR="${CONFIG_DIR:-/etc/${APP_NAME}}"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
SERVICE_FILE="${SERVICE_FILE:-/etc/systemd/system/${APP_NAME}.service}"
ENV_FILE="${ENV_FILE:-${CONFIG_DIR}/${APP_NAME}.env}"
LISTEN_ADDR="${LISTEN_ADDR:-0.0.0.0:33801}"
LISTEN_PORT="${LISTEN_ADDR##*:}"
AUTH_ENABLED="${AUTH_ENABLED:-true}"
API_KEY="${API_KEY:-}"
HOST_CREDENTIAL_KEY="${HOST_CREDENTIAL_KEY:-}"
FIREWALL_BACKEND="${FIREWALL_BACKEND:-auto}"
LOG_LEVEL="${LOG_LEVEL:-info}"
DRY_RUN="${DRY_RUN:-false}"
SKIP_FIREWALL_DEP_INSTALL="${SKIP_FIREWALL_DEP_INSTALL:-false}"
INSTALL_METADATA="${INSTALL_DIR}/install.env"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "${SCRIPT_DIR}/scripts/install-lib.sh" ]; then
	LIB_FILE="${SCRIPT_DIR}/scripts/install-lib.sh"
elif [ -f "${SCRIPT_DIR}/install-lib.sh" ]; then
	LIB_FILE="${SCRIPT_DIR}/install-lib.sh"
else
	printf '[ERROR] 缺少 install-lib.sh，发布包不完整\n' >&2
	exit 1
fi
# shellcheck source=install-lib.sh
. "${LIB_FILE}"

info() { printf '[INFO] %s\n' "$1"; }
warn() { printf '[WARN] %s\n' "$1" >&2; }
error() { printf '[ERROR] %s\n' "$1" >&2; exit 1; }

TXN_DIR=""
WAS_ACTIVE="false"
WAS_ENABLED="false"
HAD_BINARY="false"
HAD_SERVICE="false"
HAD_ENV="false"
COMMITTED="false"

cleanup() {
	[ -z "${TXN_DIR}" ] || rm -rf "${TXN_DIR}"
}
trap cleanup EXIT

validate_inputs() {
	[ "$(id -u)" = "0" ] || [ "${DRY_RUN}" = "true" ] || error "请使用 root 权限运行安装脚本"
	[[ "${APP_NAME}" =~ ^[A-Za-z0-9_.@-]+$ ]] || error "APP_NAME 包含非法字符"
	install_reject_control_chars LISTEN_ADDR "${LISTEN_ADDR}" || exit 1
	[[ "${LISTEN_PORT}" =~ ^[0-9]+$ ]] && [ "${LISTEN_PORT}" -ge 1 ] && [ "${LISTEN_PORT}" -le 65535 ] || error "LISTEN_ADDR 端口无效: ${LISTEN_ADDR}"
	case "${AUTH_ENABLED}" in true|false) ;; *) error "AUTH_ENABLED 只能是 true 或 false" ;; esac
	case "${FIREWALL_BACKEND}" in
		auto|iptables|iptables-nft|iptables-legacy|dev) ;;
		nft|nftables) error "原生 nftables 写入已禁用，请使用 iptables/iptables-nft" ;;
		*) error "不支持 FIREWALL_BACKEND=${FIREWALL_BACKEND}" ;;
	esac
	[ -z "${API_KEY}" ] || error "安装器禁止把 API_KEY 明文写入磁盘；请安装后在页面创建可撤销的动态访问密钥"
	if [ -n "${HOST_CREDENTIAL_KEY}" ] && [ "${#HOST_CREDENTIAL_KEY}" -lt 32 ]; then
		error "HOST_CREDENTIAL_KEY 配置后至少需要 32 个字符"
	fi
	install_reject_control_chars HOST_CREDENTIAL_KEY "${HOST_CREDENTIAL_KEY}" || exit 1
	install_validate_absolute_path INSTALL_DIR "${INSTALL_DIR}" || exit 1
	install_validate_runtime_path DATA_DIR "${DATA_DIR}" || exit 1
	install_validate_runtime_path CONFIG_DIR "${CONFIG_DIR}" || exit 1
	install_validate_runtime_path BIN_DIR "${BIN_DIR}" || exit 1
	install_validate_absolute_path SERVICE_FILE "${SERVICE_FILE}" || exit 1
	install_validate_runtime_path ENV_FILE "${ENV_FILE}" || exit 1
	HEALTH_URL="$(install_health_url "${LISTEN_ADDR}")"
}

detect_source_root() {
	if [ "$(basename "${SCRIPT_DIR}")" = scripts ]; then
		SOURCE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
	else
		SOURCE_ROOT="${SCRIPT_DIR}"
	fi
}

find_binary() {
	if [ -n "${BINARY_PATH_OVERRIDE:-}" ]; then
		[ -x "${BINARY_PATH_OVERRIDE}" ] || error "BINARY_PATH_OVERRIDE 不可执行: ${BINARY_PATH_OVERRIDE}"
		BINARY_PATH="${BINARY_PATH_OVERRIDE}"
		return
	fi
	local path found archive
	for path in "${SOURCE_ROOT}/bin/${APP_NAME}" "${SCRIPT_DIR}/bin/${APP_NAME}" "${SCRIPT_DIR}/../bin/${APP_NAME}"; do
		if [ -x "${path}" ]; then BINARY_PATH="${path}"; return; fi
	done
	if [ -d "${SOURCE_ROOT}/dist" ]; then
		found="$(find "${SOURCE_ROOT}/dist" -mindepth 3 -maxdepth 3 -type f -path "*/bin/${APP_NAME}" | sort -V | tail -n 1)"
		if [ -n "${found}" ] && [ -x "${found}" ]; then BINARY_PATH="${found}"; return; fi
		archive="$(find "${SOURCE_ROOT}/dist" -maxdepth 1 -type f -name "${APP_NAME}-*-linux-amd64.tar.gz" | sort -Vr | head -n 1)"
		if [ -n "${archive}" ]; then
			[ -f "${archive}.sha256" ] || error "发布压缩包缺少 SHA-256 文件: ${archive}.sha256"
			(cd "$(dirname "${archive}")" && sha256sum -c "$(basename "${archive}.sha256")") || error "发布压缩包 SHA-256 校验失败"
			TXN_DIR="$(mktemp -d /var/tmp/iptables-web-install.XXXXXX)"
			tar -xzf "${archive}" -C "${TXN_DIR}"
			found="$(find "${TXN_DIR}" -type f -path "*/bin/${APP_NAME}" | head -n 1)"
			if [ -n "${found}" ]; then chmod +x "${found}"; BINARY_PATH="${found}"; return; fi
		fi
	fi
	error "未找到预编译二进制 bin/${APP_NAME}"
}

validate_binary() {
	local output
	output="$(timeout 5 "${BINARY_PATH}" --version 2>&1)" || error "二进制无法运行: ${BINARY_PATH}"
	case "${output}" in "iptables-web "*) info "待安装版本: ${output}" ;; *) error "无法识别二进制版本: ${output}" ;; esac
}

install_firewall_deps() {
	[ "${SKIP_FIREWALL_DEP_INSTALL}" = "true" ] && return
	command -v iptables >/dev/null 2>&1 && return
	[ "${DRY_RUN}" = "true" ] && { info "DRY_RUN：跳过 iptables 依赖安装"; return; }
	if [ -f /etc/os-release ]; then . /etc/os-release; fi
	case "${ID:-unknown}" in
		ubuntu|debian) apt-get update -qq && apt-get install -y -qq iptables ca-certificates curl ;;
		centos|rhel|rocky|almalinux|kylin*)
			if command -v dnf >/dev/null 2>&1; then dnf install -y iptables-services ca-certificates curl; else yum install -y iptables-services ca-certificates curl; fi ;;
		*) error "未找到 iptables；请先安装 iptables 或 iptables-nft 兼容层" ;;
	esac
	command -v iptables >/dev/null 2>&1 || error "iptables 依赖安装失败"
}

render_files() {
	[ -n "${TXN_DIR}" ] || TXN_DIR="$(mktemp -d /var/tmp/iptables-web-install.XXXXXX)"
	install -m 0755 "${BINARY_PATH}" "${TXN_DIR}/${APP_NAME}"
	install_write_env_file "${TXN_DIR}/${APP_NAME}.env" \
		RULES_FILE "${DATA_DIR}/rules.json" \
		USERS_FILE "${DATA_DIR}/users.json" \
		HOSTS_FILE "${DATA_DIR}/hosts.json" \
		API_KEYS_FILE "${DATA_DIR}/api-keys.json" \
		AUDIT_FILE "${DATA_DIR}/audit.jsonl" \
		ROLLBACK_FILE "${DATA_DIR}/rollback.json" \
		LISTEN_ADDR "${LISTEN_ADDR}" LOG_LEVEL "${LOG_LEVEL}" \
		AUTH_ENABLED "${AUTH_ENABLED}" FIREWALL_BACKEND "${FIREWALL_BACKEND}"
	if [ -n "${HOST_CREDENTIAL_KEY}" ]; then
		install_append_env_value "${TXN_DIR}/${APP_NAME}.env" HOST_CREDENTIAL_KEY "${HOST_CREDENTIAL_KEY}"
	elif [ -f "${ENV_FILE}" ]; then
		# Preserve an existing external master key byte-for-byte. Reading it into
		# shell evaluation or printing it would risk disclosure; only the exact
		# EnvironmentFile assignment is copied into the new 0600 file.
		grep '^HOST_CREDENTIAL_KEY=' "${ENV_FILE}" | tail -n 1 >>"${TXN_DIR}/${APP_NAME}.env" || true
	fi
	cat >"${TXN_DIR}/${APP_NAME}.service" <<EOF
[Unit]
Description=iptables-web Firewall Manager
Documentation=file://${INSTALL_DIR}/README.md
After=network-online.target
Wants=network-online.target
ConditionFileIsExecutable=${BIN_DIR}/${APP_NAME}

[Service]
Type=simple
EnvironmentFile=${ENV_FILE}
ExecStart=${BIN_DIR}/${APP_NAME}
Restart=on-failure
RestartSec=5s
TimeoutStartSec=30s
TimeoutStopSec=15s
LimitNOFILE=65536
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=${DATA_DIR}
ReadOnlyPaths=/proc /sys

[Install]
WantedBy=multi-user.target
EOF
	install_verify_rendered_unit "${TXN_DIR}/${APP_NAME}.service" "${TXN_DIR}/${APP_NAME}-verify.service"
}

backup_existing() {
	systemctl is-active --quiet "${APP_NAME}" 2>/dev/null && WAS_ACTIVE="true" || true
	systemctl is-enabled --quiet "${APP_NAME}" 2>/dev/null && WAS_ENABLED="true" || true
	if [ -f "${BIN_DIR}/${APP_NAME}" ]; then cp -a "${BIN_DIR}/${APP_NAME}" "${TXN_DIR}/old-binary"; HAD_BINARY="true"; fi
	if [ -f "${SERVICE_FILE}" ]; then
		# Old releases could persist a legacy API_KEY directly in the unit. Never
		# duplicate or restore that plaintext during an upgrade.
		sed '/^Environment=.*API_KEY=/d' "${SERVICE_FILE}" >"${TXN_DIR}/old-service"
		chmod 0644 "${TXN_DIR}/old-service"
		HAD_SERVICE="true"
	fi
	if [ -f "${ENV_FILE}" ]; then
		sed '/^API_KEY=/d' "${ENV_FILE}" >"${TXN_DIR}/old-env"
		chmod 0600 "${TXN_DIR}/old-env"
		HAD_ENV="true"
	fi
}

rollback() {
	warn "新版本启动验证失败，正在恢复安装前状态"
	systemctl stop "${APP_NAME}" 2>/dev/null || true
	if [ "${HAD_BINARY}" = true ]; then install -m 0755 "${TXN_DIR}/old-binary" "${BIN_DIR}/${APP_NAME}"; else rm -f "${BIN_DIR}/${APP_NAME}"; fi
	if [ "${HAD_SERVICE}" = true ]; then install -m 0644 "${TXN_DIR}/old-service" "${SERVICE_FILE}"; else rm -f "${SERVICE_FILE}"; fi
	if [ "${HAD_ENV}" = true ]; then install -m 0600 "${TXN_DIR}/old-env" "${ENV_FILE}"; else rm -f "${ENV_FILE}"; fi
	systemctl daemon-reload || true
	if [ "${WAS_ENABLED}" = true ]; then systemctl enable "${APP_NAME}" >/dev/null 2>&1 || true; else systemctl disable "${APP_NAME}" >/dev/null 2>&1 || true; fi
	if [ "${WAS_ACTIVE}" = true ]; then systemctl start "${APP_NAME}" || warn "旧版本也未能重新启动，请立即检查 journalctl"; fi
}

install_transaction() {
	if [ "${DRY_RUN}" = true ]; then
		info "DRY_RUN：已成功渲染并校验 systemd unit，不写入系统"
		return
	fi
	install -d -m 0755 "${BIN_DIR}" "$(dirname "${SERVICE_FILE}")"
	install -d -m 0700 "${DATA_DIR}" "${CONFIG_DIR}"
	backup_existing
	install -m 0755 "${TXN_DIR}/${APP_NAME}" "${BIN_DIR}/${APP_NAME}.new"
	mv -f "${BIN_DIR}/${APP_NAME}.new" "${BIN_DIR}/${APP_NAME}"
	install -m 0600 "${TXN_DIR}/${APP_NAME}.env" "${ENV_FILE}"
	install -m 0644 "${TXN_DIR}/${APP_NAME}.service" "${SERVICE_FILE}"
	if ! systemd-analyze verify "${SERVICE_FILE}" || ! systemctl daemon-reload || ! systemctl enable "${APP_NAME}" || ! systemctl restart "${APP_NAME}"; then
		rollback
		error "systemd 安装或启动失败，已执行回滚"
	fi
	if ! install_wait_systemd_http "${APP_NAME}" "${HEALTH_URL}" 15; then
		journalctl -u "${APP_NAME}" -n 30 --no-pager >&2 || true
		rollback
		error "健康检查失败，已恢复安装前状态"
	fi
	COMMITTED="true"
}

install_support_files() {
	[ "${DRY_RUN}" = true ] && return
	install -d -m 0755 "${INSTALL_DIR}" "${INSTALL_DIR}/docs"
	[ ! -f "${SOURCE_ROOT}/README.md" ] || install -m 0644 "${SOURCE_ROOT}/README.md" "${INSTALL_DIR}/README.md"
	[ ! -d "${SOURCE_ROOT}/docs" ] || cp -R "${SOURCE_ROOT}/docs/." "${INSTALL_DIR}/docs/"
	if [ -f "${SOURCE_ROOT}/uninstall.sh" ]; then install -m 0755 "${SOURCE_ROOT}/uninstall.sh" "${INSTALL_DIR}/uninstall.sh";
	elif [ -f "${SOURCE_ROOT}/scripts/uninstall.sh" ]; then install -m 0755 "${SOURCE_ROOT}/scripts/uninstall.sh" "${INSTALL_DIR}/uninstall.sh"; fi
	cat >"${INSTALL_METADATA}" <<EOF
APP_NAME=${APP_NAME}
BIN_PATH=${BIN_DIR}/${APP_NAME}
SERVICE_FILE=${SERVICE_FILE}
ENV_FILE=${ENV_FILE}
DATA_DIR=${DATA_DIR}
CONFIG_DIR=${CONFIG_DIR}
INSTALL_DIR=${INSTALL_DIR}
LISTEN_PORT=${LISTEN_PORT}
EOF
	chmod 0600 "${INSTALL_METADATA}"
}

main() {
	validate_inputs
	detect_source_root
	find_binary
	validate_binary
	install_firewall_deps
	render_files
	install_transaction
	install_support_files
	if [ "${DRY_RUN}" = true ]; then return; fi
	info "安装完成，systemd 服务与健康检查均已通过"
	info "服务状态: systemctl status ${APP_NAME} --no-pager"
	info "访问地址: http://<服务器IP>:${LISTEN_PORT}"
	info "配置文件: ${ENV_FILE}（0600；Agent Key 不会以明文写入）"
	info "首次账号: admin / admin123；登录后必须立即改密"
}

main "$@"
