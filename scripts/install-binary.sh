#!/bin/bash
# iptables-web prebuilt binary installer.
# Run this script from an unpacked release package. It does not require Go.
set -euo pipefail

APP_NAME="${APP_NAME:-iptables-web}"
INSTALL_DIR="${INSTALL_DIR:-/opt/${APP_NAME}}"
DATA_DIR="${DATA_DIR:-/var/lib/${APP_NAME}}"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
SERVICE_FILE="${SERVICE_FILE:-/etc/systemd/system/${APP_NAME}.service}"
LISTEN_ADDR="${LISTEN_ADDR:-0.0.0.0:33801}"
LISTEN_PORT="${LISTEN_ADDR##*:}"
AUTH_ENABLED="${AUTH_ENABLED:-true}"
API_KEY="${API_KEY:-}"
FIREWALL_BACKEND="${FIREWALL_BACKEND:-auto}"
DRY_RUN="${DRY_RUN:-false}"
INSTALL_METADATA="${INSTALL_DIR}/install.env"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

run() {
	if [ "${DRY_RUN}" = "true" ]; then
		echo "+ $*"
	else
		"$@"
	fi
}

run_pkg_install() {
	run "$@" || warn "依赖安装失败，可能是内网无仓库或软件源不可用，请确认 iptables 已手动安装"
}

validate_firewall_backend() {
	case "${FIREWALL_BACKEND}" in
		auto|iptables|iptables-nft|iptables-legacy|dev) ;;
		nft|nftables) error "FIREWALL_BACKEND=${FIREWALL_BACKEND} 已禁用：原生 nftables 写入不安全，请使用 iptables/iptables-nft" ;;
		*) error "不支持 FIREWALL_BACKEND=${FIREWALL_BACKEND}；可选 auto、iptables、iptables-nft、iptables-legacy、dev" ;;
	esac
}

detect_os() {
	if [ -f /etc/os-release ]; then
		# shellcheck disable=SC1091
		. /etc/os-release
		OS="${ID:-unknown}"
		OS_VERSION="${VERSION_ID:-unknown}"
	else
		OS="unknown"
		OS_VERSION="unknown"
	fi
	info "检测到系统: ${OS} ${OS_VERSION}"
}

find_binary() {
	SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
	if [ "$(basename "${SCRIPT_DIR}")" = "scripts" ]; then
		SOURCE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
	else
		SOURCE_ROOT="${SCRIPT_DIR}"
	fi
	CANDIDATES=(
		"${SCRIPT_DIR}/${APP_NAME}"
		"${SCRIPT_DIR}/bin/${APP_NAME}"
		"${SCRIPT_DIR}/../bin/${APP_NAME}"
		"${SOURCE_ROOT}/${APP_NAME}"
		"${SOURCE_ROOT}/bin/${APP_NAME}"
	)
	for path in "${CANDIDATES[@]}"; do
		if [ -x "${path}" ]; then
			BINARY_PATH="${path}"
			return
		fi
	done

	if [ -d "${SOURCE_ROOT}/dist" ]; then
		found="$(find "${SOURCE_ROOT}/dist" -mindepth 3 -maxdepth 3 -type f -path "*/bin/${APP_NAME}" | sort -V | tail -n 1)"
		if [ -n "${found}" ] && [ -x "${found}" ]; then
			BINARY_PATH="${found}"
			return
		fi
	fi

	if [ -d "${SOURCE_ROOT}/dist" ]; then
		archive="$(find "${SOURCE_ROOT}/dist" -maxdepth 1 -type f -name "${APP_NAME}-*-linux-amd64.tar.gz" | sort -Vr | head -n 1)"
		if [ -n "${archive}" ]; then
			info "从预编译压缩包中提取二进制: ${archive}"
			verify_archive_checksum "${archive}"
			EXTRACT_TMP_DIR="$(mktemp -d)"
			tar -xzf "${archive}" -C "${EXTRACT_TMP_DIR}"
			found="$(find "${EXTRACT_TMP_DIR}" -type f -path "*/bin/${APP_NAME}" | head -n 1)"
			if [ -n "${found}" ]; then
				chmod +x "${found}"
				BINARY_PATH="${found}"
				return
			fi
		fi
	fi

	error "未找到预编译二进制。请确认 ${APP_NAME}、bin/${APP_NAME} 或 dist/${APP_NAME}-*-linux-amd64.tar.gz 存在。源码编译请执行 scripts/install.sh。"
}

verify_archive_checksum() {
	local archive="$1"
	local checksum_file="${archive}.sha256"
	if [ ! -f "${checksum_file}" ]; then
		warn "未找到校验文件 ${checksum_file}，跳过 SHA-256 校验"
		return
	fi
	command -v sha256sum >/dev/null 2>&1 || error "存在校验文件但系统缺少 sha256sum"
	local expected actual
	expected="$(awk 'NR==1 {print $1}' "${checksum_file}")"
	actual="$(sha256sum "${archive}" | awk '{print $1}')"
	[ -n "${expected}" ] && [ "${expected}" = "${actual}" ] || error "预编译包 SHA-256 校验失败: ${archive}"
	info "预编译包 SHA-256 校验通过"
}

validate_binary() {
	local output
	LC_ALL=C grep -a -q 'print version and exit' "${BINARY_PATH}" || error "预编译二进制版本过旧，不支持安全版本检查: ${BINARY_PATH}。请使用当前源码重新执行 scripts/build-package.sh。"
	output="$(timeout 5 "${BINARY_PATH}" --version 2>&1)" || error "预编译二进制无法运行或版本过旧: ${BINARY_PATH}。请使用当前源码重新执行 scripts/build-package.sh。"
	case "${output}" in
		"iptables-web "*) info "检测到预编译版本: ${output}" ;;
		*) error "无法识别预编译二进制版本: ${output}" ;;
	esac
}

install_firewall_deps() {
	if command -v iptables >/dev/null 2>&1; then
		info "已检测到 iptables（iptables-nft 兼容层也受支持），跳过防火墙依赖安装"
		return
	fi

	case "${OS}" in
		centos|rhel|rocky|almalinux|kylin*)
			info "安装防火墙依赖 (yum/dnf，不安装 Go)..."
			if command -v dnf >/dev/null 2>&1; then
				run_pkg_install dnf install -y iptables-services ca-certificates curl
			else
				run_pkg_install yum install -y iptables-services ca-certificates curl
			fi
			;;
		ubuntu|debian)
			info "安装防火墙依赖 (apt，不安装 Go)..."
			run_pkg_install apt-get update -qq
			run_pkg_install apt-get install -y -qq iptables ca-certificates curl
			;;
		*)
			warn "未知系统，请手动安装 iptables；iptables-nft 兼容层受支持，原生 nftables 写入已禁用"
			;;
	esac
}

install_files() {
	info "安装预编译程序..."
	run mkdir -p "${INSTALL_DIR}" "${BIN_DIR}"
	run install -d -m 0700 "${DATA_DIR}"
	run install -m 0755 "${BINARY_PATH}" "${BIN_DIR}/${APP_NAME}"

	if [ -d "${SOURCE_ROOT}/docs" ]; then
		run mkdir -p "${INSTALL_DIR}/docs"
		run cp -R "${SOURCE_ROOT}/docs/." "${INSTALL_DIR}/docs/"
	fi
	if [ -f "${SOURCE_ROOT}/README.md" ]; then
		run cp "${SOURCE_ROOT}/README.md" "${INSTALL_DIR}/README.md"
	fi
	if [ -f "${SOURCE_ROOT}/uninstall.sh" ]; then
		run install -m 0755 "${SOURCE_ROOT}/uninstall.sh" "${INSTALL_DIR}/uninstall.sh"
	elif [ -f "${SOURCE_ROOT}/scripts/uninstall.sh" ]; then
		run install -m 0755 "${SOURCE_ROOT}/scripts/uninstall.sh" "${INSTALL_DIR}/uninstall.sh"
	fi
	if [ -f "${SOURCE_ROOT}/scripts/healthcheck.sh" ]; then
		run install -m 0755 "${SOURCE_ROOT}/scripts/healthcheck.sh" "${INSTALL_DIR}/healthcheck.sh"
	elif [ -f "${SCRIPT_DIR}/healthcheck.sh" ]; then
		run install -m 0755 "${SCRIPT_DIR}/healthcheck.sh" "${INSTALL_DIR}/healthcheck.sh"
	fi

	info "二进制文件: ${BIN_DIR}/${APP_NAME}"
	info "数据目录: ${DATA_DIR}"
}

write_install_metadata() {
	if [ "${DRY_RUN}" = "true" ]; then
		echo "+ write ${INSTALL_METADATA}"
		return
	fi
	cat >"${INSTALL_METADATA}" <<METADATA_EOF
APP_NAME=${APP_NAME}
BIN_PATH=${BIN_DIR}/${APP_NAME}
SERVICE_FILE=${SERVICE_FILE}
DATA_DIR=${DATA_DIR}
INSTALL_DIR=${INSTALL_DIR}
LISTEN_PORT=${LISTEN_PORT}
METADATA_EOF
	chmod 0600 "${INSTALL_METADATA}"
}

install_service() {
	info "安装 systemd 服务..."
	if [ "${DRY_RUN}" = "true" ]; then
		echo "+ write ${SERVICE_FILE}"
	else
		cat >"${SERVICE_FILE}" <<SERVICE_EOF
[Unit]
Description=iptables-web Firewall Manager
Documentation=file://${INSTALL_DIR}/README.md
After=network-online.target docker.service
Wants=network-online.target docker.service

[Service]
Type=simple
ExecStart=${BIN_DIR}/${APP_NAME}
Environment=RULES_FILE=${DATA_DIR}/rules.json
Environment=USERS_FILE=${DATA_DIR}/users.json
Environment=AUDIT_FILE=${DATA_DIR}/audit.jsonl
Environment=ROLLBACK_FILE=${DATA_DIR}/rollback.json
Environment=LISTEN_ADDR=${LISTEN_ADDR}
Environment=LOG_LEVEL=info
Environment=AUTH_ENABLED=${AUTH_ENABLED}
Environment=API_KEY=${API_KEY}
Environment=FIREWALL_BACKEND=${FIREWALL_BACKEND}
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=${DATA_DIR}
ReadOnlyPaths=/proc /sys
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
SERVICE_EOF
	fi
	run systemctl daemon-reload
}

start_service() {
	info "启动 ${APP_NAME}..."
	if [ "${DRY_RUN}" = "true" ]; then
		echo "+ systemctl is-active --quiet ${APP_NAME} && systemctl restart ${APP_NAME} || systemctl enable --now ${APP_NAME}"
	elif systemctl is-active --quiet "${APP_NAME}" 2>/dev/null; then
		systemctl restart "${APP_NAME}"
		systemctl enable "${APP_NAME}" >/dev/null 2>&1 || true
	else
		systemctl enable --now "${APP_NAME}"
	fi

	if [ "${DRY_RUN}" = "true" ]; then
		return
	fi

	sleep 2
	if curl -sf "http://127.0.0.1:${LISTEN_PORT}/api/v1/health" >/dev/null 2>&1; then
		info "健康检查通过"
	else
		warn "服务可能未正常启动，请检查: journalctl -u ${APP_NAME} -f"
	fi
}

print_summary() {
	echo ""
	info "========================================="
	info "  安装完成"
	if [[ "${LISTEN_ADDR}" == 127.0.0.1:* || "${LISTEN_ADDR}" == localhost:* ]]; then
		info "  访问地址: http://127.0.0.1:${LISTEN_PORT}"
	else
		access_host="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
		[ -n "${access_host}" ] || access_host="<服务器IP>"
		info "  访问地址: http://${access_host}:${LISTEN_PORT}"
	fi
	info "  认证状态: AUTH_ENABLED=${AUTH_ENABLED}"
	info "  默认账号: admin / admin123（首次登录后请立即修改）"
	info "  规则数据: ${DATA_DIR}/rules.json"
	info "  用户数据: ${DATA_DIR}/users.json"
	info "  卸载命令: sudo bash ${INSTALL_DIR}/uninstall.sh"
	info "  查看日志: journalctl -u ${APP_NAME} -f"
	info "========================================="
}

main() {
	echo "========================================"
	echo "  iptables-web 预编译包安装"
	echo "========================================"
	echo ""

	if [ "$(id -u)" != "0" ] && [ "${DRY_RUN}" != "true" ]; then
		error "请使用 root 权限运行此脚本"
	fi

	detect_os
	validate_firewall_backend
	find_binary
	validate_binary
	install_firewall_deps
	install_files
	write_install_metadata
	install_service
	start_service
	print_summary
}

main "$@"
