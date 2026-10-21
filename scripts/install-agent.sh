#!/bin/bash
# Install the lightweight iptables-web agent. The target host does not need Go.
set -euo pipefail

AGENT_BINARY_NAME="${AGENT_BINARY_NAME:-iptables-web-agent}"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
DATA_DIR="${DATA_DIR:-/var/lib/iptables-web-agent}"
CONFIG_DIR="${CONFIG_DIR:-/etc/iptables-web-agent}"
SERVICE_FILE="${SERVICE_FILE:-/etc/systemd/system/iptables-web-agent.service}"
ENV_FILE="${ENV_FILE:-${CONFIG_DIR}/agent.env}"
AGENT_LISTEN_ADDR="${AGENT_LISTEN_ADDR:-0.0.0.0:33802}"
FIREWALL_BACKEND="${FIREWALL_BACKEND:-auto}"
ROTATE_AGENT_KEY="${ROTATE_AGENT_KEY:-false}"
DRY_RUN="${DRY_RUN:-false}"
MANAGER_URL="${MANAGER_URL:-}"
MANAGER_CA_FILE="${MANAGER_CA_FILE:-}"
AGENT_DISPLAY_NAME="${AGENT_NAME:-$(hostname -s 2>/dev/null || hostname)}"
AGENT_GROUP="${AGENT_GROUP:-}"
AGENT_PUBLIC_URL="${AGENT_PUBLIC_URL:-}"
MANAGER_CA_DEST="${CONFIG_DIR}/manager-ca.pem"
INSTALL_MODE="auto"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "${SCRIPT_DIR}/scripts/install-lib.sh" ]; then
	LIB_FILE="${SCRIPT_DIR}/scripts/install-lib.sh"
elif [ -f "${SCRIPT_DIR}/install-lib.sh" ]; then
	LIB_FILE="${SCRIPT_DIR}/install-lib.sh"
else
	echo "[ERROR] 缺少 install-lib.sh，发布包不完整" >&2
	exit 1
fi
# shellcheck source=install-lib.sh
. "${LIB_FILE}"

info() { echo "[INFO] $1"; }
warn() { echo "[WARN] $1" >&2; }
error() { echo "[ERROR] $1" >&2; exit 1; }

usage() {
	cat <<'USAGE'
用法:
  sudo MANAGER_URL=http://10.0.0.5:33801 bash install-agent.sh
  sudo bash install-agent.sh

选项:
  --interactive      强制交互填写（通常直接运行脚本即可）
  --non-interactive  只读取环境变量，缺少必填项立即失败
  -h, --help         显示帮助

常用环境变量:
  MANAGER_URL, AGENT_NAME, AGENT_GROUP, AGENT_PUBLIC_URL,
  AGENT_LISTEN_ADDR, FIREWALL_BACKEND, MANAGER_CA_FILE
USAGE
}

validate_base_url() {
	local value="$1"
	[[ "${value}" =~ ^https?://(\[[0-9A-Fa-f:]+\]|[A-Za-z0-9._-]+)(:[0-9]{1,5})?/?$ ]]
}

while [ "$#" -gt 0 ]; do
	case "$1" in
		--interactive) INSTALL_MODE="interactive" ;;
		--non-interactive) INSTALL_MODE="non-interactive" ;;
		-h|--help) usage; exit 0 ;;
		*) error "未知参数: $1（使用 --help 查看用法）" ;;
	esac
	shift
done

[ "$(id -u)" = "0" ] || [ "${DRY_RUN}" = "true" ] || error "请使用 root 权限安装 Agent"

if [ "${INSTALL_MODE}" = "auto" ]; then
	if [ -n "${MANAGER_URL}" ]; then
		INSTALL_MODE="non-interactive"
	elif [ -t 0 ] && [ -t 1 ]; then
		INSTALL_MODE="interactive"
	else
		INSTALL_MODE="non-interactive"
	fi
fi

if [ "${INSTALL_MODE}" = "non-interactive" ] && [ -z "${MANAGER_URL}" ]; then
	error "必须设置 MANAGER_URL，例如: sudo MANAGER_URL=http://10.0.0.5:33801 bash install-agent.sh"
fi

ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
for candidate in "${SCRIPT_DIR}/bin/${AGENT_BINARY_NAME}" "${ROOT_DIR}/bin/${AGENT_BINARY_NAME}" "${SCRIPT_DIR}/../bin/${AGENT_BINARY_NAME}" "${SCRIPT_DIR}/${AGENT_BINARY_NAME}"; do
	if [ -x "${candidate}" ]; then AGENT_BINARY="${candidate}"; break; fi
done
[ -n "${AGENT_BINARY:-}" ] || error "未找到 bin/${AGENT_BINARY_NAME}，请使用包含 Agent 的发布包"

command -v iptables >/dev/null 2>&1 || error "目标机必须安装 iptables 或 iptables-nft 兼容层"

AGENT_PORT="${AGENT_LISTEN_ADDR##*:}"
if [ -z "${AGENT_PUBLIC_URL}" ]; then
	AGENT_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
	[ -n "${AGENT_IP}" ] || error "无法自动确定目标机 IP，请设置 AGENT_PUBLIC_URL"
	AGENT_PUBLIC_URL="http://${AGENT_IP}:${AGENT_PORT}"
fi

if [ "${INSTALL_MODE}" = "interactive" ]; then
	[ -t 0 ] && [ -t 1 ] || error "交互安装需要终端；自动化环境请设置 MANAGER_URL 或使用 --non-interactive"
	echo "iptables-web Agent 交互安装"
	echo "直接回车可采用方括号中的默认值。"
	echo
	read -r -p "管理端 URL${MANAGER_URL:+ [${MANAGER_URL}]}: " input
	MANAGER_URL="${input:-${MANAGER_URL}}"
	read -r -p "Agent 显示名称 [${AGENT_DISPLAY_NAME}]: " input
	AGENT_DISPLAY_NAME="${input:-${AGENT_DISPLAY_NAME}}"
	read -r -p "主机分组${AGENT_GROUP:+ [${AGENT_GROUP}]}（可留空）: " input
	AGENT_GROUP="${input:-${AGENT_GROUP}}"
	read -r -p "中心回连地址 [${AGENT_PUBLIC_URL}]: " input
	AGENT_PUBLIC_URL="${input:-${AGENT_PUBLIC_URL}}"
	read -r -p "防火墙后端 [${FIREWALL_BACKEND}]: " input
	FIREWALL_BACKEND="${input:-${FIREWALL_BACKEND}}"
	read -r -p "管理端 CA 文件${MANAGER_CA_FILE:+ [${MANAGER_CA_FILE}]}（HTTP 或公共证书可留空）: " input
	MANAGER_CA_FILE="${input:-${MANAGER_CA_FILE}}"
	echo
	echo "即将安装:"
	echo "  管理端: ${MANAGER_URL:-<未填写>}"
	echo "  Agent:   ${AGENT_DISPLAY_NAME} (${AGENT_GROUP:-未分组})"
	echo "  回连:    ${AGENT_PUBLIC_URL}"
	echo "  后端:    ${FIREWALL_BACKEND}"
	read -r -p "确认继续？[y/N]: " confirm
	case "${confirm}" in y|Y|yes|YES) ;; *) error "安装已取消" ;; esac
fi

[ -n "${MANAGER_URL}" ] || error "必须设置 MANAGER_URL，例如: sudo MANAGER_URL=http://10.0.0.5:33801 bash install-agent.sh"
validate_base_url "${MANAGER_URL}" || error "MANAGER_URL 必须是无路径、无查询参数的 HTTP(S) 地址"
[[ "${AGENT_DISPLAY_NAME}" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || error "AGENT_NAME 只能包含字母、数字、点、下划线和连字符"
[[ "${AGENT_GROUP}" =~ ^[A-Za-z0-9._\ -]{0,64}$ ]] || error "AGENT_GROUP 只能包含字母、数字、空格、点、下划线和连字符"
validate_base_url "${AGENT_PUBLIC_URL}" || error "AGENT_PUBLIC_URL 必须是中心端可访问的无路径 HTTP(S) 地址"
[[ "${AGENT_PORT}" =~ ^[0-9]+$ ]] && [ "${AGENT_PORT}" -ge 1 ] && [ "${AGENT_PORT}" -le 65535 ] || error "AGENT_LISTEN_ADDR 端口无效: ${AGENT_LISTEN_ADDR}"
AGENT_HEALTH_URL="$(install_health_url "${AGENT_LISTEN_ADDR}")"
[ -z "${MANAGER_CA_FILE}" ] || [ -f "${MANAGER_CA_FILE}" ] || error "MANAGER_CA_FILE 不存在: ${MANAGER_CA_FILE}"
[ -z "${MANAGER_CA_FILE}" ] || install_validate_absolute_path MANAGER_CA_FILE "${MANAGER_CA_FILE}" || exit 1
install_validate_private_dir DATA_DIR "${DATA_DIR}" || exit 1
install_validate_private_dir CONFIG_DIR "${CONFIG_DIR}" || exit 1
install_validate_runtime_path BIN_DIR "${BIN_DIR}" || exit 1
install_validate_absolute_path SERVICE_FILE "${SERVICE_FILE}" || exit 1
install_validate_runtime_path ENV_FILE "${ENV_FILE}" || exit 1
install_reject_control_chars MANAGER_CA_FILE "${MANAGER_CA_FILE}" || exit 1
case "${FIREWALL_BACKEND}" in
	auto|iptables|iptables-nft|iptables-legacy|dev) ;;
	*) error "不支持 FIREWALL_BACKEND=${FIREWALL_BACKEND}" ;;
esac

if [ "${DRY_RUN}" != "true" ]; then
	install -d -m 0755 "${BIN_DIR}" "$(dirname "${SERVICE_FILE}")"
	install -d -m 0700 "${DATA_DIR}" "${CONFIG_DIR}"
fi

version_output="$(timeout 5 "${AGENT_BINARY}" --version 2>&1)" || error "Agent 二进制无法运行"
case "${version_output}" in "iptables-web-agent "*) info "待安装版本: ${version_output}" ;; *) error "无法识别 Agent 二进制版本: ${version_output}" ;; esac

TXN_DIR="$(mktemp -d /var/tmp/iptables-web-agent-install.XXXXXX)"
trap 'rm -rf "${TXN_DIR}"' EXIT
WAS_ACTIVE=false
WAS_ENABLED=false
HAD_BINARY=false
HAD_SERVICE=false
HAD_ENV=false
HAD_KEY_HASH=false
HAD_IDENTITY=false
HAD_MANAGER_CA=false
INSTALLED_MANAGER_CA=false
if [ "${DRY_RUN}" != "true" ]; then
	systemctl is-active --quiet iptables-web-agent 2>/dev/null && WAS_ACTIVE=true || true
	systemctl is-enabled --quiet iptables-web-agent 2>/dev/null && WAS_ENABLED=true || true
fi
[ ! -f "${BIN_DIR}/${AGENT_BINARY_NAME}" ] || { cp -a "${BIN_DIR}/${AGENT_BINARY_NAME}" "${TXN_DIR}/old-binary"; HAD_BINARY=true; }
[ ! -f "${SERVICE_FILE}" ] || { cp -a "${SERVICE_FILE}" "${TXN_DIR}/old-service"; HAD_SERVICE=true; }
[ ! -f "${ENV_FILE}" ] || { cp -a "${ENV_FILE}" "${TXN_DIR}/old-env"; HAD_ENV=true; }
[ ! -f "${MANAGER_CA_DEST}" ] || { cp -a "${MANAGER_CA_DEST}" "${TXN_DIR}/old-manager-ca"; HAD_MANAGER_CA=true; }

install -m 0755 "${AGENT_BINARY}" "${TXN_DIR}/${AGENT_BINARY_NAME}"

EFFECTIVE_MANAGER_CA_FILE=""
if [ -n "${MANAGER_CA_FILE}" ]; then
	install -m 0600 "${MANAGER_CA_FILE}" "${TXN_DIR}/manager-ca.pem"
	EFFECTIVE_MANAGER_CA_FILE="${MANAGER_CA_DEST}"
	INSTALLED_MANAGER_CA=true
elif [ -f "${MANAGER_CA_DEST}" ]; then
	# Upgrades preserve the installer-managed CA even when the caller omits the
	# source path used during the original installation.
	install -m 0600 "${MANAGER_CA_DEST}" "${TXN_DIR}/manager-ca.pem"
	EFFECTIVE_MANAGER_CA_FILE="${MANAGER_CA_DEST}"
	INSTALLED_MANAGER_CA=true
fi

KEY_HASH_FILE="${CONFIG_DIR}/agent.key.sha256"
IDENTITY_FILE="${CONFIG_DIR}/agent.identity"
[ ! -f "${KEY_HASH_FILE}" ] || { cp -a "${KEY_HASH_FILE}" "${TXN_DIR}/old-key-hash"; HAD_KEY_HASH=true; }
[ ! -f "${IDENTITY_FILE}" ] || { cp -a "${IDENTITY_FILE}" "${TXN_DIR}/old-identity"; HAD_IDENTITY=true; }

install_write_env_file "${TXN_DIR}/agent.env" \
	AGENT_LISTEN_ADDR "${AGENT_LISTEN_ADDR}" \
	AGENT_KEY_HASH_FILE "${KEY_HASH_FILE}" \
	AGENT_IDENTITY_FILE "${IDENTITY_FILE}" \
	RULES_FILE "${DATA_DIR}/rules.json" \
	FIREWALL_BACKEND "${FIREWALL_BACKEND}" \
	MANAGER_URL "${MANAGER_URL}" \
	MANAGER_CA_FILE "${EFFECTIVE_MANAGER_CA_FILE}" \
	AGENT_PUBLIC_URL "${AGENT_PUBLIC_URL}" \
	AGENT_NAME "${AGENT_DISPLAY_NAME}" \
	AGENT_GROUP "${AGENT_GROUP}" \
	LOG_LEVEL info

cat >"${TXN_DIR}/iptables-web-agent.service" <<SERVICE_EOF
[Unit]
Description=iptables-web Lightweight Firewall Agent
After=network-online.target
Wants=network-online.target
ConditionFileIsExecutable=${BIN_DIR}/${AGENT_BINARY_NAME}

[Service]
Type=simple
EnvironmentFile=${ENV_FILE}
ExecStart=${BIN_DIR}/${AGENT_BINARY_NAME}
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
ReadWritePaths=${DATA_DIR} ${CONFIG_DIR}
ReadOnlyPaths=/proc /sys

[Install]
WantedBy=multi-user.target
SERVICE_EOF

install_verify_rendered_unit "${TXN_DIR}/iptables-web-agent.service" "${TXN_DIR}/iptables-web-agent-verify.service" || error "Agent systemd unit 校验失败"
if [ "${DRY_RUN}" = "true" ]; then
	info "DRY_RUN：已成功渲染并校验 Agent systemd unit，不写入系统"
	exit 0
fi
install -m 0755 "${TXN_DIR}/${AGENT_BINARY_NAME}" "${BIN_DIR}/${AGENT_BINARY_NAME}.new"
mv -f "${BIN_DIR}/${AGENT_BINARY_NAME}.new" "${BIN_DIR}/${AGENT_BINARY_NAME}"
[ "${INSTALLED_MANAGER_CA}" != true ] || install -m 0600 "${TXN_DIR}/manager-ca.pem" "${MANAGER_CA_DEST}"
install -m 0600 "${TXN_DIR}/agent.env" "${ENV_FILE}"
install -m 0644 "${TXN_DIR}/iptables-web-agent.service" "${SERVICE_FILE}"
if [ "${ROTATE_AGENT_KEY}" = "true" ]; then
	rm -f "${KEY_HASH_FILE}"
fi

rollback_agent() {
	warn "新 Agent 启动验证失败，正在恢复安装前状态"
	systemctl stop iptables-web-agent 2>/dev/null || true
	if [ "${HAD_BINARY}" = true ]; then install -m 0755 "${TXN_DIR}/old-binary" "${BIN_DIR}/${AGENT_BINARY_NAME}"; else rm -f "${BIN_DIR}/${AGENT_BINARY_NAME}"; fi
	if [ "${HAD_SERVICE}" = true ]; then install -m 0644 "${TXN_DIR}/old-service" "${SERVICE_FILE}"; else rm -f "${SERVICE_FILE}"; fi
	if [ "${HAD_ENV}" = true ]; then install -m 0600 "${TXN_DIR}/old-env" "${ENV_FILE}"; else rm -f "${ENV_FILE}"; fi
	if [ "${HAD_KEY_HASH}" = true ]; then install -m 0600 "${TXN_DIR}/old-key-hash" "${KEY_HASH_FILE}"; else rm -f "${KEY_HASH_FILE}"; fi
	if [ "${HAD_IDENTITY}" = true ]; then install -m 0600 "${TXN_DIR}/old-identity" "${IDENTITY_FILE}"; else rm -f "${IDENTITY_FILE}"; fi
	if [ "${HAD_MANAGER_CA}" = true ]; then install -m 0600 "${TXN_DIR}/old-manager-ca" "${MANAGER_CA_DEST}"; elif [ "${INSTALLED_MANAGER_CA}" = true ]; then rm -f "${MANAGER_CA_DEST}"; fi
	systemctl daemon-reload || true
	if [ "${WAS_ENABLED}" = true ]; then systemctl enable iptables-web-agent >/dev/null 2>&1 || true; else systemctl disable iptables-web-agent >/dev/null 2>&1 || true; fi
	if [ "${WAS_ACTIVE}" = true ]; then systemctl start iptables-web-agent || warn "旧 Agent 也未能重新启动"; fi
}

if ! install_verify_unit "${SERVICE_FILE}" || ! systemctl daemon-reload || ! systemctl enable iptables-web-agent || ! systemctl restart iptables-web-agent; then
	rollback_agent
	error "Agent systemd 安装或启动失败，已执行回滚"
fi
if ! install_wait_systemd_http iptables-web-agent "${AGENT_HEALTH_URL}" 15; then
	journalctl -u iptables-web-agent -n 30 --no-pager >&2 || true
	rollback_agent
	error "Agent 健康检查失败，已执行回滚"
fi

echo
info "Agent 已安装并运行"
info "Agent 已主动向 ${MANAGER_URL} 提交纳管申请"
info "请登录管理端，在“Agent 纳管”中单台或批量确认"
info "管理端回连地址: ${AGENT_PUBLIC_URL}"
info "Agent Key 由进程自动交换；目标机磁盘只保存 SHA-256，不保存明文"
info "systemd 配置: ${ENV_FILE}（0600）"
info "安装器不会自动开放 ${AGENT_PORT} 端口，请只允许中心端 IP 访问"
