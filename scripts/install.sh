#!/bin/bash
# iptables-web 原生主机安装脚本
# 支持 CentOS 7/8/9, RHEL, Ubuntu 20.04+, Debian 11+, 麒麟 V10
set -e

APP_NAME="iptables-web"
INSTALL_DIR="/opt/${APP_NAME}"
DATA_DIR="/var/lib/${APP_NAME}"
BIN_DIR="/usr/local/bin"
SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"
LISTEN_ADDR="${LISTEN_ADDR:-0.0.0.0:33801}"
LISTEN_PORT="${LISTEN_ADDR##*:}"
AUTH_ENABLED="${AUTH_ENABLED:-true}"
API_KEY="${API_KEY:-}"
FIREWALL_BACKEND="${FIREWALL_BACKEND:-auto}"
SKIP_DEP_INSTALL="${SKIP_DEP_INSTALL:-false}"
GO_VERSION_MIN="${GO_VERSION_MIN:-1.26}"
LOCAL_GO_TARBALL="${LOCAL_GO_TARBALL:-}"
INSTALL_METADATA="${INSTALL_DIR}/install.env"

# ====== 颜色 ======
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# ====== 检测系统 ======
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    else
        error "无法检测操作系统"
    fi
    info "检测到系统: $OS $OS_VERSION"
}

repo_root() {
    cd "$(dirname "$0")/.." && pwd
}

run_pkg_install() {
    "$@" || warn "依赖安装失败，可能是内网无仓库或软件源不可用，请确认依赖已手动安装"
}

validate_firewall_backend() {
	case "${FIREWALL_BACKEND}" in
		auto|iptables|iptables-nft|iptables-legacy|dev) ;;
		nft|nftables) error "FIREWALL_BACKEND=${FIREWALL_BACKEND} 已禁用：原生 nftables 写入不安全，请使用 iptables/iptables-nft" ;;
		*) error "不支持 FIREWALL_BACKEND=${FIREWALL_BACKEND}；可选 auto、iptables、iptables-nft、iptables-legacy、dev" ;;
	esac
}

install_rpm_deps() {
    info "安装依赖 (yum/dnf)..."
    if command -v dnf >/dev/null 2>&1; then
        PKG_CMD="dnf"
    else
        PKG_CMD="yum"
    fi
	run_pkg_install "${PKG_CMD}" install -y iptables-services ca-certificates curl
    if ! command -v go >/dev/null 2>&1; then
        "${PKG_CMD}" install -y golang || warn "未能通过 yum/dnf 安装 Go，将尝试使用本地 Go 压缩包或 dist 预编译包"
    fi
}

install_deb_deps() {
    info "安装依赖 (apt)..."
    run_pkg_install apt-get update -qq
	run_pkg_install apt-get install -y -qq iptables ca-certificates curl
    if ! command -v go >/dev/null 2>&1; then
        apt-get install -y -qq golang-go || warn "未能通过 apt 安装 Go，将尝试使用本地 Go 压缩包或 dist 预编译包"
    fi
}

# ====== 安装依赖 ======
install_deps() {
    if [ "${SKIP_DEP_INSTALL}" = "true" ]; then
        warn "SKIP_DEP_INSTALL=true，跳过系统依赖安装"
        return
    fi

    case $OS in
        centos|rhel|rocky|almalinux|kylin*)
            install_rpm_deps
            ;;
        ubuntu|debian)
            install_deb_deps
            ;;
        *)
			warn "未知系统: $OS，请手动安装 Go 和 iptables；iptables-nft 兼容层受支持，原生 nftables 写入已禁用"
            ;;
    esac
}

go_minor_version() {
    go version 2>/dev/null | awk '{print $3}' | sed 's/^go//' | awk -F. '{printf "%d%03d\n", $1, $2}'
}

required_go_minor_version() {
    echo "${GO_VERSION_MIN}" | awk -F. '{printf "%d%03d\n", $1, $2}'
}

find_local_go_tarball() {
    if [ -n "${LOCAL_GO_TARBALL}" ]; then
        [ -f "${LOCAL_GO_TARBALL}" ] || error "LOCAL_GO_TARBALL 指定的文件不存在: ${LOCAL_GO_TARBALL}"
        echo "${LOCAL_GO_TARBALL}"
        return
    fi

    ROOT_DIR="$(repo_root)"
    for dir in "${ROOT_DIR}" "${ROOT_DIR}/deps" "${ROOT_DIR}/third_party" "${ROOT_DIR}/tools"; do
        [ -d "${dir}" ] || continue
        found="$(find "${dir}" -maxdepth 1 -type f -name 'go*.linux-amd64.tar.gz' | sort -Vr | head -n 1)"
        if [ -n "${found}" ]; then
            echo "${found}"
            return
        fi
    done
}

install_local_go() {
    tarball="$(find_local_go_tarball)"
    if [ -z "${tarball}" ]; then
        warn "未检测到 Go ${GO_VERSION_MIN}+，且未找到本地 Go 压缩包"
        warn "如需源码编译，请把 go${GO_VERSION_MIN}.x.linux-amd64.tar.gz 放到项目根目录、deps/、third_party/ 或 tools/，或通过 LOCAL_GO_TARBALL=/path/go.tar.gz 指定"
        return 1
    fi

    info "使用本地 Go 工具链: ${tarball}"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "${tarball}"
    ln -sf /usr/local/go/bin/go /usr/local/bin/go
    ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
}

ensure_go() {
    if command -v go >/dev/null 2>&1; then
        current="$(go_minor_version)"
        required="$(required_go_minor_version)"
        if [ "${current}" -ge "${required}" ]; then
            info "检测到 Go: $(go version)"
            return
        fi
        warn "当前 Go 版本低于 ${GO_VERSION_MIN}: $(go version)"
    fi

    if ! install_local_go; then
        return 1
    fi
    if ! command -v go >/dev/null 2>&1; then
        warn "Go 安装失败，将尝试使用预编译包"
        return 1
    fi
    info "Go 已就绪: $(go version)"
}

find_prebuilt_binary() {
    ROOT_DIR="$(repo_root)"
    for path in \
        "${ROOT_DIR}/${APP_NAME}" \
        "${ROOT_DIR}/bin/${APP_NAME}"; do
        if [ -x "${path}" ]; then
            echo "${path}"
            return
        fi
    done

    if [ -d "${ROOT_DIR}/dist" ]; then
		found="$(find "${ROOT_DIR}/dist" -mindepth 3 -maxdepth 3 -type f -path "*/bin/${APP_NAME}" | sort -V | tail -n 1)"
		if [ -n "${found}" ] && [ -x "${found}" ]; then
			echo "${found}"
			return
		fi

        archive="$(find "${ROOT_DIR}/dist" -maxdepth 1 -type f -name "${APP_NAME}-*-linux-amd64.tar.gz" | sort -Vr | head -n 1)"
        if [ -n "${archive}" ]; then
			if [ -f "${archive}.sha256" ]; then
				expected="$(awk 'NR==1 {print $1}' "${archive}.sha256")"
				actual="$(sha256sum "${archive}" | awk '{print $1}')"
				[ "${expected}" = "${actual}" ] || error "预编译包 SHA-256 校验失败: ${archive}"
				info "预编译包 SHA-256 校验通过"
			else
				warn "未找到 ${archive}.sha256，跳过预编译包校验"
			fi
            PREBUILT_TMP_DIR="$(mktemp -d)"
            tar -xzf "${archive}" -C "${PREBUILT_TMP_DIR}"
            found="$(find "${PREBUILT_TMP_DIR}" -type f -path "*/bin/${APP_NAME}" | head -n 1)"
            if [ -n "${found}" ]; then
                chmod +x "${found}"
                echo "${found}"
                return
            fi
        fi
    fi
}

install_prebuilt_app() {
    binary_path="$(find_prebuilt_binary)"
    if [ -z "${binary_path}" ]; then
        error "没有 Go 工具链，且未找到预编译二进制。请提供本地 Go 压缩包后重试，或先在有 Go 的机器执行 bash scripts/build-package.sh 并把 dist/*.tar.gz 放到本目录。"
    fi

	LC_ALL=C grep -a -q 'print version and exit' "${binary_path}" || error "预编译二进制版本过旧，不支持安全版本检查。请使用当前源码重新执行 bash scripts/build-package.sh。"
	prebuilt_version="$(timeout 5 "${binary_path}" --version 2>&1)" || error "预编译二进制无法运行: ${binary_path}"
	case "${prebuilt_version}" in "iptables-web "*) ;; *) error "无法识别预编译版本: ${prebuilt_version}" ;; esac
	info "使用预编译二进制安装: ${binary_path} (${prebuilt_version})"
	    mkdir -p "${BIN_DIR}"
	    install -d -m 0700 "${DATA_DIR}"
    install -m 0755 "${binary_path}" "${BIN_DIR}/${APP_NAME}"
	install_support_files
    info "二进制文件: ${BIN_DIR}/${APP_NAME}"
}

# ====== 编译安装 ======
install_app() {
    info "编译 ${APP_NAME}..."
    cd "$(repo_root)"

    # 同步前端资源
    rm -rf assets/web && cp -r web assets/web

    # 编译
    GOTOOLCHAIN=local go build -buildvcs=false -ldflags="-s -w -X main.version=source" -o "${BIN_DIR}/${APP_NAME}" ./cmd/server

    info "二进制文件: ${BIN_DIR}/${APP_NAME}"

    # 创建数据目录
	    install -d -m 0700 "${DATA_DIR}"
	install_support_files
}

install_support_files() {
	mkdir -p "${INSTALL_DIR}" "${INSTALL_DIR}/docs"
	[ -f "$(repo_root)/README.md" ] && cp "$(repo_root)/README.md" "${INSTALL_DIR}/README.md"
	[ -d "$(repo_root)/docs" ] && cp -R "$(repo_root)/docs/." "${INSTALL_DIR}/docs/"
	[ -f "$(repo_root)/scripts/uninstall.sh" ] && install -m 0755 "$(repo_root)/scripts/uninstall.sh" "${INSTALL_DIR}/uninstall.sh"
}

write_install_metadata() {
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

# ====== 安装 systemd 服务 ======
install_service() {
    info "安装 systemd 服务..."

    cat > "${SERVICE_FILE}" << SERVICE_EOF
[Unit]
Description=iptables-web Firewall Manager
Documentation=https://github.com/example/iptables-web
After=network-online.target docker.service
Wants=network-online.target docker.service

[Service]
Type=simple
ExecStart=${BIN_DIR}/${APP_NAME}
Environment=RULES_FILE=${DATA_DIR}/rules.json
Environment=USERS_FILE=${DATA_DIR}/users.json
Environment=LISTEN_ADDR=${LISTEN_ADDR}
Environment=LOG_LEVEL=info
Environment=AUTH_ENABLED=${AUTH_ENABLED}
Environment=API_KEY=${API_KEY}
Environment=FIREWALL_BACKEND=${FIREWALL_BACKEND}
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

# 安全加固
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=${DATA_DIR}
ReadOnlyPaths=/proc /sys
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
SERVICE_EOF

    systemctl daemon-reload
    info "服务文件: ${SERVICE_FILE}"
}

# ====== 启动 ======
start_service() {
    if systemctl is-active --quiet "${APP_NAME}" 2>/dev/null; then
        systemctl restart "${APP_NAME}" 2>/dev/null || {
            warn "无法重启 systemd 服务，尝试直接运行..."
            RULES_FILE="${DATA_DIR}/rules.json" "${BIN_DIR}/${APP_NAME}" &
            sleep 2
        }
        systemctl enable "${APP_NAME}" >/dev/null 2>&1 || true
    else
        systemctl enable --now "${APP_NAME}" 2>/dev/null || {
        warn "无法通过 systemd 启动，尝试直接运行..."
        RULES_FILE="${DATA_DIR}/rules.json" "${BIN_DIR}/${APP_NAME}" &
        sleep 2
        }
    fi

    # 验证
    sleep 2
    if curl -sf http://localhost:${LISTEN_PORT}/api/v1/health > /dev/null 2>&1; then
        if [[ "${LISTEN_ADDR}" == 127.0.0.1:* || "${LISTEN_ADDR}" == localhost:* ]]; then
            info "安装成功！访问 http://127.0.0.1:${LISTEN_PORT}"
        else
            info "安装成功！访问 http://$(hostname -I | awk '{print $1}'):${LISTEN_PORT}"
        fi
    else
        warn "服务可能未正常启动，请检查日志: journalctl -u ${APP_NAME} -f"
    fi
}

# ====== 主流程 ======
main() {
    echo "========================================"
    echo "  iptables-web 原生主机安装"
    echo "========================================"
    echo ""

    if [ "$(id -u)" != "0" ]; then
        error "请使用 root 权限运行此脚本"
    fi

	detect_os
	validate_firewall_backend
	install_deps
    if ensure_go; then
        install_app
    else
        warn "无法源码编译，尝试使用 dist 中的预编译包安装"
        install_prebuilt_app
    fi
	write_install_metadata
    install_service
    start_service

    echo ""
    info "========================================="
    info "  安装完成！"
    if [[ "${LISTEN_ADDR}" == 127.0.0.1:* || "${LISTEN_ADDR}" == localhost:* ]]; then
        info "  访问地址: http://127.0.0.1:${LISTEN_PORT}"
    else
		access_host="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
		[ -n "${access_host}" ] || access_host="<服务器IP>"
		info "  访问地址: http://${access_host}:${LISTEN_PORT}"
    fi
    info "  认证状态: AUTH_ENABLED=${AUTH_ENABLED}"
    info "  规则数据: ${DATA_DIR}/rules.json"
    info "  查看日志: journalctl -u ${APP_NAME} -f"
    info "  重启服务: systemctl restart ${APP_NAME}"
	info "  卸载命令: sudo bash ${INSTALL_DIR}/uninstall.sh"
    info "========================================="
}

main "$@"
