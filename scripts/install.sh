#!/bin/bash
# Build from source, then delegate the system installation to the transactional
# prebuilt-binary installer. The target service is always managed by systemd.
set -euo pipefail

APP_NAME="${APP_NAME:-iptables-web}"
GO_VERSION_MIN="${GO_VERSION_MIN:-1.26}"
SKIP_DEP_INSTALL="${SKIP_DEP_INSTALL:-false}"
LOCAL_GO_TARBALL="${LOCAL_GO_TARBALL:-}"
BUILD_PROCS="${BUILD_PROCS:-2}"
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR=""
SELECTED_BINARY=""

info() { printf '[INFO] %s\n' "$1"; }
warn() { printf '[WARN] %s\n' "$1" >&2; }
error() { printf '[ERROR] %s\n' "$1" >&2; exit 1; }
cleanup() { [ -z "${BUILD_DIR}" ] || rm -rf "${BUILD_DIR}"; }
trap cleanup EXIT

[ "$(id -u)" = "0" ] || error "请使用 root 权限运行安装脚本"
[[ "${BUILD_PROCS}" =~ ^[1-9][0-9]*$ ]] || error "BUILD_PROCS 必须是正整数"

if [ -f /etc/os-release ]; then
	# shellcheck disable=SC1091
	. /etc/os-release
fi

install_build_deps() {
	[ "${SKIP_DEP_INSTALL}" = true ] && { warn "跳过系统依赖安装"; return; }
	case "${ID:-unknown}" in
		ubuntu|debian)
			apt-get update -qq
			apt-get install -y -qq iptables ca-certificates curl
			command -v go >/dev/null 2>&1 || apt-get install -y -qq golang-go || true
			;;
		centos|rhel|rocky|almalinux|kylin*)
			local pkg=yum
			command -v dnf >/dev/null 2>&1 && pkg=dnf
			"${pkg}" install -y iptables-services ca-certificates curl
			command -v go >/dev/null 2>&1 || "${pkg}" install -y golang || true
			;;
		*) warn "未知系统；将使用现有 Go 和 iptables" ;;
	esac
}

go_version_number() {
	go version 2>/dev/null | awk '{print $3}' | sed 's/^go//' | awk -F. '{printf "%d%03d\n", $1, $2}'
}

required_go_number() {
	printf '%s\n' "${GO_VERSION_MIN}" | awk -F. '{printf "%d%03d\n", $1, $2}'
}

find_local_go_tarball() {
	if [ -n "${LOCAL_GO_TARBALL}" ]; then
		[ -f "${LOCAL_GO_TARBALL}" ] || error "LOCAL_GO_TARBALL 不存在: ${LOCAL_GO_TARBALL}"
		printf '%s\n' "${LOCAL_GO_TARBALL}"
		return
	fi
	local dir found
	for dir in "${ROOT_DIR}" "${ROOT_DIR}/deps" "${ROOT_DIR}/third_party" "${ROOT_DIR}/tools"; do
		[ -d "${dir}" ] || continue
		found="$(find "${dir}" -maxdepth 1 -type f -name 'go*.linux-amd64.tar.gz' | sort -Vr | head -n 1)"
		[ -z "${found}" ] || { printf '%s\n' "${found}"; return; }
	done
}

ensure_go() {
	if command -v go >/dev/null 2>&1 && [ "$(go_version_number)" -ge "$(required_go_number)" ]; then
		info "使用 $(go version)"
		return 0
	fi
	local tarball
	tarball="$(find_local_go_tarball)"
	[ -n "${tarball}" ] || return 1
	# Install into a versioned directory first; never delete an existing Go tree.
	local go_stage="/usr/local/go-iptables-web-${GO_VERSION_MIN}"
	install -d -m 0755 "${go_stage}"
	tar -xzf "${tarball}" -C "${go_stage}" --strip-components=1
	ln -sfn "${go_stage}" /usr/local/go-iptables-web
	ln -sfn /usr/local/go-iptables-web/bin/go /usr/local/bin/go
	ln -sfn /usr/local/go-iptables-web/bin/gofmt /usr/local/bin/gofmt
	command -v go >/dev/null 2>&1 && [ "$(go_version_number)" -ge "$(required_go_number)" ]
}

find_prebuilt() {
	local candidate archive extracted
	for candidate in "${ROOT_DIR}/bin/${APP_NAME}" "${ROOT_DIR}/${APP_NAME}"; do
		[ ! -x "${candidate}" ] || { SELECTED_BINARY="${candidate}"; return; }
	done
	archive="$(find "${ROOT_DIR}/dist" -maxdepth 1 -type f -name "${APP_NAME}-*-linux-amd64.tar.gz" 2>/dev/null | sort -Vr | head -n 1)"
	[ -n "${archive}" ] || return 1
	[ -f "${archive}.sha256" ] || error "预编译包缺少校验文件: ${archive}.sha256"
	(cd "$(dirname "${archive}")" && sha256sum -c "$(basename "${archive}.sha256")") >&2
	BUILD_DIR="$(mktemp -d /var/tmp/iptables-web-build.XXXXXX)"
	tar -xzf "${archive}" -C "${BUILD_DIR}"
	extracted="$(find "${BUILD_DIR}" -type f -path "*/bin/${APP_NAME}" | head -n 1)"
	[ -n "${extracted}" ] || return 1
	chmod +x "${extracted}"
	SELECTED_BINARY="${extracted}"
}

build_binary() {
	BUILD_DIR="$(mktemp -d /var/tmp/iptables-web-build.XXXXXX)"
	info "低并发编译 ${APP_NAME}（GOMAXPROCS=${BUILD_PROCS}, -p=${BUILD_PROCS}）"
	(
		cd "${ROOT_DIR}"
		GOMAXPROCS="${BUILD_PROCS}" GOTOOLCHAIN=local go build -p="${BUILD_PROCS}" -buildvcs=false \
			-ldflags="-s -w -X main.version=source" -o "${BUILD_DIR}/${APP_NAME}" ./cmd/server
	)
	SELECTED_BINARY="${BUILD_DIR}/${APP_NAME}"
}

main() {
	install_build_deps
	if ensure_go; then
		build_binary
	else
		warn "未找到 Go ${GO_VERSION_MIN}+，改用已校验的预编译包"
		find_prebuilt || error "没有可用 Go 工具链或预编译包"
	fi
	BINARY_PATH_OVERRIDE="${SELECTED_BINARY}" SKIP_FIREWALL_DEP_INSTALL=true \
		bash "${ROOT_DIR}/scripts/install-binary.sh"
}

main "$@"
