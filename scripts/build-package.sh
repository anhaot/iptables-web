#!/bin/bash
# Build a self-contained release package for hosts without Go.
set -euo pipefail

APP_NAME="${APP_NAME:-iptables-web}"
AGENT_NAME="${AGENT_NAME:-iptables-web-agent}"
VERSION="${VERSION:-$(date +%Y%m%d%H%M%S)}"
GOOS_TARGET="${GOOS_TARGET:-linux}"
GOARCH_TARGET="${GOARCH_TARGET:-amd64}"
BUILD_PROCS="${BUILD_PROCS:-2}"
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist"
WORK_DIR="${DIST_DIR}/${APP_NAME}-${VERSION}-${GOOS_TARGET}-${GOARCH_TARGET}"
ARCHIVE="${DIST_DIR}/${APP_NAME}-${VERSION}-${GOOS_TARGET}-${GOARCH_TARGET}.tar.gz"

info() { echo "[INFO] $1"; }
error() { echo "[ERROR] $1" >&2; exit 1; }

command -v go >/dev/null 2>&1 || error "构建预编译包需要 Go。目标机器安装时不需要 Go。"
[[ "${BUILD_PROCS}" =~ ^[1-9][0-9]*$ ]] || error "BUILD_PROCS 必须是正整数"

GO_VERSION="$(go env GOVERSION)"
GO_MINOR="$(printf '%s' "${GO_VERSION}" | sed -n 's/^go1\.\([0-9][0-9]*\).*/\1/p')"
[ -n "${GO_MINOR}" ] && [ "${GO_MINOR}" -ge 26 ] || \
	error "正式包必须使用 Go 1.26 或更高版本构建，当前为 ${GO_VERSION}"

cd "${ROOT_DIR}"

info "同步嵌入前端资源..."
rm -rf assets/web
cp -r web assets/web

info "运行测试..."
GO_BUILD_CACHE="${GOCACHE:-/tmp/go-build-cache}"
GOMAXPROCS="${BUILD_PROCS}" GOCACHE="${GO_BUILD_CACHE}" go test -p="${BUILD_PROCS}" ./...
if command -v node >/dev/null 2>&1; then
	node scripts/ui-logic-test.js
else
	info "未安装 Node.js，跳过可选的前端排序逻辑测试"
fi

info "编译 ${GOOS_TARGET}/${GOARCH_TARGET}..."
rm -rf "${WORK_DIR}"
mkdir -p "${WORK_DIR}/bin" "${WORK_DIR}/scripts" "${WORK_DIR}/docs" "${WORK_DIR}/deploy/systemd"
GOMAXPROCS="${BUILD_PROCS}" GOCACHE="${GO_BUILD_CACHE}" CGO_ENABLED=0 GOOS="${GOOS_TARGET}" GOARCH="${GOARCH_TARGET}" \
	go build -p="${BUILD_PROCS}" -buildvcs=false -ldflags="-s -w -X main.version=${VERSION}" -o "${WORK_DIR}/bin/${APP_NAME}" ./cmd/server
GOMAXPROCS="${BUILD_PROCS}" GOCACHE="${GO_BUILD_CACHE}" CGO_ENABLED=0 GOOS="${GOOS_TARGET}" GOARCH="${GOARCH_TARGET}" \
	go build -p="${BUILD_PROCS}" -buildvcs=false -ldflags="-s -w -X main.version=${VERSION}" -o "${WORK_DIR}/bin/${AGENT_NAME}" ./cmd/agent

info "复制安装脚本和文档..."
install -m 0755 scripts/install-binary.sh "${WORK_DIR}/install-binary.sh"
install -m 0755 scripts/uninstall.sh "${WORK_DIR}/uninstall.sh"
install -m 0755 scripts/install-agent.sh "${WORK_DIR}/install-agent.sh"
install -m 0755 scripts/uninstall-agent.sh "${WORK_DIR}/uninstall-agent.sh"
install -m 0755 scripts/install-lib.sh "${WORK_DIR}/scripts/install-lib.sh"
install -m 0755 scripts/healthcheck.sh "${WORK_DIR}/scripts/healthcheck.sh"
cp README.md "${WORK_DIR}/README.md"
cp CONTRIBUTING.md "${WORK_DIR}/CONTRIBUTING.md"
cp docs/*.md "${WORK_DIR}/docs/"
install -d -m 0755 "${WORK_DIR}/docs/images"
cp -R docs/images/. "${WORK_DIR}/docs/images/"
cp deploy/systemd/* "${WORK_DIR}/deploy/systemd/"
cp Dockerfile.release docker-compose.release.yml "${WORK_DIR}/"

cat >"${WORK_DIR}/VERSION" <<EOF
APP_NAME=${APP_NAME}
VERSION=${VERSION}
GOOS=${GOOS_TARGET}
GOARCH=${GOARCH_TARGET}
BUILT_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

info "生成压缩包..."
mkdir -p "${DIST_DIR}"
tar -C "${DIST_DIR}" -czf "${ARCHIVE}" "$(basename "${WORK_DIR}")"

if command -v sha256sum >/dev/null 2>&1; then
	(cd "${DIST_DIR}" && sha256sum "$(basename "${ARCHIVE}")" >"$(basename "${ARCHIVE}").sha256")
	info "校验文件: ${ARCHIVE}.sha256"
fi

info "离线验证发布包..."
bash scripts/verify-package.sh "${ARCHIVE}"

info "完成: ${ARCHIVE}"
info "目标机器使用:"
info "  tar -xzf $(basename "${ARCHIVE}")"
info "  cd $(basename "${WORK_DIR}")"
info "  sudo bash install-binary.sh"
info "Agent 目标机复制发布包后运行: sudo MANAGER_URL=http://中心端IP:33801 bash install-agent.sh"
info "默认监听 0.0.0.0:33801；安装/卸载脚本不会执行 firewall-cmd，请按需在程序外手工放行端口"
