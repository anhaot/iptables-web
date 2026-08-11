#!/bin/bash
# End-to-end controller/Agent smoke test. It always uses the in-memory dev
# firewall backend and loopback listeners, so it cannot modify host rules.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CONTROLLER_PORT="${CONTROLLER_PORT:-33991}"
AGENT_PORT="${AGENT_PORT:-33992}"
CONTROLLER_BINARY="${CONTROLLER_BINARY:-}"
AGENT_BINARY="${AGENT_BINARY:-}"
TEST_ROOT="$(mktemp -d /tmp/iptables-web-integration.XXXXXX)"
controller_pid=""
agent_pid=""

info() { printf '[integration] %s\n' "$1"; }
fail() { printf '[integration] ERROR: %s\n' "$1" >&2; exit 1; }

cleanup() {
	if [ -n "${agent_pid}" ]; then kill "${agent_pid}" 2>/dev/null || true; fi
	if [ -n "${controller_pid}" ]; then kill "${controller_pid}" 2>/dev/null || true; fi
	wait "${agent_pid}" 2>/dev/null || true
	wait "${controller_pid}" 2>/dev/null || true
	find "${TEST_ROOT}" -depth -delete
}
trap cleanup EXIT

for command in curl jq; do
	command -v "${command}" >/dev/null 2>&1 || fail "需要 ${command}"
done
[[ "${CONTROLLER_PORT}" =~ ^[0-9]+$ ]] || fail "CONTROLLER_PORT 必须是端口号"
[[ "${AGENT_PORT}" =~ ^[0-9]+$ ]] || fail "AGENT_PORT 必须是端口号"
[ "${CONTROLLER_PORT}" != "${AGENT_PORT}" ] || fail "中心端和 Agent 端口不能相同"

if curl -fsS --max-time 1 "http://127.0.0.1:${CONTROLLER_PORT}/api/v1/health" >/dev/null 2>&1; then
	fail "中心测试端口 ${CONTROLLER_PORT} 已被占用"
fi
if curl -fsS --max-time 1 "http://127.0.0.1:${AGENT_PORT}/api/v1/health" >/dev/null 2>&1; then
	fail "Agent 测试端口 ${AGENT_PORT} 已被占用"
fi

if [ -z "${CONTROLLER_BINARY}" ]; then
	command -v go >/dev/null 2>&1 || fail "未指定 CONTROLLER_BINARY，且找不到 Go"
	CONTROLLER_BINARY="${TEST_ROOT}/iptables-web"
	(cd "${ROOT_DIR}" && go build -o "${CONTROLLER_BINARY}" ./cmd/server)
fi
if [ -z "${AGENT_BINARY}" ]; then
	command -v go >/dev/null 2>&1 || fail "未指定 AGENT_BINARY，且找不到 Go"
	AGENT_BINARY="${TEST_ROOT}/iptables-web-agent"
	(cd "${ROOT_DIR}" && go build -o "${AGENT_BINARY}" ./cmd/agent)
fi
[ -x "${CONTROLLER_BINARY}" ] || fail "中心二进制不可执行: ${CONTROLLER_BINARY}"
[ -x "${AGENT_BINARY}" ] || fail "Agent 二进制不可执行: ${AGENT_BINARY}"

mkdir -p "${TEST_ROOT}/controller" "${TEST_ROOT}/agent-data" "${TEST_ROOT}/agent-config"

info "启动隔离中心端"
DEV_MODE=true FIREWALL_BACKEND=dev AUTH_ENABLED=false LISTEN_ADDR="127.0.0.1:${CONTROLLER_PORT}" \
	RULES_FILE="${TEST_ROOT}/controller/rules.json" USERS_FILE="${TEST_ROOT}/controller/users.json" \
	HOSTS_FILE="${TEST_ROOT}/controller/hosts.json" API_KEYS_FILE="${TEST_ROOT}/controller/api-keys.json" \
	AUDIT_FILE="${TEST_ROOT}/controller/audit.jsonl" ROLLBACK_FILE="${TEST_ROOT}/controller/rollback.json" \
	"${CONTROLLER_BINARY}" >"${TEST_ROOT}/controller.log" 2>&1 &
controller_pid="$!"

for _ in $(seq 1 50); do
	if curl -fsS "http://127.0.0.1:${CONTROLLER_PORT}/api/v1/health" >/dev/null 2>&1; then break; fi
	sleep 0.1
done
curl -fsS "http://127.0.0.1:${CONTROLLER_PORT}/api/v1/health" |
	jq -e '.success == true' >/dev/null || fail "中心健康检查失败"

info "启动无界面 Agent 并等待主动申请"
DEV_MODE=true FIREWALL_BACKEND=dev AGENT_LISTEN_ADDR="127.0.0.1:${AGENT_PORT}" \
	RULES_FILE="${TEST_ROOT}/agent-data/rules.json" AUDIT_FILE="${TEST_ROOT}/agent-data/audit.jsonl" \
	ROLLBACK_FILE="${TEST_ROOT}/agent-data/rollback.json" \
	AGENT_KEY_HASH_FILE="${TEST_ROOT}/agent-config/agent.key.sha256" \
	AGENT_IDENTITY_FILE="${TEST_ROOT}/agent-config/agent.identity" \
	MANAGER_URL="http://127.0.0.1:${CONTROLLER_PORT}" \
	AGENT_PUBLIC_URL="http://127.0.0.1:${AGENT_PORT}" \
	AGENT_NAME=integration-node AGENT_GROUP=validation \
	"${AGENT_BINARY}" >"${TEST_ROOT}/agent.log" 2>&1 &
agent_pid="$!"

agent_id=""
for _ in $(seq 1 80); do
	pending="$(curl -fsS "http://127.0.0.1:${CONTROLLER_PORT}/api/v1/agent-enrollments")"
	agent_id="$(printf '%s' "${pending}" | jq -r '.data[0].id // empty')"
	if [ -n "${agent_id}" ]; then break; fi
	sleep 0.1
done
[ -n "${agent_id}" ] || fail "未收到 Agent 申请"

info "批准申请并验证受保护回连"
approve_payload="$(jq -cn --arg id "${agent_id}" '{ids:[$id]}')"
curl -fsS -X POST -H 'Content-Type: application/json' -d "${approve_payload}" \
	"http://127.0.0.1:${CONTROLLER_PORT}/api/v1/agent-enrollments/approve" |
	jq -e '.success == true and .data[0].success == true' >/dev/null || fail "批准 Agent 失败"

hosts="$(curl -fsS "http://127.0.0.1:${CONTROLLER_PORT}/api/v1/hosts")"
host_id="$(printf '%s' "${hosts}" | jq -r --arg aid "${agent_id}" '.data[] | select(.agent_id == $aid) | .id')"
[ -n "${host_id}" ] || fail "批准后主机清单中没有 Agent"
curl -fsS "http://127.0.0.1:${CONTROLLER_PORT}/api/v1/hosts/${host_id}/probe" |
	jq -e '.success == true and .data.online == true' >/dev/null || fail "中心受保护回连失败"

http_code="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:${AGENT_PORT}/api/v1/rules")"
[ "${http_code}" = "401" ] || fail "Agent 受保护接口未拒绝无密钥请求"
http_code="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:${AGENT_PORT}/")"
[ "${http_code}" = "401" ] || fail "Agent 根路径未受密钥保护"

info "通过中心执行远程规则增删和审计读取"
rule_payload='{"chain":"INPUT","action":"ACCEPT","protocol":"tcp","source":"10.20.30.0/24","dport":"8443","position":1,"enabled":true,"desc":"integration validation"}'
created="$(curl -fsS -X POST -H 'Content-Type: application/json' -d "${rule_payload}" \
	"http://127.0.0.1:${CONTROLLER_PORT}/api/v1/hosts/${host_id}/api/rules")"
rule_id="$(printf '%s' "${created}" | jq -r '.data.id')"
[ -n "${rule_id}" ] && [ "${rule_id}" != "null" ] || fail "远程规则创建未返回标识"
curl -fsS "http://127.0.0.1:${CONTROLLER_PORT}/api/v1/hosts/${host_id}/api/rules" |
	jq -e --arg rid "${rule_id}" '.success == true and any(.data[]; .id == $rid and .dport == "8443")' >/dev/null ||
	fail "远程规则创建后不可见"
curl -fsS "http://127.0.0.1:${CONTROLLER_PORT}/api/v1/hosts/${host_id}/api/system/audit" |
	jq -e '.success == true and any(.data[]; .action == "create_rule")' >/dev/null ||
	fail "Agent 未记录规则审计"
curl -fsS -X DELETE "http://127.0.0.1:${CONTROLLER_PORT}/api/v1/hosts/${host_id}/api/rules/${rule_id}" >/dev/null
curl -fsS "http://127.0.0.1:${CONTROLLER_PORT}/api/v1/hosts/${host_id}/api/rules" |
	jq -e --arg rid "${rule_id}" '.success == true and all(.data[]; .id != $rid)' >/dev/null ||
	fail "远程规则删除后仍存在"

[ "$(stat -c '%a' "${TEST_ROOT}/agent-config/agent.key.sha256")" = "600" ] || fail "Agent 密钥摘要权限不是 0600"
[ "$(stat -c '%a' "${TEST_ROOT}/agent-config/agent.identity")" = "600" ] || fail "Agent 签名身份权限不是 0600"
if grep -RIl 'ipwa_' "${TEST_ROOT}/controller" "${TEST_ROOT}/agent-data" \
	"${TEST_ROOT}/agent-config" "${TEST_ROOT}/controller.log" "${TEST_ROOT}/agent.log" >/dev/null; then
	fail "临时文件或日志中发现 Agent 明文密钥"
fi

info "通过：主动申请、批准、回连、无界面边界、远程规则 CRUD、审计和密钥落盘检查"
