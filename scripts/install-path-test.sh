#!/bin/bash
# Exercise path checks only; never install a service or change system paths.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "${SCRIPT_DIR}/install-lib.sh"

expect_rejected() {
	local validator="$1" value="$2"
	if "${validator}" TEST_PATH "${value}" >/dev/null 2>&1; then
		printf 'FAIL: %s accepted %q\n' "${validator}" "${value}" >&2
		exit 1
	fi
}

for value in / /etc /usr /var /opt /usr/local /var/lib /etc/systemd /etc/systemd/system \
	/usr/local/bin /usr/bin /var/lib/docker /etc/ssh /proc/self /dev/shm /run/service \
	/tmp/app /var/tmp/app /var/lib/../lib /var/lib/iptables-web/.. /var/lib//iptables-web \
	/var/lib/iptables-web/ relative $'/var/lib/app\nother' '/var/lib/app with spaces'; do
	expect_rejected install_validate_private_dir "${value}"
done

for value in /var/lib/iptables-web /etc/iptables-web /opt/iptables-web \
	/var/lib/iptables-web-agent /etc/iptables-web-agent /srv/firewall/rules; do
	install_validate_private_dir TEST_PATH "${value}"
done
install_validate_runtime_path BIN_DIR /usr/local/bin
install_validate_runtime_path ENV_FILE /etc/iptables-web/iptables-web.env

scratch="$(mktemp -d)"
trap 'find "${scratch}" -depth -delete' EXIT
ln -s /etc "${scratch}/system-alias"
expect_rejected install_validate_absolute_path "${scratch}/system-alias"
expect_rejected install_validate_absolute_path "${scratch}/system-alias/app"

# Every executable uninstall test uses a distinct app, private paths, and guards
# for mutation commands. Never read the machine's real installation metadata.
mkdir -p "${scratch}/guards" "${scratch}/install" "${scratch}/config"
for command in systemctl rm find; do
	cat >"${scratch}/guards/${command}" <<'EOF'
#!/bin/bash
printf '%s\n' "${0##*/}" >>"${PATH_TEST_MUTATIONS}"
exit 97
EOF
	chmod +x "${scratch}/guards/${command}"
done
# Exercise existing metadata too: it must not hide an unsafe explicit DATA_DIR.
printf 'DATA_DIR=%s\n' "${scratch}/metadata-data" >"${scratch}/install/install.env"
if [ "$(id -u)" = 0 ]; then
	for script in uninstall.sh uninstall-agent.sh; do
		for value in /etc/ /var/lib/.. /etc/ssh; do
			if env -i PATH="${scratch}/guards:${PATH}" PATH_TEST_MUTATIONS="${scratch}/mutations" \
				APP_NAME="iptables-web-path-test-$$" SERVICE_NAME="iptables-web-path-test-$$" \
				INSTALL_DIR="${scratch}/install" CONFIG_DIR="${scratch}/config" DATA_DIR="${value}" \
				BIN_PATH="${scratch}/bin" AGENT_BIN="${scratch}/agent-bin" \
				SERVICE_FILE="${scratch}/test.service" ENV_FILE="${scratch}/config/test.env" \
				bash "${SCRIPT_DIR}/${script}" --yes >"${scratch}/uninstall.log" 2>&1; then
				printf 'FAIL: %s accepted destructive DATA_DIR=%s\n' "${script}" "${value}" >&2
				exit 1
			fi
			if [ -e "${scratch}/mutations" ]; then
				printf 'FAIL: %s attempted a mutation during rejection\n' "${script}" >&2
				exit 1
			fi
			if ! grep -q '拒绝\|规范' "${scratch}/uninstall.log"; then
				cat "${scratch}/uninstall.log" >&2
				exit 1
			fi
		done
	done
fi
printf 'Installer/uninstaller path safety checks passed\n'
