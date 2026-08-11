#!/bin/bash
# Shared, side-effect-free helpers for the systemd installers.

install_reject_control_chars() {
	local name="$1" value="$2"
	case "${value}" in
		*$'\n'*|*$'\r'*)
			printf '[ERROR] %s 不能包含换行符\n' "${name}" >&2
			return 1
			;;
	esac
}

install_validate_absolute_path() {
	local name="$1" value="$2"
	case "${value}" in
		/*) ;;
		*) printf '[ERROR] %s 必须是绝对路径: %s\n' "${name}" "${value}" >&2; return 1 ;;
	esac
	case "${value}" in
		*[[:space:]%\"\\]*)
			printf '[ERROR] %s 不能包含空白、%%、双引号或反斜杠: %s\n' "${name}" "${value}" >&2
			return 1
			;;
	esac
	install_reject_control_chars "${name}" "${value}"
}

install_validate_runtime_path() {
	local name="$1" value="$2"
	install_validate_absolute_path "${name}" "${value}" || return 1
	case "${value}" in
		/tmp|/tmp/*|/var/tmp|/var/tmp/*)
			printf '[ERROR] %s 不能位于 /tmp 或 /var/tmp；systemd PrivateTmp 会隔离该路径: %s\n' "${name}" "${value}" >&2
			return 1
			;;
	esac
}

install_env_quote() {
	local value="$1"
	value="${value//\\/\\\\}"
	value="${value//\"/\\\"}"
	printf '"%s"' "${value}"
}

# Usage: install_write_env_file FILE KEY VALUE [KEY VALUE ...]
install_write_env_file() {
	local output="$1" key value
	shift
	[ $(( $# % 2 )) -eq 0 ] || return 2
	: >"${output}"
	chmod 0600 "${output}"
	while [ "$#" -gt 0 ]; do
		key="$1"
		value="$2"
		shift 2
		install_reject_control_chars "${key}" "${value}" || return 1
		printf '%s=' "${key}" >>"${output}"
		install_env_quote "${value}" >>"${output}"
		printf '\n' >>"${output}"
	done
}

install_append_env_value() {
	local output="$1" key="$2" value="$3"
	install_reject_control_chars "${key}" "${value}" || return 1
	printf '%s=' "${key}" >>"${output}"
	install_env_quote "${value}" >>"${output}"
	printf '\n' >>"${output}"
}

install_verify_unit() {
	local unit="$1"
	if command -v systemd-analyze >/dev/null 2>&1; then
		systemd-analyze verify "${unit}"
	fi
}

# Verify unit syntax before the target executable is installed. The real unit
# is verified again after the atomic binary replacement.
install_verify_rendered_unit() {
	local unit="$1" scratch="$2"
	sed \
		-e 's|^ConditionFileIsExecutable=.*$|ConditionFileIsExecutable=/bin/true|' \
		-e 's|^ExecStart=.*$|ExecStart=/bin/true|' \
		"${unit}" >"${scratch}"
	install_verify_unit "${scratch}"
}

install_wait_http() {
	local url="$1" attempts="${2:-15}" i
	for ((i = 1; i <= attempts; i++)); do
		if curl --fail --silent --show-error --max-time 2 "${url}" >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
	done
	return 1
}

install_wait_systemd_http() {
	local service="$1" url="$2" attempts="${3:-15}" i
	for ((i = 1; i <= attempts; i++)); do
		if systemctl is-active --quiet "${service}" \
			&& [ "$(systemctl show "${service}" -p SubState --value 2>/dev/null)" = running ] \
			&& curl --fail --silent --show-error --max-time 2 "${url}" >/dev/null 2>&1; then
			sleep 1
			if systemctl is-active --quiet "${service}" \
				&& [ "$(systemctl show "${service}" -p SubState --value 2>/dev/null)" = running ] \
				&& curl --fail --silent --show-error --max-time 2 "${url}" >/dev/null 2>&1; then
				return 0
			fi
		fi
		sleep 1
	done
	return 1
}

install_health_url() {
	local listen="$1" port host
	port="${listen##*:}"
	host="${listen%:*}"
	case "${host}" in
		""|0.0.0.0|127.0.0.1|localhost) host=127.0.0.1 ;;
		"[::]"|"[::1]") host='[::1]' ;;
	esac
	printf 'http://%s:%s/api/v1/health\n' "${host}" "${port}"
}
