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
	local canonical
	canonical="$(realpath -m -- "${value}")" || return 1
	if [ "${canonical}" != "${value}" ]; then
		printf '[ERROR] %s 必须使用规范绝对路径，不能包含 ..、重复斜杠、尾部斜杠或符号链接: %s\n' "${name}" "${value}" >&2
		return 1
	fi
}

install_validate_runtime_path() {
	local name="$1" value="$2"
	install_validate_absolute_path "${name}" "${value}" || return 1
	case "${value}" in
		/|/etc|/usr|/var|/opt|/usr/local|/var/lib|/etc/systemd|/etc/systemd/system|/home|/root|/srv|/mnt|/media|/run|/var/log|/var/cache)
			printf '[ERROR] 拒绝过宽的 %s: %s\n' "${name}" "${value}" >&2
			return 1
			;;
		/dev|/dev/*|/proc|/proc/*|/sys|/sys/*|/boot|/boot/*|/run/*)
			printf '[ERROR] %s 不能使用系统运行目录: %s\n' "${name}" "${value}" >&2
			return 1
			;;
		/tmp|/tmp/*|/var/tmp|/var/tmp/*)
			printf '[ERROR] %s 不能位于 /tmp 或 /var/tmp；systemd PrivateTmp 会隔离该路径: %s\n' "${name}" "${value}" >&2
			return 1
			;;
	esac
}

# Directories chmod'ed to 0700 must be application-specific. Binary parent
# directories such as /usr/local/bin remain valid for BIN_DIR only.
install_validate_private_dir() {
	local name="$1" value="$2"
	install_validate_runtime_path "${name}" "${value}" || return 1
	case "${value}" in
		/bin|/sbin|/lib|/lib64|/usr/bin|/usr/sbin|/usr/lib|/usr/lib64|/usr/local/bin|/usr/local/sbin|/usr/local/lib|/usr/share|/usr/local/share|/etc/ssh|/etc/ssl|/etc/security|/etc/pam.d|/var/lib/systemd|/var/lib/docker)
			printf '[ERROR] %s 必须是程序专用目录: %s\n' "${name}" "${value}" >&2
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
