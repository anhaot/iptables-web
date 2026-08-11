#!/bin/sh
# Health check: asks the API to verify the configured backend and persisted
# managed rules. This works for real iptables backends and DEV_MODE without
# bypassing the application's own drift/error handling.
# Exit 0 = healthy, non-zero = unhealthy.

LISTEN_ADDR="${LISTEN_ADDR:-:33801}"
LISTEN_PORT="${LISTEN_ADDR##*:}"
LISTEN_HOST="${LISTEN_ADDR%:*}"
case "${LISTEN_HOST}" in
    ""|0.0.0.0|127.0.0.1|localhost) LISTEN_HOST=127.0.0.1 ;;
    "[::]"|"[::1]") LISTEN_HOST='[::1]' ;;
esac
wget -q --spider "http://${LISTEN_HOST}:${LISTEN_PORT}/api/v1/health" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "API health endpoint not reachable"
    exit 1
fi

exit 0
