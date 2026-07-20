#!/bin/sh
# Health check: verifies that iptables is functional and the API is responding.
# Exit 0 = healthy, non-zero = unhealthy.

# Check that iptables is accessible
iptables -L -n > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "iptables not accessible"
    exit 1
fi

# Check that the API is responding
LISTEN_ADDR="${LISTEN_ADDR:-:33801}"
LISTEN_PORT="${LISTEN_ADDR##*:}"
wget -q --spider "http://localhost:${LISTEN_PORT}/api/v1/health" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "API health endpoint not reachable"
    exit 1
fi

exit 0
