#!/bin/sh
set -eu
/docker-entrypoint.sh /usr/local/bin/nftapi >/tmp/nftapi.log 2>&1 &
pid=$!
cleanup() {
	kill "$pid" 2>/dev/null || true
}
trap cleanup EXIT
ok=0
i=0
while [ "$i" -lt 50 ]; do
	if wget -q -O - http://127.0.0.1:9789/health | grep -q '"ok":true'; then
		ok=1
		break
	fi
	i=$((i + 1))
	sleep 0.1
done
if grep -F -q -f /run/nftapi.key /tmp/nftapi.log; then
	echo "server log contains the key" >&2
	exit 1
fi
if [ "$ok" != 1 ]; then
	echo "health check failed" >&2
	cat /tmp/nftapi.log >&2
	exit 1
fi
export NFTAPI_URL=http://127.0.0.1:9789
export NFTAPI_KEY_FILE=/run/nftapi.key
status=0
/usr/local/bin/nftapi.test -test.v -test.count=1 -test.run '^TestLive$' || status=$?
if [ "$status" -ne 0 ]; then
	if grep -F -q -f /run/nftapi.key /tmp/nftapi.log; then
		echo "server log contains the key" >&2
	else
		echo "--- server log ---" >&2
		cat /tmp/nftapi.log >&2
	fi
fi
exit "$status"
