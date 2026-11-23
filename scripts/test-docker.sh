#!/bin/sh
set -eu
cd "$(dirname "$0")/.."

arch=$(uname -m)
case "$arch" in
x86_64 | amd64) goarch=amd64 ;;
arm64 | aarch64) goarch=arm64 ;;
*)
	echo "unsupported architecture: $arch" >&2
	exit 1
	;;
esac

if ! command -v docker >/dev/null 2>&1; then
	echo "docker is required" >&2
	exit 1
fi

root=$(mktemp -d)
keydir=$(mktemp -d)
cleanup() {
	docker rm -f nftapi-test >/dev/null 2>&1 || true
	rm -rf "$root" "$keydir"
}
trap cleanup EXIT

python3 -c 'import secrets; open("'"$keydir"'/key", "wb").write(secrets.token_hex(32).encode() + b"\n")'
chmod 600 "$keydir/key"

CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go build -o "$root/nftapi" ./cmd/nftapi
CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go test -c -tags integration -o "$root/nftapi.test" ./internal/httpapi
cp Dockerfile scripts/docker-entrypoint.sh scripts/docker-test-inner.sh "$root/"

docker build -t nftapi-test "$root"
docker rm -f nftapi-test >/dev/null 2>&1 || true
docker run --rm --name nftapi-test --cap-add NET_ADMIN \
	-v "$keydir/key":/run/nftapi/key.in:ro \
	nftapi-test
