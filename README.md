# nftapi

Localhost JSON API for nftables. `POST /v1` takes one JSON object and returns JSON. `GET /health` returns `{"ok":true}`.

The design is in `docs/plans/2026-11-22-nftapi-design.md`. Phase 1 is the closed match and verdict language. Named sets are phase 2 and are not in this build.

## Run

The key file must be mode `0400` or `0600`, owned by the user that runs the process, and not a symlink.

```
umask 077
python3 -c 'import secrets; open("nftapi.key","w").write(secrets.token_hex(32)+"\n")'
export NFTAPI_KEY_FILE="$PWD/nftapi.key"
export NFTAPI_ADDR=127.0.0.1:9789
go build -o nftapi ./cmd/nftapi
./nftapi
```

`NFTAPI_ADDR` defaults to `127.0.0.1:9789`. It must be a literal loopback address. `NFTAPI_NFT` is an optional absolute path to `nft`. The process needs `CAP_NET_ADMIN` in the network namespace it changes.

```
curl -sS http://127.0.0.1:9789/health
curl -sS -H "Authorization: Bearer $(cat nftapi.key)" -H 'Content-Type: application/json' \
  -d '{"op":"ruleset.list"}' http://127.0.0.1:9789/v1
```

## Feeds

`feed.list` and `feed.fetch` are built in. They return indicators and leave the ruleset unchanged. Module ids are `tor`, `tweetfeed_phishing`, `artex`, `cairn`, `hexstrike`, and `cyberstrikeai`. `tweetfeed_phishing` reads today's TweetFeed JSON and keeps rows tagged phishing.

```
curl -sS -H "Authorization: Bearer $(cat nftapi.key)" -H 'Content-Type: application/json' \
  -d '{"op":"feed.list"}' http://127.0.0.1:9789/v1
curl -sS -H "Authorization: Bearer $(cat nftapi.key)" -H 'Content-Type: application/json' \
  -d '{"op":"feed.fetch","module":"tor"}' http://127.0.0.1:9789/v1
```

## Test

Host tests do not run `nft`:

```
go test ./...
```

Live nftables tests run inside a container network namespace, with `NET_ADMIN`, and talk to the server on that container's loopback:

```
scripts/test-docker.sh
```

The script does not publish a host port and does not change the host firewall.
