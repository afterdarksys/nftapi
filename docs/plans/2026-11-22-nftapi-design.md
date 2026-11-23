# nftapi

Localhost JSON API for nftables. Phase 1 is a closed rule language. Phase 2, not in this build, adds named sets for groups and for block and unblock. systemapi will be a later client of this HTTP API. It is not coupled in this repo.

The server is a single Go binary. It binds a loopback address, requires an API key, and talks to `nft` with a fixed argv (`nft -j -f -`) and JSON on stdin. There is no shell, no raw script, and no flush.

## Call shape

`POST /v1` with `Content-Type: application/json` and `Authorization: Bearer <key>`. The body is one JSON object whose `op` selects the call. The response is JSON.

`GET /health` has no auth and returns `{"ok":true}`. It is the only other route.

Default listen address is `127.0.0.1:9789`. The address must be a literal loopback IP and a port from 1 to 65535. `0.0.0.0`, `::`, and hostnames are refused.

The body limit is 65536 bytes. Each `nft` run has a 2 second timeout. Listing stdout is capped at 1 MiB.

## Auth

The key is read from `NFTAPI_KEY_FILE`. The file must not be a symlink, must be mode `0400` or `0600`, and must be owned by the uid of the process. The key is 32 to 256 bytes. One trailing newline is stripped.

A presented bearer token and the file key are each hashed with SHA-256 and compared with `subtle.ConstantTimeCompare`. A missing header, a bad scheme, a wrong key, or a token whose length is outside 32 to 256 bytes is `401` with the same body. The key is never logged. Query-string keys are not accepted.

## Families, names, chains

Families are `inet`, `ip`, and `ip6`. Names (table and chain) are a letter followed by up to 31 letters, digits, or underscores.

Phase 1 creates filter base chains only. `type` must be `filter`. `hook` is `prerouting`, `input`, `forward`, `output`, or `postrouting`. `priority` is a required integer. `policy` is `accept` or `drop`.

## Operations

| op | result |
|---|---|
| `ruleset.list` | Tables, chains, and rules. A rule outside the closed language is `opaque: true` with its handle and expr. Other objects in a table (sets, maps, and the like) are listed under `other` so a refused delete is explainable. |
| `table.add` | Idempotent. `created` is false when the table exists. |
| `table.delete` | `409 not_empty` when the table has any chain or other object. `404 not_found` when it is already gone. |
| `chain.add` | The table must exist. The same chain with the same type, hook, priority, and policy returns `created: false`. A different definition is `409 conflict`. |
| `chain.delete` | `409 not_empty` when any rule remains, including an opaque one. |
| `rule.add` | The chain must exist. An identical rule (match, limit, verdict, comment) returns the existing handle and `created: false`. Otherwise the new handle is returned. |
| `rule.delete` | Requires `family`, `table`, `chain`, and `handle`. `404` when that handle is not in that chain. |
| `feed.list` | The built-in detection modules. No network fetch and no ruleset change. |
| `feed.fetch` | Fetch one module id and return indicators. The ruleset is unchanged. |

Parents are not created implicitly. `table.add` does not create a chain, and `rule.add` does not create a table or a chain.

A rule needs a verdict of `accept`, `drop`, or `reject`, and at least one selector. Selectors are the match fields and `limit`. A rule that matches every packet must set `match_all` to true and must not set a match or a limit. nftables 1.1.3 lists a phase-1 reject as type `icmpx` and expr `port-unreachable`. That listing projects back to verdict `reject`. A different reject type or expr stays opaque.

Match fields:

- `saddr`, `daddr`: an address or a CIDR. One rule cannot mix IPv4 and IPv6. `ip` tables take IPv4 only. `ip6` tables take IPv6 only. In `inet`, an address match also pins `nfproto`.
- `proto`: `tcp`, `udp`, `icmp`, or `icmpv6`.
- `sport`, `dport`: an integer, or `[lo, hi]`. Only with `tcp` or `udp`. Ports are 1 through 65535 and `lo` must be less than or equal to `hi`.
- `iif`, `oif`: an interface name, 1 to 15 characters from `[A-Za-z0-9_.:-]`.
- `ct_state`: a non-empty subset of `new`, `established`, `related`, `invalid`, `untracked`. Stored in that order.

`limit` counts packets: `rate` (at least 1), `per` (`second`, `minute`, `hour`, `day`), optional `burst` (at least 1), and `mode` (`over` or `under`). `over` is nft's inverted limit, so one rule can drop the excess. `under` matches while the rate remains available.

`comment` is optional, at most 128 bytes, with no ASCII control characters.

Unknown JSON fields are rejected. Fields that belong to a different op are rejected.

## Errors

```json
{"ok": false, "error": {"code": "not_empty", "message": "table filter still has chains"}}
```

| code | status |
|---|---|
| `unauthorized` | 401 |
| `invalid_argument` | 400 |
| `payload_too_large` | 413 |
| `not_found` | 404 |
| `not_empty` | 409 |
| `conflict` | 409 |
| `nft_failed` | 502 |
| `timeout` | 504 |
| `unavailable` | 503 |

`nft` stderr is trimmed, NUL bytes removed, truncated to 400 bytes, and returned as `message`. The request body is not echoed. Auth failures all use the message `unauthorized`.

## Examples

Rate-limit new SSH connections, dropping the excess:

```json
{
  "op": "rule.add",
  "family": "inet",
  "table": "filter",
  "chain": "input",
  "match": {"proto": "tcp", "dport": 22, "ct_state": ["new"]},
  "limit": {"rate": 5, "per": "minute", "burst": 10, "mode": "over"},
  "verdict": "drop"
}
```

Block one address:

```json
{
  "op": "rule.add",
  "family": "inet",
  "table": "filter",
  "chain": "input",
  "match": {"saddr": "203.0.113.5"},
  "verdict": "drop"
}
```

## Phase 2 (not built)

`set.ensure`, `set.delete`, `element.add`, `element.remove`. A match may name a set (`saddr_set`, `daddr_set`, `sport_set`, `dport_set`). That is the group path: one drop rule against a set, and block or unblock is an element change. Further nft features stay closed fields. Raw expr passthrough stays out.

## Detection feeds

`feed.list` returns the catalog. `feed.fetch` takes `module` and returns `indicators`. Both are closed ops on `POST /v1`. A module id is a lowercase name. The URLs are fixed in the binary.

| id | source |
|---|---|
| `tor` | `https://check.torproject.org/torbulkexitlist`, one IP per line |
| `tweetfeed_phishing` | `https://api.tweetfeed.live/v1/today`, JSON rows whose tags include `phishing` |
| `artex`, `cairn`, `hexstrike`, `cyberstrikeai` | ThreatDefence line files for addresses, domains, URLs, and user agents |

The fetch budget is 5 seconds. Each body is capped at 2 MiB. A module stops at 10000 indicators. One failed file fails the module. These ops do not call `nft`.

## Tests

`go test ./...` on the Mac covers the key file checks, auth failures, validation, the JSON handed to `nft`, opaque listing, and the not-empty and conflict paths. A fake runner stands in for `nft`.

`scripts/test-docker.sh` cross-compiles the binary and the integration test, builds an Alpine image with nftables, and runs both inside a container with `NET_ADMIN` and its own network namespace. The server binds `127.0.0.1` in that namespace. A published port would not reach a loopback bind, so the test runs beside the server in the container and no host port is opened. The entrypoint copies the key onto a root-owned `0600` file under `/run` so a Docker Desktop mount cannot fail the mode check.

## Threats

The key check stops a short-circuit compare and refuses a key file that is a symlink, has the wrong mode, or is owned by someone else. It does not rate-limit guesses, rotate keys, or name a caller. Loopback bind stops non-local TCP clients. It does not stop another process on the host. The closed compiler stops command injection through a shell or an nft script. It does not stop a holder of the key from dropping traffic in that network namespace. `match_all` stops a verdict-only rule from being an accident. It does not stop an explicit drop-all. A holder of the key can trigger the fixed feed fetches. The client allows only its built-in hosts, refuses a non-public address, and ignores proxy environment variables. It does not stop that holder from reading the indicators.
