//go:build integration

package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"nftapi/internal/nft"
)

func TestLive(t *testing.T) {
	base := os.Getenv("NFTAPI_URL")
	if base == "" {
		t.Fatal("NFTAPI_URL is required")
	}
	key := liveKey(t)
	c := &liveClient{base: base, key: key, http: &http.Client{Timeout: 5 * time.Second}}

	c.getOK(t, "/health")
	unauth := c.postStatus(t, "", map[string]any{"op": "ruleset.list"}, http.StatusUnauthorized)
	wrong := c.postStatus(t, strings.Repeat("b", 32), map[string]any{"op": "ruleset.list"}, http.StatusUnauthorized)
	if unauth != wrong || !strings.Contains(unauth, `"unauthorized"`) || strings.Contains(unauth, key) {
		t.Fatalf("auth %s %s", redact(unauth, key), redact(wrong, key))
	}

	c.postOK(t, map[string]any{"op": "ruleset.list"})
	add := c.postOK(t, map[string]any{"op": "table.add", "family": "inet", "table": "filter"})
	if add.Created == nil || !*add.Created {
		t.Fatalf("table %s", redact(add.raw, key))
	}
	again := c.postOK(t, map[string]any{"op": "table.add", "family": "inet", "table": "filter"})
	if again.Created == nil || *again.Created {
		t.Fatal("table exists")
	}
	chain := map[string]any{
		"op": "chain.add", "family": "inet", "table": "filter", "chain": "input",
		"type": "filter", "hook": "input", "priority": 0, "policy": "accept",
	}
	got := c.postOK(t, chain)
	if got.Created == nil || !*got.Created {
		t.Fatalf("chain %s", redact(got.raw, key))
	}
	chain["policy"] = "drop"
	if code, _ := c.post(t, key, chain); code != http.StatusConflict {
		t.Fatalf("conflict %d", code)
	}

	block := c.postOK(t, map[string]any{
		"op": "rule.add", "family": "inet", "table": "filter", "chain": "input",
		"match": map[string]any{"saddr": "203.0.113.5"}, "verdict": "drop",
	})
	if block.Handle == nil || block.Created == nil || !*block.Created {
		t.Fatalf("block %s", redact(block.raw, key))
	}
	same := c.postOK(t, map[string]any{
		"op": "rule.add", "family": "inet", "table": "filter", "chain": "input",
		"match": map[string]any{"saddr": "203.0.113.5"}, "verdict": "drop",
	})
	if same.Created == nil || *same.Created || same.Handle == nil || *same.Handle != *block.Handle {
		t.Fatalf("idempotent rule %s", redact(same.raw, key))
	}

	limited := c.postOK(t, map[string]any{
		"op": "rule.add", "family": "inet", "table": "filter", "chain": "input",
		"match":   map[string]any{"proto": "tcp", "dport": 22, "ct_state": []string{"new"}},
		"limit":   map[string]any{"rate": 5, "per": "minute", "burst": 10, "mode": "over"},
		"verdict": "drop",
	})
	// Local delivery of this reply traverses output, postrouting, prerouting,
	// and input. A match_all reject there emits icmpx port-unreachable, which
	// established TCP ignores, and the client waits until its deadline.
	// The forward hook is outside that path.
	fwd := c.postOK(t, map[string]any{
		"op": "chain.add", "family": "inet", "table": "filter", "chain": "fwd",
		"type": "filter", "hook": "forward", "priority": 0, "policy": "accept",
	})
	if fwd.Created == nil || !*fwd.Created {
		t.Fatalf("forward chain %s", redact(fwd.raw, key))
	}
	rej := c.postOK(t, map[string]any{
		"op": "rule.add", "family": "inet", "table": "filter", "chain": "fwd",
		"match_all": true, "verdict": "reject",
	})
	listed := c.postOK(t, map[string]any{"op": "ruleset.list"})
	requireLive(t, listed, *block.Handle, func(r nft.Rule) {
		if r.Opaque || r.Verdict != "drop" || r.Match == nil || r.Match.Saddr != "203.0.113.5" {
			t.Fatalf("block projection %+v expr %s", r, r.Expr)
		}
	})
	requireLive(t, listed, *limited.Handle, func(r nft.Rule) {
		if r.Opaque || r.Limit == nil || r.Limit.Rate != 5 || r.Limit.Per != "minute" || r.Limit.Mode != "over" || r.Limit.Burst == nil || *r.Limit.Burst != 10 {
			t.Fatalf("limit projection %+v expr %s", r, r.Expr)
		}
		if r.Match == nil || r.Match.Proto != "tcp" || r.Match.Dport == nil || r.Match.Dport.Lo != 22 {
			t.Fatalf("limit match %+v expr %s", r.Match, r.Expr)
		}
	})
	requireLive(t, listed, *rej.Handle, func(r nft.Rule) {
		if r.Opaque || !r.MatchAll || r.Verdict != "reject" {
			t.Fatalf("reject projection %+v expr %s", r, r.Expr)
		}
	})

	if code, body := c.post(t, key, map[string]any{"op": "table.delete", "family": "inet", "table": "filter"}); code != http.StatusConflict || !strings.Contains(body, "not_empty") {
		t.Fatalf("table delete %d %s", code, redact(body, key))
	}
	if code, body := c.post(t, key, map[string]any{"op": "chain.delete", "family": "inet", "table": "filter", "chain": "input"}); code != http.StatusConflict || !strings.Contains(body, "not_empty") {
		t.Fatalf("chain delete %d %s", code, redact(body, key))
	}

	opaque := liveOpaque(t)
	listed = c.postOK(t, map[string]any{"op": "ruleset.list"})
	var opaqueHandle uint64
	found := false
	for _, tb := range listed.Tables {
		for _, ch := range tb.Chains {
			for _, r := range ch.Rules {
				if r.Opaque {
					opaqueHandle = r.Handle
					found = true
					if len(r.Expr) == 0 {
						t.Fatal("opaque rule hid its expr")
					}
				}
			}
		}
	}
	if !found {
		t.Fatalf("opaque rule missing after %s list %s", opaque, redact(listed.raw, key))
	}
	c.postOK(t, map[string]any{"op": "rule.delete", "family": "inet", "table": "filter", "chain": "input", "handle": opaqueHandle})

	for _, h := range []uint64{*block.Handle, *limited.Handle} {
		c.postOK(t, map[string]any{"op": "rule.delete", "family": "inet", "table": "filter", "chain": "input", "handle": h})
	}
	c.postOK(t, map[string]any{"op": "rule.delete", "family": "inet", "table": "filter", "chain": "fwd", "handle": *rej.Handle})
	c.postOK(t, map[string]any{"op": "chain.delete", "family": "inet", "table": "filter", "chain": "input"})
	c.postOK(t, map[string]any{"op": "chain.delete", "family": "inet", "table": "filter", "chain": "fwd"})
	deleted := c.postOK(t, map[string]any{"op": "table.delete", "family": "inet", "table": "filter"})
	if deleted.Deleted == nil || !*deleted.Deleted {
		t.Fatalf("deleted %s", redact(deleted.raw, key))
	}
	if code, body := c.post(t, key, map[string]any{"op": "table.delete", "family": "inet", "table": "filter"}); code != http.StatusNotFound {
		t.Fatalf("gone %d %s", code, redact(body, key))
	}
}

type liveClient struct {
	base string
	key  string
	http *http.Client
}

type liveResult struct {
	OK      bool        `json:"ok"`
	Created *bool       `json:"created"`
	Deleted *bool       `json:"deleted"`
	Handle  *uint64     `json:"handle"`
	Tables  []nft.Table `json:"tables"`
	raw     string
}

func (c *liveClient) getOK(t *testing.T, path string) {
	t.Helper()
	res, err := c.http.Get(c.base + path)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK || strings.Contains(string(b), c.key) {
		t.Fatalf("get %d %s", res.StatusCode, redact(string(b), c.key))
	}
}

func (c *liveClient) postOK(t *testing.T, body map[string]any) liveResult {
	t.Helper()
	code, raw := c.post(t, c.key, body)
	if code != http.StatusOK {
		t.Fatalf("%v -> %d %s", body["op"], code, redact(raw, c.key))
	}
	var out liveResult
	if err := json.Unmarshal([]byte(raw), &out); err != nil || !out.OK {
		t.Fatalf("decode %s", redact(raw, c.key))
	}
	out.raw = raw
	if strings.Contains(raw, c.key) {
		t.Fatal("response contains the key")
	}
	return out
}

func (c *liveClient) postStatus(t *testing.T, key string, body map[string]any, want int) string {
	t.Helper()
	code, raw := c.post(t, key, body)
	if code != want {
		t.Fatalf("status %d %s", code, redact(raw, c.key))
	}
	return raw
}

func (c *liveClient) post(t *testing.T, key string, body map[string]any) (int, string) {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, c.base+"/v1", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	res, err := c.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(out)
}

func requireLive(t *testing.T, listed liveResult, handle uint64, check func(nft.Rule)) {
	t.Helper()
	for _, tb := range listed.Tables {
		for _, ch := range tb.Chains {
			for _, r := range ch.Rules {
				if r.Handle == handle {
					check(r)
					return
				}
			}
		}
	}
	t.Fatalf("handle %d missing in %s", handle, redact(listed.raw, ""))
}

func liveOpaque(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal(err)
	}
	doc := `{"nftables":[{"add":{"rule":{"family":"inet","table":"filter","chain":"input","expr":[{"match":{"left":{"meta":{"key":"mark"}},"right":1,"op":"=="}},{"drop":null}]}}}]}`
	cmd := exec.Command(path, nft.Argv()...)
	cmd.Stdin = strings.NewReader(doc)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("nft opaque: %v %s", err, out)
	}
	return doc
}

func liveKey(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(os.Getenv("NFTAPI_KEY_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	s := strings.TrimSuffix(string(b), "\n")
	if strings.ContainsAny(s, "\n\r\x00") || len(s) < 32 || len(s) > 256 {
		t.Fatal("key file is not usable")
	}
	return s
}

func redact(s, key string) string {
	if key == "" {
		return s
	}
	return strings.ReplaceAll(s, key, "[redacted]")
}
