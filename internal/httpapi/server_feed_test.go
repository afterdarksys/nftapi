package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"nftapi/internal/feed"
)

func TestFeedList(t *testing.T) {
	s, buf := newTestServer(t)
	called := false
	s.feeds = feed.GetterFunc(func(context.Context, string) ([]byte, error) {
		called = true
		return nil, errors.New("fetched")
	})
	res, body := call(s, http.MethodPost, "/v1", testKey, `{"op":"feed.list"}`)
	if res.StatusCode != http.StatusOK || called {
		t.Fatalf("list %d called %v %s", res.StatusCode, called, body)
	}
	assertHeaders(t, res)
	for _, id := range []string{"tor", "tweetfeed_phishing", "artex", "cairn", "hexstrike", "cyberstrikeai"} {
		if !strings.Contains(body, `"`+id+`"`) {
			t.Fatalf("missing %s in %s", id, body)
		}
	}
	if strings.Contains(body, "http") || strings.Contains(buf.String(), "tor") {
		t.Fatalf("body %s log %s", body, buf.String())
	}
	if buf.String() != "op=feed.list status=200\n" {
		t.Fatalf("log %q", buf.String())
	}
	if len(s.runner.(*store).ins) != 0 {
		t.Fatal("nft ran")
	}
}

func TestFeedFetch(t *testing.T) {
	s, buf := newTestServer(t)
	s.feeds = feed.GetterFunc(func(_ context.Context, u string) ([]byte, error) {
		switch u {
		case "https://check.torproject.org/torbulkexitlist":
			return []byte("# SECRET\n203.0.113.5\n"), nil
		case "https://api.tweetfeed.live/v1/today":
			return []byte("[]"), nil
		default:
			t.Fatalf("url %s", u)
			return nil, nil
		}
	})
	res, body := call(s, http.MethodPost, "/v1", testKey, `{"op":"feed.fetch","module":"tor"}`)
	if res.StatusCode != http.StatusOK || !strings.Contains(body, `"module":"tor"`) || !strings.Contains(body, `"value":"203.0.113.5"`) {
		t.Fatalf("fetch %d %s", res.StatusCode, body)
	}
	if strings.Contains(body, "SECRET") || strings.Contains(body, "created") || strings.Contains(buf.String(), "SECRET") || strings.Contains(buf.String(), "203.0.113.5") {
		t.Fatalf("leak body %s log %s", body, buf.String())
	}
	if len(s.runner.(*store).ins) != 0 {
		t.Fatal("nft ran")
	}
	res, body = call(s, http.MethodPost, "/v1", testKey, `{"op":"feed.fetch","module":"tweetfeed_phishing"}`)
	if res.StatusCode != http.StatusOK || !strings.Contains(body, `"indicators":[]`) || strings.Contains(body, "null") {
		t.Fatalf("empty %d %s", res.StatusCode, body)
	}
	res, body = call(s, http.MethodPost, "/v1", testKey, `{"op":"ruleset.list"}`)
	if res.StatusCode != http.StatusOK || !strings.Contains(body, `"tables"`) {
		t.Fatalf("ruleset %d %s", res.StatusCode, body)
	}
}

func TestFeedErrors(t *testing.T) {
	s, buf := newTestServer(t)
	called := false
	s.feeds = feed.GetterFunc(func(context.Context, string) ([]byte, error) {
		called = true
		return nil, errors.New("nope")
	})
	cases := []struct {
		body   string
		status int
		code   string
		msg    string
		fetch  bool
	}{
		{`{"op":"feed.fetch","module":"nope"}`, 404, "not_found", "unknown module", false},
		{`{"op":"feed.fetch","module":"Tor"}`, 400, "invalid_argument", "invalid module", false},
		{`{"op":"feed.fetch","module":"a/b"}`, 400, "invalid_argument", "invalid module", false},
		{`{"op":"feed.list","module":"tor"}`, 400, "invalid_argument", "unexpected field", false},
		{`{"op":"feed.fetch","url":"https://evil.example/secret"}`, 400, "invalid_argument", "invalid json", false},
		{`{"op":"ruleset.list","module":"tor"}`, 400, "invalid_argument", "invalid json", false},
		{`{"op":"feed.fetch","module":"tor"}{"x":1}`, 400, "invalid_argument", "invalid json", false},
		{`{"op":"feed.fetch"}`, 400, "invalid_argument", "invalid module", false},
	}
	for _, tc := range cases {
		called = false
		res, body := call(s, http.MethodPost, "/v1", testKey, tc.body)
		if res.StatusCode != tc.status || !strings.Contains(body, tc.code) || !strings.Contains(body, tc.msg) {
			t.Fatalf("%s -> %d %s", tc.body, res.StatusCode, body)
		}
		if strings.Contains(body, "evil.example") || strings.Contains(body, "secret") || strings.Contains(buf.String(), "evil.example") {
			t.Fatalf("leak %s log %s", body, buf.String())
		}
		if called != tc.fetch {
			t.Fatalf("fetch %v for %s", called, tc.body)
		}
	}
	if len(s.runner.(*store).ins) != 0 {
		t.Fatal("nft ran")
	}

	s.feeds = feed.GetterFunc(func(context.Context, string) ([]byte, error) {
		return nil, context.DeadlineExceeded
	})
	res, body := call(s, http.MethodPost, "/v1", testKey, `{"op":"feed.fetch","module":"tor"}`)
	if res.StatusCode != http.StatusGatewayTimeout || !strings.Contains(body, "feed timed out") {
		t.Fatalf("timeout %d %s", res.StatusCode, body)
	}
	s.feeds = feed.GetterFunc(func(context.Context, string) ([]byte, error) {
		return nil, errors.New("dial tcp secret")
	})
	res, body = call(s, http.MethodPost, "/v1", testKey, `{"op":"feed.fetch","module":"cairn"}`)
	if res.StatusCode != http.StatusServiceUnavailable || !strings.Contains(body, "feed fetch failed") || strings.Contains(body, "secret") {
		t.Fatalf("down %d %s", res.StatusCode, body)
	}
	s.feeds = feed.GetterFunc(func(context.Context, string) ([]byte, error) {
		return []byte("<html>secret</html>"), nil
	})
	res, body = call(s, http.MethodPost, "/v1", testKey, `{"op":"feed.fetch","module":"tweetfeed_phishing"}`)
	if res.StatusCode != http.StatusServiceUnavailable || !strings.Contains(body, "feed document is not usable") || strings.Contains(body, "secret") {
		t.Fatalf("doc %d %s", res.StatusCode, body)
	}
}
