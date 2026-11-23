package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"nftapi/internal/nft"
)

const testKey = "nftapi-test-key-0123456789abcdef"

func TestHealthAndAuth(t *testing.T) {
	s, buf := newTestServer(t)
	res, body := call(s, http.MethodGet, "/health", "", "")
	if res.StatusCode != http.StatusOK || strings.TrimSpace(body) != `{"ok":true}` {
		t.Fatalf("health %d %s", res.StatusCode, body)
	}
	assertHeaders(t, res)

	missing, missBody := call(s, http.MethodPost, "/v1", "", `{"op":"ruleset.list"}`)
	wrong, wrongBody := call(s, http.MethodPost, "/v1", strings.Repeat("a", 32), `{"op":"ruleset.list"}`)
	short, shortBody := call(s, http.MethodPost, "/v1", "short", `{"op":"ruleset.list"}`)
	empty, emptyBody := call(s, http.MethodPost, "/v1", "", `{"op":"ruleset.list"}`)
	scheme, schemeBody := callRaw(s, http.MethodPost, "/v1?key="+testKey, "bearer "+testKey, `{"op":"ruleset.list"}`)
	token, tokenBody := callRaw(s, http.MethodPost, "/v1", "Token "+testKey, `{"op":"ruleset.list"}`)
	blank, blankBody := callRaw(s, http.MethodPost, "/v1", "Bearer ", `{"op":"ruleset.list"}`)
	want := `{"ok":false,"error":{"code":"unauthorized","message":"unauthorized"}}`
	for _, b := range []string{missBody, wrongBody, shortBody, emptyBody, schemeBody, tokenBody, blankBody} {
		if strings.TrimSpace(b) != want {
			t.Fatalf("auth body %s", b)
		}
	}
	for _, code := range []int{missing.StatusCode, wrong.StatusCode, short.StatusCode, empty.StatusCode, scheme.StatusCode, token.StatusCode, blank.StatusCode} {
		if code != http.StatusUnauthorized {
			t.Fatal(code)
		}
	}
	if strings.Contains(buf.String()+missBody+schemeBody, testKey) {
		t.Fatal("key leaked")
	}
}

func TestDispatch(t *testing.T) {
	s, buf := newTestServer(t)
	res, body := call(s, http.MethodPost, "/v1", testKey, `{"op":"ruleset.list"}`)
	if res.StatusCode != http.StatusOK || !strings.Contains(body, `"tables":[]`) {
		t.Fatalf("list %d %s", res.StatusCode, body)
	}
	if !strings.Contains(buf.String(), "op=ruleset.list status=200\n") {
		t.Fatalf("log %q", buf.String())
	}
	assertHeaders(t, res)

	res, body = call(s, http.MethodPost, "/v1", testKey, `{"op":"table.add","family":"inet","table":"filter"}`)
	if res.StatusCode != 200 || !strings.Contains(body, `"created":true`) {
		t.Fatalf("add %d %s", res.StatusCode, body)
	}
	res, body = call(s, http.MethodPost, "/v1", testKey, `{"op":"table.add","family":"inet","table":"filter"}`)
	if res.StatusCode != 200 || !strings.Contains(body, `"created":false`) {
		t.Fatalf("idempotent %d %s", res.StatusCode, body)
	}

	res, body = call(s, http.MethodPost, "/v1", testKey, `{"op":"ruleset.list","family":"inet"}`)
	if res.StatusCode != http.StatusBadRequest || strings.Contains(body, "family") || !strings.Contains(body, `"invalid_argument"`) {
		t.Fatalf("extra %d %s", res.StatusCode, body)
	}
	res, body = call(s, http.MethodPost, "/v1", testKey, `{"op":"ruleset.list"}{"x":1}`)
	if res.StatusCode != http.StatusBadRequest || !strings.Contains(body, "invalid json") {
		t.Fatalf("junk %d %s", res.StatusCode, body)
	}
	res, body = call(s, http.MethodPost, "/v1", testKey, "{\"op\":\"flush\\ninjected\"}")
	if res.StatusCode != http.StatusBadRequest || strings.Contains(body, "injected") || strings.Contains(buf.String(), "injected") {
		t.Fatalf("op inject %d %s log %s", res.StatusCode, body, buf.String())
	}
	if !strings.Contains(buf.String(), "op=- status=400\n") {
		t.Fatalf("log %q", buf.String())
	}
	res, body = call(s, http.MethodPost, "/v1", testKey, `{"op":"table.add","family":"inet","table":"my-table"}`)
	if res.StatusCode != http.StatusBadRequest || !strings.Contains(body, "name") {
		t.Fatalf("name %d %s", res.StatusCode, body)
	}
	res, body = callRaw(s, http.MethodPost, "/nope", "Bearer "+testKey, `{"op":"ruleset.list"}`)
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("route %d %s", res.StatusCode, body)
	}
	res, body = call(s, http.MethodPost, "/v1", testKey, `{"op":"rule.delete","family":"inet","table":"filter","chain":"input","handle":1}`)
	if res.StatusCode != http.StatusNotFound || !strings.Contains(body, "rule not found") {
		t.Fatalf("missing rule %d %s", res.StatusCode, body)
	}

	prio := int32(0)
	chain, _ := json.Marshal(nft.Request{Op: "chain.add", Family: "inet", Table: "filter", Chain: "input", Type: "filter", Hook: "input", Priority: &prio, Policy: "accept"})
	res, body = call(s, http.MethodPost, "/v1", testKey, string(chain))
	if res.StatusCode != 200 {
		t.Fatalf("chain %d %s", res.StatusCode, body)
	}
	res, body = call(s, http.MethodPost, "/v1", testKey, `{"op":"table.delete","family":"inet","table":"filter"}`)
	if res.StatusCode != http.StatusConflict || !strings.Contains(body, "not_empty") {
		t.Fatalf("not empty %d %s", res.StatusCode, body)
	}
	p1 := int32(1)
	other, _ := json.Marshal(nft.Request{Op: "chain.add", Family: "inet", Table: "filter", Chain: "input", Type: "filter", Hook: "input", Priority: &p1, Policy: "drop"})
	res, body = call(s, http.MethodPost, "/v1", testKey, string(other))
	if res.StatusCode != http.StatusConflict || !strings.Contains(body, "conflict") {
		t.Fatalf("conflict %d %s", res.StatusCode, body)
	}

	rule, _ := json.Marshal(nft.Request{Op: "rule.add", Family: "inet", Table: "filter", Chain: "input", Verdict: "drop", MatchAll: true, Comment: "a&b"})
	res, body = call(s, http.MethodPost, "/v1", testKey, string(rule))
	if res.StatusCode != 200 || !strings.Contains(body, `"created":true`) || strings.Contains(body, `\u0026`) {
		t.Fatalf("rule %d %s", res.StatusCode, body)
	}
	res, body = call(s, http.MethodPost, "/v1", testKey, `{"op":"ruleset.list"}`)
	if !strings.Contains(body, "a&b") || strings.Contains(body, `\u0026`) || !strings.Contains(body, `"match_all":true`) || strings.Contains(body, `"opaque":true`) {
		t.Fatalf("list comment %s", body)
	}
	if strings.Contains(body+buf.String(), testKey) {
		t.Fatal("key leaked")
	}
	for _, in := range s.runner.(*store).ins {
		if bytes.Contains(in, []byte(testKey)) || bytes.Contains(in, []byte("flush")) {
			t.Fatalf("stdin %s", in)
		}
	}
}

func TestBodyLimit(t *testing.T) {
	s, _ := newTestServer(t)
	pad := `{"op":"ruleset.list"}`
	exact := pad + strings.Repeat(" ", (64<<10)-len(pad))
	if len(exact) != 64<<10 {
		t.Fatal(len(exact))
	}
	res, body := call(s, http.MethodPost, "/v1", testKey, exact)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("exact %d %s", res.StatusCode, body)
	}
	res, body = call(s, http.MethodPost, "/v1", testKey, exact+" ")
	if res.StatusCode != http.StatusRequestEntityTooLarge || !strings.Contains(body, "payload_too_large") {
		t.Fatalf("over %d %s", res.StatusCode, body)
	}
	res, body = callRaw(s, http.MethodPost, "/v1", "Bearer "+testKey, `{"op":"ruleset.list"}`)
	if res.StatusCode != http.StatusBadRequest || !strings.Contains(body, "content type") {
		t.Fatalf("type %d %s", res.StatusCode, body)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1", strings.NewReader(pad))
	req.Header.Set("Authorization", "Bearer "+testKey)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("charset %d %s", rec.Code, rec.Body.String())
	}
}

func TestRunnerFailureHidden(t *testing.T) {
	logs := &bytes.Buffer{}
	s := New([]byte(testKey), &store{err: errors.New("boom secret")}, log.New(logs, "", 0))
	_, body := call(s, http.MethodPost, "/v1", testKey, `{"op":"ruleset.list"}`)
	if strings.Contains(body, "boom") || !strings.Contains(body, `"nft_failed"`) || !strings.Contains(body, "nft failed") {
		t.Fatal(body)
	}
}

func TestListenLoopbackOnly(t *testing.T) {
	s := New([]byte(testKey), &store{}, nil)
	if err := s.Listen("0.0.0.0:9789"); err == nil {
		t.Fatal("non-loopback")
	}
	if err := s.Listen("127.0.0.1:0"); err == nil {
		t.Fatal("port 0")
	}
}

func TestNewCopiesKey(t *testing.T) {
	buf := []byte(testKey)
	s := New(buf, &store{}, nil)
	for i := range buf {
		buf[i] = 0
	}
	res, _ := call(s, http.MethodGet, "/health", "", "")
	if res.StatusCode != http.StatusOK {
		t.Fatal(res.StatusCode)
	}
	res, body := call(s, http.MethodPost, "/v1", testKey, `{"op":"ruleset.list"}`)
	if res.StatusCode != http.StatusOK {
		t.Fatal(body)
	}
}

func newTestServer(t *testing.T) (*Server, *bytes.Buffer) {
	t.Helper()
	buf := &bytes.Buffer{}
	return New([]byte(testKey), &store{elems: []json.RawMessage{}, next: 1}, log.New(buf, "", 0)), buf
}

func call(s *Server, method, path, key, body string) (*http.Response, string) {
	auth := ""
	if key != "" {
		auth = "Bearer " + key
	}
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	return serve(s, req)
}

func callRaw(s *Server, method, path, auth, body string) (*http.Response, string) {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	return serve(s, req)
}

func serve(s *Server, req *http.Request) (*http.Response, string) {
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	b, _ := io.ReadAll(rec.Result().Body)
	return rec.Result(), string(b)
}

func assertHeaders(t *testing.T, res *http.Response) {
	t.Helper()
	if res.Header.Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatal(res.Header.Get("Content-Type"))
	}
	if res.Header.Get("Cache-Control") != "no-store" || res.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal(res.Header)
	}
}

// store is the in-memory nft runner used by HTTP tests.
type store struct {
	elems []json.RawMessage
	next  uint64
	ins   [][]byte
	err   error
}

func (m *store) Run(_ context.Context, stdin []byte) ([]byte, error) {
	m.ins = append(m.ins, append([]byte(nil), stdin...))
	if m.err != nil {
		return nil, m.err
	}
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal(stdin, &doc) != nil || len(doc.Nftables) != 1 || len(doc.Nftables[0]) != 1 {
		return nil, errors.New("bad nft document")
	}
	var kind string
	var raw json.RawMessage
	for k, v := range doc.Nftables[0] {
		kind, raw = k, v
	}
	switch kind {
	case "list":
		if m.elems == nil {
			m.elems = []json.RawMessage{}
		}
		b, err := json.Marshal(struct {
			Nftables []json.RawMessage `json:"nftables"`
		}{m.elems})
		return b, err
	case "add":
		return m.add(raw)
	case "delete":
		return []byte(`{"nftables":[]}`), nil
	default:
		return nil, errors.New("unexpected nft command")
	}
}

func (m *store) add(raw json.RawMessage) ([]byte, error) {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil || len(obj) != 1 {
		return nil, errors.New("bad add")
	}
	var kind string
	var body json.RawMessage
	for k, v := range obj {
		kind, body = k, v
	}
	switch kind {
	case "table", "chain":
		el, err := json.Marshal(map[string]json.RawMessage{kind: body})
		if err != nil {
			return nil, err
		}
		m.elems = append(m.elems, el)
	case "rule":
		var rule map[string]any
		if err := json.Unmarshal(body, &rule); err != nil {
			return nil, err
		}
		h := m.next
		if h == 0 {
			h = 1
		}
		m.next = h + 1
		rule["handle"] = h
		nb, err := json.Marshal(rule)
		if err != nil {
			return nil, err
		}
		el, err := json.Marshal(map[string]json.RawMessage{"rule": nb})
		if err != nil {
			return nil, err
		}
		m.elems = append(m.elems, el)
	default:
		return nil, errors.New("bad add")
	}
	return []byte(`{"nftables":[]}`), nil
}
