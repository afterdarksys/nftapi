package nft

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
)

// mem is an in-memory ruleset. It parses each nftables element for one
// command key. Deletes are filtered into a new slice.
type mem struct {
	elems []json.RawMessage
	next  uint64
	ins   [][]byte
	err   error
}

func newMem() *mem {
	return &mem{elems: []json.RawMessage{}, next: 1}
}

func (m *mem) Run(_ context.Context, stdin []byte) ([]byte, error) {
	m.ins = append(m.ins, append([]byte(nil), stdin...))
	if m.err != nil {
		return nil, m.err
	}
	kind, raw, err := cmdOf(stdin)
	if err != nil {
		return nil, err
	}
	switch kind {
	case "list":
		return m.snapshot(), nil
	case "add":
		return m.add(raw)
	case "delete":
		return m.remove(raw)
	default:
		return nil, errors.New("unexpected nft command")
	}
}

func (m *mem) snapshot() []byte {
	b, err := json.Marshal(struct {
		Nftables []json.RawMessage `json:"nftables"`
	}{Nftables: m.elems})
	if err != nil {
		panic(err)
	}
	return b
}

func (m *mem) add(raw json.RawMessage) ([]byte, error) {
	kind, body, err := oneKey(raw)
	if err != nil {
		return nil, err
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
		m.next++
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
		return nil, errors.New("unexpected add")
	}
	return []byte(`{"nftables":[]}`), nil
}

func (m *mem) remove(raw json.RawMessage) ([]byte, error) {
	kind, body, err := oneKey(raw)
	if err != nil {
		return nil, err
	}
	next := make([]json.RawMessage, 0, len(m.elems))
	for _, el := range m.elems {
		ek, eb, err := oneKey(el)
		if err != nil {
			return nil, err
		}
		if ek == kind && sameObj(kind, eb, body) {
			continue
		}
		next = append(next, el)
	}
	m.elems = next
	return []byte(`{"nftables":[]}`), nil
}

func (m *mem) seed(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	if _, raw, err := oneKey(b); err == nil {
		var rule struct {
			Handle uint64 `json:"handle"`
		}
		if json.Unmarshal(raw, &rule) == nil && rule.Handle >= m.next {
			m.next = rule.Handle + 1
		}
	}
	m.elems = append(m.elems, b)
}

func (m *mem) kinds() (list, add, del int) {
	for _, in := range m.ins {
		k, _, err := cmdOf(in)
		if err != nil {
			continue
		}
		switch k {
		case "list":
			list++
		case "add":
			add++
		case "delete":
			del++
		}
	}
	return list, add, del
}

func (m *mem) noFlush(t *testing.T) {
	t.Helper()
	for _, in := range m.ins {
		if bytes.Contains(in, []byte("flush")) {
			t.Fatalf("flush in stdin %s", in)
		}
	}
}

func cmdOf(stdin []byte) (string, json.RawMessage, error) {
	var doc struct {
		Nftables []json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(stdin, &doc); err != nil || len(doc.Nftables) != 1 {
		return "", nil, errors.New("bad nft document")
	}
	return oneKey(doc.Nftables[0])
}

func oneKey(raw json.RawMessage) (string, json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || len(obj) != 1 {
		return "", nil, errors.New("nft element is not one object")
	}
	for k, v := range obj {
		return k, v, nil
	}
	return "", nil, errors.New("nft element is not one object")
}

func sameObj(kind string, have, want json.RawMessage) bool {
	var a, b objID
	if json.Unmarshal(have, &a) != nil || json.Unmarshal(want, &b) != nil {
		return false
	}
	switch kind {
	case "table":
		return a.Family == b.Family && a.Name == b.Name
	case "chain":
		return a.Family == b.Family && a.Table == b.Table && a.Name == b.Name
	case "rule":
		return a.Family == b.Family && a.Table == b.Table && a.Chain == b.Chain && a.Handle == b.Handle
	default:
		return false
	}
}

type objID struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Chain  string `json:"chain"`
	Name   string `json:"name"`
	Handle uint64 `json:"handle"`
}

func TestApplyLifecycle(t *testing.T) {
	m := newMem()
	ctx := context.Background()
	rs, err := Apply(ctx, m, Request{Op: "ruleset.list"})
	if err != nil || rs.Ruleset == nil || len(rs.Ruleset.Tables) != 0 {
		t.Fatalf("list %v %+v", err, rs.Ruleset)
	}
	got := mustApply(t, m, Request{Op: "table.add", Family: "inet", Table: "filter"})
	if got.Created == nil || !*got.Created {
		t.Fatal(got.Created)
	}
	n := len(m.ins)
	again := mustApply(t, m, Request{Op: "table.add", Family: "inet", Table: "filter"})
	if again.Created == nil || *again.Created {
		t.Fatal("second table add")
	}
	if len(m.ins) != n+1 {
		t.Fatalf("idempotent table add wrote %d commands", len(m.ins)-n)
	}
	prio := int32(0)
	chain := Request{Op: "chain.add", Family: "inet", Table: "filter", Chain: "input", Type: "filter", Hook: "input", Priority: &prio, Policy: "accept"}
	got = mustApply(t, m, chain)
	if got.Created == nil || !*got.Created {
		t.Fatal("chain")
	}
	again = mustApply(t, m, chain)
	if again.Created == nil || *again.Created {
		t.Fatal("same chain")
	}
	other := chain
	p1 := int32(1)
	other.Priority = &p1
	_, err = Apply(ctx, m, other)
	if codeOf(err) != "conflict" {
		t.Fatal(err)
	}
	_, _, del := m.kinds()
	if del != 0 {
		t.Fatal("delete before any delete op")
	}
	rule := Request{Op: "rule.add", Family: "inet", Table: "filter", Chain: "input", Verdict: "drop", MatchAll: true, Comment: "a&b"}
	got = mustApply(t, m, rule)
	if got.Created == nil || !*got.Created || got.Handle == nil || *got.Handle == 0 {
		t.Fatalf("rule %+v", got)
	}
	h := *got.Handle
	again = mustApply(t, m, rule)
	if again.Created == nil || *again.Created || again.Handle == nil || *again.Handle != h {
		t.Fatalf("idempotent rule %+v", again)
	}
	_, err = Apply(ctx, m, Request{Op: "chain.delete", Family: "inet", Table: "filter", Chain: "input"})
	if codeOf(err) != "not_empty" {
		t.Fatal(err)
	}
	_, err = Apply(ctx, m, Request{Op: "rule.delete", Family: "inet", Table: "filter", Chain: "input", Handle: uintPtr(h + 9)})
	if codeOf(err) != "not_found" {
		t.Fatal(err)
	}
	got = mustApply(t, m, Request{Op: "rule.delete", Family: "inet", Table: "filter", Chain: "input", Handle: &h})
	if got.Deleted == nil || !*got.Deleted {
		t.Fatal("rule delete")
	}
	got = mustApply(t, m, Request{Op: "chain.delete", Family: "inet", Table: "filter", Chain: "input"})
	if got.Deleted == nil || !*got.Deleted {
		t.Fatal("chain delete")
	}
	_, err = Apply(ctx, m, Request{Op: "table.delete", Family: "ip", Table: "filter"})
	if codeOf(err) != "not_found" {
		t.Fatal(err)
	}
	got = mustApply(t, m, Request{Op: "table.delete", Family: "inet", Table: "filter"})
	if got.Deleted == nil || !*got.Deleted {
		t.Fatal("table delete")
	}
	_, err = Apply(ctx, m, Request{Op: "table.delete", Family: "inet", Table: "filter"})
	if codeOf(err) != "not_found" {
		t.Fatal(err)
	}
	for _, in := range m.ins {
		k, _, err := cmdOf(in)
		if err != nil {
			t.Fatal(err)
		}
		if k == "list" && !bytes.Equal(in, listStdin()) {
			t.Fatalf("list stdin %s", in)
		}
	}
	m.noFlush(t)
	if _, err := Apply(ctx, m, Request{Op: "rule.add", Family: "inet", Table: "filter", Chain: "input", Verdict: "drop", MatchAll: true}); codeOf(err) != "not_found" {
		t.Fatal(err)
	}
	if _, err := Apply(ctx, newMem(), chain); codeOf(err) != "not_found" {
		t.Fatal(err)
	}
}

func TestApplyTableNotEmpty(t *testing.T) {
	m := newMem()
	mustApply(t, m, Request{Op: "table.add", Family: "inet", Table: "filter"})
	prio := int32(0)
	mustApply(t, m, Request{Op: "chain.add", Family: "inet", Table: "filter", Chain: "input", Type: "filter", Hook: "input", Priority: &prio, Policy: "accept"})
	_, err := Apply(context.Background(), m, Request{Op: "table.delete", Family: "inet", Table: "filter"})
	if codeOf(err) != "not_empty" {
		t.Fatal(err)
	}
	_, _, del := m.kinds()
	if del != 0 {
		t.Fatal("not_empty still deleted")
	}
	m.noFlush(t)
}

func TestApplyOpaqueAndLowestHandle(t *testing.T) {
	m := newMem()
	m.seed(map[string]any{"table": map[string]any{"family": "inet", "name": "filter"}})
	m.seed(map[string]any{"chain": map[string]any{
		"family": "inet", "table": "filter", "name": "input",
		"type": "filter", "hook": "input", "prio": 0, "policy": "accept",
	}})
	m.seed(dropRule(20))
	m.seed(dropRule(8))
	m.seed(markRule(9))
	rule := Request{Op: "rule.add", Family: "inet", Table: "filter", Chain: "input", Verdict: "drop", MatchAll: true}
	n := len(m.ins)
	got := mustApply(t, m, rule)
	if got.Created == nil || *got.Created || got.Handle == nil || *got.Handle != 8 {
		t.Fatalf("lowest %+v err handle", got)
	}
	if len(m.ins) != n+1 {
		t.Fatal("identity match still added")
	}
	_, err := Apply(context.Background(), m, Request{Op: "chain.add", Family: "inet", Table: "filter", Chain: "input", Type: "filter", Hook: "input", Priority: int32Ptr(1), Policy: "accept"})
	if codeOf(err) != "conflict" {
		t.Fatal(err)
	}
	bare := newMem()
	bare.seed(markRule(4))
	_, err = Apply(context.Background(), bare, Request{Op: "chain.add", Family: "inet", Table: "filter", Chain: "input", Type: "filter", Hook: "input", Priority: int32Ptr(0), Policy: "accept"})
	if codeOf(err) != "conflict" {
		t.Fatalf("non-base chain: %v", err)
	}
	got = mustApply(t, bare, rule)
	if got.Created == nil || !*got.Created || got.Handle == nil || *got.Handle == 4 {
		t.Fatalf("opaque matched %+v", got)
	}
	_, err = Apply(context.Background(), bare, Request{Op: "chain.delete", Family: "inet", Table: "filter", Chain: "input"})
	if codeOf(err) != "not_empty" {
		t.Fatal(err)
	}
}

func TestApplyRunnerErrors(t *testing.T) {
	ctx := context.Background()
	req := Request{Op: "ruleset.list"}
	_, err := Apply(ctx, nil, req)
	if codeOf(err) != "unavailable" {
		t.Fatal(err)
	}
	m := newMem()
	m.err = errors.New("boom secret")
	_, err = Apply(ctx, m, req)
	if codeOf(err) != "nft_failed" || err.Error() != "nft failed" {
		t.Fatal(err)
	}
	m.err = ErrTimeout
	_, err = Apply(ctx, m, req)
	if codeOf(err) != "timeout" {
		t.Fatal(err)
	}
	m.err = ErrTooBig
	_, err = Apply(ctx, m, req)
	if codeOf(err) != "nft_failed" || err.Error() != "nft output exceeded 1MiB" {
		t.Fatal(err)
	}
	m.err = ErrUnavailable
	_, err = Apply(ctx, m, req)
	if codeOf(err) != "unavailable" {
		t.Fatal(err)
	}
	m.err = nftFailed("from nft")
	_, err = Apply(ctx, m, req)
	if codeOf(err) != "nft_failed" || err.Error() != "from nft" {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	m.err = nil
	_, err = Apply(canceled, m, req)
	if codeOf(err) != "timeout" {
		t.Fatal(err)
	}

	empty := []byte(`{"nftables":[{"table":{"family":"inet","name":"filter"}},{"chain":{"family":"inet","table":"filter","name":"input","type":"filter","hook":"input","prio":0,"policy":"accept"}}]}`)
	two := []byte(`{"nftables":[{"table":{"family":"inet","name":"filter"}},{"chain":{"family":"inet","table":"filter","name":"input","type":"filter","hook":"input","prio":0,"policy":"accept"}},{"rule":{"family":"inet","table":"filter","chain":"input","handle":1,"expr":[{"drop":null}]}},{"rule":{"family":"inet","table":"filter","chain":"input","handle":2,"expr":[{"drop":null}]}}]}`)
	s := &scripted{outs: [][]byte{empty, []byte(`{"nftables":[]}`), empty}}
	_, err = Apply(ctx, s, Request{Op: "rule.add", Family: "inet", Table: "filter", Chain: "input", Verdict: "drop", MatchAll: true})
	if codeOf(err) != "nft_failed" || err.Error() != "added rule was not found" {
		t.Fatal(err)
	}
	s = &scripted{outs: [][]byte{empty, []byte(`{"nftables":[]}`), two}}
	_, err = Apply(ctx, s, Request{Op: "rule.add", Family: "inet", Table: "filter", Chain: "input", Verdict: "drop", MatchAll: true})
	if codeOf(err) != "nft_failed" || err.Error() != "added rule was not found" {
		t.Fatal(err)
	}
	for _, in := range s.ins {
		if bytes.Contains(in, []byte("flush")) {
			t.Fatalf("flush %s", in)
		}
	}
}

type scripted struct {
	outs [][]byte
	ins  [][]byte
	i    int
}

func (s *scripted) Run(_ context.Context, stdin []byte) ([]byte, error) {
	s.ins = append(s.ins, append([]byte(nil), stdin...))
	if s.i >= len(s.outs) {
		return nil, errors.New("extra nft call")
	}
	out := s.outs[s.i]
	s.i++
	return out, nil
}

func dropRule(handle uint64) map[string]any {
	return map[string]any{"rule": map[string]any{
		"family": "inet", "table": "filter", "chain": "input", "handle": handle,
		"expr": []any{map[string]any{"drop": nil}},
	}}
}

func markRule(handle uint64) map[string]any {
	return map[string]any{"rule": map[string]any{
		"family": "inet", "table": "filter", "chain": "input", "handle": handle,
		"expr": []any{
			map[string]any{"match": map[string]any{
				"left":  map[string]any{"meta": map[string]any{"key": "mark"}},
				"right": 1,
				"op":    "==",
			}},
			map[string]any{"drop": nil},
		},
	}}
}

func mustApply(t *testing.T, m *mem, req Request) Result {
	t.Helper()
	res, err := Apply(context.Background(), m, req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func codeOf(err error) string {
	var ne *Error
	if errors.As(err, &ne) {
		return ne.Code
	}
	return ""
}

func int32Ptr(n int32) *int32 { return &n }
