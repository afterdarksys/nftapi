package nft

import (
	"encoding/json"
	"strings"
	"testing"
)

func roundTrip(t *testing.T, req Request) Rule {
	t.Helper()
	if err := req.Validate(); err != nil {
		t.Fatal(err)
	}
	doc, err := Compile(req)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(doc, &parsed); err != nil || len(parsed.Nftables) != 1 {
		t.Fatal(err)
	}
	var add map[string]json.RawMessage
	if err := json.Unmarshal(parsed.Nftables[0]["add"], &add); err != nil {
		t.Fatal(err)
	}
	var rm map[string]any
	if err := json.Unmarshal(add["rule"], &rm); err != nil {
		t.Fatal(err)
	}
	rm["handle"] = 7
	rb, err := json.Marshal(rm)
	if err != nil {
		t.Fatal(err)
	}
	listed := []byte(`{"nftables":[{"rule":` + string(rb) + `}]}`)
	rs, err := Project(listed)
	if err != nil {
		t.Fatalf("%v %s", err, listed)
	}
	rule := rs.Tables[0].Chains[0].Rules[0]
	if rule.Opaque {
		t.Fatalf("opaque expr %s", rule.Expr)
	}
	if !rule.spec().Equal(req.spec()) {
		t.Fatalf("spec mismatch listed %s", listed)
	}
	return rule
}

func TestRoundTrip(t *testing.T) {
	burst := 10
	roundTrip(t, Request{
		Op: "rule.add", Family: "inet", Table: "filter", Chain: "input", Verdict: "drop", Comment: "a&b",
		Match: &Match{Proto: "tcp", Dport: &Port{Lo: 22, Hi: 22}, CtState: []string{"new"}},
		Limit: &Limit{Rate: 5, Per: "minute", Burst: &burst, Mode: "over"},
	})
	roundTrip(t, Request{
		Op: "rule.add", Family: "inet", Table: "filter", Chain: "input", Verdict: "drop",
		Match: &Match{Saddr: "203.0.113.5"},
	})
	roundTrip(t, Request{
		Op: "rule.add", Family: "inet", Table: "filter", Chain: "input", Verdict: "reject", MatchAll: true,
	})
	roundTrip(t, Request{
		Op: "rule.add", Family: "ip6", Table: "filter", Chain: "input", Verdict: "accept",
		Match: &Match{Proto: "icmpv6", Saddr: "2001:db8::/32"},
	})
}

func TestProjectVariants(t *testing.T) {
	base := func(expr string) Rule {
		t.Helper()
		raw := `{"nftables":[{"rule":{"family":"inet","table":"filter","chain":"input","handle":4,"expr":[` + expr + `]}}]}`
		rs, err := Project([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		return rs.Tables[0].Chains[0].Rules[0]
	}
	drop := `{"drop":null}`
	if r := base(`{"counter":null},{"counter":{"packets":1,"bytes":2}},` + drop); r.Opaque || !r.MatchAll || r.Verdict != "drop" {
		t.Fatalf("%+v", r)
	}
	if r := base(`{"counter":"cnt"},` + drop); !r.Opaque {
		t.Fatal("named counter")
	}
	if r := base(`{"reject":null}`); r.Opaque || r.Verdict != "reject" {
		t.Fatalf("%+v", r)
	}
	if r := base(`{"reject":{}}`); r.Opaque || r.Verdict != "reject" {
		t.Fatalf("%+v", r)
	}
	if r := base(`{"reject":{"type":"tcp reset"}}`); !r.Opaque {
		t.Fatal("typed reject")
	}
	if r := base(`{"reject":{"type":"icmpx","expr":"port-unreachable"}}`); r.Opaque || !r.MatchAll || r.Verdict != "reject" {
		t.Fatalf("default reject %+v expr %s", r, r.Expr)
	}
	if r := base(`{"reject":{"type":"icmpx","expr":"admin-prohibited"}}`); !r.Opaque {
		t.Fatal("other icmpx expr")
	}
	if r := base(`{"reject":{"type":"icmp","expr":"port-unreachable"}}`); !r.Opaque {
		t.Fatal("icmp type reject")
	}
	if r := base(`{"reject":{"type":"icmpx","expr":"port-unreachable","extra":true}}`); !r.Opaque {
		t.Fatal("reject extra field")
	}
	liveLimit := `{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":22}},{"match":{"op":"==","left":{"ct":{"key":"state"}},"right":"new"}},{"limit":{"rate":5,"burst":10,"per":"minute","inv":true}},{"drop":null}`
	if r := base(liveLimit); r.Opaque || r.Verdict != "drop" || r.Match == nil || r.Match.Proto != "tcp" || r.Match.Dport == nil || r.Match.Dport.Lo != 22 || len(r.Match.CtState) != 1 || r.Match.CtState[0] != "new" || r.Limit == nil || r.Limit.Rate != 5 || r.Limit.Per != "minute" || r.Limit.Mode != "over" || r.Limit.Burst == nil || *r.Limit.Burst != 10 {
		t.Fatalf("live limit %+v match %+v expr %s", r.Limit, r.Match, r.Expr)
	}
	if r := base(`{"match":{"left":{"ct":{"key":"state"}},"op":"in","right":{"set":["related","established"]}}},` + drop); r.Opaque || strings.Join(r.Match.CtState, ",") != "established,related" {
		t.Fatalf("%+v", r)
	}
	if r := base(`{"match":{"left":{"meta":{"key":"l4proto"}},"op":"==","right":6}},{"match":{"left":{"payload":{"protocol":"tcp","field":"dport"}},"op":"==","right":22}},` + drop); r.Opaque || r.Match.Proto != "tcp" || r.Match.Dport.Lo != 22 {
		t.Fatalf("%+v", r)
	}
	if r := base(`{"match":{"left":{"meta":{"key":"nfproto"}},"op":"==","right":2}},{"match":{"left":{"payload":{"protocol":"ip","field":"saddr"}},"op":"==","right":{"prefix":{"addr":"203.0.113.5","len":32}}}},` + drop); r.Opaque || r.Match.Saddr != "203.0.113.5" {
		t.Fatalf("%+v %s", r, r.Expr)
	}
	if r := base(`{"match":{"left":{"meta":{"key":"nfproto"}},"op":"==","right":"ipv4"}},{"match":{"left":{"meta":{"key":"l4proto"}},"op":"==","right":"tcp"}},` + drop); !r.Opaque {
		t.Fatal("extra nfproto")
	}
	ip4 := `{"nftables":[{"rule":{"family":"ip","table":"filter","chain":"input","handle":1,"expr":[{"match":{"left":{"meta":{"key":"nfproto"}},"op":"==","right":"ipv4"}},{"drop":null}]}}]}`
	rs, err := Project([]byte(ip4))
	if err != nil {
		t.Fatal(err)
	}
	if rs.Tables[0].Chains[0].Rules[0].Opaque || !rs.Tables[0].Chains[0].Rules[0].MatchAll {
		t.Fatal("ip nfproto ipv4")
	}
	ip6bad := `{"nftables":[{"rule":{"family":"ip","table":"filter","chain":"input","handle":1,"expr":[{"match":{"left":{"meta":{"key":"nfproto"}},"op":"==","right":"ipv6"}},{"drop":null}]}}]}`
	rs, err = Project([]byte(ip6bad))
	if err != nil || !rs.Tables[0].Chains[0].Rules[0].Opaque {
		t.Fatal("ip nfproto ipv6")
	}
	ip6ok := `{"nftables":[{"rule":{"family":"ip6","table":"filter","chain":"input","handle":1,"expr":[{"match":{"left":{"meta":{"key":"nfproto"}},"op":"==","right":10}},{"drop":null}]}}]}`
	rs, err = Project([]byte(ip6ok))
	if err != nil || rs.Tables[0].Chains[0].Rules[0].Opaque || !rs.Tables[0].Chains[0].Rules[0].MatchAll {
		t.Fatal("ip6 nfproto ipv6")
	}
	ip6v4 := `{"nftables":[{"rule":{"family":"ip6","table":"filter","chain":"input","handle":1,"expr":[{"match":{"left":{"meta":{"key":"nfproto"}},"op":"==","right":"ipv4"}},{"drop":null}]}}]}`
	rs, err = Project([]byte(ip6v4))
	if err != nil || !rs.Tables[0].Chains[0].Rules[0].Opaque {
		t.Fatal("ip6 nfproto ipv4")
	}
}

func TestProjectFailClosed(t *testing.T) {
	bad := []string{
		`{"nftables":[{"table":{"family":"inet","name":"filter"}},{"table":{"family":"inet","name":"filter"}}]}`,
		`{"nftables":[{"chain":{"family":"inet","table":"filter","name":"input","hook":"input"}},{"chain":{"family":"inet","table":"filter","name":"input","hook":"input"}}]}`,
		`{"nftables":[{"rule":{"family":"inet","table":"filter","chain":"input","expr":[{"drop":null}]}}]}`,
		`{"nftables":[{"a":1,"b":2}]}`,
		``,
	}
	for _, raw := range bad {
		if _, err := Project([]byte(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	raw := `{"nftables":[{"metainfo":{"version":"1"}},{"table":{"family":"inet","name":"filter"}},{"set":{"family":"inet","table":"filter","name":"blocked4"}}]}`
	rs, err := Project([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Tables) != 1 || len(rs.Tables[0].Other) != 1 || rs.Tables[0].Other[0] != "set:blocked4" {
		t.Fatalf("%+v", rs.Tables)
	}
	if rs.Tables[0].Chains == nil || rs.Tables[0].Other == nil {
		t.Fatal("nil slice")
	}
}
