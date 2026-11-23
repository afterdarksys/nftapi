package nft

import (
	"strings"
	"testing"
)

func TestValidateClosed(t *testing.T) {
	prio := int32(0)
	h := uint64(0)
	cases := []struct {
		name string
		req  Request
		want string
	}{
		{"hyphen", Request{Op: "table.add", Family: "inet", Table: "my-table"}, "name"},
		{"inject semi", Request{Op: "table.add", Family: "inet", Table: "filter;rm"}, "name"},
		{"inject subst", Request{Op: "table.add", Family: "inet", Table: "$(id)"}, "name"},
		{"digit", Request{Op: "table.add", Family: "inet", Table: "1abc"}, "name"},
		{"family", Request{Op: "table.add", Family: "bridge", Table: "filter"}, "family"},
		{"type", Request{Op: "chain.add", Family: "inet", Table: "filter", Chain: "input", Type: "nat", Hook: "input", Priority: &prio, Policy: "accept"}, "filter"},
		{"hook", Request{Op: "chain.add", Family: "inet", Table: "filter", Chain: "input", Type: "filter", Hook: "ingress", Priority: &prio, Policy: "accept"}, "hook"},
		{"policy", Request{Op: "chain.add", Family: "inet", Table: "filter", Chain: "input", Type: "filter", Hook: "input", Priority: &prio, Policy: "reject"}, "policy"},
		{"handle zero", Request{Op: "rule.delete", Family: "inet", Table: "filter", Chain: "input", Handle: &h}, "handle"},
		{"mixed", Request{Op: "rule.add", Family: "inet", Table: "filter", Chain: "input", Verdict: "drop", Match: &Match{Saddr: "203.0.113.5", Daddr: "2001:db8::1"}}, "mixed"},
		{"icmp port", Request{Op: "rule.add", Family: "inet", Table: "filter", Chain: "input", Verdict: "drop", Match: &Match{Proto: "icmp", Dport: &Port{Lo: 22, Hi: 22}}}, "ports"},
		{"proto", Request{Op: "rule.add", Family: "inet", Table: "filter", Chain: "input", Verdict: "drop", Match: &Match{Proto: "sctp"}}, "proto"},
		{"ip6 icmp", Request{Op: "rule.add", Family: "ip6", Table: "filter", Chain: "input", Verdict: "drop", Match: &Match{Proto: "icmp"}}, "proto"},
		{"ip icmpv6", Request{Op: "rule.add", Family: "ip", Table: "filter", Chain: "input", Verdict: "drop", Match: &Match{Proto: "icmpv6"}}, "proto"},
		{"icmp v6 addr", Request{Op: "rule.add", Family: "inet", Table: "filter", Chain: "input", Verdict: "drop", Match: &Match{Proto: "icmp", Saddr: "2001:db8::1"}}, "proto"},
		{"mode", Request{Op: "rule.add", Family: "inet", Table: "filter", Chain: "input", Verdict: "drop", Limit: &Limit{Rate: 5, Per: "minute"}}, "mode"},
		{"burst", Request{Op: "rule.add", Family: "inet", Table: "filter", Chain: "input", Verdict: "drop", Limit: &Limit{Rate: 5, Per: "minute", Burst: intPtr(0), Mode: "over"}}, "burst"},
		{"verdict only", Request{Op: "rule.add", Family: "inet", Table: "filter", Chain: "input", Verdict: "drop"}, "match_all"},
		{"match all plus", Request{Op: "rule.add", Family: "inet", Table: "filter", Chain: "input", Verdict: "drop", MatchAll: true, Match: &Match{Proto: "tcp"}}, "match_all"},
		{"iface dot", Request{Op: "rule.add", Family: "inet", Table: "filter", Chain: "input", Verdict: "drop", Match: &Match{Iif: "."}}, "interface"},
		{"iface dots", Request{Op: "rule.add", Family: "inet", Table: "filter", Chain: "input", Verdict: "drop", Match: &Match{Oif: ".."}}, "interface"},
		{"host bits", Request{Op: "rule.add", Family: "inet", Table: "filter", Chain: "input", Verdict: "drop", Match: &Match{Saddr: "203.0.113.5/24"}}, "host bits"},
		{"mapped cidr", Request{Op: "rule.add", Family: "inet", Table: "filter", Chain: "input", Verdict: "drop", Match: &Match{Saddr: "::ffff:203.0.113.5/128"}}, "address"},
		{"comment ctl", Request{Op: "rule.add", Family: "inet", Table: "filter", Chain: "input", Verdict: "drop", MatchAll: true, Comment: "bad\n"}, "comment"},
		{"extra field", Request{Op: "ruleset.list", Family: "inet"}, "unexpected"},
		{"handle on add", Request{Op: "rule.add", Family: "inet", Table: "filter", Chain: "input", Verdict: "drop", MatchAll: true, Handle: uintPtr(1)}, "unexpected"},
		{"unknown op", Request{Op: "flush"}, "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.req.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestValidateCanonical(t *testing.T) {
	req := Request{Op: "rule.add", Family: "inet", Table: "filter", Chain: "input", Verdict: "drop", Match: &Match{
		Saddr:   "203.0.113.5/32",
		Daddr:   "::ffff:203.0.113.9",
		CtState: []string{"related", "established", "new"},
	}}
	if err := req.Validate(); err != nil {
		t.Fatal(err)
	}
	if req.Match.Saddr != "203.0.113.5" {
		t.Fatalf("saddr %s", req.Match.Saddr)
	}
	if req.Match.Daddr != "203.0.113.9" {
		t.Fatalf("daddr %s", req.Match.Daddr)
	}
	if strings.Join(req.Match.CtState, ",") != "new,established,related" {
		t.Fatalf("states %v", req.Match.CtState)
	}
	v6 := Request{Op: "rule.add", Family: "inet", Table: "filter", Chain: "input", Verdict: "accept", Match: &Match{Saddr: "2001:db8::1/128"}}
	if err := v6.Validate(); err != nil {
		t.Fatal(err)
	}
	if v6.Match.Saddr != "2001:db8::1" {
		t.Fatalf("collapsed %s", v6.Match.Saddr)
	}
}

func intPtr(n int) *int { return &n }

func uintPtr(n uint64) *uint64 { return &n }
