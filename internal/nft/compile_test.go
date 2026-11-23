package nft

import (
	"strings"
	"testing"
)

func TestArgvAndList(t *testing.T) {
	got := Argv()
	if len(got) != 3 || got[0] != "-j" || got[1] != "-f" || got[2] != "-" {
		t.Fatalf("%q", got)
	}
	if string(listStdin()) != `{"nftables":[{"list":{"ruleset":null}}]}` {
		t.Fatalf("%s", listStdin())
	}
	doc, err := Compile(Request{Op: "ruleset.list"})
	if err != nil {
		t.Fatal(err)
	}
	if string(doc) != string(listStdin()) {
		t.Fatalf("compile list %s", doc)
	}
}

func TestGoldenSSHRule(t *testing.T) {
	burst := 10
	req := Request{
		Op: "rule.add", Family: "inet", Table: "filter", Chain: "input", Verdict: "drop",
		Match: &Match{Proto: "tcp", Dport: &Port{Lo: 22, Hi: 22}, CtState: []string{"new"}},
		Limit: &Limit{Rate: 5, Per: "minute", Burst: &burst, Mode: "over"},
	}
	doc, err := Compile(req)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"nftables":[{"add":{"rule":{"family":"inet","table":"filter","chain":"input","expr":[{"match":{"left":{"meta":{"key":"l4proto"}},"right":"tcp","op":"=="}},{"match":{"left":{"payload":{"protocol":"tcp","field":"dport"}},"right":22,"op":"=="}},{"match":{"left":{"ct":{"key":"state"}},"right":"new","op":"=="}},{"limit":{"rate":5,"rate_unit":"packets","per":"minute","burst":10,"inv":true}},{"drop":null}]}}}]}`
	if string(doc) != want {
		t.Fatalf("got %s", doc)
	}
	if strings.Contains(string(doc), "flush") || strings.Contains(string(doc), "nfproto") || strings.Contains(string(doc), `"in"`) {
		t.Fatalf("%s", doc)
	}
}

func TestCompileShapes(t *testing.T) {
	prio := int32(0)
	h := uint64(5)
	cases := []struct {
		name string
		req  Request
		want string
	}{
		{"table", Request{Op: "table.add", Family: "inet", Table: "filter"}, `{"nftables":[{"add":{"table":{"family":"inet","name":"filter"}}}]}`},
		{"chain", Request{Op: "chain.add", Family: "inet", Table: "filter", Chain: "input", Type: "filter", Hook: "input", Priority: &prio, Policy: "drop"}, `{"nftables":[{"add":{"chain":{"family":"inet","table":"filter","name":"input","type":"filter","hook":"input","prio":0,"policy":"drop"}}}]}`},
		{"delete", Request{Op: "rule.delete", Family: "inet", Table: "filter", Chain: "input", Handle: &h}, `{"nftables":[{"delete":{"rule":{"family":"inet","table":"filter","chain":"input","handle":5}}}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := Compile(tc.req)
			if err != nil {
				t.Fatal(err)
			}
			if string(doc) != tc.want {
				t.Fatalf("got %s", doc)
			}
			if strings.Contains(string(doc), "flush") {
				t.Fatal(doc)
			}
			if tc.name == "chain" && strings.Contains(string(doc), `"priority"`) {
				t.Fatal(doc)
			}
		})
	}
	req := Request{Op: "rule.add", Family: "inet", Table: "filter", Chain: "input", Verdict: "drop", Comment: "a&b", Match: &Match{CtState: []string{"related", "established"}}}
	doc, err := Compile(req)
	if err != nil {
		t.Fatal(err)
	}
	s := string(doc)
	if strings.Contains(s, `\u0026`) || !strings.Contains(s, `"comment":"a&b"`) {
		t.Fatal(s)
	}
	if !strings.Contains(s, `"set":["established","related"]`) || strings.Contains(s, `"op":"in"`) {
		t.Fatal(s)
	}
	if !strings.Contains(s, `{"drop":null}`) {
		t.Fatal(s)
	}
	rej := Request{Op: "rule.add", Family: "inet", Table: "filter", Chain: "input", Verdict: "reject", MatchAll: true}
	doc, err = Compile(rej)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(doc), `{"reject":{}}`) {
		t.Fatal(string(doc))
	}
}
