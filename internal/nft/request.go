package nft

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
)

// Port is a single port or an inclusive range. A range of one value is stored
// as a single port.
type Port struct {
	Lo, Hi uint16
	Range  bool
	bad    string
}

func (p Port) MarshalJSON() ([]byte, error) {
	if !p.Range || p.Lo == p.Hi {
		return json.Marshal(p.Lo)
	}
	return json.Marshal([]uint16{p.Lo, p.Hi})
}

func (p *Port) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return invalid("port must be an integer from 1 to 65535")
	}
	if b[0] == '[' {
		var raw []json.RawMessage
		if err := json.Unmarshal(b, &raw); err != nil || len(raw) != 2 {
			return invalid("port range needs two integers")
		}
		lo, err := portNum(raw[0])
		if err != nil {
			return err
		}
		hi, err := portNum(raw[1])
		if err != nil {
			return err
		}
		if lo > hi {
			p.bad = "port range is reversed"
			return nil
		}
		p.Lo, p.Hi = lo, hi
		p.Range = lo != hi
		return nil
	}
	n, err := portNum(b)
	if err != nil {
		return err
	}
	p.Lo, p.Hi = n, n
	return nil
}

func portNum(b []byte) (uint16, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var num json.Number
	if err := dec.Decode(&num); err != nil {
		return 0, invalid("port must be an integer from 1 to 65535")
	}
	if dec.More() {
		return 0, invalid("port must be an integer from 1 to 65535")
	}
	s := num.String()
	if strings.ContainsAny(s, ".eE") {
		return 0, invalid("port must be an integer from 1 to 65535")
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, invalid("port must be an integer from 1 to 65535")
	}
	return uint16(n), nil
}

// Match is the closed set of selectors on a rule.
type Match struct {
	Saddr   string   `json:"saddr,omitempty"`
	Daddr   string   `json:"daddr,omitempty"`
	Proto   string   `json:"proto,omitempty"`
	Sport   *Port    `json:"sport,omitempty"`
	Dport   *Port    `json:"dport,omitempty"`
	Iif     string   `json:"iif,omitempty"`
	Oif     string   `json:"oif,omitempty"`
	CtState []string `json:"ct_state,omitempty"`
}

func (m *Match) empty() bool {
	if m == nil {
		return true
	}
	return m.Saddr == "" && m.Daddr == "" && m.Proto == "" && m.Sport == nil &&
		m.Dport == nil && m.Iif == "" && m.Oif == "" && len(m.CtState) == 0
}

// Limit is a packet rate. Burst nil means the field was omitted.
type Limit struct {
	Rate  int    `json:"rate"`
	Per   string `json:"per"`
	Burst *int   `json:"burst,omitempty"`
	Mode  string `json:"mode"`
}

// Request is one POST /v1 body.
type Request struct {
	Op       string  `json:"op"`
	Family   string  `json:"family,omitempty"`
	Table    string  `json:"table,omitempty"`
	Chain    string  `json:"chain,omitempty"`
	Type     string  `json:"type,omitempty"`
	Hook     string  `json:"hook,omitempty"`
	Priority *int32  `json:"priority,omitempty"`
	Policy   string  `json:"policy,omitempty"`
	Handle   *uint64 `json:"handle,omitempty"`
	Match    *Match  `json:"match,omitempty"`
	Limit    *Limit  `json:"limit,omitempty"`
	MatchAll bool    `json:"match_all,omitempty"`
	Verdict  string  `json:"verdict,omitempty"`
	Comment  string  `json:"comment,omitempty"`
}

// Spec is the identity of a rule: match, limit, verdict, and comment.
type Spec struct {
	Match    *Match
	Limit    *Limit
	MatchAll bool
	Verdict  string
	Comment  string
}

func (s Spec) Equal(o Spec) bool {
	if s.Verdict != o.Verdict || s.Comment != o.Comment || s.MatchAll != o.MatchAll {
		return false
	}
	if !matchEqual(s.Match, o.Match) || !limitEqual(s.Limit, o.Limit) {
		return false
	}
	return true
}

func matchEqual(a, b *Match) bool {
	ae, be := a.empty(), b.empty()
	if ae || be {
		return ae && be
	}
	if a.Saddr != b.Saddr || a.Daddr != b.Daddr || a.Proto != b.Proto ||
		a.Iif != b.Iif || a.Oif != b.Oif {
		return false
	}
	if !portEqual(a.Sport, b.Sport) || !portEqual(a.Dport, b.Dport) {
		return false
	}
	if len(a.CtState) != len(b.CtState) {
		return false
	}
	for i := range a.CtState {
		if a.CtState[i] != b.CtState[i] {
			return false
		}
	}
	return true
}

func portEqual(a, b *Port) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	ar, br := a.Range && a.Lo != a.Hi, b.Range && b.Lo != b.Hi
	if ar != br {
		return false
	}
	return a.Lo == b.Lo && a.Hi == b.Hi
}

func limitEqual(a, b *Limit) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if a.Rate != b.Rate || a.Per != b.Per || a.Mode != b.Mode {
		return false
	}
	if a.Burst == nil || b.Burst == nil {
		return a.Burst == nil && b.Burst == nil
	}
	return *a.Burst == *b.Burst
}

// Ruleset is the projected live ruleset.
type Ruleset struct {
	Tables []Table `json:"tables"`
}

// Table is one nft table. Other lists objects this phase does not manage.
type Table struct {
	Family string   `json:"family"`
	Name   string   `json:"name"`
	Chains []Chain  `json:"chains"`
	Other  []string `json:"other"`
}

// Chain is one chain. Priority is nft's prio.
type Chain struct {
	Name     string `json:"name"`
	Base     bool   `json:"base"`
	Type     string `json:"type,omitempty"`
	Hook     string `json:"hook,omitempty"`
	Priority *int32 `json:"priority,omitempty"`
	Policy   string `json:"policy,omitempty"`
	Rules    []Rule `json:"rules"`
}

// Rule is one rule. Opaque rules keep the raw expr so they can be deleted
// by handle.
type Rule struct {
	Handle   uint64          `json:"handle"`
	Opaque   bool            `json:"opaque,omitempty"`
	Comment  string          `json:"comment,omitempty"`
	Match    *Match          `json:"match,omitempty"`
	Limit    *Limit          `json:"limit,omitempty"`
	MatchAll bool            `json:"match_all,omitempty"`
	Verdict  string          `json:"verdict,omitempty"`
	Expr     json.RawMessage `json:"expr,omitempty"`
}

func (r Rule) spec() Spec {
	return Spec{
		Match:    r.Match,
		Limit:    r.Limit,
		MatchAll: r.MatchAll,
		Verdict:  r.Verdict,
		Comment:  r.Comment,
	}
}

// Result is the success payload of one op, before the HTTP envelope.
type Result struct {
	Ruleset *Ruleset
	Created *bool
	Deleted *bool
	Handle  *uint64
}
