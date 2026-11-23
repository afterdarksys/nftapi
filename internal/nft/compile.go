package nft

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
)

// Packet limits only. Filter base chains only. No named sets in this phase.
// No flush is ever emitted.

type (
	nftDoc struct {
		Nftables []any `json:"nftables"`
	}
	listCmd struct {
		List struct {
			Ruleset *struct{} `json:"ruleset"`
		} `json:"list"`
	}
	addCmd struct {
		Add any `json:"add"`
	}
	deleteCmd struct {
		Delete any `json:"delete"`
	}
	tableObj struct {
		Table struct {
			Family string `json:"family"`
			Name   string `json:"name"`
		} `json:"table"`
	}
	chainAdd struct {
		Chain struct {
			Family string `json:"family"`
			Table  string `json:"table"`
			Name   string `json:"name"`
			Type   string `json:"type"`
			Hook   string `json:"hook"`
			Prio   int32  `json:"prio"`
			Policy string `json:"policy"`
		} `json:"chain"`
	}
	chainDel struct {
		Chain struct {
			Family string `json:"family"`
			Table  string `json:"table"`
			Name   string `json:"name"`
		} `json:"chain"`
	}
	ruleAdd struct {
		Rule struct {
			Family  string `json:"family"`
			Table   string `json:"table"`
			Chain   string `json:"chain"`
			Comment string `json:"comment,omitempty"`
			Expr    []any  `json:"expr"`
		} `json:"rule"`
	}
	ruleDel struct {
		Rule struct {
			Family string `json:"family"`
			Table  string `json:"table"`
			Chain  string `json:"chain"`
			Handle uint64 `json:"handle"`
		} `json:"rule"`
	}
	matchStmt struct {
		Match struct {
			Left  any    `json:"left"`
			Right any    `json:"right"`
			Op    string `json:"op"`
		} `json:"match"`
	}
	metaExpr struct {
		Meta struct {
			Key string `json:"key"`
		} `json:"meta"`
	}
	payloadExpr struct {
		Payload struct {
			Protocol string `json:"protocol"`
			Field    string `json:"field"`
		} `json:"payload"`
	}
	ctExpr struct {
		Ct struct {
			Key string `json:"key"`
		} `json:"ct"`
	}
	prefixExpr struct {
		Prefix struct {
			Addr string `json:"addr"`
			Len  int    `json:"len"`
		} `json:"prefix"`
	}
	rangeExpr struct {
		Range [2]int `json:"range"`
	}
	setExpr struct {
		Set []string `json:"set"`
	}
	limitStmt struct {
		Limit struct {
			Rate     int    `json:"rate"`
			RateUnit string `json:"rate_unit"`
			Per      string `json:"per"`
			Burst    int    `json:"burst,omitempty"`
			Inv      bool   `json:"inv,omitempty"`
		} `json:"limit"`
	}
	acceptStmt struct {
		Accept *struct{} `json:"accept"`
	}
	dropStmt struct {
		Drop *struct{} `json:"drop"`
	}
	rejectStmt struct {
		Reject struct{} `json:"reject"`
	}
)

func eq(left, right any) matchStmt {
	var m matchStmt
	m.Match.Left = left
	m.Match.Right = right
	m.Match.Op = "=="
	return m
}

func meta(key string) metaExpr {
	var m metaExpr
	m.Meta.Key = key
	return m
}

func payload(proto, field string) payloadExpr {
	var p payloadExpr
	p.Payload.Protocol = proto
	p.Payload.Field = field
	return p
}

func ctKey(key string) ctExpr {
	var c ctExpr
	c.Ct.Key = key
	return c
}

// Argv is the fixed nft argument list. The JSON document is written to stdin.
func Argv() []string {
	return []string{"-j", "-f", "-"}
}

func listStdin() []byte {
	return []byte(`{"nftables":[{"list":{"ruleset":null}}]}`)
}

// Compile validates req and returns one nft JSON document.
func Compile(req Request) ([]byte, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	var elem any
	switch req.Op {
	case "ruleset.list":
		var c listCmd
		elem = c
	case "table.add":
		elem = addCmd{Add: tableElem(req.Family, req.Table)}
	case "table.delete":
		elem = deleteCmd{Delete: tableElem(req.Family, req.Table)}
	case "chain.add":
		var c chainAdd
		c.Chain.Family = req.Family
		c.Chain.Table = req.Table
		c.Chain.Name = req.Chain
		c.Chain.Type = "filter"
		c.Chain.Hook = req.Hook
		c.Chain.Prio = *req.Priority
		c.Chain.Policy = req.Policy
		elem = addCmd{Add: c}
	case "chain.delete":
		var c chainDel
		c.Chain.Family = req.Family
		c.Chain.Table = req.Table
		c.Chain.Name = req.Chain
		elem = deleteCmd{Delete: c}
	case "rule.add":
		var r ruleAdd
		r.Rule.Family = req.Family
		r.Rule.Table = req.Table
		r.Rule.Chain = req.Chain
		r.Rule.Comment = req.Comment
		r.Rule.Expr = ruleExpr(req)
		elem = addCmd{Add: r}
	case "rule.delete":
		var r ruleDel
		r.Rule.Family = req.Family
		r.Rule.Table = req.Table
		r.Rule.Chain = req.Chain
		r.Rule.Handle = *req.Handle
		elem = deleteCmd{Delete: r}
	default:
		return nil, invalid("unknown op")
	}
	return marshalDoc(nftDoc{Nftables: []any{elem}})
}

func tableElem(family, name string) tableObj {
	var t tableObj
	t.Table.Family = family
	t.Table.Name = name
	return t
}

func ruleExpr(req Request) []any {
	var expr []any
	m := req.Match
	if m == nil {
		m = &Match{}
	}
	if p, ok := nfproto(req.Family, m); ok {
		expr = append(expr, eq(meta("nfproto"), p))
	}
	if m.Iif != "" {
		expr = append(expr, eq(meta("iifname"), m.Iif))
	}
	if m.Oif != "" {
		expr = append(expr, eq(meta("oifname"), m.Oif))
	}
	if m.Saddr != "" {
		expr = append(expr, eq(payload(l3proto(m.Saddr), "saddr"), addrRight(m.Saddr)))
	}
	if m.Daddr != "" {
		expr = append(expr, eq(payload(l3proto(m.Daddr), "daddr"), addrRight(m.Daddr)))
	}
	if m.Proto != "" {
		expr = append(expr, eq(meta("l4proto"), m.Proto))
	}
	if m.Sport != nil {
		expr = append(expr, eq(payload(m.Proto, "sport"), portRight(m.Sport)))
	}
	if m.Dport != nil {
		expr = append(expr, eq(payload(m.Proto, "dport"), portRight(m.Dport)))
	}
	switch len(m.CtState) {
	case 0:
	case 1:
		expr = append(expr, eq(ctKey("state"), m.CtState[0]))
	default:
		expr = append(expr, eq(ctKey("state"), setExpr{Set: append([]string(nil), m.CtState...)}))
	}
	if req.Limit != nil {
		var lim limitStmt
		lim.Limit.Rate = req.Limit.Rate
		lim.Limit.RateUnit = "packets"
		lim.Limit.Per = req.Limit.Per
		if req.Limit.Burst != nil {
			lim.Limit.Burst = *req.Limit.Burst
		}
		lim.Limit.Inv = req.Limit.Mode == "over"
		expr = append(expr, lim)
	}
	expr = append(expr, verdictStmt(req.Verdict))
	return expr
}

func nfproto(family string, m *Match) (string, bool) {
	if family != "inet" {
		return "", false
	}
	_, v6 := addrVer(m.Saddr)
	_, d6 := addrVer(m.Daddr)
	if v6 || d6 || m.Proto == "icmpv6" {
		if m.Saddr != "" || m.Daddr != "" || m.Proto == "icmpv6" {
			return "ipv6", true
		}
	}
	if m.Saddr != "" || m.Daddr != "" || m.Proto == "icmp" {
		return "ipv4", true
	}
	return "", false
}

func addrVer(s string) (v4, v6 bool) {
	if s == "" {
		return false, false
	}
	if strings.Contains(s, ":") {
		return false, true
	}
	return true, false
}

func l3proto(addr string) string {
	if strings.Contains(addr, ":") {
		return "ip6"
	}
	return "ip"
}

func addrRight(s string) any {
	addr, nlen, ok := strings.Cut(s, "/")
	if !ok {
		return s
	}
	n, err := strconv.Atoi(nlen)
	if err != nil {
		return s
	}
	var p prefixExpr
	p.Prefix.Addr = addr
	p.Prefix.Len = n
	return p
}

func portRight(p *Port) any {
	if p.Range && p.Lo != p.Hi {
		return rangeExpr{Range: [2]int{int(p.Lo), int(p.Hi)}}
	}
	return int(p.Lo)
}

func verdictStmt(v string) any {
	switch v {
	case "accept":
		return acceptStmt{}
	case "reject":
		return rejectStmt{}
	default:
		return dropStmt{}
	}
}

func marshalDoc(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, nftFailed("could not encode nft json")
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
