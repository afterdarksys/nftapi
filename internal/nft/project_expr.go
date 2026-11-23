package nft

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
)

// projectExpr reports ok when every statement is in the closed language.
// Anonymous counters are ignored. Anything else makes the rule opaque.
func projectExpr(family string, expr []json.RawMessage) (Spec, bool) {
	var (
		m        Match
		lim      *Limit
		verdict  string
		verdicts int
		nf       string
		sawNF    bool
	)
	for _, st := range expr {
		kind, raw, ok := oneField(st)
		if !ok {
			return Spec{}, false
		}
		switch kind {
		case "counter":
			if !anonCounter(raw) {
				return Spec{}, false
			}
		case "accept", "drop":
			if !jsonNull(raw) {
				return Spec{}, false
			}
			verdict = kind
			verdicts++
		case "reject":
			if !plainReject(raw) {
				return Spec{}, false
			}
			verdict = "reject"
			verdicts++
		case "limit":
			if lim != nil {
				return Spec{}, false
			}
			got, ok := projectLimit(raw)
			if !ok {
				return Spec{}, false
			}
			lim = got
		case "match":
			if !projectMatch(raw, &m, &nf, &sawNF) {
				return Spec{}, false
			}
		default:
			return Spec{}, false
		}
	}
	if verdicts != 1 {
		return Spec{}, false
	}
	if !nfOK(family, &m, nf, sawNF) {
		return Spec{}, false
	}
	spec := Spec{Verdict: verdict, Limit: lim}
	if m.empty() && lim == nil {
		spec.MatchAll = true
		return spec, true
	}
	if !m.empty() {
		cp := m
		spec.Match = &cp
	}
	return spec, true
}

func nfOK(family string, m *Match, nf string, saw bool) bool {
	v4, v6 := false, false
	if strings.Contains(m.Saddr, ":") || strings.Contains(m.Daddr, ":") {
		v6 = true
	}
	if (m.Saddr != "" && !strings.Contains(m.Saddr, ":")) || (m.Daddr != "" && !strings.Contains(m.Daddr, ":")) {
		v4 = true
	}
	if v4 && v6 {
		return false
	}
	want := ""
	switch {
	case v6 || m.Proto == "icmpv6":
		want = "ipv6"
	case v4 || m.Proto == "icmp":
		want = "ipv4"
	}
	if saw {
		if want != "" && nf != want {
			return false
		}
		if want == "" {
			// nfproto is an extra selector this API does not store.
			if family == "inet" {
				return false
			}
			if family == "ip" && nf != "ipv4" || family == "ip6" && nf != "ipv6" {
				return false
			}
		}
	}
	return true
}

func projectMatch(raw json.RawMessage, m *Match, nf *string, sawNF *bool) bool {
	var body struct {
		Left  json.RawMessage `json:"left"`
		Right json.RawMessage `json:"right"`
		Op    string          `json:"op"`
	}
	if json.Unmarshal(raw, &body) != nil || len(body.Left) == 0 || len(body.Right) == 0 {
		return false
	}
	lk, lv, ok := oneField(body.Left)
	if !ok {
		return false
	}
	switch lk {
	case "meta":
		var key struct {
			Key string `json:"key"`
		}
		if json.Unmarshal(lv, &key) != nil {
			return false
		}
		return projectMeta(key.Key, body.Op, body.Right, m, nf, sawNF)
	case "payload":
		var p struct {
			Protocol string `json:"protocol"`
			Field    string `json:"field"`
		}
		if json.Unmarshal(lv, &p) != nil {
			return false
		}
		return projectPayload(p.Protocol, p.Field, body.Op, body.Right, m)
	case "ct":
		var c struct {
			Key    string `json:"key"`
			Family string `json:"family"`
			Dir    string `json:"dir"`
		}
		if json.Unmarshal(lv, &c) != nil || c.Key != "state" || c.Family != "" || c.Dir != "" {
			return false
		}
		return projectStates(body.Op, body.Right, m)
	default:
		return false
	}
}

func projectMeta(key, op string, right json.RawMessage, m *Match, nf *string, sawNF *bool) bool {
	if op != "==" {
		return false
	}
	switch key {
	case "nfproto":
		s, ok := nfValue(right)
		if !ok || *sawNF {
			return false
		}
		*nf = s
		*sawNF = true
		return true
	case "iifname":
		s, ok := jsonString(right)
		if !ok || m.Iif != "" || checkIface(s) != nil {
			return false
		}
		m.Iif = s
		return true
	case "oifname":
		s, ok := jsonString(right)
		if !ok || m.Oif != "" || checkIface(s) != nil {
			return false
		}
		m.Oif = s
		return true
	case "l4proto":
		s, ok := protoValue(right)
		if !ok || (m.Proto != "" && m.Proto != s) {
			return false
		}
		m.Proto = s
		return true
	default:
		return false
	}
}

func projectPayload(proto, field, op string, right json.RawMessage, m *Match) bool {
	if op != "==" {
		return false
	}
	switch {
	case (proto == "ip" || proto == "ip6") && (field == "saddr" || field == "daddr"):
		addr, ok := projectAddr(right, proto == "ip6")
		if !ok {
			return false
		}
		if field == "saddr" {
			if m.Saddr != "" {
				return false
			}
			m.Saddr = addr
		} else {
			if m.Daddr != "" {
				return false
			}
			m.Daddr = addr
		}
		return true
	case (proto == "tcp" || proto == "udp") && (field == "sport" || field == "dport"):
		p, ok := projectPort(right)
		if !ok {
			return false
		}
		if m.Proto != "" && m.Proto != proto {
			return false
		}
		m.Proto = proto
		if field == "sport" {
			if m.Sport != nil {
				return false
			}
			m.Sport = p
		} else {
			if m.Dport != nil {
				return false
			}
			m.Dport = p
		}
		return true
	default:
		return false
	}
}

func projectStates(op string, right json.RawMessage, m *Match) bool {
	if len(m.CtState) != 0 {
		return false
	}
	var states []string
	switch op {
	case "==":
		if s, ok := jsonString(right); ok {
			states = []string{s}
			break
		}
		var ok bool
		states, ok = stateList(right)
		if !ok {
			return false
		}
	case "in":
		var ok bool
		states, ok = stateList(right)
		if !ok {
			return false
		}
	default:
		return false
	}
	sorted, err := canonStates(states)
	if err != nil {
		return false
	}
	m.CtState = sorted
	return true
}

func stateList(raw json.RawMessage) ([]string, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, false
	}
	if raw[0] == '{' {
		var wrap struct {
			Set []string `json:"set"`
		}
		if json.Unmarshal(raw, &wrap) != nil || len(wrap.Set) == 0 {
			return nil, false
		}
		return wrap.Set, true
	}
	var list []string
	if json.Unmarshal(raw, &list) != nil || len(list) == 0 {
		return nil, false
	}
	return list, true
}

func projectAddr(raw json.RawMessage, want6 bool) (string, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return "", false
	}
	if raw[0] == '"' {
		s, ok := jsonString(raw)
		if !ok {
			return "", false
		}
		c, is6, err := canonAddr(s)
		if err != nil || is6 != want6 || strings.Contains(c, "/") {
			return "", false
		}
		return c, true
	}
	var p struct {
		Prefix struct {
			Addr string `json:"addr"`
			Len  int    `json:"len"`
		} `json:"prefix"`
	}
	if json.Unmarshal(raw, &p) != nil || p.Prefix.Addr == "" {
		return "", false
	}
	s := p.Prefix.Addr + "/" + strconv.Itoa(p.Prefix.Len)
	c, is6, err := canonAddr(s)
	if err != nil || is6 != want6 {
		return "", false
	}
	return c, true
}

func projectPort(raw json.RawMessage) (*Port, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, false
	}
	if raw[0] == '{' {
		var r struct {
			Range []json.RawMessage `json:"range"`
		}
		if json.Unmarshal(raw, &r) != nil || len(r.Range) != 2 {
			return nil, false
		}
		lo, ok1 := jsonUint(r.Range[0])
		hi, ok2 := jsonUint(r.Range[1])
		if !ok1 || !ok2 || lo < 1 || hi > 65535 || lo > hi {
			return nil, false
		}
		return &Port{Lo: uint16(lo), Hi: uint16(hi), Range: lo != hi}, true
	}
	n, ok := jsonUint(raw)
	if !ok || n < 1 || n > 65535 {
		return nil, false
	}
	return &Port{Lo: uint16(n), Hi: uint16(n)}, true
}

func projectLimit(raw json.RawMessage) (*Limit, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] == '"' {
		return nil, false
	}
	var body struct {
		Rate     *int   `json:"rate"`
		RateUnit string `json:"rate_unit"`
		Per      string `json:"per"`
		Burst    *int   `json:"burst"`
		Inv      bool   `json:"inv"`
	}
	if json.Unmarshal(raw, &body) != nil || body.Rate == nil || *body.Rate < 1 {
		return nil, false
	}
	if body.RateUnit != "" && body.RateUnit != "packets" {
		return nil, false
	}
	if !pers[body.Per] {
		return nil, false
	}
	mode := "under"
	if body.Inv {
		mode = "over"
	}
	lim := &Limit{Rate: *body.Rate, Per: body.Per, Mode: mode}
	if body.Burst != nil && *body.Burst != 0 {
		if *body.Burst < 1 {
			return nil, false
		}
		b := *body.Burst
		lim.Burst = &b
	}
	return lim, true
}

func anonCounter(raw json.RawMessage) bool {
	raw = bytes.TrimSpace(raw)
	if bytes.Equal(raw, []byte("null")) {
		return true
	}
	return len(raw) > 0 && raw[0] == '{'
}

// plainReject accepts the forms this API emits and the default nftables
// 1.1.3 listing of those forms. nft rewrites both {"reject":{}} and
// {"reject":null} to type icmpx and expr port-unreachable. Any other type
// or expr stays outside the closed language.
func plainReject(raw json.RawMessage) bool {
	raw = bytes.TrimSpace(raw)
	if bytes.Equal(raw, []byte("null")) {
		return true
	}
	if len(raw) == 0 || raw[0] != '{' {
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var body struct {
		Type string `json:"type"`
		Expr string `json:"expr"`
	}
	if dec.Decode(&body) != nil || dec.More() {
		return false
	}
	if body.Type == "" && body.Expr == "" {
		return true
	}
	return body.Type == "icmpx" && body.Expr == "port-unreachable"
}

func jsonNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func oneField(raw json.RawMessage) (string, json.RawMessage, bool) {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || len(m) != 1 {
		return "", nil, false
	}
	for k, v := range m {
		return k, v, true
	}
	return "", nil, false
}

func jsonString(raw json.RawMessage) (string, bool) {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

func jsonUint(raw json.RawMessage) (int, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var n json.Number
	if dec.Decode(&n) != nil || dec.More() {
		return 0, false
	}
	if strings.ContainsAny(n.String(), ".eE") {
		return 0, false
	}
	v, err := strconv.Atoi(n.String())
	if err != nil {
		return 0, false
	}
	return v, true
}

func nfValue(raw json.RawMessage) (string, bool) {
	if s, ok := jsonString(raw); ok {
		switch s {
		case "ipv4", "ipv6":
			return s, true
		default:
			return "", false
		}
	}
	n, ok := jsonUint(raw)
	if !ok {
		return "", false
	}
	switch n {
	case 2:
		return "ipv4", true
	case 10:
		return "ipv6", true
	default:
		return "", false
	}
}

func protoValue(raw json.RawMessage) (string, bool) {
	if s, ok := jsonString(raw); ok {
		if protos[s] {
			return s, true
		}
		return "", false
	}
	n, ok := jsonUint(raw)
	if !ok {
		return "", false
	}
	switch n {
	case 6:
		return "tcp", true
	case 17:
		return "udp", true
	case 1:
		return "icmp", true
	case 58:
		return "icmpv6", true
	default:
		return "", false
	}
}
