package nft

import (
	"net"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

var (
	nameRe  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,31}$`)
	ifaceRe = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)
)

var (
	families = map[string]bool{"inet": true, "ip": true, "ip6": true}
	hooks    = map[string]bool{"prerouting": true, "input": true, "forward": true, "output": true, "postrouting": true}
	protos   = map[string]bool{"tcp": true, "udp": true, "icmp": true, "icmpv6": true}
	pers     = map[string]bool{"second": true, "minute": true, "hour": true, "day": true}
	ctOrder  = []string{"new", "established", "related", "invalid", "untracked"}
)

// Validate checks req and canonicalizes addresses, ports, and ct_state.
func (req *Request) Validate() error {
	switch req.Op {
	case "ruleset.list":
		return req.only()
	case "table.add", "table.delete":
		if err := req.only("family", "table"); err != nil {
			return err
		}
		return req.needFamilyTable()
	case "chain.add":
		if err := req.only("family", "table", "chain", "type", "hook", "priority", "policy"); err != nil {
			return err
		}
		if err := req.needFamilyTable(); err != nil {
			return err
		}
		if err := needName("chain", req.Chain); err != nil {
			return err
		}
		if req.Type != "filter" {
			return invalid("type must be filter")
		}
		if !hooks[req.Hook] {
			return invalid("invalid hook")
		}
		if req.Priority == nil {
			return invalid("priority is required")
		}
		if req.Policy != "accept" && req.Policy != "drop" {
			return invalid("policy must be accept or drop")
		}
		return nil
	case "chain.delete":
		if err := req.only("family", "table", "chain"); err != nil {
			return err
		}
		if err := req.needFamilyTable(); err != nil {
			return err
		}
		return needName("chain", req.Chain)
	case "rule.add":
		if err := req.only("family", "table", "chain", "match", "limit", "match_all", "verdict", "comment"); err != nil {
			return err
		}
		if err := req.needFamilyTable(); err != nil {
			return err
		}
		if err := needName("chain", req.Chain); err != nil {
			return err
		}
		if err := checkComment(req.Comment); err != nil {
			return err
		}
		if req.Verdict != "accept" && req.Verdict != "drop" && req.Verdict != "reject" {
			return invalid("verdict must be accept, drop, or reject")
		}
		if err := req.validateMatchLimit(); err != nil {
			return err
		}
		selectors := (req.Match != nil && !req.Match.empty()) || req.Limit != nil
		if req.MatchAll {
			if selectors {
				return invalid("match_all cannot be combined with a match or a limit")
			}
			return nil
		}
		if !selectors {
			return invalid("a rule needs a match, a limit, or match_all")
		}
		return nil
	case "rule.delete":
		if err := req.only("family", "table", "chain", "handle"); err != nil {
			return err
		}
		if err := req.needFamilyTable(); err != nil {
			return err
		}
		if err := needName("chain", req.Chain); err != nil {
			return err
		}
		if req.Handle == nil || *req.Handle == 0 {
			return invalid("handle is required")
		}
		return nil
	default:
		return invalid("unknown op")
	}
}

func (req *Request) only(allow ...string) error {
	ok := map[string]bool{}
	for _, f := range allow {
		ok[f] = true
	}
	if req.Family != "" && !ok["family"] ||
		req.Table != "" && !ok["table"] ||
		req.Chain != "" && !ok["chain"] ||
		req.Type != "" && !ok["type"] ||
		req.Hook != "" && !ok["hook"] ||
		req.Priority != nil && !ok["priority"] ||
		req.Policy != "" && !ok["policy"] ||
		req.Handle != nil && !ok["handle"] ||
		req.Match != nil && !ok["match"] ||
		req.Limit != nil && !ok["limit"] ||
		req.MatchAll && !ok["match_all"] ||
		req.Verdict != "" && !ok["verdict"] ||
		req.Comment != "" && !ok["comment"] {
		return invalid("unexpected field")
	}
	return nil
}

func (req *Request) needFamilyTable() error {
	if !families[req.Family] {
		return invalid("invalid family")
	}
	return needName("table", req.Table)
}

func needName(what, name string) error {
	if !nameRe.MatchString(name) {
		return invalid("invalid " + what + " name")
	}
	return nil
}

func checkComment(s string) error {
	if len(s) > 128 || !utf8.ValidString(s) {
		return invalid("invalid comment")
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return invalid("invalid comment")
		}
	}
	return nil
}

func (req *Request) validateMatchLimit() error {
	if req.Match != nil {
		if err := req.Match.validate(req.Family); err != nil {
			return err
		}
	}
	if req.Limit != nil {
		if err := req.Limit.validate(); err != nil {
			return err
		}
	}
	return nil
}

func (m *Match) validate(family string) error {
	if m.Sport != nil && m.Sport.bad != "" {
		return invalid(m.Sport.bad)
	}
	if m.Dport != nil && m.Dport.bad != "" {
		return invalid(m.Dport.bad)
	}
	var v4, v6 bool
	var err error
	if m.Saddr, v4, v6, err = canonAddrField(m.Saddr, v4, v6); err != nil {
		return err
	}
	if m.Daddr, v4, v6, err = canonAddrField(m.Daddr, v4, v6); err != nil {
		return err
	}
	if v4 && v6 {
		return invalid("mixed address family")
	}
	if family == "ip" && v6 || family == "ip6" && v4 {
		return invalid("address family does not match the table")
	}
	if m.Proto != "" && !protos[m.Proto] {
		return invalid("invalid proto")
	}
	if (m.Sport != nil || m.Dport != nil) && m.Proto != "tcp" && m.Proto != "udp" {
		return invalid("ports require tcp or udp")
	}
	if m.Proto == "icmp" && v6 || m.Proto == "icmpv6" && v4 {
		return invalid("proto does not match the address")
	}
	if family == "ip" && m.Proto == "icmpv6" || family == "ip6" && m.Proto == "icmp" {
		return invalid("proto does not match the table")
	}
	if err := checkIface(m.Iif); err != nil {
		return err
	}
	if err := checkIface(m.Oif); err != nil {
		return err
	}
	if m.CtState != nil {
		sorted, err := canonStates(m.CtState)
		if err != nil {
			return err
		}
		m.CtState = sorted
	}
	if m.empty() {
		return invalid("match is empty")
	}
	return nil
}

func canonAddrField(s string, v4, v6 bool) (string, bool, bool, error) {
	if s == "" {
		return "", v4, v6, nil
	}
	c, is6, err := canonAddr(s)
	if err != nil {
		return "", false, false, err
	}
	if is6 {
		v6 = true
	} else {
		v4 = true
	}
	return c, v4, v6, nil
}

func canonAddr(s string) (string, bool, error) {
	if strings.IndexByte(s, '%') >= 0 {
		return "", false, invalid("invalid address")
	}
	if strings.IndexByte(s, '/') >= 0 {
		ip, network, err := net.ParseCIDR(s)
		if err != nil {
			return "", false, invalid("invalid address")
		}
		ones, bits := network.Mask.Size()
		if bits == 128 && ip.To4() != nil {
			return "", false, invalid("invalid address")
		}
		is6 := bits == 128
		if bits != 32 && bits != 128 {
			return "", false, invalid("invalid address")
		}
		if !ip.Equal(network.IP) {
			if !((bits == 32 && ones == 32) || (bits == 128 && ones == 128)) {
				return "", false, invalid("address has host bits set")
			}
		}
		if (bits == 32 && ones == 32) || (bits == 128 && ones == 128) {
			return ipString(ip), is6, nil
		}
		base := network.IP
		if bits == 32 {
			if v4 := base.To4(); v4 != nil {
				base = v4
			}
		}
		return base.String() + "/" + strconv.Itoa(ones), is6, nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return "", false, invalid("invalid address")
	}
	if ip.To4() != nil {
		return ip.To4().String(), false, nil
	}
	return ip.String(), true, nil
}

func ipString(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

func checkIface(s string) error {
	if s == "" {
		return nil
	}
	if s == "." || s == ".." || !ifaceRe.MatchString(s) {
		return invalid("invalid interface")
	}
	return nil
}

func canonStates(in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, invalid("ct_state is empty")
	}
	seen := map[string]bool{}
	for _, s := range in {
		ok := false
		for _, want := range ctOrder {
			if s == want {
				ok = true
				break
			}
		}
		if !ok || seen[s] {
			return nil, invalid("invalid ct_state")
		}
		seen[s] = true
	}
	var out []string
	for _, s := range ctOrder {
		if seen[s] {
			out = append(out, s)
		}
	}
	return out, nil
}

func (l *Limit) validate() error {
	if l.Rate < 1 {
		return invalid("limit rate must be at least 1")
	}
	if !pers[l.Per] {
		return invalid("invalid limit per")
	}
	if l.Burst != nil && *l.Burst < 1 {
		return invalid("limit burst must be at least 1")
	}
	if l.Mode != "over" && l.Mode != "under" {
		return invalid("limit mode must be over or under")
	}
	return nil
}
