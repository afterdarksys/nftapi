package nft

import (
	"bytes"
	"encoding/json"
)

// Project reads `nft -j list ruleset` output. A rule this phase cannot
// describe is returned opaque, with its handle and expr. An object that
// cannot be placed, or a chain or rule that cannot be decoded, fails closed.
func Project(out []byte) (*Ruleset, error) {
	out = bytes.TrimSpace(out)
	if len(out) == 0 {
		return nil, nftFailed("empty nft output")
	}
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	dec := json.NewDecoder(bytes.NewReader(out))
	if err := dec.Decode(&doc); err != nil {
		return nil, nftFailed("nft output is not ruleset json")
	}
	b := &builder{
		index:         map[string]*Table{},
		explicit:      map[string]bool{},
		explicitChain: map[string]bool{},
	}
	for _, el := range doc.Nftables {
		if len(el) != 1 {
			return nil, nftFailed("nft element is not one object")
		}
		var kind string
		var raw json.RawMessage
		for k, v := range el {
			kind, raw = k, v
		}
		if kind == "metainfo" {
			continue
		}
		if err := b.add(kind, raw); err != nil {
			return nil, err
		}
	}
	return b.done(), nil
}

type builder struct {
	tables        []*Table
	index         map[string]*Table
	explicit      map[string]bool
	explicitChain map[string]bool
}

func (b *builder) done() *Ruleset {
	if b.tables == nil {
		return &Ruleset{Tables: []Table{}}
	}
	out := make([]Table, len(b.tables))
	for i, t := range b.tables {
		out[i] = *t
		if out[i].Chains == nil {
			out[i].Chains = []Chain{}
		}
		if out[i].Other == nil {
			out[i].Other = []string{}
		}
		for j := range out[i].Chains {
			if out[i].Chains[j].Rules == nil {
				out[i].Chains[j].Rules = []Rule{}
			}
		}
	}
	return &Ruleset{Tables: out}
}

func (b *builder) add(kind string, raw json.RawMessage) error {
	switch kind {
	case "table":
		var t struct {
			Family string `json:"family"`
			Name   string `json:"name"`
		}
		if err := json.Unmarshal(raw, &t); err != nil || t.Family == "" || t.Name == "" {
			return nftFailed("table could not be read")
		}
		if _, ok := b.explicit[tableKey(t.Family, t.Name)]; ok {
			return nftFailed("duplicate table")
		}
		tb := b.table(t.Family, t.Name)
		b.explicit[tableKey(t.Family, t.Name)] = true
		_ = tb
		return nil
	case "chain":
		var c struct {
			Family string `json:"family"`
			Table  string `json:"table"`
			Name   string `json:"name"`
			Type   string `json:"type"`
			Hook   string `json:"hook"`
			Prio   *int32 `json:"prio"`
			Policy string `json:"policy"`
		}
		if err := json.Unmarshal(raw, &c); err != nil || c.Family == "" || c.Table == "" || c.Name == "" {
			return nftFailed("chain could not be read")
		}
		key := chainKey(c.Family, c.Table, c.Name)
		if b.explicitChain[key] {
			return nftFailed("duplicate chain")
		}
		ch := b.chain(c.Family, c.Table, c.Name)
		ch.Base = c.Hook != "" || c.Type != "" || c.Prio != nil || c.Policy != ""
		ch.Type = c.Type
		ch.Hook = c.Hook
		ch.Priority = c.Prio
		ch.Policy = c.Policy
		b.explicitChain[key] = true
		return nil
	case "rule":
		return b.addRule(raw)
	default:
		return b.addOther(kind, raw)
	}
}

func (b *builder) addRule(raw json.RawMessage) error {
	var r struct {
		Family  string            `json:"family"`
		Table   string            `json:"table"`
		Chain   string            `json:"chain"`
		Handle  *uint64           `json:"handle"`
		Comment string            `json:"comment"`
		Expr    []json.RawMessage `json:"expr"`
	}
	if err := json.Unmarshal(raw, &r); err != nil || r.Family == "" || r.Table == "" || r.Chain == "" {
		return nftFailed("rule could not be read")
	}
	if r.Handle == nil {
		return nftFailed("rule has no handle")
	}
	ch := b.chain(r.Family, r.Table, r.Chain)
	rule := Rule{Handle: *r.Handle, Comment: r.Comment}
	var exprRaw []byte
	var err error
	if r.Expr == nil {
		exprRaw = []byte("[]")
	} else {
		exprRaw, err = json.Marshal(r.Expr)
		if err != nil {
			return nftFailed("rule could not be read")
		}
	}
	spec, ok := projectExpr(r.Family, r.Expr)
	if !ok {
		rule.Opaque = true
		rule.Expr = exprRaw
		rule.Comment = r.Comment
	} else {
		rule.Match = spec.Match
		rule.Limit = spec.Limit
		rule.MatchAll = spec.MatchAll
		rule.Verdict = spec.Verdict
		rule.Comment = spec.Comment
		if rule.Comment == "" {
			rule.Comment = r.Comment
		}
	}
	ch.Rules = append(ch.Rules, rule)
	return nil
}

func (b *builder) addOther(kind string, raw json.RawMessage) error {
	var obj struct {
		Family string `json:"family"`
		Table  string `json:"table"`
		Name   string `json:"name"`
	}
	if json.Unmarshal(raw, &obj) != nil || obj.Family == "" || obj.Table == "" {
		return nftFailed("ruleset object could not be placed")
	}
	label := kind
	if obj.Name != "" {
		label = kind + ":" + obj.Name
	}
	tb := b.table(obj.Family, obj.Table)
	tb.Other = append(tb.Other, label)
	return nil
}

func tableKey(family, name string) string { return family + "\x00" + name }
func chainKey(family, table, name string) string {
	return family + "\x00" + table + "\x00" + name
}

func (b *builder) table(family, name string) *Table {
	if b.explicit == nil {
		b.explicit = map[string]bool{}
	}
	if b.explicitChain == nil {
		b.explicitChain = map[string]bool{}
	}
	k := tableKey(family, name)
	if t, ok := b.index[k]; ok {
		return t
	}
	t := &Table{Family: family, Name: name, Chains: []Chain{}, Other: []string{}}
	b.index[k] = t
	b.tables = append(b.tables, t)
	return t
}

func (b *builder) chain(family, table, name string) *Chain {
	tb := b.table(family, table)
	for i := range tb.Chains {
		if tb.Chains[i].Name == name {
			return &tb.Chains[i]
		}
	}
	tb.Chains = append(tb.Chains, Chain{Name: name, Rules: []Rule{}})
	return &tb.Chains[len(tb.Chains)-1]
}
