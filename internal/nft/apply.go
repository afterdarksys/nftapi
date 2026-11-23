package nft

import (
	"context"
	"errors"
)

// Runner executes one nft JSON document. The argv is fixed by the caller.
type Runner interface {
	Run(ctx context.Context, stdin []byte) (stdout []byte, err error)
}

// Apply lists the live ruleset, decides the op, and runs at most one mutation.
func Apply(ctx context.Context, r Runner, req Request) (Result, error) {
	if err := req.Validate(); err != nil {
		return Result{}, err
	}
	switch req.Op {
	case "ruleset.list":
		rs, err := load(ctx, r)
		if err != nil {
			return Result{}, err
		}
		return Result{Ruleset: rs}, nil
	case "table.add":
		rs, err := load(ctx, r)
		if err != nil {
			return Result{}, err
		}
		if rs.findTable(req.Family, req.Table) != nil {
			return Result{Created: boolPtr(false)}, nil
		}
		if err := mutate(ctx, r, req); err != nil {
			return Result{}, err
		}
		return Result{Created: boolPtr(true)}, nil
	case "table.delete":
		rs, err := load(ctx, r)
		if err != nil {
			return Result{}, err
		}
		tb := rs.findTable(req.Family, req.Table)
		if tb == nil {
			return Result{}, notFound("table not found")
		}
		if len(tb.Chains) != 0 || len(tb.Other) != 0 {
			return Result{}, notEmpty("table is not empty")
		}
		if err := mutate(ctx, r, req); err != nil {
			return Result{}, err
		}
		return Result{Deleted: boolPtr(true)}, nil
	case "chain.add":
		rs, err := load(ctx, r)
		if err != nil {
			return Result{}, err
		}
		tb := rs.findTable(req.Family, req.Table)
		if tb == nil {
			return Result{}, notFound("table not found")
		}
		if ch := tb.findChain(req.Chain); ch != nil {
			if ch.sameDef(req) {
				return Result{Created: boolPtr(false)}, nil
			}
			return Result{}, conflict("chain already exists")
		}
		if err := mutate(ctx, r, req); err != nil {
			return Result{}, err
		}
		return Result{Created: boolPtr(true)}, nil
	case "chain.delete":
		rs, err := load(ctx, r)
		if err != nil {
			return Result{}, err
		}
		ch := rs.findChain(req.Family, req.Table, req.Chain)
		if ch == nil {
			return Result{}, notFound("chain not found")
		}
		if len(ch.Rules) != 0 {
			return Result{}, notEmpty("chain is not empty")
		}
		if err := mutate(ctx, r, req); err != nil {
			return Result{}, err
		}
		return Result{Deleted: boolPtr(true)}, nil
	case "rule.add":
		rs, err := load(ctx, r)
		if err != nil {
			return Result{}, err
		}
		ch := rs.findChain(req.Family, req.Table, req.Chain)
		if rs.findTable(req.Family, req.Table) == nil {
			return Result{}, notFound("table not found")
		}
		if ch == nil {
			return Result{}, notFound("chain not found")
		}
		want := req.spec()
		if h, ok := ch.matchSpec(want); ok {
			return Result{Created: boolPtr(false), Handle: &h}, nil
		}
		before := append([]Rule(nil), ch.Rules...)
		if err := mutate(ctx, r, req); err != nil {
			return Result{}, err
		}
		again, err := load(ctx, r)
		if err != nil {
			return Result{}, err
		}
		after := again.findChain(req.Family, req.Table, req.Chain)
		if after == nil {
			return Result{}, nftFailed("added rule was not found")
		}
		h, err := addedHandle(before, after.Rules, want)
		if err != nil {
			return Result{}, err
		}
		return Result{Created: boolPtr(true), Handle: &h}, nil
	case "rule.delete":
		rs, err := load(ctx, r)
		if err != nil {
			return Result{}, err
		}
		ch := rs.findChain(req.Family, req.Table, req.Chain)
		if ch == nil || !ch.hasHandle(*req.Handle) {
			return Result{}, notFound("rule not found")
		}
		if err := mutate(ctx, r, req); err != nil {
			return Result{}, err
		}
		return Result{Deleted: boolPtr(true)}, nil
	default:
		return Result{}, invalid("unknown op")
	}
}

func (req Request) spec() Spec {
	return Spec{
		Match:    req.Match,
		Limit:    req.Limit,
		MatchAll: req.MatchAll,
		Verdict:  req.Verdict,
		Comment:  req.Comment,
	}
}

func load(ctx context.Context, r Runner) (*Ruleset, error) {
	out, err := call(ctx, r, listStdin())
	if err != nil {
		return nil, err
	}
	return Project(out)
}

func mutate(ctx context.Context, r Runner, req Request) error {
	doc, err := Compile(req)
	if err != nil {
		return err
	}
	_, err = call(ctx, r, doc)
	return err
}

func call(ctx context.Context, r Runner, stdin []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, timeoutErr("nft timed out")
	}
	if r == nil {
		return nil, unavailable("nft unavailable")
	}
	out, err := r.Run(ctx, stdin)
	if err == nil {
		return out, nil
	}
	if errors.Is(err, ErrTimeout) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return nil, timeoutErr("nft timed out")
	}
	if errors.Is(err, ErrTooBig) {
		return nil, nftFailed("nft output exceeded 1MiB")
	}
	if errors.Is(err, ErrUnavailable) {
		return nil, unavailable("nft unavailable")
	}
	var ne *Error
	if errors.As(err, &ne) {
		return nil, ne
	}
	return nil, nftFailed("nft failed")
}

func (rs *Ruleset) findTable(family, name string) *Table {
	if rs == nil {
		return nil
	}
	for i := range rs.Tables {
		if rs.Tables[i].Family == family && rs.Tables[i].Name == name {
			return &rs.Tables[i]
		}
	}
	return nil
}

func (rs *Ruleset) findChain(family, table, name string) *Chain {
	tb := rs.findTable(family, table)
	if tb == nil {
		return nil
	}
	return tb.findChain(name)
}

func (t *Table) findChain(name string) *Chain {
	for i := range t.Chains {
		if t.Chains[i].Name == name {
			return &t.Chains[i]
		}
	}
	return nil
}

func (c *Chain) sameDef(req Request) bool {
	if !c.Base || c.Type != "filter" || c.Hook != req.Hook || c.Policy != req.Policy {
		return false
	}
	if c.Priority == nil || req.Priority == nil || *c.Priority != *req.Priority {
		return false
	}
	return true
}

func (c *Chain) matchSpec(s Spec) (uint64, bool) {
	var found uint64
	ok := false
	for _, rule := range c.Rules {
		if rule.Opaque || !rule.spec().Equal(s) {
			continue
		}
		if !ok || rule.Handle < found {
			found = rule.Handle
			ok = true
		}
	}
	return found, ok
}

func (c *Chain) hasHandle(h uint64) bool {
	for _, rule := range c.Rules {
		if rule.Handle == h {
			return true
		}
	}
	return false
}

func addedHandle(before, after []Rule, want Spec) (uint64, error) {
	old := map[uint64]struct{}{}
	for _, rule := range before {
		old[rule.Handle] = struct{}{}
	}
	var hits []uint64
	for _, rule := range after {
		if _, ok := old[rule.Handle]; ok || rule.Opaque || !rule.spec().Equal(want) {
			continue
		}
		hits = append(hits, rule.Handle)
	}
	if len(hits) != 1 {
		return 0, nftFailed("added rule was not found")
	}
	return hits[0], nil
}

func boolPtr(v bool) *bool { return &v }
