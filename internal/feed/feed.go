package feed

import (
	"context"
	"regexp"
	"sync"
	"time"
)

var idRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

const (
	maxFeedBody   = 2 << 20
	maxIndicators = 10000
	maxLines      = 20000
	maxObjects    = 50000
	fetchBudget   = 5 * time.Second
)

// Indicator is one detected value. Type is ip, domain, url, user_agent,
// sha256, or md5.
type Indicator struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Module is one built-in detector. Catalog does not fetch it.
type Module struct {
	ID     string   `json:"id"`
	Format string   `json:"format"`
	Kinds  []string `json:"kinds"`
}

// Getter downloads a URL the module already chose. Get returns when ctx is done.
type Getter interface {
	Get(ctx context.Context, rawURL string) ([]byte, error)
}

// GetterFunc adapts a function to Getter.
type GetterFunc func(ctx context.Context, rawURL string) ([]byte, error)

// Get calls the function.
func (f GetterFunc) Get(ctx context.Context, rawURL string) ([]byte, error) {
	return f(ctx, rawURL)
}

type source struct {
	url   string
	parse func([]byte, *set) error
}

type spec struct {
	id      string
	format  string
	kinds   []string
	sources []source
}

const frameworkBase = "https://raw.githubusercontent.com/ThreatDefence/agentic-attack-detections/main/feeds/by-framework/"

var registry = []spec{
	{
		id:     "tor",
		format: "list",
		kinds:  []string{"ip"},
		sources: []source{{
			url:   "https://check.torproject.org/torbulkexitlist",
			parse: parseTor,
		}},
	},
	{
		id:     "tweetfeed_phishing",
		format: "json",
		kinds:  []string{"ip", "domain", "url", "sha256", "md5"},
		sources: []source{{
			url:   "https://api.tweetfeed.live/v1/today",
			parse: parseTweet,
		}},
	},
	frameworkSpec("artex"),
	frameworkSpec("cairn"),
	frameworkSpec("hexstrike"),
	frameworkSpec("cyberstrikeai"),
}

var byID = func() map[string]spec {
	m := make(map[string]spec, len(registry))
	for _, s := range registry {
		m[s.id] = s
	}
	return m
}()

func frameworkSpec(id string) spec {
	base := frameworkBase + id + "/"
	return spec{
		id:     id,
		format: "list",
		kinds:  []string{"ip", "domain", "url", "user_agent"},
		sources: []source{
			{url: base + "ipv4.txt", parse: parseIPFile},
			{url: base + "ipv6.txt", parse: parseIPFile},
			{url: base + "domains.txt", parse: parseDomains},
			{url: base + "urls.txt", parse: parseURLs},
			{url: base + "user_agents.txt", parse: parseUAs},
		},
	}
}

// Catalog is the built-in module list, in a fixed order.
func Catalog() []Module {
	out := make([]Module, len(registry))
	for i, m := range registry {
		kinds := make([]string, len(m.kinds))
		copy(kinds, m.kinds)
		out[i] = Module{ID: m.id, Format: m.format, Kinds: kinds}
	}
	return out
}

// Fetch loads one module and returns its indicators. An empty result is a
// non-nil slice. One failed source fails the module.
func Fetch(ctx context.Context, g Getter, id string) ([]Indicator, error) {
	if !idRe.MatchString(id) {
		return nil, invalid("invalid module")
	}
	mod, ok := byID[id]
	if !ok {
		return nil, notFound("unknown module")
	}
	if g == nil {
		return nil, errFetch
	}
	ctx, cancel := context.WithTimeout(ctx, fetchBudget)
	defer cancel()

	bodies := make([][]byte, len(mod.sources))
	errs := make([]error, len(mod.sources))
	var wg sync.WaitGroup
	for i, src := range mod.sources {
		wg.Add(1)
		go func(i int, rawURL string) {
			defer wg.Done()
			b, err := g.Get(ctx, rawURL)
			bodies[i] = b
			errs[i] = err
		}(i, src.url)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return nil, classify(err)
		}
	}
	got := &set{seen: map[string]struct{}{}}
	for i, src := range mod.sources {
		if len(bodies[i]) > maxFeedBody {
			return nil, errTooLarge
		}
		if err := src.parse(bodies[i], got); err != nil {
			return nil, err
		}
	}
	if got.out == nil {
		got.out = []Indicator{}
	}
	return got.out, nil
}

type set struct {
	seen map[string]struct{}
	out  []Indicator
}

func (s *set) add(typ, val string) error {
	key := typ + "\x00" + val
	if _, ok := s.seen[key]; ok {
		return nil
	}
	if len(s.out) >= maxIndicators {
		return errTooMany
	}
	s.seen[key] = struct{}{}
	s.out = append(s.out, Indicator{Type: typ, Value: val})
	return nil
}
