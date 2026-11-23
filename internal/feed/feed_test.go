package feed

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestCatalog(t *testing.T) {
	mods := Catalog()
	want := []string{"tor", "tweetfeed_phishing", "artex", "cairn", "hexstrike", "cyberstrikeai"}
	if len(mods) != len(want) {
		t.Fatalf("len %d", len(mods))
	}
	for i, id := range want {
		if mods[i].ID != id || !idRe.MatchString(id) {
			t.Fatalf("id %s", mods[i].ID)
		}
		if len(mods[i].Kinds) == 0 || mods[i].Format == "" {
			t.Fatalf("meta %+v", mods[i])
		}
	}
	if mods[0].Format != "list" || mods[1].Format != "json" {
		t.Fatalf("format %+v", mods[:2])
	}
	mods[0].Kinds[0] = "mutated"
	if Catalog()[0].Kinds[0] != "ip" {
		t.Fatal("catalog alias")
	}
}

func TestFetchTor(t *testing.T) {
	var got string
	g := GetterFunc(func(_ context.Context, u string) ([]byte, error) {
		got = u
		return []byte("# comment\n\n1.2.3.4\n::ffff:203.0.113.9\nnot-an-ip\n203.0.113.0/24\n10.0.0.1\n2001:db8::1\n1.2.3.4\n"), nil
	})
	inds, err := Fetch(context.Background(), g, "tor")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://check.torproject.org/torbulkexitlist" {
		t.Fatal(got)
	}
	want := []Indicator{
		{"ip", "1.2.3.4"},
		{"ip", "203.0.113.9"},
		{"ip", "10.0.0.1"},
		{"ip", "2001:db8::1"},
	}
	if !same(inds, want) {
		t.Fatalf("%+v", inds)
	}
}

func TestFetchTweet(t *testing.T) {
	sha := strings.Repeat("AB", 32)
	md := strings.Repeat("cd", 16)
	body := `[
		{"type":"url","value":"http://malware.example/a","tags":["#malware"],"tweet":"x"},
		{"type":"domain","value":"Phish.Example","tags":["#malware","#phishing"]},
		{"type":"ip","value":"203.0.113.5","tags":[" phishing "]},
		{"type":"sha256","value":"` + sha + `","tags":["#Phishing"]},
		{"type":"md5","value":"` + md + `","tags":["#phishing"]},
		{"type":"email","value":"a@b.c","tags":["#phishing"]},
		{"type":"ip","value":"999.1.1.1","tags":["#phishing"]},
		{"type":"url","value":"ftp://x","tags":["#phishing"]},
		{"type":"url","value":"https://phish.example/a","tags":["##phishing"]}
	]`
	var got string
	g := GetterFunc(func(_ context.Context, u string) ([]byte, error) {
		got = u
		return []byte(body), nil
	})
	inds, err := Fetch(context.Background(), g, "tweetfeed_phishing")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://api.tweetfeed.live/v1/today" {
		t.Fatal(got)
	}
	want := []Indicator{
		{"domain", "phish.example"},
		{"ip", "203.0.113.5"},
		{"sha256", strings.ToLower(sha)},
		{"md5", md},
	}
	if !same(inds, want) {
		t.Fatalf("%+v", inds)
	}
}

func TestTweetRejectsNonArray(t *testing.T) {
	for _, body := range []string{`{"items":[]}`, `<html></html>`, `{"ok":true}`, ``} {
		_, err := Fetch(context.Background(), bodyGetter(body), "tweetfeed_phishing")
		if !errors.Is(err, errBadDoc) {
			t.Fatalf("%q %v", body, err)
		}
	}
	inds, err := Fetch(context.Background(), bodyGetter(`[]`), "tweetfeed_phishing")
	if err != nil || len(inds) != 0 || inds == nil {
		t.Fatalf("%v %+v", err, inds)
	}
}

func TestFrameworkFiles(t *testing.T) {
	files := map[string]string{
		"ipv4.txt":        "101.53.80.20\n92.255.57.0/24\n92.255.57.1/24\n1.2.3.4/32\n::ffff:203.0.113.0/24\nbad\n# c\n",
		"ipv6.txt":        "2001:db8::/32\n2001:db8::1/128\n2001:0db8::1\n::ffff:198.51.100.9\n",
		"domains.txt":     "down.zhzy999.net\nlocalhost\nNot A.example\n-bad.com\na..b.com\nOK-host.Example\n",
		"urls.txt":        "https://evil.example/a\nhttp://evil.example\nnot a url\njavascript:alert(1)\nhttps://\n",
		"user_agents.txt": "ARTEX-worker/1.0\nartex-agent\n\n",
	}
	seen := map[string]bool{}
	g := GetterFunc(func(_ context.Context, u string) ([]byte, error) {
		seen[u] = true
		if strings.Contains(u, "md5.txt") || strings.Contains(u, "sha256.txt") {
			t.Fatalf("hash file %s", u)
		}
		for name, body := range files {
			if strings.HasSuffix(u, "/hexstrike/"+name) {
				return []byte(body), nil
			}
		}
		t.Fatalf("url %s", u)
		return nil, errors.New("missing")
	})
	inds, err := Fetch(context.Background(), g, "hexstrike")
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 5 {
		t.Fatalf("urls %v", seen)
	}
	want := []Indicator{
		{"ip", "101.53.80.20"},
		{"ip", "92.255.57.0/24"},
		{"ip", "1.2.3.4"},
		{"ip", "2001:db8::/32"},
		{"ip", "2001:db8::1"},
		{"ip", "198.51.100.9"},
		{"domain", "down.zhzy999.net"},
		{"domain", "ok-host.example"},
		{"url", "https://evil.example/a"},
		{"url", "http://evil.example"},
		{"user_agent", "ARTEX-worker/1.0"},
		{"user_agent", "artex-agent"},
	}
	if !same(inds, want) {
		t.Fatalf("%+v", inds)
	}
}

func TestEmptyFrameworkFile(t *testing.T) {
	g := GetterFunc(func(_ context.Context, u string) ([]byte, error) {
		if strings.HasSuffix(u, "user_agents.txt") {
			return []byte("ARTEX-worker/1.0\n"), nil
		}
		return []byte("\n"), nil
	})
	inds, err := Fetch(context.Background(), g, "hexstrike")
	if err != nil {
		t.Fatal(err)
	}
	if !same(inds, []Indicator{{"user_agent", "ARTEX-worker/1.0"}}) {
		t.Fatalf("%+v", inds)
	}
}

func TestFetchFailClosed(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	g := GetterFunc(func(ctx context.Context, u string) ([]byte, error) {
		if strings.Contains(u, "ipv4.txt") {
			return nil, errors.New("nope")
		}
		if strings.Contains(u, "domains.txt") {
			select {
			case <-started:
			default:
				close(started)
			}
			select {
			case <-release:
				return []byte("a.example\n"), nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return []byte("\n"), nil
	})
	done := make(chan error, 1)
	go func() {
		_, err := Fetch(context.Background(), g, "artex")
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("sibling did not start")
	}
	select {
	case err := <-done:
		t.Fatalf("returned early %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	err := <-done
	var fe *Error
	if !errors.As(err, &fe) || fe.Msg != "feed fetch failed" {
		t.Fatal(err)
	}
}

func TestFetchTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	g := GetterFunc(func(ctx context.Context, _ string) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	_, err := Fetch(ctx, g, "tor")
	var fe *Error
	if !errors.As(err, &fe) || fe.Code != "timeout" || fe.Msg != "feed timed out" {
		t.Fatal(err)
	}
}

func TestModuleIDs(t *testing.T) {
	g := GetterFunc(func(context.Context, string) ([]byte, error) {
		t.Fatal("fetched")
		return nil, nil
	})
	_, err := Fetch(context.Background(), g, "nope")
	var fe *Error
	if !errors.As(err, &fe) || fe.Code != "not_found" || fe.Msg != "unknown module" {
		t.Fatal(err)
	}
	for _, id := range []string{"", "Tor", "a/b", strings.Repeat("a", 33), "has space"} {
		_, err = Fetch(context.Background(), g, id)
		if !errors.As(err, &fe) || fe.Code != "invalid_argument" {
			t.Fatalf("%q %v", id, err)
		}
	}
}

func TestCaps(t *testing.T) {
	_, err := Fetch(context.Background(), bodyGetter(strings.Repeat("x\n", maxLines+1)), "tor")
	if !errors.Is(err, errBadDoc) {
		t.Fatal(err)
	}
	inds, err := Fetch(context.Background(), bodyGetter(ips(maxIndicators)+"1.0.0.0\n"), "tor")
	if err != nil || len(inds) != maxIndicators {
		t.Fatalf("%v %d", err, len(inds))
	}
	_, err = Fetch(context.Background(), bodyGetter(ips(maxIndicators+1)), "tor")
	if !errors.Is(err, errTooMany) {
		t.Fatal(err)
	}
	big := bytes.Repeat([]byte("a"), maxFeedBody+1)
	_, err = Fetch(context.Background(), GetterFunc(func(context.Context, string) ([]byte, error) {
		return big, nil
	}), "tor")
	if !errors.Is(err, errTooLarge) {
		t.Fatal(err)
	}
	objs := "[" + strings.Repeat("{},", maxObjects) + "{}]"
	_, err = Fetch(context.Background(), bodyGetter(objs), "tweetfeed_phishing")
	if !errors.Is(err, errBadDoc) {
		t.Fatal(err)
	}
}

func TestUAAndURLEdges(t *testing.T) {
	if _, ok := canonUA(strings.Repeat("a", 256)); !ok {
		t.Fatal("256")
	}
	if _, ok := canonUA(strings.Repeat("a", 257)); ok {
		t.Fatal("257")
	}
	if _, ok := canonUA("bad\x00ua"); ok {
		t.Fatal("nul")
	}
	if _, ok := canonUA("héllo"); !ok {
		t.Fatal("utf8")
	}
	if _, ok := canonURL("https://user:pass@example.com/a"); !ok {
		t.Fatal("userinfo indicator")
	}
}

func TestPublicAddresses(t *testing.T) {
	ok := []string{"1.1.1.1", "8.8.8.8", "100.128.0.1", "2001:4860:4860::8888", "::ffff:1.1.1.1"}
	bad := []string{
		"127.0.0.1", "::1", "10.0.0.1", "172.16.0.1", "192.168.1.1",
		"169.254.1.1", "100.64.0.1", "100.127.255.255", "224.0.0.1",
		"255.255.255.255", "0.0.0.0", "fe80::1", "ff02::1", "fc00::1", "::",
		"::ffff:10.0.0.1", "::ffff:169.254.1.1",
	}
	for _, s := range ok {
		if !public(net.ParseIP(s)) {
			t.Fatalf("want public %s", s)
		}
	}
	for _, s := range bad {
		if public(net.ParseIP(s)) {
			t.Fatalf("want refused %s", s)
		}
	}
	if public(nil) {
		t.Fatal("nil")
	}
}

func TestDialRefusesNonPublic(t *testing.T) {
	c := NewClient()
	c.resolver = fixedResolver{ips: []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("10.0.0.1")}}
	c.connect = func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("connected")
		return nil, errors.New("connected")
	}
	_, err := c.dial(context.Background(), "tcp", "check.torproject.org:443")
	if !errors.Is(err, ErrNonPublic) {
		t.Fatal(err)
	}

	c.resolver = fixedResolver{ips: []net.IP{net.ParseIP("127.0.0.1")}}
	_, err = c.dial(context.Background(), "tcp", "check.torproject.org:443")
	if !errors.Is(err, ErrNonPublic) {
		t.Fatal(err)
	}

	called := false
	c.resolver = fixedResolver{err: errors.New("secret.internal"), called: &called}
	_, err = c.dial(context.Background(), "tcp", "evil.example:443")
	if called || !errors.Is(err, errFetch) || strings.Contains(err.Error(), "secret") {
		t.Fatal(err, called)
	}
	_, err = c.dial(context.Background(), "tcp", "check.torproject.org:8443")
	if !errors.Is(err, errFetch) {
		t.Fatal(err)
	}
}

func TestGetRefusesURL(t *testing.T) {
	c := NewClient()
	c.resolver = fixedResolver{err: errors.New("lookup")}
	c.connect = func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("connected")
		return nil, errors.New("connected")
	}
	for _, raw := range []string{
		"http://check.torproject.org/torbulkexitlist",
		"https://evil.example/x",
		"https://check.torproject.org.evil.com/x",
		"https://user:pass@check.torproject.org/x",
		"https://127.0.0.1/x",
		"file:///etc/passwd",
		"https://check.torproject.org:8443/x",
		"https://raw.githubusercontent.com.evil/x",
	} {
		_, err := c.Get(context.Background(), raw)
		if !errors.Is(err, errFetch) {
			t.Fatalf("%s %v", raw, err)
		}
	}
}

func TestRedirectAllowlist(t *testing.T) {
	c := NewClient()
	ok, err := url.Parse("https://raw.githubusercontent.com/a")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.redirect(&http.Request{URL: ok}, nil); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"https://evil.example/a", "http://check.torproject.org/a"} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.redirect(&http.Request{URL: u}, nil); !errors.Is(err, errFetch) {
			t.Fatalf("%s %v", raw, err)
		}
	}
	via := []*http.Request{{}, {}, {}}
	if err := c.redirect(&http.Request{URL: ok}, via); !errors.Is(err, errFetch) {
		t.Fatal(err)
	}
}

func TestClientTransport(t *testing.T) {
	c := NewClient()
	tr, ok := c.http.Transport.(*http.Transport)
	if !ok || tr.Proxy != nil || tr.DialContext == nil {
		t.Fatal("transport")
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion != tls.VersionTLS13 || tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("tls")
	}
	if c.http.Timeout != fetchBudget {
		t.Fatal(c.http.Timeout)
	}
}

func TestGetStatusAndSize(t *testing.T) {
	c := NewClient()
	c.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "check.torproject.org" || r.Header.Get("User-Agent") != "nftapi" {
			t.Fatalf("%+v", r)
		}
		return &http.Response{
			StatusCode: 404,
			Body:       io.NopCloser(strings.NewReader("missing")),
			Header:     make(http.Header),
			Request:    r,
		}, nil
	})
	_, err := c.Get(context.Background(), "https://check.torproject.org/torbulkexitlist")
	if !errors.Is(err, errFetch) {
		t.Fatal(err)
	}
	c.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("a"), maxFeedBody+1))),
			Header:     make(http.Header),
			Request:    r,
		}, nil
	})
	_, err = c.Get(context.Background(), "https://check.torproject.org/torbulkexitlist")
	if !errors.Is(err, errTooLarge) {
		t.Fatal(err)
	}
}

type fixedResolver struct {
	ips    []net.IP
	err    error
	called *bool
}

func (f fixedResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	if f.called != nil {
		*f.called = true
	}
	if f.err != nil {
		return nil, f.err
	}
	out := make([]net.IPAddr, len(f.ips))
	for i, ip := range f.ips {
		out[i] = net.IPAddr{IP: ip}
	}
	return out, nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func bodyGetter(body string) Getter {
	return GetterFunc(func(context.Context, string) ([]byte, error) {
		return []byte(body), nil
	})
}

func ips(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString("1.")
		b.WriteString(itoa((i >> 16) & 255))
		b.WriteByte('.')
		b.WriteString(itoa((i >> 8) & 255))
		b.WriteByte('.')
		b.WriteString(itoa(i & 255))
		b.WriteByte('\n')
	}
	return b.String()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d [3]byte
	i := len(d)
	for n > 0 {
		i--
		d[i] = byte('0' + n%10)
		n /= 10
	}
	return string(d[i:])
}

func same(got, want []Indicator) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
