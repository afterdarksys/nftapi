package feed

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Threats: feed URLs are fixed in the binary. Get refuses any other host,
// any scheme other than https, any port other than 443, and any address that
// is loopback, private, link-local, multicast, unspecified, or 100.64.0.0/10.
// One non-public answer fails the lookup before a connect. Redirects stay on
// the same host allowlist. Proxy environment variables are ignored. TLS is
// 1.3 or newer with the system roots. A body past 2 MiB fails closed. This
// does not stop a holder of the key from reading indicators those hosts publish.

const userAgent = "nftapi"

// ErrNonPublic is returned by the dial path when a resolved address is not
// public. The connect is not attempted.
var ErrNonPublic = errors.New("non-public address")

var errBadDoc = unavailable("feed document is not usable")
var errTooMany = unavailable("feed exceeded 10000 indicators")
var errTooLarge = unavailable("feed too large")
var errFetch = unavailable("feed fetch failed")
var errTimed = timeoutErr("feed timed out")

var allowedHosts = map[string]struct{}{
	"check.torproject.org":      {},
	"api.tweetfeed.live":        {},
	"raw.githubusercontent.com": {},
}

var cgnat = net.IPNet{IP: net.IPv4(100, 64, 0, 0).To4(), Mask: net.CIDRMask(10, 32)}

type ipLookup interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// Client fetches the built-in feed URLs.
type Client struct {
	http     *http.Client
	resolver ipLookup
	connect  func(ctx context.Context, network, addr string) (net.Conn, error)
}

// NewClient is the production fetcher. It does not use HTTP_PROXY.
func NewClient() *Client {
	c := &Client{}
	tr := &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     true,
		DisableCompression:    true,
		MaxIdleConns:          4,
		IdleConnTimeout:       time.Second,
		ResponseHeaderTimeout: 4 * time.Second,
		TLSHandshakeTimeout:   4 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
		},
	}
	tr.DialContext = c.dial
	c.http = &http.Client{
		Timeout:       fetchBudget,
		CheckRedirect: c.redirect,
		Transport:     tr,
	}
	return c
}

// Get downloads one allowlisted https URL. It returns when ctx is done.
func (c *Client) Get(ctx context.Context, rawURL string) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil || !allowedURL(u) {
		return nil, errFetch
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, errFetch
	}
	req.Header.Set("User-Agent", userAgent)
	res, err := c.http.Do(req)
	if err != nil {
		return nil, classify(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		_, drainErr := io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
		if drainErr != nil {
			return nil, classify(drainErr)
		}
		return nil, errFetch
	}
	return readLimited(res.Body)
}

func (c *Client) redirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 3 || !allowedURL(req.URL) {
		return errFetch
	}
	return nil
}

func (c *Client) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port != "443" || !allowedHost(host) {
		return nil, errFetch
	}
	ips, err := c.lookup(ctx, host)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errFetch
	}
	if len(ips) == 0 {
		return nil, errFetch
	}
	for _, ip := range ips {
		if !public(ip.IP) {
			return nil, ErrNonPublic
		}
	}
	var last error
	for _, ip := range ips {
		conn, dialErr := c.connectTo(ctx, network, net.JoinHostPort(ip.IP.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		last = dialErr
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	if last == nil {
		return nil, errFetch
	}
	return nil, last
}

func (c *Client) lookup(ctx context.Context, host string) ([]net.IPAddr, error) {
	r := c.resolver
	if r == nil {
		r = net.DefaultResolver
	}
	return r.LookupIPAddr(ctx, host)
}

func (c *Client) connectTo(ctx context.Context, network, addr string) (net.Conn, error) {
	if c.connect != nil {
		return c.connect(ctx, network, addr)
	}
	d := net.Dialer{Timeout: 3 * time.Second}
	return d.DialContext(ctx, network, addr)
}

func allowedURL(u *url.URL) bool {
	if u == nil || u.Scheme != "https" || u.User != nil {
		return false
	}
	host := u.Hostname()
	if !allowedHost(host) {
		return false
	}
	port := u.Port()
	return port == "" || port == "443"
}

func allowedHost(host string) bool {
	host = strings.TrimSuffix(host, ".")
	if host == "" || strings.IndexByte(host, '%') >= 0 {
		return false
	}
	_, ok := allowedHosts[strings.ToLower(host)]
	return ok
}

func public(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() || ip.Equal(net.IPv4bcast) {
		return false
	}
	if cgnat.Contains(ip) {
		return false
	}
	return true
}

func readLimited(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxFeedBody+1))
	if err != nil {
		return nil, classify(err)
	}
	if len(b) > maxFeedBody {
		return nil, errTooLarge
	}
	return b, nil
}

func classify(err error) error {
	if err == nil {
		return nil
	}
	var fe *Error
	if errors.As(err, &fe) {
		return fe
	}
	if errors.Is(err, ErrNonPublic) {
		return errFetch
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return errTimed
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return errTimed
	}
	return errFetch
}
