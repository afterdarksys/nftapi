package feed

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Threats: a line or a JSON row that is not a usable indicator is skipped.
// A document that is not the expected shape, a line count past 20000, or an
// object count past 50000 fails the module. The parsers do not install
// firewall rules.

func parseTor(b []byte, s *set) error {
	return parseLines(b, true, func(line string) error {
		ip, ok := canonIP(line, false)
		if !ok {
			return nil
		}
		return s.add("ip", ip)
	})
}

func parseIPFile(b []byte, s *set) error {
	return parseLines(b, true, func(line string) error {
		ip, ok := canonIP(line, true)
		if !ok {
			return nil
		}
		return s.add("ip", ip)
	})
}

func parseDomains(b []byte, s *set) error {
	return parseLines(b, true, func(line string) error {
		d, ok := canonDomain(line)
		if !ok {
			return nil
		}
		return s.add("domain", d)
	})
}

func parseURLs(b []byte, s *set) error {
	return parseLines(b, true, func(line string) error {
		u, ok := canonURL(line)
		if !ok {
			return nil
		}
		return s.add("url", u)
	})
}

func parseUAs(b []byte, s *set) error {
	return parseLines(b, false, func(line string) error {
		ua, ok := canonUA(line)
		if !ok {
			return nil
		}
		return s.add("user_agent", ua)
	})
}

func parseLines(b []byte, comments bool, each func(string) error) error {
	b = bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 4096), maxFeedBody+1)
	n := 0
	for sc.Scan() {
		n++
		if n > maxLines {
			return errBadDoc
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if comments && strings.HasPrefix(line, "#") {
			continue
		}
		if err := each(line); err != nil {
			return err
		}
	}
	if sc.Err() != nil {
		return errBadDoc
	}
	return nil
}

func canonIP(s string, allowPrefix bool) (string, bool) {
	if s == "" || strings.IndexByte(s, '%') >= 0 {
		return "", false
	}
	if strings.IndexByte(s, '/') >= 0 {
		if !allowPrefix {
			return "", false
		}
		return canonPrefix(s)
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return "", false
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String(), true
	}
	return ip.String(), true
}

func canonPrefix(s string) (string, bool) {
	ip, network, err := net.ParseCIDR(s)
	if err != nil {
		return "", false
	}
	ones, bits := network.Mask.Size()
	if bits == 128 && ip.To4() != nil {
		return "", false
	}
	if bits != 32 && bits != 128 {
		return "", false
	}
	if !ip.Equal(network.IP) {
		if !((bits == 32 && ones == 32) || (bits == 128 && ones == 128)) {
			return "", false
		}
	}
	if (bits == 32 && ones == 32) || (bits == 128 && ones == 128) {
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), true
		}
		return ip.String(), true
	}
	base := network.IP
	if bits == 32 {
		if v4 := base.To4(); v4 != nil {
			base = v4
		}
	}
	return base.String() + "/" + strconv.Itoa(ones), true
}

func canonDomain(s string) (string, bool) {
	if len(s) == 0 || len(s) > 253 {
		return "", false
	}
	s = strings.ToLower(s)
	if strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") {
		return "", false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return "", false
	}
	for _, lab := range labels {
		if len(lab) == 0 || len(lab) > 63 {
			return "", false
		}
		if lab[0] == '-' || lab[len(lab)-1] == '-' {
			return "", false
		}
		for i := 0; i < len(lab); i++ {
			c := lab[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return "", false
			}
		}
	}
	return s, true
}

func canonURL(s string) (string, bool) {
	if s == "" || len(s) > 2048 || hasControl(s) || strings.IndexByte(s, ' ') >= 0 {
		return "", false
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return "", false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", false
	}
	if u.Hostname() == "" {
		return "", false
	}
	return s, true
}

func canonUA(s string) (string, bool) {
	if s == "" || len(s) > 256 || !utf8.ValidString(s) || hasControl(s) {
		return "", false
	}
	return s, true
}

func hasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

func parseTweet(b []byte, s *set) error {
	b = bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})
	dec := json.NewDecoder(bytes.NewReader(b))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('[') {
		return errBadDoc
	}
	n := 0
	for dec.More() {
		n++
		if n > maxObjects {
			return errBadDoc
		}
		var row struct {
			Type  string   `json:"type"`
			Value string   `json:"value"`
			Tags  []string `json:"tags"`
		}
		if err := dec.Decode(&row); err != nil {
			return errBadDoc
		}
		if !phishingTag(row.Tags) {
			continue
		}
		typ, val, ok := tweetValue(row.Type, strings.TrimSpace(row.Value))
		if !ok {
			continue
		}
		if err := s.add(typ, val); err != nil {
			return err
		}
	}
	tok, err = dec.Token()
	if err != nil || tok != json.Delim(']') {
		return errBadDoc
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errBadDoc
	}
	return nil
}

func phishingTag(tags []string) bool {
	for _, t := range tags {
		t = strings.TrimSpace(t)
		t = strings.TrimPrefix(t, "#")
		if strings.EqualFold(t, "phishing") {
			return true
		}
	}
	return false
}

func tweetValue(typ, val string) (string, string, bool) {
	switch strings.ToLower(strings.TrimSpace(typ)) {
	case "ip":
		ip, ok := canonIP(val, false)
		return "ip", ip, ok
	case "domain":
		d, ok := canonDomain(val)
		return "domain", d, ok
	case "url":
		u, ok := canonURL(val)
		return "url", u, ok
	case "sha256":
		h, ok := hexLen(val, 64)
		return "sha256", h, ok
	case "md5":
		h, ok := hexLen(val, 32)
		return "md5", h, ok
	default:
		return "", "", false
	}
}

func hexLen(s string, n int) (string, bool) {
	if len(s) != n {
		return "", false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return "", false
		}
	}
	return strings.ToLower(s), true
}
