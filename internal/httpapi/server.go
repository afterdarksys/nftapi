// Threats: the bearer check hashes both sides and does not stop at the
// first differing byte. A missing header, a bad scheme, a wrong key, and a
// token whose length is outside 32 to 256 bytes all get the same 401 body.
// It does not rate-limit guesses, rotate keys, or name a caller. Loopback
// bind stops non-local TCP clients. It does not stop another process on
// this host. The closed compiler stops a request from choosing a shell, an
// nft script, or a flush. It does not stop a holder of the key from dropping
// traffic in this network namespace. match_all stops a verdict-only rule
// from being an accident. It does not stop an explicit drop of every packet.
// There is no TLS because the socket is loopback. feed.fetch can reach
// only the built-in feed hosts. A request cannot choose that URL.
package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"

	"nftapi/internal/auth"
	"nftapi/internal/config"
	"nftapi/internal/feed"
	"nftapi/internal/nft"
)

const maxBody = 64 << 10

// Server is the localhost JSON API.
type Server struct {
	key    []byte
	runner nft.Runner
	feeds  feed.Getter
	log    *log.Logger
}

// New copies key. The caller may wipe its own buffer after New returns.
func New(key []byte, runner nft.Runner, logger *log.Logger) *Server {
	cp := make([]byte, len(key))
	copy(cp, key)
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	return &Server{key: cp, runner: runner, feeds: feed.NewClient(), log: logger}
}

// Listen refuses any address that is not a literal loopback IP and a port
// from 1 to 65535, then serves until the process exits.
func (s *Server) Listen(addr string) error {
	if err := config.ValidateAddr(addr); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	hs := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8192,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	return hs.Serve(ln)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Path == "/health" {
		s.write(w, http.StatusOK, "health", map[string]bool{"ok": true})
		return
	}
	if !s.authorized(r) {
		s.writeErr(w, "unauthorized", "unauthorized", "-")
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != "/v1" {
		s.writeErr(w, "not_found", "not found", "-")
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		s.writeErr(w, "invalid_argument", "content type must be application/json", "-")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		code, msg := decodeErr(err)
		s.writeErr(w, code, msg, "-")
		return
	}
	switch peekOp(raw) {
	case "feed.list", "feed.fetch":
		s.serveFeed(w, r, raw)
		return
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var req nft.Request
	if err := dec.Decode(&req); err != nil {
		code, msg := decodeErr(err)
		s.writeErr(w, code, msg, "-")
		return
	}
	var extra struct{}
	if err := dec.Decode(&extra); err != nil {
		if !errors.Is(err, io.EOF) {
			code, msg := decodeErr(err)
			s.writeErr(w, code, msg, "-")
			return
		}
	} else {
		s.writeErr(w, "invalid_argument", "invalid json", "-")
		return
	}
	res, err := nft.Apply(r.Context(), s.runner, req)
	if err != nil {
		var ne *nft.Error
		if !errors.As(err, &ne) {
			s.writeErr(w, "nft_failed", "nft failed", req.Op)
			return
		}
		s.writeErr(w, ne.Code, ne.Msg, req.Op)
		return
	}
	if res.Ruleset != nil {
		tables := res.Ruleset.Tables
		if tables == nil {
			tables = []nft.Table{}
		}
		s.write(w, http.StatusOK, req.Op, struct {
			OK     bool        `json:"ok"`
			Tables []nft.Table `json:"tables"`
		}{OK: true, Tables: tables})
		return
	}
	s.write(w, http.StatusOK, req.Op, struct {
		OK      bool    `json:"ok"`
		Created *bool   `json:"created,omitempty"`
		Deleted *bool   `json:"deleted,omitempty"`
		Handle  *uint64 `json:"handle,omitempty"`
	}{OK: true, Created: res.Created, Deleted: res.Deleted, Handle: res.Handle})
}

func peekOp(raw []byte) string {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var head struct {
		Op string `json:"op"`
	}
	if err := dec.Decode(&head); err != nil {
		return ""
	}
	return head.Op
}

func (s *Server) serveFeed(w http.ResponseWriter, r *http.Request, raw []byte) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var req struct {
		Op     string  `json:"op"`
		Module *string `json:"module"`
	}
	if err := dec.Decode(&req); err != nil {
		code, msg := decodeErr(err)
		s.writeErr(w, code, msg, req.Op)
		return
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			s.writeErr(w, "invalid_argument", "invalid json", req.Op)
			return
		}
		code, msg := decodeErr(err)
		s.writeErr(w, code, msg, req.Op)
		return
	}
	switch req.Op {
	case "feed.list":
		if req.Module != nil {
			s.writeErr(w, "invalid_argument", "unexpected field", req.Op)
			return
		}
		s.write(w, http.StatusOK, req.Op, struct {
			OK      bool          `json:"ok"`
			Modules []feed.Module `json:"modules"`
		}{OK: true, Modules: feed.Catalog()})
	case "feed.fetch":
		if req.Module == nil {
			s.writeErr(w, "invalid_argument", "invalid module", req.Op)
			return
		}
		inds, err := feed.Fetch(r.Context(), s.feeds, *req.Module)
		if err != nil {
			var fe *feed.Error
			if !errors.As(err, &fe) {
				s.writeErr(w, "unavailable", "feed fetch failed", req.Op)
				return
			}
			s.writeErr(w, fe.Code, fe.Msg, req.Op)
			return
		}
		if inds == nil {
			inds = []feed.Indicator{}
		}
		s.write(w, http.StatusOK, req.Op, struct {
			OK         bool             `json:"ok"`
			Module     string           `json:"module"`
			Indicators []feed.Indicator `json:"indicators"`
		}{OK: true, Module: *req.Module, Indicators: inds})
	default:
		s.writeErr(w, "invalid_argument", "invalid json", "-")
	}
}

func (s *Server) authorized(r *http.Request) bool {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return false
	}
	tok := h[len(prefix):]
	ok := auth.Equal(tok, s.key)
	if len(tok) < 32 || len(tok) > 256 {
		return false
	}
	return ok
}

func (s *Server) writeErr(w http.ResponseWriter, code, msg, op string) {
	s.write(w, statusFor(code), op, struct {
		OK    bool `json:"ok"`
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{OK: false, Error: struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}{Code: code, Message: msg}})
}

func (s *Server) write(w http.ResponseWriter, status int, op string, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	s.log.Printf("op=%s status=%d", safeOp(op), status)
}

func statusFor(code string) int {
	switch code {
	case "unauthorized":
		return http.StatusUnauthorized
	case "invalid_argument":
		return http.StatusBadRequest
	case "payload_too_large":
		return http.StatusRequestEntityTooLarge
	case "not_found":
		return http.StatusNotFound
	case "not_empty", "conflict":
		return http.StatusConflict
	case "timeout":
		return http.StatusGatewayTimeout
	case "unavailable":
		return http.StatusServiceUnavailable
	default:
		return http.StatusBadGateway
	}
}

func safeOp(op string) string {
	switch op {
	case "health", "ruleset.list", "table.add", "table.delete",
		"chain.add", "chain.delete", "rule.add", "rule.delete",
		"feed.list", "feed.fetch":
		return op
	default:
		return "-"
	}
}

func decodeErr(err error) (string, string) {
	var max *http.MaxBytesError
	if errors.As(err, &max) {
		return "payload_too_large", "payload too large"
	}
	var ne *nft.Error
	if errors.As(err, &ne) {
		return ne.Code, ne.Msg
	}
	return "invalid_argument", "invalid json"
}
