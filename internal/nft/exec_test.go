package nft

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeScript(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "nft")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestExecArgvAndStdin(t *testing.T) {
	p := writeScript(t, "printf '%s\\n' \"$1\" \"$2\" \"$3\"\ncat\n")
	out, err := (&Exec{Path: p}).Run(context.Background(), []byte("{\"ok\":true}"))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "-j\n-f\n-\n{\"ok\":true}" {
		t.Fatalf("%q", out)
	}
}

func TestExecTimeout(t *testing.T) {
	p := writeScript(t, "sleep 5\n")
	start := time.Now()
	_, err := (&Exec{Path: p}).Run(context.Background(), nil)
	if !errors.Is(err, ErrTimeout) {
		t.Fatal(err)
	}
	if time.Since(start) > 4*time.Second {
		t.Fatal("timeout was late")
	}
}

func TestExecTooBig(t *testing.T) {
	p := writeScript(t, "dd if=/dev/zero bs=1024 count=1025 2>/dev/null\n")
	_, err := (&Exec{Path: p}).Run(context.Background(), nil)
	if !errors.Is(err, ErrTooBig) {
		t.Fatal(err)
	}
}

func TestExecStderr(t *testing.T) {
	p := writeScript(t, "i=0\nwhile [ \"$i\" -lt 500 ]; do printf E >&2; i=$((i+1)); done\nexit 1\n")
	_, err := (&Exec{Path: p}).Run(context.Background(), nil)
	var ne *Error
	if !errors.As(err, &ne) || len(ne.Msg) != 400 || strings.Trim(ne.Msg, "E") != "" {
		t.Fatalf("%v", err)
	}
	p = writeScript(t, "printf 'bad\\0thing\\n' >&2\nexit 1\n")
	_, err = (&Exec{Path: p}).Run(context.Background(), nil)
	if !errors.As(err, &ne) || ne.Msg != "badthing" {
		t.Fatalf("%v", err)
	}
	p = writeScript(t, "exit 1\n")
	_, err = (&Exec{Path: p}).Run(context.Background(), nil)
	if !errors.As(err, &ne) || ne.Msg != "nft failed" {
		t.Fatalf("%v", err)
	}
}

func TestExecMissing(t *testing.T) {
	_, err := (&Exec{Path: filepath.Join(t.TempDir(), "missing")}).Run(context.Background(), nil)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	_, err = (&Exec{}).Run(context.Background(), nil)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
}
