package auth

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeKey(t *testing.T, body []byte, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(p, body, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadAcceptsOwnerModes(t *testing.T) {
	body := []byte(strings.Repeat("k", 32) + "\n")
	for _, mode := range []os.FileMode{0o600, 0o400} {
		got, err := Load(writeKey(t, body, mode))
		if err != nil {
			t.Fatalf("mode %o: %v", mode, err)
		}
		if !bytes.Equal(got, bytes.Repeat([]byte("k"), 32)) {
			t.Fatalf("mode %o: key bytes mismatch", mode)
		}
	}
	long := bytes.Repeat([]byte("m"), 256)
	got, err := Load(writeKey(t, append(append([]byte(nil), long...), '\n'), 0o600))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, long) {
		t.Fatal("256-byte key mismatch")
	}
}

func TestLoadRejectsBadFiles(t *testing.T) {
	good := []byte(strings.Repeat("k", 32))
	cases := []struct {
		name string
		body []byte
		mode os.FileMode
		want string
	}{
		{"world", good, 0o644, "mode"},
		{"short", bytes.Repeat([]byte("k"), 31), 0o600, "length"},
		{"long", bytes.Repeat([]byte("k"), 257), 0o600, "length"},
		{"too big", append(bytes.Repeat([]byte("k"), 257), '\n'), 0o600, "too large"},
		{"newline", append([]byte(strings.Repeat("k", 16)+"\n"), bytes.Repeat([]byte("k"), 16)...), 0o600, "newline"},
		{"cr", append([]byte(strings.Repeat("k", 16)+"\r"), bytes.Repeat([]byte("k"), 16)...), 0o600, "newline"},
		{"nul", append(append(bytes.Repeat([]byte("k"), 16), 0), bytes.Repeat([]byte("k"), 16)...), 0o600, "newline"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeKey(t, tc.body, tc.mode))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestLoadRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.WriteFile(real, []byte(strings.Repeat("k", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	_, err := Load(link)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("got %v", err)
	}
}

func TestEqual(t *testing.T) {
	key := bytes.Repeat([]byte("k"), 32)
	if !Equal(string(key), key) {
		t.Fatal("same key")
	}
	if Equal(string(key)+"x", key) || Equal("short", key) || Equal(strings.Repeat("k", 300), key) || Equal("", key) {
		t.Fatal("mismatched key compared equal")
	}
}
