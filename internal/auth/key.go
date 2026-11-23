// Threats: stops a short-circuit compare of the API key, and refuses a key
// file that is a symlink, has a mode other than 0400 or 0600, or is owned
// by a uid other than this process. Does not rate-limit guesses, rotate
// keys, or bind a key to a caller. Loopback bind is a separate control.
package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

const (
	minKey = 32
	maxKey = 256
)

// Load reads the key file. One trailing newline is removed. The file must
// be a regular file, mode 0400 or 0600, owned by the current uid, and not
// a symlink.
func Load(path string) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("key file: %w", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("key file: symlink refused")
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("key file: not a regular file")
	}
	perm := fi.Mode().Perm()
	if perm != 0o400 && perm != 0o600 {
		return nil, fmt.Errorf("key file: mode %o refused", perm)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, errors.New("key file: owner check unavailable")
	}
	if st.Uid != uint32(os.Getuid()) {
		return nil, errors.New("key file: owner is not this process")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, errors.New("key file: symlink refused")
		}
		return nil, fmt.Errorf("key file: %w", err)
	}
	defer f.Close()
	buf, err := io.ReadAll(io.LimitReader(f, maxKey+2))
	if err != nil {
		wipe(buf)
		return nil, fmt.Errorf("key file: %w", err)
	}
	defer wipe(buf)
	if len(buf) > maxKey+1 {
		return nil, errors.New("key file: too large")
	}
	if len(buf) > 0 && buf[len(buf)-1] == '\n' {
		buf = buf[:len(buf)-1]
	}
	if len(buf) < minKey || len(buf) > maxKey {
		return nil, errors.New("key file: length must be 32 to 256 bytes")
	}
	for _, c := range buf {
		if c == '\n' || c == '\r' || c == 0 {
			return nil, errors.New("key file: contains a newline or NUL")
		}
	}
	out := make([]byte, len(buf))
	copy(out, buf)
	return out, nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Equal reports whether got is the key. Both sides are SHA-256 hashed
// before the compare, so the compare does not stop at the first differing
// byte and does not leak the key length through the compare itself.
func Equal(got string, key []byte) bool {
	sumGot := sha256.Sum256([]byte(got))
	sumKey := sha256.Sum256(key)
	return subtle.ConstantTimeCompare(sumGot[:], sumKey[:]) == 1
}
