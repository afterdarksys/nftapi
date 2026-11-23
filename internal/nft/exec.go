package nft

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"time"
)

// Threats: argv is fixed (`-j -f -`) and the JSON document is the only
// input, so a request cannot choose a shell, an nft script, or a flush.
// It does not stop a holder of the key from dropping traffic in this
// network namespace. Stdout is capped at 1 MiB. The process is killed
// after 2 seconds.

const (
	nftTimeout = 2 * time.Second
	maxStdout  = 1 << 20
	maxStderr  = 8192
	maxMsg     = 400
)

var (
	ErrTimeout     = errors.New("nft timeout")
	ErrTooBig      = errors.New("nft output exceeded 1MiB")
	ErrUnavailable = errors.New("nft unavailable")
)

// Exec runs the nft binary.
type Exec struct {
	Path string
}

func (e *Exec) Run(ctx context.Context, stdin []byte) ([]byte, error) {
	if e == nil || e.Path == "" {
		return nil, ErrUnavailable
	}
	runCtx, cancel := context.WithTimeout(ctx, nftTimeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, e.Path, Argv()...)
	cmd.Stdin = bytes.NewReader(stdin)
	cmd.WaitDelay = 200 * time.Millisecond
	stdout := &limitBuf{max: maxStdout}
	stderr := &truncBuf{max: maxStderr}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	if stdout.over {
		return nil, ErrTooBig
	}
	if runCtx.Err() != nil {
		return nil, ErrTimeout
	}
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
			return nil, ErrUnavailable
		}
		return nil, nftFailed(trimMsg(stderr.buf))
	}
	return stdout.buf, nil
}

type limitBuf struct {
	buf  []byte
	max  int
	over bool
}

func (l *limitBuf) Write(p []byte) (int, error) {
	if l.over || len(l.buf)+len(p) > l.max {
		l.over = true
		return 0, ErrTooBig
	}
	l.buf = append(l.buf, p...)
	return len(p), nil
}

type truncBuf struct {
	buf []byte
	max int
}

func (t *truncBuf) Write(p []byte) (int, error) {
	if rem := t.max - len(t.buf); rem > 0 {
		if len(p) < rem {
			rem = len(p)
		}
		t.buf = append(t.buf, p[:rem]...)
	}
	return len(p), nil
}

func trimMsg(b []byte) string {
	b = bytes.ReplaceAll(b, []byte{0}, nil)
	b = bytes.TrimSpace(b)
	if len(b) > maxMsg {
		b = b[:maxMsg]
	}
	if len(b) == 0 {
		return "nft failed"
	}
	return string(b)
}
