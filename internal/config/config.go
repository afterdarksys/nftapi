// Package config loads the process settings. The listen address is refused
// unless it is a literal loopback IP and an explicit port.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	Addr    string
	KeyFile string
	Nft     string
}

func Load() (Config, error) {
	addr := os.Getenv("NFTAPI_ADDR")
	if addr == "" {
		addr = "127.0.0.1:9789"
	}
	if err := ValidateAddr(addr); err != nil {
		return Config{}, err
	}
	keyFile := os.Getenv("NFTAPI_KEY_FILE")
	if keyFile == "" {
		return Config{}, errors.New("NFTAPI_KEY_FILE is required")
	}
	nftPath, err := ResolveNft(os.Getenv("NFTAPI_NFT"))
	if err != nil {
		return Config{}, err
	}
	return Config{Addr: addr, KeyFile: keyFile, Nft: nftPath}, nil
}

// ValidateAddr accepts only a literal loopback IP and a port from 1 to 65535.
func ValidateAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("listen address: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("listen address must be a literal loopback IP")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return errors.New("listen port must be 1 to 65535")
	}
	return nil
}

// ResolveNft returns an absolute path to the nft binary. A value containing
// a slash must already be absolute. A bare name is looked up on PATH once.
func ResolveNft(path string) (string, error) {
	if path == "" {
		path = "nft"
	}
	if strings.Contains(path, "/") {
		if !filepath.IsAbs(path) {
			return "", errors.New("NFTAPI_NFT must be an absolute path")
		}
		return path, nil
	}
	found, err := exec.LookPath(path)
	if err != nil {
		return "", fmt.Errorf("nft: %w", err)
	}
	return found, nil
}
