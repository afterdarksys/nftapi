package config

import (
	"testing"
)

func TestLoad(t *testing.T) {
	t.Setenv("NFTAPI_KEY_FILE", "/tmp/nftapi.key")
	t.Setenv("NFTAPI_NFT", "/usr/sbin/nft")
	t.Setenv("NFTAPI_ADDR", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Addr != "127.0.0.1:9789" || cfg.Nft != "/usr/sbin/nft" || cfg.KeyFile != "/tmp/nftapi.key" {
		t.Fatalf("%+v", cfg)
	}
}

func TestLoadRequiresKeyFile(t *testing.T) {
	t.Setenv("NFTAPI_KEY_FILE", "")
	t.Setenv("NFTAPI_NFT", "/usr/sbin/nft")
	if _, err := Load(); err == nil {
		t.Fatal("missing key file was accepted")
	}
}

func TestValidateAddr(t *testing.T) {
	ok := []string{"127.0.0.1:9789", "127.1.2.3:1", "[::1]:9789"}
	for _, addr := range ok {
		if err := ValidateAddr(addr); err != nil {
			t.Fatalf("%s: %v", addr, err)
		}
	}
	bad := []string{"0.0.0.0:9789", "[::]:9789", "localhost:9789", "127.0.0.1:0", "127.0.0.1:65536", "10.0.0.1:9", "::1:9789"}
	for _, addr := range bad {
		if err := ValidateAddr(addr); err == nil {
			t.Fatalf("%s was accepted", addr)
		}
	}
}

func TestResolveNft(t *testing.T) {
	got, err := ResolveNft("/usr/sbin/nft")
	if err != nil || got != "/usr/sbin/nft" {
		t.Fatalf("%s %v", got, err)
	}
	if _, err := ResolveNft("bin/nft"); err == nil {
		t.Fatal("relative path was accepted")
	}
	if _, err := ResolveNft("nftapi-not-a-binary"); err == nil {
		t.Fatal("missing bare name was accepted")
	}
}
