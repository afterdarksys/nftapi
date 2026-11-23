package main

import (
	"log"
	"os"

	"nftapi/internal/auth"
	"nftapi/internal/config"
	"nftapi/internal/httpapi"
	"nftapi/internal/nft"
)

func main() {
	logger := log.New(os.Stderr, "", 0)
	cfg, err := config.Load()
	if err != nil {
		logger.Fatal(err)
	}
	key, err := auth.Load(cfg.KeyFile)
	if err != nil {
		logger.Fatal(err)
	}
	srv := httpapi.New(key, &nft.Exec{Path: cfg.Nft}, logger)
	for i := range key {
		key[i] = 0
	}
	if err := srv.Listen(cfg.Addr); err != nil {
		logger.Fatal(err)
	}
}
