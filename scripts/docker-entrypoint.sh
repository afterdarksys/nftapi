#!/bin/sh
set -eu
rm -f /run/nftapi.key
cp /run/nftapi/key.in /run/nftapi.key
chown root:root /run/nftapi.key
chmod 600 /run/nftapi.key
NFTAPI_NFT=$(command -v nft)
export NFTAPI_NFT
export NFTAPI_KEY_FILE=/run/nftapi.key
export NFTAPI_ADDR="${NFTAPI_ADDR:-127.0.0.1:9789}"
exec "$@"
