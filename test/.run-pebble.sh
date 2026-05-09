#!/usr/bin/env bash

docker pull ghcr.io/letsencrypt/pebble:latest
docker run --platform linux/amd64 -d --rm -e 'PEBBLE_VA_NOSLEEP=1' -e 'PEBBLE_VA_ALWAYS_VALID=1' -p 15000:15000 -p 14000:14000 --name pebble ghcr.io/letsencrypt/pebble:latest
