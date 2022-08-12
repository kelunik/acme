#!/usr/bin/env bash

docker pull letsencrypt/pebble
docker run --platform linux/amd64 -d -e 'PEBBLE_VA_NOSLEEP=1' -p 15000:15000 -p 14000:14000 --name pebble letsencrypt/pebble
