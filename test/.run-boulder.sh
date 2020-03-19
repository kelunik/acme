#!/usr/bin/env bash

docker pull letsencrypt/pebble
docker run -d -p 15000:15000 -p 14000:14000 --name boulder letsencrypt/pebble
#docker run -d --name boulder --net host letsencrypt/pebble
