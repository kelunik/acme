#!/usr/bin/env bash

docker pull acmephp/testing-ca:1.0.0
docker run -d --name boulder --net host acmephp/testing-ca:1.0.0