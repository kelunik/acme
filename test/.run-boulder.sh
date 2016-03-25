#!/usr/bin/env bash

docker pull acmephp/testing-ca
docker run -d --name boulder --net host acmephp/testing-ca