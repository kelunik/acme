<?php

namespace Kelunik\Acme;

interface KeyGenerator {
    public function generate(int $bits): KeyPair;
}