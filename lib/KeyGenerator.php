<?php

namespace Kelunik\Acme;

/**
 * @author Niklas Keller <me@kelunik.com>
 * @copyright Copyright (c) 2015, Niklas Keller
 * @package Kelunik\Acme
 */
interface KeyGenerator {
    /**
     * Generates a new key pair with the given length in bits.
     *
     * @api
     * @param int $bits length of the key
     * @return KeyPair generated key pair
     */
    public function generate($bits);
}