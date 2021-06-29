<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2017, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme\Crypto;

/**
 * Key generator interface to generate private keys.
 *
 * @author Niklas Keller <me@kelunik.com>
 * @package Kelunik\Acme
 */
interface KeyGenerator
{
    /**
     * Generates a new key pair.
     *
     * @return PrivateKey Resolves to the generated key pair.
     * @api
     */
    public function generateKey(): PrivateKey;
}
