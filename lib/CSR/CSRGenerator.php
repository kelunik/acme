<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2016, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme\CSR;

use Amp\Promise;
use Kelunik\Acme\KeyPair;

/**
 * Allows generating certificate signing requests.
 *
 * @package Kelunik\Acme
 */
interface CSRGenerator {
    /**
     * Generates a CSR for the given DNS names.
     *
     * @param KeyPair $keyPair domain key pair
     * @param array $domains list of domain names
     * @return Promise resolves to a string (PEM encoded CSR)
     */
    public function generate(KeyPair $keyPair, array $domains);
}