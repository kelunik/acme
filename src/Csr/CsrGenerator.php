<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2017, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme\Csr;

use Kelunik\Acme\AcmeException;
use Kelunik\Acme\Crypto\PrivateKey;

/**
 * Allows generating certificate signing requests.
 *
 * @package Kelunik\Acme
 */
interface CsrGenerator
{
    /**
     * Generates a CSR for the given DNS names.
     *
     * @param PrivateKey $key Key to use for signing.
     * @param array      $domains List of domain names.
     *
     * @return string Resolves to a string (PEM encoded CSR).
     * @throws AcmeException If CSR generation fails.
     */
    public function generateCsr(PrivateKey $key, array $domains): string;
}
