<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2017, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme\Crypto;

final class PrivateKey
{
    private $pem;

    public function __construct(string $pem)
    {
        $this->pem = $pem;
    }

    public function toPem(): string
    {
        return $this->pem;
    }
}
