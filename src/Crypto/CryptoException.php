<?php declare(strict_types=1);

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2025, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme\Crypto;

use Kelunik\Acme\AcmeException;

class CryptoException extends AcmeException
{
    public function __construct(string $message)
    {
        parent::__construct($message);
    }
}
