<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2017, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme;

use Exception;

/**
 * Generic ACME exception.
 *
 * @author Niklas Keller <me@kelunik.com>
 * @package Kelunik\Acme
 */
class AcmeException extends Exception {
    /**
     * AcmeException constructor.
     *
     * @param string          $message Detailed error message.
     * @param string|null     $code ACME error code.
     * @param \Throwable|null $previous Previous exception.
     */
    public function __construct(string $message, string $code = null, \Throwable $previous = null) {
        parent::__construct($message, 0, $previous);
        $this->code = $code;
    }
}